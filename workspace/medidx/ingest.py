"""影像入库：解析 -> 冻结原始摘要（封口）-> 建版本 1 -> 入派生队列。

冻结载荷写 vault（0700 目录，内容寻址）+ frozen_summaries 表（HMAC 封口，只增）。
冻结载荷含原始 PHI，除回链导出外任何服务/API 路径都不读取其明文。
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

from . import audit
from .dicom import parse
from .policy import default_rules
from .security import ApiError, new_id, seal_payload
from . import queue as queue_mod


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _vault_path(vault_dir: Path, sha: str) -> Path:
    return vault_dir / sha[:2] / f"{sha}.frozen.json"


def write_frozen(vault_dir: Path, payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    path = _vault_path(vault_dir, sha)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(raw)
        try:
            os.chmod(tmp, 0o600)
        except PermissionError:
            pass
        os.replace(tmp, path)
    return sha


def ingest(conn: sqlite3.Connection, *, cfg, project_id: str, raw: bytes,
           media_type: str | None, filename: str, user_id: str) -> dict:
    """幂等入库；返回 (image, version, already_exists)。同项目同内容只冻结一次。"""
    content_sha = hashlib.sha256(raw).hexdigest()
    existing = conn.execute(
        "SELECT id FROM images WHERE project_id=? AND content_sha256=?",
        (project_id, content_sha)).fetchone()
    if existing is not None:
        img = conn.execute("SELECT * FROM images WHERE id=?", (existing["id"],)).fetchone()
        ver = conn.execute(
            "SELECT * FROM derived_versions WHERE image_id=? AND revision=1",
            (img["id"],)).fetchone()
        audit.record(conn, cfg.audit_key, action="ingest.duplicate", actor_id=user_id,
                     object_type="image", object_id=img["id"],
                     detail={"content_sha256": content_sha})
        return {"image_id": img["id"], "version_id": ver["id"] if ver else None,
                "already_exists": True}

    ds = parse(raw, media_type=media_type, filename=filename)
    now = _iso_now()
    image_id = new_id()
    # 1) 冻结原始摘要（含 PHI）
    frozen_payload = {
        "schema": "frozen-dicom-summary/v1",
        "image_id": image_id,
        "project_id": project_id,
        "media_type": ds.media_type,
        "elements": ds.elements,
        "pixel_sheet": ds.pixel_sheet,
        "content_sha256": content_sha,
        "frozen_at": now,
    }
    stored_sha = write_frozen(cfg.vault_dir, frozen_payload)
    seal = seal_payload(cfg.seal_key, frozen_payload)
    if stored_sha != seal.payload_sha256:
        raise ApiError(500, "seal_mismatch", "冻结载荷哈希不一致，中止入库")

    # 2) 项目当前最高策略（未建策略则用默认 v1 的临时快照）
    pol = conn.execute(
        "SELECT * FROM policies WHERE project_id=? ORDER BY version DESC LIMIT 1",
        (project_id,)).fetchone()
    if pol is None:
        from .policy import create_policy
        policy_id = create_policy(
            conn, project_id=project_id, name="DEFAULT", rules=default_rules(1),
            version=1, notes="入库时自动创建的默认基础策略", user_id=user_id, now=now)
    else:
        policy_id = pol["id"]

    study_uid = ds.get("(0020,000d)")
    conn.execute(
        "INSERT INTO images(id, project_id, source_uid, media_type, content_sha256,"
        " current_revision, created_at) VALUES (?,?,?,?,?,?,?)",
        (image_id, project_id, str(study_uid) if study_uid is not None else None,
         ds.media_type, content_sha, 1, now))
    conn.execute(
        "INSERT INTO frozen_summaries(image_id, sealed_json, seal_hmac, payload_sha256,"
        " frozen_at, frozen_by) VALUES (?,?,?,?,?,?)",
        (image_id, seal.sealed_json, seal.seal_hmac, seal.payload_sha256, now, user_id))

    version_id = new_id()
    conn.execute(
        "INSERT INTO derived_versions(id, image_id, revision, policy_id, triggered_by,"
        " reason, status, created_at) VALUES (?,?,?,?,?,?, 'pending_qc',?)",
        (version_id, image_id, 1, policy_id, user_id, "initial_ingest", now))
    job_id = queue_mod.enqueue(conn, image_id=image_id, version_id=version_id, now=now)
    audit.record(conn, cfg.audit_key, action="ingest.frozen", actor_id=user_id,
                 object_type="image", object_id=image_id,
                 detail={"content_sha256": content_sha, "media_type": ds.media_type,
                         "version_id": version_id, "policy_id": policy_id,
                         "element_count": len(ds.elements)})
    return {"image_id": image_id, "version_id": version_id, "already_exists": False,
            "job_id": job_id}


def load_frozen(conn: sqlite3.Connection, cfg, image_id: str) -> dict:
    """读取并验封冻结载荷（仅限受控内部路径：回链导出）。"""
    row = conn.execute(
        "SELECT sealed_json, seal_hmac, payload_sha256 FROM frozen_summaries WHERE image_id=?",
        (image_id,)).fetchone()
    if row is None:
        raise ApiError(404, "frozen_not_found", "冻结摘要不存在")
    from .security import verify_seal
    payload = verify_seal(cfg.seal_key, row["sealed_json"], row["seal_hmac"],
                          row["payload_sha256"])
    vault_sha = hashlib.sha256(row["sealed_json"].encode("utf-8")).hexdigest()
    path = _vault_path(cfg.vault_dir, vault_sha)
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() != vault_sha:
        raise ApiError(409, "vault_tampered", "vault 冻结文件与库内封口不一致")
    return payload
