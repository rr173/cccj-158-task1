"""派生管线。

每个派生版本永远从**冻结摘要**重新计算（先验封再处理），所以策略升级可复现、可审计；
处理步骤逐行追加；遮盖瞬时故障走重试（新 attempt 行），持续故障/残留 PHI 走质检阻断；
没有任何路径能在质检通过前把版本置为 published。
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

from . import audit, pixel, policy as policy_mod, pseudonym, queue as queue_mod
from .security import ApiError, new_id, verify_seal

# 从冻结页的区域参数读取"遮盖器将在第 N 次尝试前失败"，便于确定性演示批量重试
FAIL_INJECT_KEY = "mask_fail_before_attempt"


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _artifact_path(vault_dir: Path, sha: str) -> Path:
    return vault_dir / "derived" / f"{sha}.artifact.json"


def write_artifact(vault_dir: Path, artifact: dict) -> str:
    raw = json.dumps(artifact, sort_keys=True, ensure_ascii=False,
                     separators=(",", ":")).encode("utf-8")
    sha = hashlib.sha256(raw).hexdigest()
    path = _artifact_path(vault_dir, sha)
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(raw)
        os.replace(tmp, path)
    return sha


def load_artifact(cfg, sha: str) -> dict:
    path = _artifact_path(cfg.vault_dir, sha)
    if not path.exists():
        raise ApiError(404, "artifact_missing", "派生工件文件缺失")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != sha:
        raise ApiError(409, "artifact_tampered", "派生工件哈希不一致")
    return json.loads(raw.decode("utf-8"))


def add_qc_finding(conn: sqlite3.Connection, *, version_id: str, severity: str,
                   code: str, message: str, detail: dict | None = None,
                   now: str | None = None) -> str:
    fid = new_id()
    conn.execute(
        "INSERT INTO qc_findings(id, version_id, severity, code, message, detail_json, created_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (fid, version_id, severity, code, message,
         json.dumps(detail or {}, ensure_ascii=False), now or _iso_now()))
    return fid


def _add_step(conn, *, version_id: str, attempt_id: str, no: int, name: str, detail: dict) -> None:
    conn.execute(
        "INSERT INTO processing_steps(id, version_id, attempt_id, step_no, name, detail_json, recorded_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (new_id(), version_id, attempt_id, no, name,
         json.dumps(detail, ensure_ascii=False, sort_keys=True), _iso_now()))


def create_derived_version(conn: sqlite3.Connection, *, cfg, image_id: str,
                           reason: str, user_id: str,
                           policy_id: str | None = None) -> dict:
    """策略升级/临床纠错：产生新 revision，绝不触碰旧版本。"""
    now = _iso_now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        img = conn.execute("SELECT * FROM images WHERE id=?", (image_id,)).fetchone()
        if img is None:
            conn.execute("ROLLBACK")
            raise ApiError(404, "image_not_found", "影像不存在")
        # 并发修订：已有未终审版本时拒绝（防止两个修订互相覆盖）
        busy = conn.execute(
            "SELECT id FROM derived_versions WHERE image_id=? AND status='pending_qc'",
            (image_id,)).fetchone()
        if busy is not None:
            conn.execute("ROLLBACK")
            raise ApiError(409, "concurrent_revision",
                           "该影像已有待质检版本，请先完成质检再发起新修订")
        if policy_id is None:
            pol = conn.execute(
                "SELECT * FROM policies WHERE project_id=? ORDER BY version DESC LIMIT 1",
                (img["project_id"],)).fetchone()
            policy_id = pol["id"]
        else:
            pol = conn.execute("SELECT * FROM policies WHERE id=?", (policy_id,)).fetchone()
            if pol is None or pol["project_id"] != img["project_id"]:
                conn.execute("ROLLBACK")
                raise ApiError(404, "policy_not_found", "策略不存在或不属于该项目")
        rev = conn.execute("SELECT COALESCE(MAX(revision),0)+1 r FROM derived_versions"
                           " WHERE image_id=?", (image_id,)).fetchone()["r"]
        vid = new_id()
        conn.execute(
            "INSERT INTO derived_versions(id, image_id, revision, policy_id, triggered_by,"
            " reason, status, created_at) VALUES (?,?,?,?,?,?, 'pending_qc',?)",
            (vid, image_id, rev, policy_id, user_id, reason, now))
        conn.execute("UPDATE images SET current_revision=? WHERE id=?", (rev, image_id))
        job_id = queue_mod.enqueue(conn, image_id=image_id, version_id=vid, now=now)
        audit.record(conn, cfg.audit_key, action="derive.version_created",
                     actor_id=user_id, object_type="derived_version", object_id=vid,
                     detail={"image_id": image_id, "revision": rev, "reason": reason,
                             "policy_id": policy_id})
        conn.execute("COMMIT")
        return {"version_id": vid, "revision": rev, "job_id": job_id}
    except ApiError:
        raise
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _run_pipeline(conn, frozen: dict, rules: dict, *, cfg, project_id: str, attempt_no: int):
    """纯计算管线：不碰数据库。返回 (outcome, payload)。

    outcome:
      transient      —— 遮盖器瞬时故障（payload 含 error），应退避重试
      unmaskable     —— 区域不可遮盖，版本必须驳回
      done           —— 管线完成，payload 含 masked_sheet/cleaned/residual/leaked/steps
    """
    steps: list[tuple[int, str, dict]] = []
    steps.append((1, "freeze.verify", {"seal": "ok", "payload_sha256": frozen["content_sha256"]}))

    elements = dict(frozen["elements"])
    sheet = dict(frozen["pixel_sheet"] or {"width": 256, "height": 256, "regions": []})
    pixel.validate_sheet(sheet)

    known_phi = [str(elements[t]) for t in ("(0010,0010)", "(0010,0020)", "(0008,0050)")
                 if elements.get(t) is not None]
    if elements.get("(0010,0030)"):
        known_phi.append(str(elements["(0010,0030)"]))

    phi_regions = pixel.locate_phi_regions(sheet, known_phi)
    # 步骤日志只记录数量与 PHI 指纹，不记录明文 OCR 内容（避免 PHI 经日志泄露）
    steps.append((2, "pixel.ocr_locate",
                  {"regions": [r.get("id") for r in phi_regions],
                   "ocr_read_count": len(pixel.run_ocr(sheet)),
                   "phi_fingerprints": [pixel.phi_fingerprint(o.text)
                                        for o in pixel.run_ocr(sheet)
                                        if pixel.classify_phi_text(o.text, known_phi)]}))

    fail_before = int(sheet.get(FAIL_INJECT_KEY, 0))
    try:
        masked_sheet = pixel.mask_regions(
            sheet, phi_regions, attempt_no=attempt_no, fail_before_attempt=fail_before)
    except pixel.TransientMaskError as exc:
        steps.append((3, "pixel.mask", {"outcome": "transient_failure", "error": str(exc)}))
        return "transient", {"error": "MASKER_BUSY", "steps": steps}
    except pixel.UnmaskableError as exc:
        steps.append((3, "pixel.mask", {"outcome": "unmaskable", "error": str(exc)}))
        return "unmaskable", {"error": str(exc), "steps": steps,
                              "phi_region_count": len(phi_regions)}
    steps.append((3, "pixel.mask", {"outcome": "masked", "count": len(phi_regions)}))

    residual = pixel.residual_phi_scan(masked_sheet, known_phi)
    steps.append((4, "pixel.residual_scan",
                  {"residual_count": len(residual),
                   "residual": [{"region": o.region_id,
                                 "text_fingerprint": pixel.phi_fingerprint(o.text)}
                                for o in residual]}))

    cleaned: dict[str, str] = {}
    tag_log = []
    for tag, value in elements.items():
        action = policy_mod.action_for(rules, tag)
        if action == "remove":
            tag_log.append({"tag": tag, "action": "remove"})
        elif action == "blank":
            cleaned[tag] = ""
            tag_log.append({"tag": tag, "action": "blank"})
        elif action == "keep":
            cleaned[tag] = value
            tag_log.append({"tag": tag, "action": "keep"})
        elif action == "shift":
            cleaned[tag] = pseudonym.shift_date(value, cfg.seal_key, project_id)
            tag_log.append({"tag": tag, "action": "shift"})
        elif action.startswith("replace:"):
            kind = action.split(":", 1)[1]
            salt = pseudonym._project_salt(conn, cfg.seal_key, project_id)
            alt = pseudonym._default_alt(kind, salt, str(value))
            cleaned[tag] = alt
            tag_log.append({"tag": tag, "action": f"replace:{kind}"})
    steps.append((5, "tags.policy_apply",
                  {"removed": sum(1 for x in tag_log if x["action"] == "remove"),
                   "replaced": [x["tag"] for x in tag_log if x["action"].startswith("replace")],
                   "shifted": [x["tag"] for x in tag_log if x["action"] == "shift"]}))

    leaked = []
    phi_values = {str(v).lower() for v in known_phi if v}
    for tag, value in cleaned.items():
        val = str(value).lower()
        if any(phi and phi in val for phi in phi_values):
            leaked.append(tag)
    steps.append((6, "tags.phi_self_check", {"leaked_tags": leaked}))

    return "done", {"masked_sheet": masked_sheet, "cleaned": cleaned,
                    "residual": residual, "leaked": leaked,
                    "phi_region_count": len(phi_regions), "steps": steps}


def _insert_attempt(conn, *, attempt_id, version_id, attempt_no, job_id, worker_id,
                    result, error_code, at) -> None:
    conn.execute(
        "INSERT INTO processing_attempts(id, version_id, attempt_no, job_id, worker_id,"
        " result, error_code, started_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (attempt_id, version_id, attempt_no, job_id, worker_id, result, error_code, at, at))


def process_job(conn: sqlite3.Connection, *, cfg, job: dict, worker_id: str) -> str:
    """执行一次已领取的派生任务。返回 ready_for_qc / rejected / retried / dead / failed。

    全部写库动作放在单个 BEGIN IMMEDIATE 事务：尝试行只增插入（结果在插入时即确定），
    处理步骤/质检发现只增，版本与队列状态原子推进。任何异常整体回滚——绝不会留下
    半成品版本。
    """
    version = conn.execute("SELECT * FROM derived_versions WHERE id=?",
                           (job["version_id"],)).fetchone()
    image = conn.execute("SELECT * FROM images WHERE id=?", (version["image_id"],)).fetchone()
    pol = policy_mod.get_policy(conn, version["policy_id"])
    rules = policy_mod.rules_of(pol)

    conn.execute("BEGIN IMMEDIATE")
    try:
        attempt_no = conn.execute(
            "SELECT COALESCE(MAX(attempt_no),0)+1 n FROM processing_attempts WHERE version_id=?",
            (version["id"],)).fetchone()["n"]
        attempt_id = new_id()
        at = _iso_now()

        frow = conn.execute(
            "SELECT sealed_json, seal_hmac, payload_sha256 FROM frozen_summaries WHERE image_id=?",
            (image["id"],)).fetchone()
        frozen = verify_seal(cfg.seal_key, frow["sealed_json"], frow["seal_hmac"],
                             frow["payload_sha256"])

        outcome, data = _run_pipeline(conn, frozen, rules, cfg=cfg,
                                      project_id=image["project_id"], attempt_no=attempt_no)

        if outcome == "transient":
            _insert_attempt(conn, attempt_id=attempt_id, version_id=version["id"],
                            attempt_no=attempt_no, job_id=job["id"], worker_id=worker_id,
                            result="mask_failure", error_code="MASKER_BUSY", at=at)
            for no, name, detail in data["steps"]:
                _add_step(conn, version_id=version["id"], attempt_id=attempt_id,
                          no=no, name=name, detail=detail)
            add_qc_finding(conn, version_id=version["id"], severity="warning",
                           code="mask_transient",
                           message=f"遮盖器瞬时故障（第 {attempt_no} 次尝试），已安排重试", now=at)
            state = queue_mod.mark_failure(
                conn, job, max_attempts=cfg.max_attempts,
                backoff_base=cfg.backoff_base_seconds, error="MASKER_BUSY")
            audit.record(conn, cfg.audit_key, action="derive.mask_transient",
                         actor_id=worker_id, object_type="derived_version",
                         object_id=version["id"], detail={"attempt": attempt_no})
            conn.execute("COMMIT")
            return "retried" if state == "queued" else "dead"

        if outcome == "unmaskable":
            _insert_attempt(conn, attempt_id=attempt_id, version_id=version["id"],
                            attempt_no=attempt_no, job_id=job["id"], worker_id=worker_id,
                            result="mask_failure", error_code="UNMASKABLE", at=at)
            for no, name, detail in data["steps"]:
                _add_step(conn, version_id=version["id"], attempt_id=attempt_id,
                          no=no, name=name, detail=detail)
            add_qc_finding(conn, version_id=version["id"], severity="blocker",
                           code="mask_unmaskable",
                           message="存在不可遮盖的烧录 PHI 区域，版本被自动驳回",
                           detail={"error": data["error"]}, now=at)
            conn.execute("UPDATE derived_versions SET status='rejected',"
                         " mask_region_count=? WHERE id=?",
                         (data["phi_region_count"], version["id"]))
            queue_mod.mark_failed(conn, job["id"], "UNMASKABLE_PHI_REGION")
            audit.record(conn, cfg.audit_key, action="derive.auto_rejected",
                         actor_id=worker_id, object_type="derived_version",
                         object_id=version["id"], detail={"reason": "unmaskable_phi"})
            conn.execute("COMMIT")
            return "failed"

        # outcome == done：建立映射（只增），落工件，写步骤
        for tag, value in frozen["elements"].items():
            action = policy_mod.action_for(rules, tag)
            if action.startswith("replace:"):
                kind = action.split(":", 1)[1]
                pseudonym.mapped_value(conn, cfg.seal_key, image["project_id"],
                                       kind, str(value), now=at)
        artifact = {
            "schema": "derived-artifact/v1",
            "image_id": image["id"],
            "version_id": version["id"],
            "revision": version["revision"],
            "policy_id": pol["id"],
            "policy_version": pol["version"],
            "elements": data["cleaned"],
            "pixel_sheet": data["masked_sheet"],
        }
        sha = write_artifact(cfg.vault_dir, artifact)
        data["steps"].append((7, "artifact.persist", {"artifact_sha256": sha}))

        residual, leaked = data["residual"], data["leaked"]
        blockers = []
        if residual:
            blockers.append(("pixel_residual_phi",
                             f"遮盖后二次 OCR 仍读到 {len(residual)} 处 PHI",
                             {"items": [{"region": o.region_id,
                                         "text_fingerprint": pixel.phi_fingerprint(o.text)}
                                        for o in residual]}))
        if leaked:
            blockers.append(("tag_phi_leak", f"标签清理结果仍含原身份值: {leaked}",
                             {"tags": leaked}))
        data["steps"].append((8, "qc.auto_summary", {"blockers": len(blockers)}))

        _insert_attempt(conn, attempt_id=attempt_id, version_id=version["id"],
                        attempt_no=attempt_no, job_id=job["id"], worker_id=worker_id,
                        result="success", error_code=None, at=at)
        for no, name, detail in data["steps"]:
            _add_step(conn, version_id=version["id"], attempt_id=attempt_id,
                      no=no, name=name, detail=detail)
        for code, message, detail in blockers:
            add_qc_finding(conn, version_id=version["id"], severity="blocker",
                           code=code, message=message, detail=detail, now=at)

        if blockers:
            conn.execute("UPDATE derived_versions SET status='rejected', artifact_sha256=?,"
                         " phi_residual_count=?, mask_region_count=? WHERE id=?",
                         (sha, len(residual), data["phi_region_count"], version["id"]))
            audit.record(conn, cfg.audit_key, action="derive.auto_rejected",
                         actor_id=worker_id, object_type="derived_version",
                         object_id=version["id"],
                         detail={"reasons": [c for c, _, _ in blockers]})
        else:
            conn.execute("UPDATE derived_versions SET status='pending_qc', artifact_sha256=?,"
                         " phi_residual_count=0, mask_region_count=? WHERE id=?",
                         (sha, data["phi_region_count"], version["id"]))
            audit.record(conn, cfg.audit_key, action="derive.ready_for_qc",
                         actor_id=worker_id, object_type="derived_version",
                         object_id=version["id"],
                         detail={"masked_regions": data["phi_region_count"]})
        queue_mod.mark_success(conn, job["id"])
        conn.execute("COMMIT")
        return "rejected" if blockers else "ready_for_qc"
    except Exception:
        conn.execute("ROLLBACK")
        raise


def publish_version(conn: sqlite3.Connection, *, cfg, version_id: str, user_id: str) -> dict:
    """人工质检发布：在同一事务内重验工件哈希 + blocker 清单，再置 published。"""
    now = _iso_now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        ver = conn.execute("SELECT * FROM derived_versions WHERE id=?",
                           (version_id,)).fetchone()
        if ver is None:
            conn.execute("ROLLBACK")
            raise ApiError(404, "version_not_found", "派生版本不存在")
        if ver["status"] == "published":
            conn.execute("ROLLBACK")
            raise ApiError(409, "already_published", "版本已发布")
        if ver["status"] == "rejected":
            conn.execute("ROLLBACK")
            raise ApiError(409, "version_rejected",
                           "版本已驳回（存在阻断性质检问题），请发起新修订而非发布")
        blockers = conn.execute(
            "SELECT COUNT(*) c FROM qc_findings WHERE version_id=? AND severity='blocker'",
            (version_id,)).fetchone()["c"]
        if blockers:
            conn.execute("ROLLBACK")
            raise ApiError(409, "qc_blockers", f"存在 {blockers} 条阻断性质检发现，禁止发布")
        if not ver["artifact_sha256"]:
            conn.execute("ROLLBACK")
            raise ApiError(409, "no_artifact", "派生工件缺失（处理尚未完成），禁止发布半成品")
        artifact = load_artifact(cfg, ver["artifact_sha256"])
        if artifact["version_id"] != version_id:
            conn.execute("ROLLBACK")
            raise ApiError(409, "artifact_mismatch", "工件与版本不绑定")
        # 发布前再做一次残留 PHI 复算，杜绝工件被调换
        known_phi = _known_phi_from_frozen(conn, cfg, ver["image_id"])
        residual = pixel.residual_phi_scan(artifact["pixel_sheet"], known_phi)
        if residual:
            add_qc_finding(conn, version_id=version_id, severity="blocker",
                           code="pixel_residual_phi_recheck",
                           message="发布前复验发现残留 PHI", now=now)
            conn.execute("UPDATE derived_versions SET status='rejected' WHERE id=?",
                         (version_id,))
            conn.execute("COMMIT")
            raise ApiError(409, "residual_phi_on_publish", "发布前复验发现残留 PHI，已驳回")
        conn.execute("UPDATE derived_versions SET status='published', published_at=? WHERE id=?",
                     (now, version_id))
        audit.record(conn, cfg.audit_key, action="qc.published", actor_id=user_id,
                     object_type="derived_version", object_id=version_id,
                     detail={"revision": ver["revision"]})
        conn.execute("COMMIT")
        return {"version_id": version_id, "status": "published", "published_at": now}
    except ApiError:
        raise
    except Exception:
        conn.execute("ROLLBACK")
        raise


def reject_version(conn: sqlite3.Connection, *, cfg, version_id: str, reason: str,
                   user_id: str) -> None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        ver = conn.execute("SELECT * FROM derived_versions WHERE id=?",
                           (version_id,)).fetchone()
        if ver is None:
            conn.execute("ROLLBACK")
            raise ApiError(404, "version_not_found", "派生版本不存在")
        if ver["status"] != "pending_qc":
            conn.execute("ROLLBACK")
            raise ApiError(409, "not_pending", "仅待质检版本可驳回")
        conn.execute("UPDATE derived_versions SET status='rejected' WHERE id=?", (version_id,))
        add_qc_finding(conn, version_id=version_id, severity="info", code="manual_reject",
                       message=f"人工驳回：{reason}")
        audit.record(conn, cfg.audit_key, action="qc.rejected", actor_id=user_id,
                     object_type="derived_version", object_id=version_id,
                     detail={"reason": reason})
        conn.execute("COMMIT")
    except ApiError:
        raise
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _known_phi_from_frozen(conn, cfg, image_id: str) -> list[str]:
    frow = conn.execute(
        "SELECT sealed_json, seal_hmac, payload_sha256 FROM frozen_summaries WHERE image_id=?",
        (image_id,)).fetchone()
    frozen = verify_seal(cfg.seal_key, frow["sealed_json"], frow["seal_hmac"],
                         frow["payload_sha256"])
    out = [str(frozen["elements"][t]) for t in
           ("(0010,0010)", "(0010,0020)", "(0008,0050)", "(0010,0030)")
           if frozen["elements"].get(t) is not None]
    return out
