"""服务层：连接、会话鉴权、面向 API 的查询/动作编排（去标识安全视图）。"""
from __future__ import annotations

import json
import sqlite3
import time

from . import audit, derive, ingest, policy as policy_mod, queue as queue_mod, relink
from .config import Config
from .db import connect, init_db
from .pixel import render_svg
from .security import (
    ApiError, ROLE_ADMIN, ROLE_CLINICIAN, ROLE_PRIVACY_OFFICER, ROLE_QC_REVIEWER,
    new_token,
)

SESSION_TTL = 8 * 3600


class Service:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.ensure_dirs()
        self._local = __import__("threading").local()
        self.conn = self._open()  # 初始化建库
        init_db(self.conn)

    def _open(self):
        return connect(self.cfg.db_path)

    @property
    def conn(self):
        """每线程独立连接：HTTP 多线程下事务绝不交错；SQLite 用 BEGIN IMMEDIATE 串行化。"""
        c = getattr(self._local, "conn", None)
        if c is None:
            c = self._open()
            self._local.conn = c
        return c

    @conn.setter
    def conn(self, value):
        # 构造期直连写入（init 用）；线程局部延迟建立
        self._local.__dict__["conn"] = value

    def release_conn(self) -> None:
        """请求结束关闭该线程连接（线程结束时也会自动回收）。"""
        c = getattr(self._local, "conn", None)
        if c is not None:
            try:
                c.close()
            finally:
                self._local.conn = None

    # ---- 会话/鉴权 ----
    def login(self, username: str) -> dict:
        row = self.conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            raise ApiError(401, "bad_login", "用户名不存在（演示环境无需密码）")
        token = new_token()
        now = time.time()
        self.conn.execute("INSERT INTO sessions(token, user_id, issued_at, expires_at)"
                          " VALUES (?,?,?,?)", (token, row["id"], now, now + SESSION_TTL))
        audit.record(self.conn, self.cfg.audit_key, action="auth.login",
                     actor_id=row["id"], object_type="user", object_id=row["id"])
        return {"token": token, "user": self._user_public(row)}

    def authenticate(self, token: str | None) -> sqlite3.Row:
        if not token:
            raise ApiError(401, "unauthorized", "缺少会话令牌")
        row = self.conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?",
            (token,)).fetchone()
        if row is None:
            raise ApiError(401, "unauthorized", "会话无效或已过期")
        if time.time() > self.conn.execute(
                "SELECT expires_at FROM sessions WHERE token=?", (token,)).fetchone()[0]:
            raise ApiError(401, "session_expired", "会话已过期")
        return row

    def require_role(self, user: sqlite3.Row, *roles: str) -> None:
        if user["role"] not in roles:
            raise ApiError(403, "forbidden_role",
                           f"该操作需要角色 {'/'.join(roles)}，当前为 {user['role']}")

    @staticmethod
    def _user_public(row: sqlite3.Row) -> dict:
        return {"id": row["id"], "username": row["username"],
                "display_name": row["display_name"], "role": row["role"]}

    # ---- 项目 ----
    def create_project(self, user, name: str, description: str = "") -> dict:
        from .security import new_id
        pid = new_id()
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            self.conn.execute(
                "INSERT INTO projects(id, name, description, created_at) VALUES (?,?,?,?)",
                (pid, name, description, now))
        except sqlite3.IntegrityError as exc:
            raise ApiError(409, "project_exists", "项目名已存在") from exc
        audit.record(self.conn, self.cfg.audit_key, action="project.created",
                     actor_id=user["id"], object_type="project", object_id=pid,
                     detail={"name": name})
        return {"id": pid, "name": name, "description": description}

    def list_projects(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM projects ORDER BY created_at").fetchall()]

    # ---- 策略 ----
    def create_policy(self, user, project_id: str, name: str, rules: dict | None,
                      version: int | None, notes: str) -> dict:
        self.require_role(user, ROLE_PRIVACY_OFFICER)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pid = policy_mod.create_policy(self.conn, project_id=project_id, name=name,
                                       rules=rules, version=version, notes=notes,
                                       user_id=user["id"], now=now)
        audit.record(self.conn, self.cfg.audit_key, action="policy.created",
                     actor_id=user["id"], object_type="policy", object_id=pid,
                     detail={"project_id": project_id, "name": name})
        return self.get_policy(user, pid)

    def get_policy(self, user, policy_id: str) -> dict:
        pol = policy_mod.get_policy(self.conn, policy_id)
        return {"id": pol["id"], "project_id": pol["project_id"], "name": pol["name"],
                "version": pol["version"], "notes": pol["notes"],
                "created_at": pol["created_at"],
                "rules": policy_mod.describe_rules(policy_mod.rules_of(pol))}

    def list_policies(self, project_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM policies WHERE project_id=? ORDER BY name, version",
            (project_id,)).fetchall()
        return [{"id": r["id"], "name": r["name"], "version": r["version"],
                 "notes": r["notes"], "created_at": r["created_at"],
                 "rules_count": len(json.loads(r["rules_json"]))} for r in rows]

    # ---- 入库 ----
    def ingest(self, user, project_id: str, raw: bytes, media_type: str | None,
               filename: str) -> dict:
        return ingest.ingest(self.conn, cfg=self.cfg, project_id=project_id, raw=raw,
                             media_type=media_type, filename=filename, user_id=user["id"])

    def _version_view(self, row: sqlite3.Row, *, include_artifact: bool = False) -> dict:
        pol = self.conn.execute("SELECT name, version FROM policies WHERE id=?",
                                (row["policy_id"],)).fetchone()
        findings = [dict(r) for r in self.conn.execute(
            "SELECT severity, code, message, detail_json, created_at FROM qc_findings"
            " WHERE version_id=? ORDER BY created_at", (row["id"],)).fetchall()]
        steps = [dict(r) for r in self.conn.execute(
            "SELECT step_no, name, detail_json, recorded_at FROM processing_steps"
            " WHERE version_id=? ORDER BY step_no, recorded_at", (row["id"],)).fetchall()]
        attempts = [dict(r) for r in self.conn.execute(
            "SELECT attempt_no, worker_id, result, error_code, started_at, finished_at"
            " FROM processing_attempts WHERE version_id=? ORDER BY attempt_no",
            (row["id"],)).fetchall()]
        d = {"id": row["id"], "image_id": row["image_id"], "revision": row["revision"],
             "policy_id": row["policy_id"], "policy_name": pol["name"],
             "policy_version": pol["version"], "triggered_by": row["triggered_by"],
             "reason": row["reason"], "status": row["status"],
             "phi_residual_count": row["phi_residual_count"],
             "mask_region_count": row["mask_region_count"],
             "created_at": row["created_at"], "published_at": row["published_at"],
             "findings": findings, "steps": steps, "attempts": attempts}
        if include_artifact and row["artifact_sha256"] and row["status"] in (
                "pending_qc", "published"):
            art = derive.load_artifact(self.cfg, row["artifact_sha256"])
            d["elements"] = art["elements"]
            # 派生 SVG 不输出任何已遮盖文本原文
            d["svg"] = render_svg(art["pixel_sheet"], known_phi=None)
        return d

    def list_images(self, project_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM images WHERE project_id=? ORDER BY created_at",
            (project_id,)).fetchall()
        out = []
        for r in rows:
            versions = self.conn.execute(
                "SELECT revision, status, reason FROM derived_versions WHERE image_id=?"
                " ORDER BY revision", (r["id"],)).fetchall()
            out.append({"id": r["id"], "media_type": r["media_type"],
                        "created_at": r["created_at"],
                        "current_revision": r["current_revision"],
                        "versions": [dict(v) for v in versions]})
        return out

    def get_version(self, user, version_id: str, include_artifact: bool = True) -> dict:
        row = self.conn.execute("SELECT * FROM derived_versions WHERE id=?",
                                (version_id,)).fetchone()
        if row is None:
            raise ApiError(404, "version_not_found", "版本不存在")
        return self._version_view(row, include_artifact=include_artifact)

    def list_versions_for_image(self, image_id: str) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM derived_versions WHERE image_id=? ORDER BY revision",
            (image_id,)).fetchall()
        return [self._version_view(r, include_artifact=False) for r in rows]

    def pending_qc_queue(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT * FROM derived_versions WHERE status='pending_qc'"
            " AND artifact_sha256 IS NOT NULL ORDER BY created_at").fetchall()
        return [self._version_view(r, include_artifact=False) for r in rows]

    def publish(self, user, version_id: str) -> dict:
        self.require_role(user, ROLE_QC_REVIEWER)
        return derive.publish_version(self.conn, cfg=self.cfg, version_id=version_id,
                                      user_id=user["id"])

    def reject(self, user, version_id: str, reason: str) -> None:
        self.require_role(user, ROLE_QC_REVIEWER)
        derive.reject_version(self.conn, cfg=self.cfg, version_id=version_id,
                              reason=reason, user_id=user["id"])

    def new_revision(self, user, image_id: str, reason: str,
                     policy_id: str | None = None) -> dict:
        if reason not in ("policy_upgrade", "clinical_correction"):
            raise ApiError(400, "bad_reason", "reason 须为 policy_upgrade/clinical_correction")
        if reason == "policy_upgrade":
            self.require_role(user, ROLE_PRIVACY_OFFICER, ROLE_QC_REVIEWER)
        return derive.create_derived_version(
            self.conn, cfg=self.cfg, image_id=image_id, reason=reason,
            user_id=user["id"], policy_id=policy_id)

    def retry_dead(self, user, image_id: str) -> None:
        self.require_role(user, ROLE_ADMIN, ROLE_QC_REVIEWER)
        queue_mod.retry_dead(self.conn, image_id=image_id)
        audit.record(self.conn, self.cfg.audit_key, action="queue.retry_dead",
                     actor_id=user["id"], object_type="image", object_id=image_id)

    def queue_list(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT j.*, i.project_id FROM queue_jobs j JOIN images i ON i.id=j.image_id"
            " ORDER BY j.created_at").fetchall()
        return [dict(r) for r in rows]

    # ---- 回链 ----
    def create_grant(self, user, image_id: str, purpose: str, window_start: str,
                     window_end: str, approver_username: str) -> dict:
        self.require_role(user, ROLE_CLINICIAN)
        approver = self.conn.execute("SELECT * FROM users WHERE username=?",
                                     (approver_username,)).fetchone()
        if approver is None:
            raise ApiError(404, "approver_not_found", "审批隐私官不存在")
        return relink.create_grant(
            self.conn, cfg=self.cfg, image_id=image_id, purpose=purpose,
            window_start=window_start, window_end=window_end,
            requested_by=user["id"], approved_by=approver["id"])

    def revoke_grant(self, user, grant_id: str, reason: str) -> dict:
        self.require_role(user, ROLE_PRIVACY_OFFICER)
        return relink.revoke_grant(self.conn, cfg=self.cfg, grant_id=grant_id,
                                   revoked_by=user["id"], reason=reason)

    def redeem(self, user, token: str) -> dict:
        self.require_role(user, ROLE_CLINICIAN)
        return relink.redeem_token(self.conn, cfg=self.cfg, token=token,
                                   user_id=user["id"])

    def list_grants(self, user, image_id: str | None = None) -> list[dict]:
        self.require_role(user, ROLE_PRIVACY_OFFICER, ROLE_ADMIN)
        return relink.list_grants(self.conn, image_id=image_id)

    # ---- 审计 ----
    def audit_list(self, user, **filters) -> list[dict]:
        self.require_role(user, ROLE_ADMIN, ROLE_PRIVACY_OFFICER)
        return audit.list_events(self.conn, **filters)

    def audit_verify(self, user) -> dict:
        self.require_role(user, ROLE_ADMIN)
        return audit.verify_chain(self.conn, self.cfg.audit_key)

    def audit_export(self, user, **filters) -> str:
        self.require_role(user, ROLE_ADMIN)
        rows = audit.list_events(self.conn, **filters)
        result = audit.verify_chain(self.conn, self.cfg.audit_key)
        if not result["ok"]:
            raise ApiError(409, "audit_chain_broken", "导出前校验发现审计链异常")
        audit.record(self.conn, self.cfg.audit_key, action="audit.exported",
                     actor_id=user["id"], object_type="audit", object_id="*",
                     detail={"rows": len(rows), "filters": {k: v for k, v in filters.items() if v}})
        return audit.export_csv(rows)
