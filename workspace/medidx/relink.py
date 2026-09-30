"""受控回链。

授权（relink_grants）：
* 申请人必须是临床医生（clinician），审批人必须是隐私官（privacy_officer），
  两者不能为同一人（CHECK requested_by <> approved_by）；
* 授权绑定 病例(image) + 项目 + 目的(purpose) + 时间窗 [window_start, window_end]；
* 状态机 active -> exported/revoked/expired，由数据库触发器约束，终态不可再变。

导出（relink_exports）：
* 授权创建后一次性生成领取令牌（仅返回一次明文，库内只存 SHA-256）；
* 领取在单条条件 UPDATE 上原子完成：必须同时满足
  grant=active + 未领取 + 当前时间在窗内。撤销与领取并发时只有一个赢家，
  撤销若先到，领取得到 revoked_race 且绝不吐身份；
* 领取成功立即把授权置 exported（"导出后立即失效"），令牌再用即拒；
* 导出载荷来自验封后的冻结摘要，每次导出留审计。
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
from datetime import datetime, timezone

from . import audit
from .ingest import load_frozen
from .security import ApiError, new_id, new_token


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _parse_window(value: str) -> datetime:
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ApiError(400, "bad_window", "时间格式应为 YYYY-MM-DDTHH:MM（UTC）")


def create_grant(conn: sqlite3.Connection, *, cfg, image_id: str, purpose: str,
                 window_start: str, window_end: str, requested_by: str,
                 approved_by: str) -> dict:
    ws, we = _parse_window(window_start), _parse_window(window_end)
    if we <= ws:
        raise ApiError(400, "bad_window", "时间窗结束必须晚于开始")
    now = datetime.now(timezone.utc)
    if we <= now:
        raise ApiError(400, "bad_window", "时间窗必须延伸到未来")

    requester = conn.execute("SELECT role FROM users WHERE id=?", (requested_by,)).fetchone()
    approver = conn.execute("SELECT role FROM users WHERE id=?", (approved_by,)).fetchone()
    if requester is None or approver is None:
        raise ApiError(404, "user_not_found", "用户不存在")
    if requester["role"] != "clinician":
        raise ApiError(403, "not_clinician", "仅临床医生可申请回链")
    if approver["role"] != "privacy_officer":
        raise ApiError(403, "not_privacy_officer", "仅隐私官可审批回链")

    img = conn.execute("SELECT * FROM images WHERE id=?", (image_id,)).fetchone()
    if img is None:
        raise ApiError(404, "image_not_found", "病例不存在")

    grant_id = new_id()
    export_id = new_id()
    token = new_token()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now_s = _iso_now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute(
            "INSERT INTO relink_grants(id, image_id, project_id, purpose, requested_by,"
            " approved_by, window_start, window_end, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,'active',?)",
            (grant_id, image_id, img["project_id"], purpose, requested_by, approved_by,
             window_start, window_end, now_s))
        conn.execute(
            "INSERT INTO relink_exports(id, grant_id, token_hash, created_at)"
            " VALUES (?,?,?,?)",
            (export_id, grant_id, token_hash, now_s))
        audit.record(conn, cfg.audit_key, action="relink.grant_created",
                     actor_id=approved_by, object_type="relink_grant", object_id=grant_id,
                     detail={"image_id": image_id, "purpose": purpose,
                             "window_start": window_start, "window_end": window_end,
                             "requested_by": requested_by})
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    # 明文令牌仅此一次返回
    return {"grant_id": grant_id, "export_id": export_id, "one_time_token": token,
            "expires_at": window_end}


def revoke_grant(conn: sqlite3.Connection, *, cfg, grant_id: str, revoked_by: str,
                 reason: str) -> dict:
    """撤销：active -> revoked。若领取同时进行，由条件更新决出唯一赢家。"""
    row = conn.execute("SELECT * FROM relink_grants WHERE id=?", (grant_id,)).fetchone()
    if row is None:
        raise ApiError(404, "grant_not_found", "授权不存在")
    approver = conn.execute("SELECT role FROM users WHERE id=?", (revoked_by,)).fetchone()
    if approver is None or approver["role"] != "privacy_officer":
        raise ApiError(403, "not_privacy_officer", "仅隐私官可撤销回链授权")

    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "UPDATE relink_grants SET status='revoked', revoke_reason=?, revoked_by=?,"
            " revoked_at=? WHERE id=? AND status='active'",
            (reason, revoked_by, _iso_now(), grant_id))
        if cur.rowcount == 1:
            audit.record(conn, cfg.audit_key, action="relink.revoked", actor_id=revoked_by,
                         object_type="relink_grant", object_id=grant_id,
                         detail={"reason": reason})
            conn.execute("COMMIT")
            return {"grant_id": grant_id, "status": "revoked", "revoked": True}
        # 已被领取（exported）或已撤销/过期：给出确定结果，不暴露任何身份
        fresh = conn.execute("SELECT status FROM relink_grants WHERE id=?",
                             (grant_id,)).fetchone()
        audit.record(conn, cfg.audit_key, action="relink.revoke_late",
                     actor_id=revoked_by, object_type="relink_grant", object_id=grant_id,
                     detail={"state": fresh["status"], "reason": reason})
        conn.execute("COMMIT")
        return {"grant_id": grant_id, "status": fresh["status"], "revoked": False}
    except Exception:
        conn.execute("ROLLBACK")
        raise


def redeem_token(conn: sqlite3.Connection, *, cfg, token: str, user_id: str) -> dict:
    """一次性领取原身份。所有失败路径返回理由但绝不附带身份数据。"""
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now_s = _iso_now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        exp = conn.execute("SELECT * FROM relink_exports WHERE token_hash=?",
                           (token_hash,)).fetchone()
        if exp is None:
            conn.execute("ROLLBACK")
            raise ApiError(404, "bad_token", "领取凭证无效")
        grant = conn.execute("SELECT * FROM relink_grants WHERE id=?",
                             (exp["grant_id"],)).fetchone()

        # 一次性：已领取的凭证任何情况下都不再可用
        if exp["claimed_at"] is not None:
            conn.execute("ROLLBACK")
            raise ApiError(409, "token_already_used",
                           "凭证已使用：回链导出为一次性，授权已失效")
        # 时间窗判定（不改状态先判断）
        now = datetime.now(timezone.utc)
        win_start = _parse_window(grant["window_start"])
        win_end = _parse_window(grant["window_end"])
        in_window = win_start <= now <= win_end

        if not in_window:
            # active 才迁移 expired；撤销/已导出等终态不碰（状态机触发器保证）
            conn.execute(
                "UPDATE relink_grants SET status='expired' WHERE id=? AND status='active'",
                (grant["id"],))
            conn.execute("UPDATE relink_exports SET outcome='window_closed' WHERE id=?",
                         (exp["id"],))
            audit.record(conn, cfg.audit_key, action="relink.redeem_denied",
                         actor_id=user_id, object_type="relink_grant", object_id=grant["id"],
                         detail={"reason": "outside_window", "at": now_s})
            conn.execute("COMMIT")
            raise ApiError(403, "outside_window", "当前时间不在授权时间窗内")

        # 竞态裁决：单条原子条件 UPDATE。
        # 与撤销并发时，revoke 的 WHERE status='active' 与本 UPDATE 只有一个会改到行。
        cur = conn.execute(
            "UPDATE relink_grants SET status='exported' WHERE id=? AND status='active'",
            (grant["id"],))
        if cur.rowcount != 1:
            # 行已被并发撤销（或被其他路径置终态）：重新读取确定原因，绝不解密身份
            fresh = conn.execute("SELECT status FROM relink_grants WHERE id=?",
                                 (grant["id"],)).fetchone()
            reason = fresh["status"] if fresh is not None else "missing"
            outcome = {"revoked": "revoked_race", "expired": "expired",
                       "exported": "grant_exported"}.get(reason, "grant_not_active")
            conn.execute("UPDATE relink_exports SET outcome=? WHERE id=?",
                         (outcome, exp["id"]))
            audit.record(conn, cfg.audit_key, action="relink.redeem_denied",
                         actor_id=user_id, object_type="relink_grant", object_id=grant["id"],
                         detail={"reason": reason, "race": True})
            conn.execute("COMMIT")
            if reason == "revoked":
                raise ApiError(409, "revoked_race",
                               "授权在领取瞬间被撤销，本次不返回任何身份信息")
            raise ApiError(409, "grant_not_active",
                           f"授权当前状态为 {reason}，拒绝回链")

        # 认领成功才核销凭证并解密冻结摘要 —— 身份数据存在时间最短
        conn.execute(
            "UPDATE relink_exports SET claimed_at=?, outcome='exposed', exposed_at=? WHERE id=?",
            (now_s, now_s, exp["id"]))
        payload = load_frozen(conn, cfg, grant["image_id"])
        identity = {
            "patient_name": payload["elements"].get("(0010,0010)"),
            "patient_id": payload["elements"].get("(0010,0020)"),
            "birth_date": payload["elements"].get("(0010,0030)"),
            "accession_number": payload["elements"].get("(0008,0050)"),
            "study_instance_uid": payload["elements"].get("(0020,000d)"),
        }
        audit.record(conn, cfg.audit_key, action="relink.exposed", actor_id=user_id,
                     object_type="relink_grant", object_id=grant["id"],
                     detail={"image_id": grant["image_id"], "purpose": grant["purpose"]})
        conn.execute("COMMIT")
        return {
            "grant_id": grant["id"],
            "image_id": grant["image_id"],
            "purpose": grant["purpose"],
            "exposed_at": now_s,
            "identity": identity,
            "note": "一次性导出已完成，授权立即失效；请在最小必要范围内使用并记录于病历。",
        }
    except ApiError:
        raise
    except Exception:
        conn.execute("ROLLBACK")
        raise


def list_grants(conn: sqlite3.Connection, *, image_id: str | None = None) -> list[dict]:
    sql = ("SELECT g.*, u1.display_name AS requester_name, u2.display_name AS approver_name"
           " FROM relink_grants g JOIN users u1 ON u1.id=g.requested_by"
           " JOIN users u2 ON u2.id=g.approved_by")
    args: list = []
    if image_id:
        sql += " WHERE g.image_id=?"
        args.append(image_id)
    sql += " ORDER BY g.created_at DESC"
    rows = conn.execute(sql, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        out.append(d)
    return out
