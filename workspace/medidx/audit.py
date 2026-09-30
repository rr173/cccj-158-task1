"""哈希链式审计日志。

每条事件包含前一条 entry_hash，形成只增哈希链；append-only 由数据库触发器兜底。
verify_chain 可全链重算检测任何缺口/重排/篡改；export 输出 CSV。
"""
from __future__ import annotations

import csv
import io
import json
import sqlite3
import time

from .security import ApiError, canonical, hmac_hex, new_id

GENESIS = "0" * 64


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def record(conn: sqlite3.Connection, audit_key: bytes, *, action: str,
           actor_id: str | None = None, object_type: str | None = None,
           object_id: str | None = None, detail: dict | None = None) -> dict:
    """串行化地追加一条审计事件。调用方须在应用事务内（与业务动作同提交/回滚）。"""
    detail_json = json.dumps(detail or {}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    row = conn.execute("SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    prev = row["entry_hash"] if row else GENESIS
    event_id = new_id()
    at = _iso_now()
    entry = canonical({
        "event_id": event_id, "actor_id": actor_id, "action": action,
        "object_type": object_type, "object_id": object_id,
        "detail_json": detail_json, "prev_hash": prev, "recorded_at": at,
    })
    entry_hash = hmac_hex(audit_key, prev.encode(), entry)
    conn.execute(
        "INSERT INTO audit_events(event_id, actor_id, action, object_type, object_id,"
        " detail_json, prev_hash, entry_hash, recorded_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (event_id, actor_id, action, object_type, object_id,
         detail_json, prev, entry_hash, at))
    return {"event_id": event_id, "entry_hash": entry_hash}


def list_events(conn: sqlite3.Connection, *, limit: int = 500, action: str | None = None,
                object_type: str | None = None, object_id: str | None = None) -> list[dict]:
    sql, args = "SELECT * FROM audit_events WHERE 1=1", []
    if action:
        sql += " AND action=?"
        args.append(action)
    if object_type:
        sql += " AND object_type=?"
        args.append(object_type)
    if object_id:
        sql += " AND object_id=?"
        args.append(object_id)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def verify_chain(conn: sqlite3.Connection, audit_key: bytes) -> dict:
    rows = conn.execute("SELECT * FROM audit_events ORDER BY id ASC").fetchall()
    prev = GENESIS
    for i, r in enumerate(rows):
        if r["prev_hash"] != prev:
            raise ApiError(409, "audit_chain_broken",
                           f"审计链断裂于第 {i + 1} 条（{r['event_id']}）：prev_hash 不衔接")
        entry = canonical({
            "event_id": r["event_id"], "actor_id": r["actor_id"], "action": r["action"],
            "object_type": r["object_type"], "object_id": r["object_id"],
            "detail_json": r["detail_json"], "prev_hash": r["prev_hash"],
            "recorded_at": r["recorded_at"],
        })
        expect = hmac_hex(audit_key, prev.encode(), entry)
        if expect != r["entry_hash"]:
            raise ApiError(409, "audit_chain_tampered",
                           f"审计事件内容被篡改：{r['event_id']}")
        prev = r["entry_hash"]
    return {"events": len(rows), "tip": prev, "ok": True}


def export_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["seq", "event_id", "recorded_at", "actor_id", "action",
                     "object_type", "object_id", "prev_hash", "entry_hash", "detail_json"])
    for i, r in enumerate(rows, 1):
        writer.writerow([i, r["event_id"], r["recorded_at"], r["actor_id"], r["action"],
                         r["object_type"], r["object_id"], r["prev_hash"],
                         r["entry_hash"], r["detail_json"]])
    return buf.getvalue()
