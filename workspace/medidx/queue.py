"""处理队列：原子租约、指数退避重试、死信、崩溃租约回收。

租约/领取全部在单个 BEGIN IMMEDIATE 事务内用条件 UPDATE 完成，
两个 worker 同时抢同一行只有一个成功（changes()=1）。
"""
from __future__ import annotations

import sqlite3
import time

from .security import ApiError, new_id


def _now() -> float:
    return time.time()


def enqueue(conn: sqlite3.Connection, *, image_id: str, version_id: str, now: str) -> str:
    job_id = new_id()
    # 初次插入；若该影像已有任务行（UNIQUE(image_id,kind)）则整体复活重置
    conn.execute(
        "INSERT INTO queue_jobs(id, image_id, version_id, kind, status, attempts,"
        " available_at, created_at) VALUES (?,?,?, 'derive','queued',0,?,?)"
        " ON CONFLICT(image_id, kind) DO UPDATE SET"
        " status='queued', attempts=0, available_at=excluded.available_at,"
        " lease_owner=NULL, lease_expires_at=NULL, last_error=NULL, version_id=excluded.version_id",
        (job_id, image_id, version_id, _now(), now))
    return job_id


def lease(conn: sqlite3.Connection, *, worker_id: str, lease_seconds: int) -> dict | None:
    """原子领取一个到期任务；同时回收崩溃 worker 的过期租约。"""
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT * FROM queue_jobs WHERE"
            " (status='queued' AND available_at<=:now)"
            " OR (status='leased' AND lease_expires_at<:now)"
            " ORDER BY available_at LIMIT 1",
            {"now": _now()}).fetchone()
        if row is None:
            conn.execute("COMMIT")
            return None
        cur = conn.execute(
            "UPDATE queue_jobs SET status='leased', lease_owner=:owner,"
            " lease_expires_at=:exp, attempts=attempts+1, last_error=NULL"
            " WHERE id=:id AND (status='queued' OR lease_expires_at<:now2)",
            {"owner": worker_id, "exp": _now() + lease_seconds,
             "id": row["id"], "now2": _now()})
        if cur.rowcount != 1:
            conn.execute("ROLLBACK")
            return None
        conn.execute("COMMIT")
        return dict(conn.execute("SELECT * FROM queue_jobs WHERE id=?", (row["id"],)).fetchone())
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _requeue_or_dead(conn: sqlite3.Connection, job: dict, *, max_attempts: int,
                     backoff_base: int, error: str) -> str:
    attempts = job["attempts"]
    if attempts >= max_attempts:
        conn.execute("UPDATE queue_jobs SET status='dead', lease_owner=NULL,"
                     " lease_expires_at=NULL, last_error=? WHERE id=?",
                     (error, job["id"]))
        return "dead"
    delay = backoff_base ** min(attempts, 6)
    conn.execute("UPDATE queue_jobs SET status='queued', lease_owner=NULL,"
                 " lease_expires_at=NULL, available_at=?, last_error=? WHERE id=?",
                 (_now() + delay, error, job["id"]))
    return "queued"


def mark_success(conn: sqlite3.Connection, job_id: str) -> None:
    conn.execute("UPDATE queue_jobs SET status='succeeded', lease_owner=NULL,"
                 " lease_expires_at=NULL, last_error=NULL WHERE id=?", (job_id,))


def mark_failed(conn: sqlite3.Connection, job_id: str, error: str) -> None:
    """确定性终态失败（如不可遮盖 PHI）：不再重试，版本自动驳回。"""
    conn.execute("UPDATE queue_jobs SET status='failed', lease_owner=NULL,"
                 " lease_expires_at=NULL, last_error=? WHERE id=?", (error, job_id,))


def mark_failure(conn: sqlite3.Connection, job: dict, *, max_attempts: int,
                 backoff_base: int, error: str) -> str:
    """瞬时失败：退避重试；超过上限：dead（半成品永远 pending，不会发布）。"""
    return _requeue_or_dead(conn, job, max_attempts=max_attempts,
                            backoff_base=backoff_base, error=error)


def retry_dead(conn: sqlite3.Connection, *, image_id: str) -> bool:
    """运维/批量重试：复活该影像的死信任务（产生新尝试，历史尝试只增保留）。"""
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "SELECT * FROM queue_jobs WHERE image_id=? AND kind='derive'",
            (image_id,)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            raise ApiError(404, "job_not_found", "该影像没有处理任务")
        if row["status"] not in ("dead", "queued"):
            conn.execute("ROLLBACK")
            raise ApiError(409, "job_not_retryable",
                           f"任务当前状态 {row['status']}，不可重试")
        conn.execute("UPDATE queue_jobs SET status='queued', attempts=0,"
                     " available_at=?, last_error=NULL, lease_owner=NULL,"
                     " lease_expires_at=NULL WHERE id=?", (_now(), row["id"]))
        conn.execute("COMMIT")
        return True
    except ApiError:
        raise
    except Exception:
        conn.execute("ROLLBACK")
        raise


def queue_stats(conn: sqlite3.Connection) -> dict:
    rows = conn.execute("SELECT status, COUNT(*) c FROM queue_jobs GROUP BY status").fetchall()
    return {r["status"]: r["c"] for r in rows}
