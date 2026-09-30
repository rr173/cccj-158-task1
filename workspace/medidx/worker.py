"""派生队列 worker：循环原子租约任务并执行管线。"""
from __future__ import annotations

import sys
import time

from . import derive, queue as queue_mod
from .security import new_id


def run_once(svc, worker_id: str) -> str:
    job = queue_mod.lease(svc.conn, worker_id=worker_id,
                          lease_seconds=svc.cfg.lease_seconds)
    if job is None:
        return "idle"
    try:
        result = derive.process_job(svc.conn, cfg=svc.cfg, job=job, worker_id=worker_id)
        print(f"[worker {worker_id}] job {job['id'][:8]} -> {result}", file=sys.stderr)
        return result
    except Exception as exc:  # 管线意外错误：退避重试，绝不发布
        svc.conn.execute("BEGIN IMMEDIATE")
        try:
            state = queue_mod.mark_failure(
                svc.conn, job, max_attempts=svc.cfg.max_attempts,
                backoff_base=svc.cfg.backoff_base_seconds,
                error=f"{type(exc).__name__}: {exc}")
            svc.conn.execute("COMMIT")
            print(f"[worker {worker_id}] job {job['id'][:8]} EXCEPTION -> {state}: {exc}",
                  file=sys.stderr)
            return "error:" + state
        except Exception:
            svc.conn.execute("ROLLBACK")
            raise


def run_loop(svc, *, max_iterations: int | None = None, idle_sleep: float = 0.2) -> int:
    worker_id = "worker-" + new_id()[:8]
    processed = 0
    i = 0
    while max_iterations is None or i < max_iterations:
        result = run_once(svc, worker_id)
        i += 1
        if result == "idle":
            if max_iterations is not None:
                break
            time.sleep(idle_sleep)
            continue
        processed += 1
    return processed
