"""SQLite 持久层。

关键防护由数据库触发器兜底（即使应用代码出 bug）：
* 冻结摘要、身份映射、派生版本、处理尝试/步骤、审计日志均只增（禁 UPDATE/DELETE）；
* 已发布派生版本不可变；版本状态只允许 pending_qc -> published/rejected；
* 回链授权只能在受控状态机内移动；
* 审计日志由行级触发器联动校验（详见 audit.py）。
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from .security import (
    ROLE_ADMIN, ROLE_CLINICIAN, ROLE_PRIVACY_OFFICER, ROLE_QC_REVIEWER,
    new_id,
)

SCHEMA = r"""
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS projects (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('clinician','privacy_officer','qc_reviewer','admin')),
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    id              TEXT PRIMARY KEY,
    project_id      TEXT NOT NULL REFERENCES projects(id),
    name            TEXT NOT NULL,
    version         INTEGER NOT NULL,
    rules_json      TEXT NOT NULL,           -- 规范化后的规则集
    notes           TEXT NOT NULL DEFAULT '',
    created_by      TEXT NOT NULL REFERENCES users(id),
    created_at      TEXT NOT NULL,
    UNIQUE (project_id, name, version)
);

CREATE TABLE IF NOT EXISTS images (
    id                 TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL REFERENCES projects(id),
    source_uid         TEXT,                 -- 原始 StudyInstanceUID（仅受控可见，不随派生返回）
    media_type         TEXT NOT NULL,        -- dicom_explicit_le / dicom_json
    content_sha256     TEXT NOT NULL,
    current_revision   INTEGER NOT NULL DEFAULT 1,  -- 派生版本号高水位
    created_at         TEXT NOT NULL,
    UNIQUE (project_id, content_sha256)      -- 同一项目重复入库幂等
);

-- 入库即冻结的原始 DICOM 摘要（含 PHI），HMAC 封口、只增、API 永不直接输出
CREATE TABLE IF NOT EXISTS frozen_summaries (
    image_id          TEXT PRIMARY KEY REFERENCES images(id),
    sealed_json       TEXT NOT NULL,         -- 规范化冻结载荷
    seal_hmac         TEXT NOT NULL,
    payload_sha256    TEXT NOT NULL,
    frozen_at         TEXT NOT NULL,
    frozen_by         TEXT NOT NULL REFERENCES users(id)
);

-- 原始身份 -> 项目级替代身份 的映射，只增（策略升级可新增映射，但不可改写旧映射）
CREATE TABLE IF NOT EXISTS identity_map (
    id                 TEXT PRIMARY KEY,
    project_id         TEXT NOT NULL REFERENCES projects(id),
    key_type           TEXT NOT NULL,        -- patient_id / uid
    source_value_hash  TEXT NOT NULL,        -- HMAC 后的原身份值（库内不存明文 PHI）
    alt_value          TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    UNIQUE (project_id, key_type, source_value_hash)
);

CREATE TABLE IF NOT EXISTS derived_versions (
    id                  TEXT PRIMARY KEY,
    image_id            TEXT NOT NULL REFERENCES images(id),
    revision            INTEGER NOT NULL,     -- 该影像下版本号
    policy_id           TEXT NOT NULL REFERENCES policies(id),
    triggered_by        TEXT NOT NULL,        -- user id 或 worker 标识
    reason              TEXT NOT NULL,        -- initial_ingest / policy_upgrade / clinical_correction / batch_retry
    status              TEXT NOT NULL CHECK (status IN ('pending_qc','published','rejected')),
    -- 处理结果（标签清理结果 + 遮盖后像素表单）落内容寻址文件，库内存内容哈希
    artifact_sha256     TEXT,
    phi_residual_count  INTEGER NOT NULL DEFAULT 0,
    mask_region_count   INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL,
    published_at        TEXT,
    UNIQUE (image_id, revision)
);

-- 派生处理尝试：每次 worker 领取都新插一行（可因崩溃/遮盖失败出现多行），只增
CREATE TABLE IF NOT EXISTS processing_attempts (
    id              TEXT PRIMARY KEY,
    version_id      TEXT NOT NULL REFERENCES derived_versions(id),
    attempt_no      INTEGER NOT NULL,
    job_id          TEXT NOT NULL,
    worker_id       TEXT NOT NULL,
    result          TEXT NOT NULL CHECK (result IN ('success','mask_failure','error')),
    error_code      TEXT,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    UNIQUE (version_id, attempt_no)             -- 并发保护：同版本同尝试号唯一
);

-- 处理步骤只增，append 时锁序固定，完整记录管线每一步
CREATE TABLE IF NOT EXISTS processing_steps (
    id            TEXT PRIMARY KEY,
    version_id    TEXT NOT NULL REFERENCES derived_versions(id),
    attempt_id    TEXT NOT NULL REFERENCES processing_attempts(id),
    step_no       INTEGER NOT NULL,
    name          TEXT NOT NULL,
    detail_json   TEXT NOT NULL DEFAULT '{}',
    recorded_at   TEXT NOT NULL,
    UNIQUE (version_id, attempt_id, step_no)   -- 每次尝试内步骤唯一；重试产生新 attempt
);

CREATE TABLE IF NOT EXISTS qc_findings (
    id           TEXT PRIMARY KEY,
    version_id   TEXT NOT NULL REFERENCES derived_versions(id),
    severity     TEXT NOT NULL CHECK (severity IN ('blocker','warning','info')),
    code         TEXT NOT NULL,
    message      TEXT NOT NULL,
    detail_json  TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS queue_jobs (
    id               TEXT PRIMARY KEY,
    image_id         TEXT NOT NULL REFERENCES images(id),
    version_id       TEXT NOT NULL REFERENCES derived_versions(id),
    kind             TEXT NOT NULL,           -- derive
    status           TEXT NOT NULL CHECK (status IN ('queued','leased','succeeded','failed','dead')),
    attempts         INTEGER NOT NULL DEFAULT 0,
    available_at     REAL NOT NULL,           -- 指数退避
    lease_owner      TEXT,
    lease_expires_at REAL,
    last_error       TEXT,
    created_at       TEXT NOT NULL,
    UNIQUE (image_id, kind)                  -- 每个影像同时只有一个活跃处理任务，支持 ON CONFLICT
);
CREATE INDEX IF NOT EXISTS idx_queue_pick ON queue_jobs(status, available_at);

-- 回链授权：双角色，绑定病例/目的/时间窗；状态机由触发器约束
CREATE TABLE IF NOT EXISTS relink_grants (
    id               TEXT PRIMARY KEY,
    image_id         TEXT NOT NULL REFERENCES images(id),
    project_id       TEXT NOT NULL REFERENCES projects(id),
    purpose          TEXT NOT NULL,
    requested_by     TEXT NOT NULL REFERENCES users(id),  -- 临床医生（申请人）
    approved_by      TEXT NOT NULL REFERENCES users(id),  -- 隐私官（审批人）
    window_start     TEXT NOT NULL,
    window_end       TEXT NOT NULL,
    status           TEXT NOT NULL CHECK (status IN ('active','exported','revoked','expired')),
    revoke_reason    TEXT,
    revoked_by       TEXT REFERENCES users(id),
    revoked_at       TEXT,
    created_at       TEXT NOT NULL,
    CHECK (requested_by <> approved_by)
);

-- 一次性导出凭证：生成即绑定授权；核销/撤销竞态由原子条件 UPDATE 保证只成功一次
CREATE TABLE IF NOT EXISTS relink_exports (
    id           TEXT PRIMARY KEY,
    grant_id     TEXT NOT NULL REFERENCES relink_grants(id),
    token_hash   TEXT NOT NULL UNIQUE,        -- 只存令牌哈希
    claimed_at   TEXT,
    outcome      TEXT CHECK (outcome IS NULL OR outcome IN
                 ('exposed','revoked_race','expired','window_closed','grant_exported','grant_not_active')),
    exposed_at   TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     TEXT NOT NULL UNIQUE,
    actor_id     TEXT,
    action       TEXT NOT NULL,
    object_type  TEXT,
    object_id    TEXT,
    detail_json  TEXT NOT NULL DEFAULT '{}',
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL,
    recorded_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token       TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id),
    issued_at   REAL NOT NULL,
    expires_at  REAL NOT NULL
);

-- ---------- 只增表：禁 UPDATE / DELETE ----------
CREATE TRIGGER IF NOT EXISTS trg_frozen_no_upd BEFORE UPDATE ON frozen_summaries
BEGIN SELECT RAISE(ABORT, 'frozen_summaries 是只增表'); END;
CREATE TRIGGER IF NOT EXISTS trg_frozen_no_del BEFORE DELETE ON frozen_summaries
BEGIN SELECT RAISE(ABORT, 'frozen_summaries 是只增表'); END;

CREATE TRIGGER IF NOT EXISTS trg_idmap_no_upd BEFORE UPDATE ON identity_map
BEGIN SELECT RAISE(ABORT, 'identity_map 是只增表'); END;
CREATE TRIGGER IF NOT EXISTS trg_idmap_no_del BEFORE DELETE ON identity_map
BEGIN SELECT RAISE(ABORT, 'identity_map 是只增表'); END;

CREATE TRIGGER IF NOT EXISTS trg_attempts_no_upd BEFORE UPDATE ON processing_attempts
BEGIN SELECT RAISE(ABORT, 'processing_attempts 是只增表'); END;
CREATE TRIGGER IF NOT EXISTS trg_attempts_no_del BEFORE DELETE ON processing_attempts
BEGIN SELECT RAISE(ABORT, 'processing_attempts 是只增表'); END;

CREATE TRIGGER IF NOT EXISTS trg_steps_no_upd BEFORE UPDATE ON processing_steps
BEGIN SELECT RAISE(ABORT, 'processing_steps 是只增表'); END;
CREATE TRIGGER IF NOT EXISTS trg_steps_no_del BEFORE DELETE ON processing_steps
BEGIN SELECT RAISE(ABORT, 'processing_steps 是只增表'); END;

CREATE TRIGGER IF NOT EXISTS trg_findings_no_upd BEFORE UPDATE ON qc_findings
BEGIN SELECT RAISE(ABORT, 'qc_findings 是只增表'); END;
CREATE TRIGGER IF NOT EXISTS trg_findings_no_del BEFORE DELETE ON qc_findings
BEGIN SELECT RAISE(ABORT, 'qc_findings 是只增表'); END;

CREATE TRIGGER IF NOT EXISTS trg_audit_no_upd BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events 是只增表'); END;
CREATE TRIGGER IF NOT EXISTS trg_audit_no_del BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events 是只增表'); END;

CREATE TRIGGER IF NOT EXISTS trg_policies_no_upd BEFORE UPDATE ON policies
BEGIN SELECT RAISE(ABORT, 'policies 只可新增版本，禁止修改'); END;
CREATE TRIGGER IF NOT EXISTS trg_policies_no_del BEFORE DELETE ON policies
BEGIN SELECT RAISE(ABORT, 'policies 禁止删除'); END;

-- ---------- 派生版本：已发布不可变 + 状态机 ----------
CREATE TRIGGER IF NOT EXISTS trg_version_update_guard BEFORE UPDATE ON derived_versions
BEGIN
    SELECT CASE
        -- pending_qc 只允许迁移到 published / rejected，且只能改允许的列
        WHEN OLD.status = 'pending_qc'
             AND NEW.status NOT IN ('pending_qc','published','rejected')
        THEN RAISE(ABORT, '版本状态只允许 pending_qc -> published/rejected')
        WHEN OLD.status IN ('published','rejected')
             AND (NEW.status IS NOT OLD.status
                  OR NEW.policy_id IS NOT OLD.policy_id
                  OR NEW.artifact_sha256 IS NOT OLD.artifact_sha256
                  OR NEW.phi_residual_count IS NOT OLD.phi_residual_count
                  OR NEW.mask_region_count IS NOT OLD.mask_region_count
                  OR NEW.image_id IS NOT OLD.image_id
                  OR NEW.revision IS NOT OLD.revision)
        THEN RAISE(ABORT, '已发布/已驳回派生版本不可变')
    END;
END;
CREATE TRIGGER IF NOT EXISTS trg_version_no_del BEFORE DELETE ON derived_versions
BEGIN SELECT RAISE(ABORT, '派生版本禁止删除'); END;

-- ---------- 回链授权状态机 ----------
CREATE TRIGGER IF NOT EXISTS trg_grant_status_guard BEFORE UPDATE ON relink_grants
BEGIN
    SELECT CASE
        WHEN OLD.status = 'active' AND NEW.status NOT IN ('exported','revoked','expired')
        THEN RAISE(ABORT, '授权仅可从 active 迁移到 exported/revoked/expired')
        WHEN OLD.status IN ('exported','revoked','expired') AND NEW.status IS NOT OLD.status
        THEN RAISE(ABORT, '终态授权不可再变更')
    END;
END;
"""

SEED_USERS = [
    ("u_clinician", "clinic.zhang", "张医生（临床）", ROLE_CLINICIAN),
    ("u_privacy", "privacy.li", "李隐私官", ROLE_PRIVACY_OFFICER),
    ("u_qc", "qc.wang", "王质检医生", ROLE_QC_REVIEWER),
    ("u_admin", "admin.chen", "陈管理员", ROLE_ADMIN),
]


def connect(db_path: str | Path, timeout: float = 30.0) -> sqlite3.Connection:
    # check_same_thread=False：写操作全部以 BEGIN IMMEDIATE 串行化，可跨线程使用
    conn = sqlite3.connect(str(db_path), timeout=timeout, isolation_level=None,
                           check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
    # 并发写入串行化，配合显式事务保证竞态安全
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    now = _iso_now()
    for uid, username, display, role in SEED_USERS:
        conn.execute(
            "INSERT OR IGNORE INTO users(id, username, display_name, role, created_at) "
            "VALUES (?,?,?,?,?)",
            (uid, username, display, role, now),
        )


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
