"""安全原语：规范化序列化、HMAC 封口、令牌、角色。"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass

# 角色：临床医生（申请/使用回链）、隐私官（审批/撤销回链、升级策略）、
# 质检医生（质检发布）、管理员（审计导出、系统运维）。
ROLE_CLINICIAN = "clinician"
ROLE_PRIVACY_OFFICER = "privacy_officer"
ROLE_QC_REVIEWER = "qc_reviewer"
ROLE_ADMIN = "admin"
ROLES = {ROLE_CLINICIAN, ROLE_PRIVACY_OFFICER, ROLE_QC_REVIEWER, ROLE_ADMIN}


def canonical(obj) -> bytes:
    """确定性规范化 JSON，用于封口/哈希/去重。"""
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def hmac_hex(key: bytes, *parts: bytes) -> str:
    msg = b"\x1f".join(parts)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class Seal:
    sealed_json: str
    seal_hmac: str
    payload_sha256: str

    def as_dict(self) -> dict:
        return {"sealed_json": self.sealed_json, "seal_hmac": self.seal_hmac,
                "payload_sha256": self.payload_sha256}


def seal_payload(key: bytes, payload: dict) -> Seal:
    raw = canonical(payload)
    text = raw.decode("utf-8")
    return Seal(text, hmac.new(key, raw, hashlib.sha256).hexdigest(),
                hashlib.sha256(raw).hexdigest())


def verify_seal(key: bytes, sealed_json: str, seal_hmac: str, payload_sha256: str | None = None) -> dict:
    """校验封口并还原载荷；任何篡改都抛 SealError。"""
    raw = sealed_json.encode("utf-8")
    expected = hmac.new(key, raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, seal_hmac):
        raise SealError("HMAC 封口校验失败：冻结摘要已被篡改或密钥不匹配")
    if payload_sha256 is not None and not hmac.compare_digest(
            hashlib.sha256(raw).hexdigest(), payload_sha256):
        raise SealError("载荷 SHA-256 不匹配")
    return json.loads(sealed_json)


class SealError(Exception):
    pass


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def new_token() -> str:
    return secrets.token_urlsafe(32)


def new_id() -> str:
    return secrets.token_hex(16)
