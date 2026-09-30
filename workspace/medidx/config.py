"""平台配置与密钥材料管理（仅标准库）。"""
from __future__ import annotations

import os
import secrets
from pathlib import Path


class Config:
    def __init__(self, home: str | Path | None = None):
        self.home = Path(home or os.environ.get("MEDIDX_HOME", str(Path.cwd() / ".data")))
        self.db_path = self.home / "medidx.db"
        self.vault_dir = self.home / "vault"
        self.keys_dir = self.home / "keys"
        self.static_dir = Path(__file__).resolve().parent.parent / "static"
        # 租约超时：worker 崩溃后任务可被安全重领
        self.lease_seconds = 30
        # 派生任务最大尝试次数（含首次），超过即进入 dead，禁止半成品流出
        self.max_attempts = 3
        self.backoff_base_seconds = 2

    def ensure_dirs(self) -> None:
        for d in (self.home, self.vault_dir, self.keys_dir):
            d.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(d, 0o700)  # 密钥/冻结库仅本机当前用户可访问
            except PermissionError:
                pass

    def _load_or_create_key(self, name: str) -> bytes:
        self.ensure_dirs()
        path = self.keys_dir / name
        if not path.exists():
            path.write_bytes(secrets.token_bytes(32))
            try:
                os.chmod(path, 0o600)
            except PermissionError:
                pass
        return path.read_bytes()

    @property
    def seal_key(self) -> bytes:
        """冻结摘要 HMAC 封口密钥。"""
        return self._load_or_create_key("seal.key")

    @property
    def audit_key(self) -> bytes:
        """审计哈希链 HMAC 密钥。"""
        return self._load_or_create_key("audit.key")
