"""项目级确定性替代身份与身份映射存储。

* 同一项目内同一原值 => 同一替代值（纵向研究可关联），跨项目不可关联（项目盐）；
* 派生只看到替代值；库内 identity_map 不存明文原值，只存原值的 HMAC 指纹；
* 日期按项目秘密做确定性天数偏移，保留时间间隔，掩盖真实年龄/年份。
"""
from __future__ import annotations

import datetime as dt
import sqlite3

from .security import ApiError, hmac_hex, new_id


def _source_fingerprint(project_salt: bytes, key_type: str, value: str) -> str:
    return hmac_hex(project_salt, key_type.encode(), value.encode("utf-8"))


def _project_salt(conn: sqlite3.Connection, seal_key: bytes, project_id: str) -> bytes:
    return hmac_hex(seal_key, b"project-salt", project_id.encode()).encode()


def mapped_value(conn: sqlite3.Connection, seal_key: bytes, project_id: str,
                 key_type: str, source_value: str, *, now: str,
                 generator=None) -> str:
    """查询（不存在则建立）原值 -> 替代值映射。只增。"""
    salt = _project_salt(conn, seal_key, project_id)
    fp = _source_fingerprint(salt, key_type, source_value)
    row = conn.execute(
        "SELECT alt_value FROM identity_map WHERE project_id=? AND key_type=? AND source_value_hash=?",
        (project_id, key_type, fp)).fetchone()
    if row is not None:
        return row["alt_value"]
    alt = generator(salt, source_value) if generator else _default_alt(key_type, salt, source_value)
    conn.execute(
        "INSERT INTO identity_map(id, project_id, key_type, source_value_hash, alt_value, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (new_id(), project_id, key_type, fp, alt, now))
    return alt


def _default_alt(key_type: str, salt: bytes, source: str) -> str:
    digest = hmac_hex(salt, key_type.encode(), source.encode())
    if key_type == "patient_id":
        return "PID-" + digest[:12].upper()
    if key_type == "patient_name":
        return "PHANTOM^" + digest[8:12].upper()
    if key_type == "accession":
        return "ACC-" + digest[:10].upper()
    if key_type == "uid":
        # 合法 DICOM UID：数字+点、<=64 字符
        body = f"2.25.{int(digest[:32], 16)}"
        return body[:64]
    return "ALT-" + digest[:12].upper()


def date_shift_days(seal_key: bytes, project_id: str) -> int:
    """项目固定日期偏移天数（确定性、项目隔离），范围约 ±15 年。"""
    h = hmac_hex(seal_key, b"date-shift", project_id.encode())
    n = int(h[:8], 16)
    return (n % (2 * 5478)) - 5478  # -5478..+5477 天


def shift_date(value, seal_key: bytes, project_id: str):
    """DA(YYYYMMDD) / DT 前缀日期位移；非法值原样保留并由上层标记 warning。"""
    days = date_shift_days(seal_key, project_id)
    if value is None:
        return value
    text = str(value)

    def _shift_one(token: str) -> str:
        date_part, _, suffix = token.partition(".")
        suffix = ("." + suffix) if suffix else ""
        try:
            d = dt.datetime.strptime(date_part[:8], "%Y%m%d").date()
        except ValueError:
            return token
        shifted = (d + dt.timedelta(days=days)).strftime("%Y%m%d")
        tail = date_part[8:]
        return shifted + tail + suffix

    if "\\" in text:
        return "\\".join(_shift_one(t) for t in text.split("\\"))
    return _shift_one(text)
