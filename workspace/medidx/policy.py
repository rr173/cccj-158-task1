"""去标识化策略。

策略是项目级不可变文档：每次升级 => 新行 (project,name,version+1)，旧版本永远保留，
已发布派生版本永远引用其当时策略，保证可追溯、可复算。

规则动作：
* remove       —— 删除标签（D/X）
* keep         —— 保留原值（K）
* replace      —— 项目级确定性替代值：patient_id / patient_name / accession / study_uid
* shift        —— 日期按项目秘密偏移（DA/DT，保留时间间隔）
* blank        —— 置空但保留标签存在（用于结构校验）
默认（未列出的标签）= remove（白名单式，避免漏网 PHI）。
"""
from __future__ import annotations

import json
import sqlite3

from .security import ApiError, canonical, new_id

# 常见标签简表（仅覆盖演示/档案所需；未覆盖标签一律 remove）
TAG_NAMES = {
    "(0008,0005)": "SpecificCharacterSet",
    "(0008,0008)": "ImageType",
    "(0008,0016)": "SOPClassUID",
    "(0008,0018)": "SOPInstanceUID",
    "(0008,0020)": "StudyDate",
    "(0008,0030)": "StudyTime",
    "(0008,0050)": "AccessionNumber",
    "(0008,0060)": "Modality",
    "(0008,0070)": "Manufacturer",
    "(0008,1030)": "StudyDescription",
    "(0010,0010)": "PatientName",
    "(0010,0020)": "PatientID",
    "(0010,0030)": "PatientBirthDate",
    "(0010,0040)": "PatientSex",
    "(0010,1000)": "OtherPatientIDs",
    "(0010,21b0)": "AdditionalPatientHistory",
    "(0018,0015)": "BodyPartExamined",
    "(0018,1030)": "ProtocolName",
    "(0020,000d)": "StudyInstanceUID",
    "(0020,000e)": "SeriesInstanceUID",
    "(0020,0010)": "StudyID",
    "(0020,0011)": "SeriesNumber",
    "(0020,0013)": "InstanceNumber",
    "(0028,0008)": "NumberOfFrames",
}

# 基础策略：Baseline DICOM De-Identification Profile 的最小演示集
_BASE_PROFILE: dict[str, str] = {
    "(0010,0010)": "replace:patient_name",
    "(0010,0020)": "replace:patient_id",
    "(0008,0005)": "keep",
    "(0008,0008)": "keep",
    "(0008,0016)": "keep",
    "(0008,0018)": "replace:uid",
    "(0008,0020)": "shift",
    "(0008,0030)": "keep",
    "(0008,0050)": "replace:accession",
    "(0008,0060)": "keep",
    "(0008,0070)": "keep",
    "(0010,0030)": "shift",
    "(0010,0040)": "keep",
    "(0018,0015)": "keep",
    "(0018,1030)": "keep",                # v1 保留协议名/检查描述（通常无身份信息）
    "(0010,1000)": "remove",              # 其他患者号：直接 PHI，v1 即清除
    "(0010,21b0)": "remove",              # 附加病史：可能含自由文本 PHI，v1 即清除
    "(0020,000d)": "replace:uid",
    "(0020,000e)": "replace:uid",
    "(0020,0010)": "replace:accession",
    "(0020,0011)": "keep",
    "(0020,0013)": "keep",
}

# v2：升级——连检查描述/协议名也清除（可能含研究项目身份或自由文本线索）
_V2_EXTRA = {
    "(0008,1030)": "remove",
    "(0018,1030)": "remove",
}


def default_rules(version: int) -> dict[str, str]:
    rules = dict(_BASE_PROFILE)
    if version >= 2:
        rules.update(_V2_EXTRA)
    if version > 2:
        raise ApiError(400, "unknown_default_version", f"内置默认策略只到 v2，收到 v{version}")
    return rules


def describe_rules(rules: dict[str, str]) -> list[dict]:
    return [
        {"tag": tag, "name": TAG_NAMES.get(tag, "?"), "action": action}
        for tag, action in sorted(rules.items())
    ]


def validate_rules(rules: dict) -> None:
    allowed = {"remove", "keep", "shift", "blank"}
    repl_prefix = "replace:"
    for tag, action in rules.items():
        if tag not in TAG_NAMES and not (tag.startswith("(") and len(tag) == 11):
            raise ApiError(400, "bad_rule", f"非法标签 {tag}")
        if not (action in allowed or action.startswith(repl_prefix)):
            raise ApiError(400, "bad_rule", f"标签 {tag} 的动作非法: {action}")


def create_policy(conn: sqlite3.Connection, *, project_id: str, name: str,
                  rules: dict[str, str] | None, version: int | None,
                  notes: str, user_id: str, now: str) -> str:
    """新建一个策略版本。永不覆盖：同名策略 version 自动 +1。"""
    validate_rules(rules or default_rules(version or 1))
    final_rules = rules if rules is not None else default_rules(version or 1)
    row = conn.execute(
        "SELECT COALESCE(MAX(version),0) AS v FROM policies WHERE project_id=? AND name=?",
        (project_id, name)).fetchone()
    next_version = row["v"] + 1
    pid = new_id()
    conn.execute(
        "INSERT INTO policies(id, project_id, name, version, rules_json, notes, created_by, created_at)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (pid, project_id, name, next_version,
         json.dumps(final_rules, sort_keys=True, ensure_ascii=False), notes, user_id, now))
    return pid


def get_policy(conn: sqlite3.Connection, policy_id: str) -> dict:
    row = conn.execute("SELECT * FROM policies WHERE id=?", (policy_id,)).fetchone()
    if row is None:
        raise ApiError(404, "policy_not_found", "策略不存在")
    return dict(row)


def rules_of(policy: dict) -> dict[str, str]:
    return json.loads(policy["rules_json"])


def action_for(rules: dict[str, str], tag: str) -> str:
    return rules.get(tag, "remove")
