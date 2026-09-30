"""演示/测试种子数据：项目、策略、四类影像（含遮盖故障与漏标 PHI 用例）。"""
from __future__ import annotations

import json
import time

from . import audit
from .policy import create_policy, default_rules
from .security import new_id


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sheet(regions, **extra):
    s = {"width": 320, "height": 320, "regions": regions}
    s.update(extra)
    return s


def _rid(i):
    return f"r{i:02d}"


def sample_images() -> list[tuple[str, dict]]:
    base_elements = {
        "(0008,0005)": "ISO_IR 100",
        "(0008,0008)": ["ORIGINAL", "PRIMARY"],
        "(0008,0016)": "1.2.840.10008.5.1.4.1.1.2",
        "(0008,0018)": "1.2.840.113619.2.55.3.604688120.933.1362210176.633",
        "(0008,0020)": "20240315",
        "(0008,0030)": "091530",
        "(0008,0050)": "ACC2024031501",
        "(0008,0060)": "MR",
        "(0008,0070)": "DEMO VENDOR",
        "(0008,1030)": "STROKE FOLLOWUP 2024",
        "(0010,0010)": "ZHANG^SAN",
        "(0010,0020)": "MRN-88990011",
        "(0010,0030)": "19790909",
        "(0010,0040)": "M",
        "(0010,1000)": "MRN-88990011 / OTHER HOSPITAL 0921",
        "(0018,0015)": "BRAIN",
        "(0018,1030)": "STROKE^PROJECT^ARM-3",
        "(0020,000d)": "1.2.840.113619.2.55.3.604688120.933.1362210176.630",
        "(0020,000e)": "1.2.840.113619.2.55.3.604688120.933.1362210176.631",
        "(0020,0010)": "STUDY-001",
        "(0020,0011)": 1,
        "(0020,0013)": 1,
        "(0028,0008)": 1,
    }
    pixel_phi_name = {"x": 14, "y": 14, "w": 110, "h": 18,
                      "text": "ZHANG^SAN MRN-88990011", "phi": True, "id": _rid(1)}
    pixel_phi_corner = {"x": 190, "y": 296, "w": 120, "h": 16,
                        "text": "ACC2024031501 2024-03-15", "phi": True, "id": _rid(2)}
    clinical_text = {"x": 120, "y": 180, "w": 80, "h": 16,
                     "text": "R 4mm lesion", "id": _rid(3)}

    samples = []

    def make(name, elements, sheet):
        payload = {"media_type": "dicom_json", "elements": elements, "pixel_sheet": sheet}
        return name, payload

    # 1) 正常：两处角落烧录 PHI，遮盖成功
    e = dict(base_elements)
    samples.append(make("01_normal_masked.json", e,
                        _sheet([dict(pixel_phi_name), dict(pixel_phi_corner),
                                dict(clinical_text)])))
    # 2) 遮盖器前两次瞬时故障，第三次成功（批量重试演示）
    e = {**base_elements, "(0008,0018)": "1.2.840.113619.2.55.3.604688120.933.1362210177.634",
         "(0008,0050)": "ACC2024031502", "(0020,0010)": "STUDY-002"}
    samples.append(make("02_masker_busy_retry.json", e,
                        _sheet([dict(pixel_phi_name), dict(clinical_text)],
                               **{"mask_fail_before_attempt": 2})))
    # 3) 遮盖不彻底（半透明）=> 二次 OCR 残留 PHI => 自动驳回
    e = {**base_elements, "(0008,0018)": "1.2.840.113619.2.55.3.604688120.933.1362210178.635",
         "(0008,0050)": "ACC2024031503", "(0020,0010)": "STUDY-003"}
    bad = dict(pixel_phi_name)
    bad["mask_effect"] = "translucent"
    samples.append(make("03_mask_incomplete_rejected.json", e,
                        _sheet([bad, dict(clinical_text)])))
    # 4) 不可遮盖区域（会破坏诊断视野）=> 持续失败/驳回
    e = {**base_elements, "(0008,0018)": "1.2.840.113619.2.55.3.604688120.933.1362210179.636",
         "(0008,0050)": "ACC2024031504", "(0020,0010)": "STUDY-004"}
    unm = dict(pixel_phi_corner)
    unm["unmaskable"] = True
    samples.append(make("04_unmaskable_rejected.json", e,
                        _sheet([dict(pixel_phi_name), unm, dict(clinical_text)])))
    # 5) 像素内漏标 PHI（phi 未标注，但文本含患者姓名）=> 独立 OCR 文本匹配仍须抓到
    e = {**base_elements, "(0008,0018)": "1.2.840.113619.2.55.3.604688120.933.1362210180.637",
         "(0008,0050)": "ACC2024031505", "(0020,0010)": "STUDY-005"}
    sneaky = {"x": 150, "y": 90, "w": 150, "h": 16,
              "text": "scan note: ZHANG^SAN follow-up", "id": _rid(4)}  # 无 phi 标记
    samples.append(make("05_stealth_phi_caught.json", e,
                        _sheet([sneaky, dict(clinical_text)])))
    return samples


def seed_demo(svc, *, count: int = 4) -> dict:
    conn = svc.conn
    now = _iso_now()
    admin = conn.execute("SELECT * FROM users WHERE id='u_admin'").fetchone()
    project = conn.execute("SELECT * FROM projects WHERE name='DEMO-NEURO'").fetchone()
    if project is None:
        pid = new_id()
        conn.execute("INSERT INTO projects(id, name, description, created_at) VALUES (?,?,?,?)",
                     (pid, "DEMO-NEURO", "神经影像科研项目（演示）", now))
        project = conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone()
        create_policy(conn, project_id=pid, name="NEURO-DEID", rules=default_rules(1),
                      version=1, notes="基础去标识化策略 v1", user_id=admin["id"], now=now)
        audit.record(conn, svc.cfg.audit_key, action="demo.seeded", actor_id=admin["id"],
                     object_type="project", object_id=pid, detail={"phase": "project"})

    ingested = []
    for name, payload in sample_images()[:count]:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        # 幂等：重复 seed 不产生重复影像
        import hashlib
        sha = hashlib.sha256(raw).hexdigest()
        exists = conn.execute("SELECT id FROM images WHERE project_id=? AND content_sha256=?",
                              (project["id"], sha)).fetchone()
        if exists:
            ingested.append({"file": name, "image_id": exists["id"], "already_exists": True})
            continue
        res = svc.ingest(admin, project["id"], raw, "json", name)
        ingested.append({"file": name, **res})
    return {"project_id": project["id"], "ingested": ingested}
