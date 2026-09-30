import json

from tests.helpers import ServiceCase

# 任何非回链接口路径的返回/持久视图中都绝不能出现的原始 PHI
SECRET_STRINGS = ["ZHANG^SAN", "MRN-88990011", "ACC20240315", "19790909"]


def _scan(obj, path="$"):
    """递归找出现在 JSON 结构中的 PHI 字符串。"""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits += _scan(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += _scan(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        for secret in SECRET_STRINGS:
            if secret in obj:
                hits.append((path, secret))
    return hits


class TestNoPhiLeak(ServiceCase):
    def test_no_phi_in_any_non_relink_view(self):
        image_ids = []
        for name in self.samples:
            image_ids.append(self.ingest(name)["image_id"])
        self.pump(rounds=2, wait=2.3)
        self.pump(rounds=2, wait=2.3)  # 等退避重试全部落定

        all_hits = []
        for image_id in image_ids:
            versions = self.svc.list_versions_for_image(image_id)
            for v in versions:
                all_hits += [("version-list", p, s) for p, s in _scan(v)]
                # 含工件的详情视图（pending/published 附带；rejected 不附带）
                detail = self.svc.get_version(self.qc, v["id"])
                all_hits += [("version-detail", p, s) for p, s in _scan(detail)]
            imgs = self.svc.list_images(self.project_id)
            all_hits += [("image-list", p, s) for p, s in _scan(imgs)]
            jobs = self.svc.queue_list()
            all_hits += [("queue", p, s) for p, s in _scan(jobs)]
        # 审计事件（非回链部分）：动作/对象/详情不得明文出现 PHI
        events = self.svc.audit_list(self.admin, limit=1000)
        for ev in events:
            if ev["action"].startswith("relink."):
                continue
            all_hits += [("audit", ev["action"], s) for _, s in _scan(ev)]
        self.assertEqual(all_hits, [], f"发现 PHI 泄露: {all_hits}")

    def test_rejected_versions_do_not_expose_artifact_phi(self):
        image_id = self.ingest("03_mask_incomplete_rejected.json")["image_id"]
        self.pump()
        v = self.only_version(image_id)
        detail = self.svc.get_version(self.qc, v["id"])
        self.assertNotIn("svg", detail)
        self.assertNotIn("elements", detail)
        # 质检发现只含指纹不含原文
        blob = json.dumps(detail["findings"], ensure_ascii=False)
        self.assertNotIn("ZHANG", blob)

    def test_published_artifact_has_no_raw_text_for_covered_regions(self):
        from medidx import derive
        image_id = self.ingest("01_normal_masked.json")["image_id"]
        self.pump()
        v = self.only_version(image_id)
        art = derive.load_artifact(self.svc.cfg, v["artifact_sha256"])
        blob = json.dumps(art, ensure_ascii=False)
        for s in SECRET_STRINGS[:2]:
            self.assertNotIn(s, blob)
