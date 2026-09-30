import sqlite3
import time

from tests.helpers import ServiceCase
from medidx.security import ApiError
from medidx import queue as queue_mod


class TestMaskingAndQC(ServiceCase):
    def test_normal_image_publishes_with_clean_artifact(self):
        image_id = self.image_id("01_normal_masked.json")
        self.pump()
        v = self.only_version(image_id)
        self.assertEqual(v["status"], "pending_qc")
        self.svc.publish(self.qc, v["id"])
        from medidx import derive
        art = derive.load_artifact(self.svc.cfg, v["artifact_sha256"])
        # 所有直接 PHI 标签被替代/移除，像素文本中不再可读姓名
        self.assertNotIn("ZHANG^SAN", str(art["elements"]))
        self.assertNotIn("MRN-88990011", str(art["elements"]))
        self.assertTrue(art["elements"]["(0010,0020)"].startswith("PID-"))
        # 原始文本仍保留在冻结结构里但被不透明遮盖块覆盖：任何 OCR 都读不到
        from medidx.pixel import run_ocr
        self.assertFalse(any("ZHANG" in o.text for o in run_ocr(art["pixel_sheet"])))
        self.assertFalse(any("ACC2024" in o.text for o in run_ocr(art["pixel_sheet"])))

    def test_transient_mask_failure_retries_then_succeeds(self):
        image_id = self.image_id("02_masker_busy_retry.json")
        self.pump()
        job = self.svc.conn.execute(
            "SELECT * FROM queue_jobs WHERE image_id=?", (image_id,)).fetchone()
        self.assertEqual(job["status"], "queued")   # 已退避
        attempts = self.svc.conn.execute(
            "SELECT attempt_no, result FROM processing_attempts ORDER BY attempt_no").fetchall()
        self.assertEqual([(r["attempt_no"], r["result"]) for r in attempts],
                         [(1, "mask_failure")])
        # 版本仍是 pending_qc（无 artifact 占位 => 半成品不可发布）
        v = self.only_version(image_id)
        self.assertEqual(v["artifact_sha256"], None)
        with self.assertRaises(ApiError):
            self.svc.publish(self.qc, v["id"])
        # 经历退避窗口直到成功（第 3 次尝试）
        for _ in range(6):
            time.sleep(2.2)
            self.pump()
            job = self.svc.conn.execute(
                "SELECT status FROM queue_jobs WHERE image_id=?", (image_id,)).fetchone()
            if job["status"] == "succeeded":
                break
        self.assertEqual(job["status"], "succeeded")
        rows = self.svc.conn.execute(
            "SELECT attempt_no, result FROM processing_attempts ORDER BY attempt_no").fetchall()
        self.assertEqual([r["result"] for r in rows],
                         ["mask_failure", "mask_failure", "success"])
        v = self.only_version(image_id)
        self.assertEqual(v["status"], "pending_qc")
        self.svc.publish(self.qc, v["id"])

    def test_incomplete_mask_auto_rejected(self):
        image_id = self.image_id("03_mask_incomplete_rejected.json")
        self.pump()
        v = self.only_version(image_id)
        self.assertEqual(v["status"], "rejected")
        codes = [r["code"] for r in self.svc.conn.execute(
            "SELECT code FROM qc_findings WHERE version_id=? AND severity='blocker'",
            (v["id"],))]
        self.assertIn("pixel_residual_phi", codes)
        with self.assertRaises(ApiError):
            self.svc.publish(self.qc, v["id"])  # 驳回版永远不能发布

    def test_unmaskable_fails_job_and_rejects_version(self):
        image_id = self.image_id("04_unmaskable_rejected.json")
        self.pump()
        v = self.only_version(image_id)
        self.assertEqual(v["status"], "rejected")
        job = self.svc.conn.execute(
            "SELECT status, last_error FROM queue_jobs WHERE image_id=?",
            (image_id,)).fetchone()
        self.assertEqual(job["status"], "failed")
        # 不可重试（确定性终态）
        with self.assertRaises(ApiError):
            self.svc.retry_dead(self.admin, image_id)

    def test_stealth_pixel_phi_caught_without_annotation(self):
        image_id = self.image_id("05_stealth_phi_caught.json")
        self.pump()
        v = self.only_version(image_id)
        self.assertEqual(v["status"], "pending_qc")  # 文本匹配抓到并遮盖了
        from medidx import derive
        from medidx.pixel import run_ocr
        art = derive.load_artifact(self.svc.cfg, v["artifact_sha256"])
        self.assertFalse(any("ZHANG" in o.text for o in run_ocr(art["pixel_sheet"])))

    def test_dead_letter_requires_exhausting_retries_and_manual_retry(self):
        # 把退避基数调大不必要：直接造一个永远故障的影像（fail_before_attempt 很大）
        payload = self.samples["02_masker_busy_retry.json"]
        payload["pixel_sheet"]["mask_fail_before_attempt"] = 99
        image_id = self.svc.ingest(
            self.admin, self.project_id,
            __import__("json").dumps(payload).encode(), "json",
            "always_fail.json")["image_id"]
        for _ in range(4):
            self.pump()
            time.sleep(2.2)
        job = self.svc.conn.execute(
            "SELECT * FROM queue_jobs WHERE image_id=?", (image_id,)).fetchone()
        self.assertEqual(job["status"], "dead")
        self.assertEqual(job["attempts"], self.svc.cfg.max_attempts)
        # 人工批量重试：复活，历史尝试只增保留
        self.svc.retry_dead(self.admin, image_id)
        n_attempts = self.svc.conn.execute(
            "SELECT COUNT(*) c FROM processing_attempts WHERE version_id=?",
            (job["version_id"],)).fetchone()["c"]
        self.assertEqual(n_attempts, self.svc.cfg.max_attempts)  # 旧尝试未被删改


class TestQueueLease(ServiceCase):
    def test_two_workers_cannot_lease_same_job(self):
        self.image_id("01_normal_masked.json")
        j1 = queue_mod.lease(self.svc.conn, worker_id="w1", lease_seconds=30)
        self.assertIsNotNone(j1)
        j2 = queue_mod.lease(self.svc.conn, worker_id="w2", lease_seconds=30)
        self.assertIsNone(j2)  # 队列为空

    def test_expired_lease_is_reaped_and_reprocessed_once(self):
        image_id = self.image_id("01_normal_masked.json")
        j = queue_mod.lease(self.svc.conn, worker_id="w-crashed", lease_seconds=0)
        time.sleep(0.05)
        j2 = queue_mod.lease(self.svc.conn, worker_id="w-recovery", lease_seconds=30)
        self.assertEqual(j["id"], j2["id"])
        self.assertEqual(j2["lease_owner"], "w-recovery")
