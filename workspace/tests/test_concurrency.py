import threading

from tests.helpers import ServiceCase
from medidx.config import Config
from medidx.db import connect, init_db
from medidx import derive, queue as queue_mod
from medidx.security import ApiError


class TestConcurrency(ServiceCase):
    def _own_service(self):
        conn = connect(self.svc.cfg.db_path)
        return conn

    def test_concurrent_revisions_only_one_pending(self):
        image_id = self.image_id("01_normal_masked.json")
        self.pump()
        self.svc.publish(self.qc, self.only_version(image_id)["id"])

        conn2 = self._own_service()
        results = []
        barrier = threading.Barrier(2)

        def rev1():
            barrier.wait()
            try:
                derive.create_derived_version(
                    self.svc.conn, cfg=self.svc.cfg, image_id=image_id,
                    reason="policy_upgrade", user_id=self.privacy["id"])
                results.append("ok1")
            except ApiError as e:
                results.append(("err1", e.code))

        def rev2():
            barrier.wait()
            try:
                derive.create_derived_version(
                    conn2, cfg=self.svc.cfg, image_id=image_id,
                    reason="clinical_correction", user_id=self.clinician["id"])
                results.append("ok2")
            except ApiError as e:
                results.append(("err2", e.code))

        t1, t2 = threading.Thread(target=rev1), threading.Thread(target=rev2)
        t1.start(); t2.start(); t1.join(); t2.join()
        conn2.close()
        oks = [r for r in results if r in ("ok1", "ok2")]
        errs = [r for r in results if isinstance(r, tuple)]
        self.assertEqual(len(oks), 1)
        self.assertTrue(any(code == "concurrent_revision" for _, code in errs))
        pending = self.svc.conn.execute(
            "SELECT COUNT(*) c FROM derived_versions WHERE image_id=? AND status='pending_qc'",
            (image_id,)).fetchone()["c"]
        self.assertEqual(pending, 1)

    def test_concurrent_worker_leases_attempts_are_deduped(self):
        image_id = self.image_id("01_normal_masked.json")
        out = {}

        def grab(name):
            conn = self._own_service()
            job = queue_mod.lease(conn, worker_id=name, lease_seconds=30)
            out[name] = job
            if job:
                try:
                    derive.process_job(conn, cfg=self.svc.cfg, job=job, worker_id=name)
                except Exception as e:
                    out[name + "_err"] = type(e).__name__
            conn.close()

        t1 = threading.Thread(target=grab, args=("a",))
        t2 = threading.Thread(target=grab, args=("b",))
        t1.start(); t2.start(); t1.join(); t2.join()
        owners = [j["lease_owner"] for j in out.values() if isinstance(j, dict)]
        self.assertEqual(len(owners), 1)  # 只有一个 worker 拿到
        v = self.only_version(image_id)
        n = self.svc.conn.execute(
            "SELECT COUNT(*) c FROM processing_attempts WHERE version_id=?",
            (v["id"],)).fetchone()["c"]
        self.assertEqual(n, 1)  # 只有一次尝试

    def test_publish_is_guarded_by_transaction(self):
        # 两个质检员同时发布同一版本：只允许一个成功；绝不出现重复发布/半状态
        image_id = self.image_id("01_normal_masked.json")
        self.pump()
        vid = self.only_version(image_id)["id"]
        outcomes = []

        def publish(conn, name):
            try:
                derive.publish_version(conn, cfg=self.svc.cfg, version_id=vid,
                                       user_id=self.qc["id"])
                outcomes.append((name, "ok"))
            except ApiError as e:
                outcomes.append((name, e.code))

        c1, c2 = self._own_service(), self._own_service()
        t1 = threading.Thread(target=publish, args=(c1, "p1"))
        t2 = threading.Thread(target=publish, args=(c2, "p2"))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(sorted(o[1] for o in outcomes), ["already_published", "ok"])
        self.assertEqual(self.only_version(image_id)["status"], "published")
        c1.close(); c2.close()
