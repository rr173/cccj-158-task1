import io

from tests.helpers import ServiceCase
from medidx.security import ApiError
from medidx import audit


class TestAudit(ServiceCase):
    def test_chain_records_and_verifies(self):
        self.image_id("01_normal_masked.json")
        self.pump()
        res = self.svc.audit_verify(self.admin)
        self.assertTrue(res["ok"])
        self.assertGreaterEqual(res["events"], 2)

    def test_tampering_breaks_chain_verification(self):
        self.image_id("01_normal_masked.json")
        # 只增触发器阻止 UPDATE；模拟库文件被攻击者离线改写：在不带触发器的
        # 新连接上重建一张同构库（DROP TRIGGER 需要绕开，这里用独立临时库复制数据）
        import sqlite3, os
        self.svc.conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        self.svc.conn.close()
        path = self.svc.cfg.db_path
        import shutil
        from pathlib import Path
        bak = str(path) + ".bak"
        shutil.copy(path, bak)
        attacker = sqlite3.connect(bak)
        triggers = [r[0] for r in attacker.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='audit_events'")]
        for t in triggers:
            attacker.execute(f"DROP TRIGGER {t}")
        attacker.execute(
            "UPDATE audit_events SET detail_json='{\"hacked\":true}'"
            " WHERE id=(SELECT MAX(id) FROM audit_events)")
        attacker.commit(); attacker.close()
        from medidx.db import connect
        evil = connect(bak)
        old_conn = self.svc.conn
        self.svc.conn = evil
        try:
            with self.assertRaises(ApiError) as cm:
                self.svc.audit_verify(self.admin)
            self.assertIn(cm.exception.code, ("audit_chain_tampered", "audit_chain_broken"))
        finally:
            self.svc.conn = old_conn
            evil.close()
            os.remove(bak)
            self.svc.conn = connect(path)

    def test_audit_export_requires_admin_and_is_csv(self):
        self.image_id("01_normal_masked.json")
        with self.assertRaises(ApiError):
            self.svc.audit_export(self.clinician)
        csv_text = self.svc.audit_export(self.admin, limit=10)
        self.assertIn("event_id", csv_text.splitlines()[0])
        self.assertIn("ingest.frozen", csv_text)

    def test_key_actions_all_audited(self):
        image_id = self.image_id("01_normal_masked.json")
        self.pump()
        v = self.only_version(image_id)
        self.svc.publish(self.qc, v["id"])
        ws, we = __import__("tests.test_relink", fromlist=["window"]).window()
        g = self.svc.create_grant(self.clinician, image_id, "目的X", ws, we, "privacy.li")
        self.svc.redeem(self.clinician, g["one_time_token"])
        actions = {r["action"] for r in self.svc.audit_list(self.admin, limit=500)}
        for required in ("ingest.frozen", "derive.ready_for_qc", "qc.published",
                         "relink.grant_created", "relink.exposed"):
            self.assertIn(required, actions)


class TestRBAC(ServiceCase):
    def test_only_privacy_officer_creates_policy(self):
        with self.assertRaises(ApiError) as cm:
            self.svc.create_policy(self.clinician, self.project_id, "X",
                                   None, 1, "nope")
        self.assertEqual(cm.exception.code, "forbidden_role")

    def test_only_qc_publishes(self):
        image_id = self.image_id("01_normal_masked.json")
        self.pump()
        with self.assertRaises(ApiError):
            self.svc.publish(self.clinician, self.only_version(image_id)["id"])
        with self.assertRaises(ApiError):
            self.svc.publish(self.privacy, self.only_version(image_id)["id"])

    def test_clinician_cannot_read_grant_list(self):
        with self.assertRaises(ApiError):
            self.svc.list_grants(self.clinician)
