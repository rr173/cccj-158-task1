import json
import sqlite3

from tests.helpers import ServiceCase
from medidx.security import verify_seal, SealError


class TestFreeze(ServiceCase):
    def test_ingest_freezes_and_never_leaks(self):
        res = self.ingest("01_normal_masked.json")
        image = self.svc.conn.execute("SELECT * FROM images WHERE id=?",
                                      (res["image_id"],)).fetchone()
        # images 表不存放明文姓名/患者号
        cols = [r[1] for r in self.svc.conn.execute("PRAGMA table_info(images)")]
        self.assertNotIn("patient_name", cols)
        self.assertNotIn("ZHANG^SAN", json.dumps([dict(r) for r in
                         self.svc.conn.execute("SELECT id,media_type,source_uid FROM images")]))

        row = self.svc.conn.execute(
            "SELECT * FROM frozen_summaries WHERE image_id=?", (res["image_id"],)).fetchone()
        payload = verify_seal(self.svc.cfg.seal_key, row["sealed_json"],
                              row["seal_hmac"], row["payload_sha256"])
        self.assertEqual(payload["elements"]["(0010,0010)"], "ZHANG^SAN")

    def test_tampered_frozen_is_detected(self):
        res = self.ingest("01_normal_masked.json")
        row = self.svc.conn.execute(
            "SELECT sealed_json, seal_hmac FROM frozen_summaries WHERE image_id=?",
            (res["image_id"],)).fetchone()
        # 冻结载荷被改过（哪怕一个字符），HMAC 立即不匹配
        tampered = row["sealed_json"].replace("ZHANG^SAN", "LI^SI")
        self.assertNotEqual(tampered, row["sealed_json"])
        with self.assertRaises(SealError):
            verify_seal(self.svc.cfg.seal_key, tampered, row["seal_hmac"])

    def test_frozen_table_is_append_only(self):
        res = self.ingest("01_normal_masked.json")
        with self.assertRaises(sqlite3.IntegrityError):
            self.svc.conn.execute("UPDATE frozen_summaries SET frozen_by='x' WHERE image_id=?",
                                  (res["image_id"],))
        with self.assertRaises(sqlite3.IntegrityError):
            self.svc.conn.execute("DELETE FROM frozen_summaries WHERE image_id=?",
                                  (res["image_id"],))

    def test_idempotent_ingest(self):
        r1 = self.ingest("01_normal_masked.json")
        r2 = self.ingest("01_normal_masked.json")
        self.assertEqual(r1["image_id"], r2["image_id"])
        self.assertTrue(r2["already_exists"])
        n = self.svc.conn.execute("SELECT COUNT(*) c FROM frozen_summaries").fetchone()["c"]
        self.assertEqual(n, 1)
