import sqlite3

from tests.helpers import ServiceCase


class TestPolicyVersions(ServiceCase):
    def test_policy_upgrade_creates_new_revision_never_overwrites(self):
        image_id = self.image_id("01_normal_masked.json")
        self.pump()
        v1 = self.only_version(image_id, 1)
        self.svc.publish(self.qc, v1["id"])

        # 升级到 v2（额外清理协议名/其他患者 ID 等）
        from medidx.policy import create_policy, default_rules
        pid2 = create_policy(self.svc.conn, project_id=self.project_id, name="NEURO-DEID",
                             rules=default_rules(2), version=2, notes="更严格 v2",
                             user_id=self.privacy["id"], now="2026-01-01T00:00:00Z")
        res = self.svc.new_revision(self.privacy, image_id, "policy_upgrade", pid2)
        self.assertEqual(res["revision"], 2)
        self.pump()
        v2 = self.only_version(image_id, 2)
        self.svc.publish(self.qc, v2["id"])

        # 旧版本仍在、仍指向 v1 策略、状态仍是 published
        v1_after = self.only_version(image_id, 1)
        self.assertEqual(v1_after["status"], "published")
        self.assertNotEqual(v1_after["policy_id"], v2["policy_id"])

        from medidx import derive
        art1 = derive.load_artifact(self.svc.cfg, v1_after["artifact_sha256"])
        art2 = derive.load_artifact(self.svc.cfg, v2["artifact_sha256"])
        self.assertIn("(0018,1030)", art1["elements"])       # v1 保留协议名
        self.assertNotIn("(0018,1030)", art2["elements"])    # v2 已清除
        # 替代身份在版本间保持稳定（同项目同原值）
        self.assertEqual(art1["elements"]["(0010,0020)"],
                         art2["elements"]["(0010,0020)"])

    def test_policy_rows_immutable_and_versioned(self):
        from medidx.policy import create_policy, default_rules
        p1 = create_policy(self.svc.conn, project_id=self.project_id, name="X",
                           rules=default_rules(1), version=1, notes="a",
                           user_id=self.privacy["id"], now="2026-01-01T00:00:00Z")
        p2 = create_policy(self.svc.conn, project_id=self.project_id, name="X",
                           rules=default_rules(2), version=2, notes="b",
                           user_id=self.privacy["id"], now="2026-02-01T00:00:00Z")
        self.assertNotEqual(p1, p2)
        with self.assertRaises(sqlite3.IntegrityError):
            self.svc.conn.execute("UPDATE policies SET notes='hacked' WHERE id=?", (p1,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.svc.conn.execute("DELETE FROM policies WHERE id=?", (p1,))

    def test_published_version_immutable(self):
        image_id = self.image_id("01_normal_masked.json")
        self.pump()
        v = self.only_version(image_id, 1)
        self.svc.publish(self.qc, v["id"])
        with self.assertRaises(sqlite3.IntegrityError):
            self.svc.conn.execute(
                "UPDATE derived_versions SET status='rejected' WHERE id=?", (v["id"],))
        with self.assertRaises(sqlite3.IntegrityError):
            self.svc.conn.execute(
                "UPDATE derived_versions SET artifact_sha256='deadbeef' WHERE id=?", (v["id"],))
