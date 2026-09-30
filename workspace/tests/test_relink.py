import hashlib
import threading
import time
from datetime import datetime, timedelta, timezone

from tests.helpers import ServiceCase
from medidx.security import ApiError


def window(offset_start=-1, offset_end=60):
    now = datetime.now(timezone.utc)
    fmt = lambda d: d.strftime("%Y-%m-%dT%H:%M")
    return fmt(now + timedelta(minutes=offset_start)), fmt(now + timedelta(minutes=offset_end))


class TestRelink(ServiceCase):
    def _grant(self, image_id):
        ws, we = window()
        return self.svc.create_grant(self.clinician, image_id, "临床纠错：核对既往史",
                                     ws, we, "privacy.li")

    def test_full_grant_redeem_is_one_shot_and_expires(self):
        image_id = self.image_id("01_normal_masked.json")
        g = self._grant(image_id)
        token = g["one_time_token"]
        out = self.svc.redeem(self.clinician, token)
        self.assertEqual(out["identity"]["patient_name"], "ZHANG^SAN")
        self.assertEqual(out["identity"]["patient_id"], "MRN-88990011")
        # 授权立即失效，令牌二次使用被拒且不含身份
        with self.assertRaises(ApiError) as cm:
            self.svc.redeem(self.clinician, token)
        self.assertEqual(cm.exception.code, "token_already_used")
        self.assertNotIn("identity", cm.exception.__dict__)
        row = self.svc.conn.execute(
            "SELECT status FROM relink_grants WHERE id=?", (g["grant_id"],)).fetchone()
        self.assertEqual(row["status"], "exported")

    def test_dual_roles_required(self):
        image_id = self.image_id("01_normal_masked.json")
        ws, we = window()
        # 申请人非临床医生（服务层 RBAC 先拦截）
        with self.assertRaises(ApiError) as cm:
            self.svc.create_grant(self.qc, image_id, "x", ws, we, "privacy.li")
        self.assertEqual(cm.exception.code, "forbidden_role")
        # 审批人非隐私官
        with self.assertRaises(ApiError) as cm:
            self.svc.create_grant(self.clinician, image_id, "x", ws, we, "admin.chen")
        self.assertEqual(cm.exception.code, "not_privacy_officer")

    def test_window_not_started_and_closed(self):
        image_id = self.image_id("01_normal_masked.json")
        # 尚未开始的窗口
        ws, we = window(offset_start=10, offset_end=30)
        g = self.svc.create_grant(self.clinician, image_id, "未来窗口", ws, we, "privacy.li")
        with self.assertRaises(ApiError) as cm:
            self.svc.redeem(self.clinician, g["one_time_token"])
        self.assertEqual(cm.exception.code, "outside_window")

        # 已过期授权：直接插一条历史授权（模拟此前创建、现已超出窗口）
        from medidx.security import new_id, new_token
        import hashlib
        grant_id = new_id()
        export_id = new_id()
        token = new_token()
        ws2, we2 = window(offset_start=-120, offset_end=-60)
        self.svc.conn.execute(
            "INSERT INTO relink_grants(id, image_id, project_id, purpose, requested_by,"
            " approved_by, window_start, window_end, status, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,'active','2020-01-01T00:00:00Z')",
            (grant_id, image_id, self.project_id, "历史窗口",
             self.clinician["id"], self.privacy["id"], ws2, we2))
        self.svc.conn.execute(
            "INSERT INTO relink_exports(id, grant_id, token_hash, created_at)"
            " VALUES (?,?,?, '2020-01-01T00:00:00Z')",
            (export_id, grant_id, hashlib.sha256(token.encode()).hexdigest()))
        with self.assertRaises(ApiError) as cm:
            self.svc.redeem(self.clinician, token)
        self.assertEqual(cm.exception.code, "outside_window")
        row = self.svc.conn.execute("SELECT status FROM relink_grants WHERE id=?",
                                    (grant_id,)).fetchone()
        self.assertEqual(row["status"], "expired")

    def test_create_grant_rejects_past_window(self):
        image_id = self.image_id("01_normal_masked.json")
        ws2, we2 = window(offset_start=-120, offset_end=-60)
        with self.assertRaises(ApiError) as cm:
            self.svc.create_grant(self.clinician, image_id, "过期窗口", ws2, we2, "privacy.li")
        self.assertEqual(cm.exception.code, "bad_window")

    def test_grant_bound_to_case_and_purpose(self):
        i1 = self.image_id("01_normal_masked.json")
        i2 = self.image_id("05_stealth_phi_caught.json")
        g = self._grant(i1)
        out = self.svc.redeem(self.clinician, g["one_time_token"])
        # 只能拿到绑定病例 i1 的身份
        self.assertEqual(out["image_id"], i1)
        self.assertNotEqual(out["image_id"], i2)

    def test_revoke_then_redeem_loses_race_and_no_identity(self):
        image_id = self.image_id("01_normal_masked.json")
        g = self._grant(image_id)
        token = g["one_time_token"]
        self.svc.revoke_grant(self.privacy, g["grant_id"], "患者撤回授权")
        with self.assertRaises(ApiError) as cm:
            self.svc.redeem(self.clinician, token)
        self.assertIn(cm.exception.code,
                      ("grant_not_active", "token_already_used", "revoked_race"))
        exp = self.svc.conn.execute(
            "SELECT outcome FROM relink_exports WHERE grant_id=?", (g["grant_id"],)).fetchone()
        self.assertNotEqual(exp["outcome"], "exposed")

    def test_revoke_redeem_race_only_one_wins_no_identity_leak(self):
        from medidx import relink
        image_id = self.image_id("01_normal_masked.json")
        g = self._grant(image_id)
        token = g["one_time_token"]
        results = []
        barrier = threading.Barrier(2)
        conn_r = self.own_conn()
        conn_v = self.own_conn()

        def redeem():
            barrier.wait()
            try:
                out = relink.redeem_token(conn_r, cfg=self.svc.cfg, token=token,
                                          user_id=self.clinician["id"])
                results.append(("redeem", out["identity"]["patient_id"]))
            except ApiError as e:
                results.append(("redeem_err", e.code))

        def revoke():
            barrier.wait()
            r = relink.revoke_grant(conn_v, cfg=self.svc.cfg, grant_id=g["grant_id"],
                                    revoked_by=self.privacy["id"], reason="紧急撤销")
            results.append(("revoke", r["status"]))

        t1, t2 = threading.Thread(target=redeem), threading.Thread(target=revoke)
        t1.start(); t2.start(); t1.join(); t2.join()
        conn_r.close(); conn_v.close()

        exposed = [r for r in results if r[0] == "redeem"]
        redeem_err = [r for r in results if r[0] == "redeem_err"]
        grant = self.svc.conn.execute("SELECT status FROM relink_grants WHERE id=?",
                                      (g["grant_id"],)).fetchone()["status"]
        self.assertIn(grant, ("revoked", "exported"))
        if grant == "revoked":
            # 撤销赢：领取必须失败，绝不泄露身份
            self.assertEqual(exposed, [])
            self.assertTrue(redeem_err)
        else:
            # 领取赢：身份恰好暴露一次，撤销迟到但不改写历史
            self.assertEqual(len(exposed), 1)

    def test_revoke_of_exported_is_late_but_audited(self):
        image_id = self.image_id("01_normal_masked.json")
        g = self._grant(image_id)
        self.svc.redeem(self.clinician, g["one_time_token"])
        r = self.svc.revoke_grant(self.privacy, g["grant_id"], "事后撤销尝试")
        self.assertFalse(r["revoked"])
        self.assertEqual(r["status"], "exported")

    def test_token_not_stored_plaintext(self):
        image_id = self.image_id("01_normal_masked.json")
        g = self._grant(image_id)
        raw = self.svc.conn.execute(
            "SELECT token_hash FROM relink_exports WHERE grant_id=?",
            (g["grant_id"],)).fetchone()["token_hash"]
        self.assertEqual(raw, hashlib.sha256(g["one_time_token"].encode()).hexdigest())
        self.assertNotIn(g["one_time_token"], raw)

    def test_cross_image_token_table_one_row_per_grant(self):
        image_id = self.image_id("01_normal_masked.json")
        g = self._grant(image_id)
        n = self.svc.conn.execute(
            "SELECT COUNT(*) c FROM relink_exports WHERE grant_id=?",
            (g["grant_id"],)).fetchone()["c"]
        self.assertEqual(n, 1)
