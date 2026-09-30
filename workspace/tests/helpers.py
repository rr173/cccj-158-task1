import json
import tempfile
import unittest

from medidx.config import Config
from medidx.demo import sample_images
from medidx.service import Service


class ServiceCase(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.svc = Service(Config(self._dir.name))
        self.admin = self.user("u_admin")
        self.qc = self.user("u_qc")
        self.clinician = self.user("u_clinician")
        self.privacy = self.user("u_privacy")
        proj = self.svc.create_project(self.admin, "P-TEST", "测试项目")
        self.project_id = proj["id"]
        self.samples = {name: payload for name, payload in sample_images()}

    def tearDown(self):
        self.svc.conn.close()
        self._dir.cleanup()

    def user(self, uid):
        return self.svc.conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

    def ingest(self, name):
        payload = self.samples[name]
        return self.svc.ingest(self.admin, self.project_id,
                               json.dumps(payload).encode(), "json", name)

    def pump(self, rounds=1, wait=0):
        from medidx import worker
        import time
        total = 0
        for _ in range(rounds):
            total += worker.run_loop(self.svc, max_iterations=50)
            if wait:
                time.sleep(wait)
        return total

    def image_id(self, name):
        return self.ingest(name)["image_id"]

    def only_version(self, image_id, revision=1):
        return self.svc.conn.execute(
            "SELECT * FROM derived_versions WHERE image_id=? AND revision=?",
            (image_id, revision)).fetchone()

    def own_conn(self):
        from medidx.db import connect
        return connect(self.svc.cfg.db_path)
