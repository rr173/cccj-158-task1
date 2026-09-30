"""HTTP API + 静态前端（仅标准库 http.server）。

所有 /api/* 返回 JSON；错误统一 {"error": {code,message}}；
身份令牌经 Authorization: Bearer 传递；原始身份只在回链领取响应中出现。
"""
from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import worker as worker_mod
from .security import ApiError
from .service import Service


def make_handler(svc: Service):
    class Handler(BaseHTTPRequestHandler):
        server_version = "MedIdx/1.0"

        def log_message(self, fmt, *args):  # 安静
            return

        # ---------- 基础收发 ----------
        def _send_json(self, obj, status: int = 200, headers: dict | None = None):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send_text(self, text: str, status: int = 200, ctype: str = "text/csv; charset=utf-8",
                       filename: str = "audit.csv"):
            body = text.encode("utf-8-sig")
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Disposition",
                             f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if not length:
                return {}
            try:
                obj = json.loads(self.rfile.read(length).decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ApiError(400, "bad_json", f"请求体不是合法 JSON: {exc}")
            if not isinstance(obj, dict):
                raise ApiError(400, "bad_json", "请求体必须是 JSON 对象")
            return obj

        def _multipart(self) -> dict:
            ctype = self.headers.get("Content-Type", "")
            m = re.search(r'boundary=("?)([^";]+)\1', ctype)
            if not m:
                raise ApiError(400, "bad_multipart", "缺少 multipart boundary")
            boundary = b"--" + m.group(2).encode()
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            parts: dict[str, dict] = {}
            for chunk in body.split(boundary):
                chunk = chunk.strip(b"\r\n")
                if not chunk or chunk == b"--":
                    continue
                if b"\r\n\r\n" not in chunk:
                    continue
                head, _, content = chunk.partition(b"\r\n\r\n")
                headers = head.decode("latin-1", "replace")
                cd = re.search(r'name="([^"]+)"(?:;\s*filename="([^"]*)")?', headers)
                if not cd:
                    continue
                name, filename = cd.group(1), cd.group(2)
                if filename is not None:
                    parts[name] = {"filename": filename, "content": content}
                else:
                    parts[name] = {"value": content.decode("utf-8").strip()}
            return parts

        def _user(self):
            auth = self.headers.get("Authorization", "")
            token = auth[7:].strip() if auth.startswith("Bearer ") else None
            return svc.authenticate(token)

        # ---------- 路由 ----------
        def do_GET(self):
            self._dispatch("GET")

        def do_POST(self):
            self._dispatch("POST")

        def _dispatch(self, method: str):
            parsed = urlparse(self.path)
            path, qs = parsed.path, parse_qs(parsed.query)
            try:
                if not path.startswith("/api/"):
                    return self._serve_static(path)
                route = self._match(method, path, qs)
                if route is None:
                    raise ApiError(404, "not_found", f"无此接口: {method} {path}")
                route()
            except ApiError as exc:
                self._send_json({"error": {"code": exc.code, "message": exc.message}},
                                exc.status)
            except Exception as exc:  # 兜底：不向前端泄露堆栈细节
                self._send_json({"error": {"code": "internal_error",
                                           "message": f"服务器内部错误: {type(exc).__name__}"}}, 500)
                raise
            finally:
                # 兜底回滚未提交事务并回收本线程连接，避免连接/事务泄漏
                try:
                    if svc.conn.in_transaction:
                        svc.conn.execute("ROLLBACK")
                except Exception:
                    pass
                svc.release_conn()

        def _match(self, method: str, path: str, qs: dict):
            u = self._user if not (method == "POST" and path == "/api/login") else lambda: None
            routes = self._routes(method, qs)
            for pattern, handler in routes:
                m = re.fullmatch(pattern, path)
                if m:
                    return lambda: handler(u(), **m.groupdict())
            return None

        def _routes(self, method: str, qs: dict):
            q = lambda key, default=None: qs.get(key, [default])[0]
            if method == "GET":
                return [
                    (r"/api/me", lambda user: self._send_json({"user": {
                        "id": user["id"], "username": user["username"],
                        "display_name": user["display_name"], "role": user["role"]}})),
                    (r"/api/projects", lambda user: self._send_json(
                        {"projects": svc.list_projects()})),
                    (r"/api/projects/(?P<pid>[0-9a-f]+)/policies",
                     lambda user, pid: self._send_json(
                         {"policies": svc.list_policies(pid)})),
                    (r"/api/projects/(?P<pid>[0-9a-f]+)/images",
                     lambda user, pid: self._send_json({"images": svc.list_images(pid)})),
                    (r"/api/images/(?P<iid>[0-9a-f]+)/versions",
                     lambda user, iid: self._send_json(
                         {"versions": svc.list_versions_for_image(iid)})),
                    (r"/api/versions/(?P<vid>[0-9a-f]+)",
                     lambda user, vid: self._send_json(svc.get_version(user, vid))),
                    (r"/api/qc/pending", lambda user: self._send_json(
                        {"queue": svc.pending_qc_queue()})),
                    (r"/api/queue", lambda user: self._send_json(
                        {"jobs": svc.queue_list()})),
                    (r"/api/grants", lambda user: self._send_json(
                        {"grants": svc.list_grants(user, image_id=q("image_id"))})),
                    (r"/api/audit", lambda user: self._send_json(
                        {"events": svc.audit_list(
                            user, limit=int(q("limit", "500")), action=q("action"),
                            object_type=q("object_type"), object_id=q("object_id"))})),
                    (r"/api/audit/verify", lambda user: self._send_json(svc.audit_verify(user))),
                    (r"/api/audit/export",
                     lambda user: self._audit_export(user, qs)),
                ]
            # POST
            return [
                (r"/api/login", lambda user: self._do_login()),
                (r"/api/projects", lambda user: self._create_project(user)),
                (r"/api/policies", lambda user: self._create_policy(user)),
                (r"/api/ingest", lambda user: self._ingest(user)),
                (r"/api/worker/pump", lambda user: self._worker_pump(user)),
                (r"/api/versions/(?P<vid>[0-9a-f]+)/publish",
                 lambda user, vid: self._send_json(svc.publish(user, vid))),
                (r"/api/versions/(?P<vid>[0-9a-f]+)/reject",
                 lambda user, vid: self._reject(user, vid)),
                (r"/api/images/(?P<iid>[0-9a-f]+)/revisions",
                 lambda user, iid: self._new_revision(user, iid)),
                (r"/api/images/(?P<iid>[0-9a-f]+)/retry",
                 lambda user, iid: self._retry(user, iid)),
                (r"/api/relink/grants", lambda user: self._create_grant(user)),
                (r"/api/relink/grants/(?P<gid>[0-9a-f]+)/revoke",
                 lambda user, gid: self._revoke(user, gid)),
                (r"/api/relink/redeem", lambda user: self._redeem(user)),
                (r"/api/audit/export", lambda user: self._audit_export(user, qs)),
            ]

        # ---------- 动作 ----------
        def _do_login(self):
            body = self._read_json()
            self._send_json(svc.login(body.get("username", "")))

        def _create_project(self, user):
            body = self._read_json()
            self._send_json(svc.create_project(
                user, body.get("name", ""), body.get("description", "")), 201)

        def _create_policy(self, user):
            body = self._read_json()
            res = svc.create_policy(user, body["project_id"], body.get("name", "DEFAULT"),
                                    body.get("rules"), body.get("base_version"),
                                    body.get("notes", ""))
            self._send_json(res, 201)

        def _ingest(self, user):
            parts = self._multipart()
            if "project_id" not in parts:
                raise ApiError(400, "missing_field", "缺少 project_id")
            project_id = parts["project_id"]["value"]
            if "file" not in parts:
                raise ApiError(400, "missing_file", "缺少 file（DICOM / DICOM-JSON）")
            mt = parts.get("media_type", {}).get("value")
            f = parts["file"]
            res = svc.ingest(user, project_id, f["content"], mt, f.get("filename", ""))
            self._send_json(res, 201)

        def _worker_pump(self, user):
            body = self._read_json()
            n = worker_mod.run_loop(svc, max_iterations=body.get("max_jobs") or 10)
            self._send_json({"processed": n, "queue": svc.queue_list()})

        def _reject(self, user, vid):
            body = self._read_json()
            svc.reject(user, vid, body.get("reason", ""))
            self._send_json({"ok": True})

        def _new_revision(self, user, iid):
            body = self._read_json()
            self._send_json(svc.new_revision(user, iid, body.get("reason", ""),
                                             body.get("policy_id")), 201)

        def _retry(self, user, iid):
            svc.retry_dead(user, iid)
            self._send_json({"ok": True, "queued": True})

        def _create_grant(self, user):
            body = self._read_json()
            res = svc.create_grant(user, body["image_id"], body["purpose"],
                                   body["window_start"], body["window_end"],
                                   body["approver_username"])
            self._send_json(res, 201)

        def _revoke(self, user, gid):
            body = self._read_json()
            self._send_json(svc.revoke_grant(user, gid, body.get("reason", "")))

        def _redeem(self, user):
            body = self._read_json()
            self._send_json(svc.redeem(user, body.get("token", "")))

        def _audit_export(self, user, qs):
            csv_text = svc.audit_export(
                user, limit=int(qs.get("limit", ["500"])[0]),
                action=qs.get("action", [None])[0],
                object_type=qs.get("object_type", [None])[0],
                object_id=qs.get("object_id", [None])[0])
            self._send_text(csv_text)

        # ---------- 静态前端 ----------
        def _serve_static(self, path: str):
            if path in ("/", ""):
                path = "/index.html"
            safe = path.lstrip("/").replace("..", "")
            full = svc.cfg.static_dir / safe
            if not full.is_file():
                raise ApiError(404, "not_found", "静态资源不存在")
            ctype = {"html": "text/html; charset=utf-8", "js": "text/javascript; charset=utf-8",
                     "css": "text/css"}.get(full.suffix.lstrip("."), "application/octet-stream")
            data = full.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return Handler


def serve(cfg, host: str = "127.0.0.1", port: int = 8080) -> None:
    svc = Service(cfg)
    httpd = ThreadingHTTPServer((host, port), make_handler(svc))
    print(f"MedIdx 平台已启动：http://{host}:{port}/  数据目录 {cfg.home}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
