"""命令行入口：python -m medidx.cli ..."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import audit
from .config import Config
from .security import ApiError
from .service import Service
from . import worker as worker_mod


def _svc(args) -> Service:
    return Service(Config(args.home))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="medidx", description="医学影像去标识化与受控回链平台")
    parser.add_argument("--home", default=None, help="数据目录（默认 ./.data 或 $MEDIDX_HOME）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("serve", help="启动 HTTP 服务与前端")
    p = sub.add_parser("worker", help="运行队列 worker（消费所有待处理任务后退出）")
    p.add_argument("--loop", action="store_true", help="持续运行")

    p = sub.add_parser("init-demo", help="创建演示项目/策略/示例影像并入队")
    p.add_argument("--count", type=int, default=4, help="示例影像数量（含故障用例）")

    p = sub.add_parser("ingest", help="入库一个 DICOM-JSON/影像文件")
    p.add_argument("--project", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--media-type", default=None)

    p = sub.add_parser("audit", help="审计操作")
    p.add_argument("audit_cmd", choices=["verify", "export", "tail"])
    p.add_argument("--out", default=None)
    p.add_argument("--limit", type=int, default=500)

    args = parser.parse_args(argv)
    cfg = Config(args.home)

    if args.cmd == "serve":
        from .api import serve
        serve(cfg, port=8080)
        return 0

    svc = _svc(args)
    try:
        if args.cmd == "worker":
            from . import queue as queue_mod
            n = worker_mod.run_loop(svc, max_iterations=None if args.loop else 200)
            print(f"处理任务 {n} 个；队列状态 {queue_mod.queue_stats(svc.conn)}")
        elif args.cmd == "init-demo":
            from .demo import seed_demo
            print(json.dumps(seed_demo(svc, count=args.count), ensure_ascii=False, indent=2))
        elif args.cmd == "ingest":
            admin = svc.conn.execute("SELECT * FROM users WHERE id='u_admin'").fetchone()
            raw = Path(args.file).read_bytes()
            print(json.dumps(svc.ingest(admin, args.project, raw, args.media_type,
                                        args.file), ensure_ascii=False, indent=2))
        elif args.cmd == "audit":
            admin = svc.conn.execute("SELECT * FROM users WHERE id='u_admin'").fetchone()
            if args.audit_cmd == "verify":
                print(json.dumps(svc.audit_verify(admin), ensure_ascii=False, indent=2))
            elif args.audit_cmd == "export":
                csv_text = svc.audit_export(admin, limit=args.limit)
                if args.out:
                    Path(args.out).write_text(csv_text, encoding="utf-8-sig")
                    print(f"已导出 {csv_text.count(chr(10)) - 1} 条事件 -> {args.out}")
                else:
                    sys.stdout.write(csv_text)
            else:
                rows = svc.audit_list(admin, limit=args.limit)
                print(json.dumps(rows, ensure_ascii=False, indent=2))
    except ApiError as exc:
        print(f"[{exc.code}] {exc.message}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
