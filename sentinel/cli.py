"""Headless command line for SENTINEL AI.

Useful on a Kali box without the desktop UI, and for a scope dry-run:

    sentinel tools                      # Kali tool health check
    sentinel targets -c config/targets.yaml
    sentinel check lab.example tls -c config/targets.yaml   # scope dry-run

``check`` runs the full policy gate (allowlist, authorization, mode, DNS/address
validation) and prints whether the request would be allowed, resolving real DNS.
It never launches a scanner.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .errors import PolicyError
from .modes import ModeManager
from .policy.scope import ScopeEngine
from .scanners.tools import detect_all


def _cmd_version(_args: argparse.Namespace) -> int:
    print(f"sentinel-ai {__version__}")
    return 0


def _cmd_tools(_args: argparse.Namespace) -> int:
    for name, info in detect_all().items():
        detail = f"{info.path} ({info.version})" if info.available else "missing"
        print(f"[{info.status:>9}] {name}: {detail}")
    return 0


def _cmd_targets(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    for t in cfg.targets:
        active = "active" if t.authorization.is_active() else "INACTIVE"
        print(f"{t.domain}  [{active}]  checks={sorted(t.permitted_checks)}")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    cfg = load_config(args.config)
    engine = ScopeEngine(cfg, ModeManager())
    try:
        vt = engine.validate_scan_request(args.target, args.check)
    except PolicyError as exc:
        print(f"REJECTED: {exc}")
        return 1
    print(
        f"ALLOWED: {vt.hostname} -> {vt.pinned_ip} "
        f"(mode={vt.mode}, check={args.check}, scan_id={vt.scan_id})"
    )
    return 0


def _cmd_migrate(args: argparse.Namespace) -> int:
    from .db import SqliteStore

    store = SqliteStore(args.db)
    version = store.migrate()
    store.close()
    print(f"database {args.db} at schema version {version}")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    from .db import SqliteStore
    from .errors import PolicyError
    from .service import ScanService

    cfg = load_config(args.config)
    store = SqliteStore(args.db)
    store.migrate()
    service = ScanService(cfg, store)
    try:
        vt = service.request_scan(args.target, args.check, args.by)
    except PolicyError as exc:
        print(f"REJECTED: {exc}")
        store.close()
        return 1
    print(f"queued scan {vt.scan_id} ({vt.hostname} -> {vt.pinned_ip}, mode={vt.mode})")
    summary = service.process_next()
    store.close()
    if summary is None:
        print("nothing to process")
        return 1
    print(
        f"scan {summary['state']}: tool={summary['tool']} "
        f"findings={summary['findings']} new={summary['new']}"
        + (f" error={summary['error']}" if summary.get("error") else "")
    )
    return 0 if summary["state"] in ("completed", "partial") else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("version").set_defaults(func=_cmd_version)
    sub.add_parser("tools", help="Kali tool health check").set_defaults(
        func=_cmd_tools
    )

    p_targets = sub.add_parser("targets", help="list authorized targets")
    p_targets.add_argument("-c", "--config", default="config/targets.yaml", type=Path)
    p_targets.set_defaults(func=_cmd_targets)

    p_check = sub.add_parser("check", help="scope dry-run for a target and check")
    p_check.add_argument("target")
    p_check.add_argument("check")
    p_check.add_argument("-c", "--config", default="config/targets.yaml", type=Path)
    p_check.set_defaults(func=_cmd_check)

    p_migrate = sub.add_parser("migrate", help="create or upgrade the database")
    p_migrate.add_argument("--db", default="sentinel.sqlite3", type=Path)
    p_migrate.set_defaults(func=_cmd_migrate)

    p_scan = sub.add_parser("scan", help="request and process one scan")
    p_scan.add_argument("target")
    p_scan.add_argument("check")
    p_scan.add_argument("-c", "--config", default="config/targets.yaml", type=Path)
    p_scan.add_argument("--db", default="sentinel.sqlite3", type=Path)
    p_scan.add_argument("--by", default="operator", help="who requested the scan")
    p_scan.set_defaults(func=_cmd_scan)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
