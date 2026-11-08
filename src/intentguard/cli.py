"""The `intentguard` command.

    intentguard init                      write a documented intentguard.toml to edit
    intentguard check-config FILE         validate a config file and say what it sets
    intentguard serve --demo              run the HTTP service with the mock tools (dashboard backend)
    intentguard serve --upstream "CMD" --config intentguard.toml
                                          run the service in front of an existing MCP server
    intentguard mcp ...                   run the MCP gateway (same options as `python -m intentguard.mcp_gateway`)
    intentguard verify-audit FILE         check a persisted audit log's hash chain
    intentguard report FILE [--session ID]  readable summary of an audit log, per session
"""

from __future__ import annotations

import argparse
import os
import sys
from importlib import resources
from pathlib import Path

from .audit import AuditLog
from .config import Config, ConfigError, load_config
from .engine import PolicyEngine
from .gateway import Gateway
from .mock_env import MockEnv

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def cmd_init(a: argparse.Namespace) -> int:
    target = Path(a.path)
    if target.exists() and not a.force:
        print(f"{target} already exists; use --force to overwrite", file=sys.stderr)
        return 1
    target.write_text(resources.files("intentguard").joinpath("sample_config.toml").read_text(encoding="utf-8"),
                      encoding="utf-8")
    print(f"wrote {target}. Edit it, then: intentguard check-config {target}")
    return 0


def cmd_check_config(a: argparse.Namespace) -> int:
    try:
        c = load_config(a.path)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 1
    e = c.engine
    print(f"ok: {a.path}")
    print(f"  engine: quarantine at {e.quarantine_at}, ladder "
          f"{', '.join(f'{cap} at {at}' for at, cap in sorted(e.ladder))}")
    print(f"  catalog: {len(c.classes)} classified resources, {len(c.trust)} destinations, {len(c.tables)} tables")
    print(f"  tools: {', '.join(c.tools) or 'none (demo or default tools)'}")
    print(f"  default grants: {'set' if c.grants else 'none'}")
    return 0


def cmd_verify_audit(a: argparse.Namespace) -> int:
    if not Path(a.path).exists():
        print(f"no such file: {a.path}", file=sys.stderr)
        return 1
    log = AuditLog(a.path)
    ok, bad = log.verify()
    if ok:
        print(f"ok: {len(log.entries)} entries, hash chain intact")
        return 0
    print(f"TAMPERED: the chain breaks at entry {bad} of {len(log.entries)}", file=sys.stderr)
    return 1


def cmd_report(a: argparse.Namespace) -> int:
    from .report import build_report
    if not Path(a.path).exists():
        print(f"error: no such file: {a.path}", file=sys.stderr)
        return 2
    log = AuditLog(a.path)
    print(build_report(log, a.session), end="")
    return 0 if log.verify()[0] else 1


def build_service(a: argparse.Namespace):
    """The FastAPI app for `serve`. Raises ConfigError or ValueError for a bad setup."""
    from .service.app import add_demo_seed, create_app  # needs the 'api' extra (fastapi, uvicorn)
    cfg = load_config(a.config) if a.config else Config()
    agent_token = a.agent_token or os.environ.get("INTENTGUARD_AGENT_TOKEN")
    admin_token = a.admin_token or os.environ.get("INTENTGUARD_ADMIN_TOKEN")
    if a.host not in LOOPBACK and not (agent_token and admin_token):
        raise ValueError(f"refusing to listen on {a.host} without both --agent-token and --admin-token "
                         "(or INTENTGUARD_AGENT_TOKEN / INTENTGUARD_ADMIN_TOKEN)")
    audit = AuditLog(a.audit_file or os.environ.get("INTENTGUARD_AUDIT_FILE"))
    engine = PolicyEngine(cfg.engine)
    if a.demo:
        env = MockEnv()
        has_catalog = cfg.classes or cfg.trust or cfg.tables
        gw = Gateway(env.tools(), cfg.catalog() if has_catalog else env.catalog(), engine, audit)
    else:
        from .mcp_gateway import StdioUpstream, build_proxy, split_command
        if not cfg.tools:
            raise ValueError("--upstream needs --config with at least one [tools.<name>] section")
        gw, _ = build_proxy(StdioUpstream(split_command(a.upstream)), cfg.proxy_dict(), engine)
        gw.audit = audit
    db = getattr(a, "db", None) or os.environ.get("INTENTGUARD_DB")
    if db:
        from .store import SessionStore
        n = gw.attach_store(SessionStore(db))
        if n:
            print(f"restored {n} session(s) from {db}", file=sys.stderr)
    app = create_app(gw, agent_token, admin_token, cfg.grants or None)
    if a.demo:
        add_demo_seed(app, admin_token)
    return app


def cmd_serve(a: argparse.Namespace) -> int:
    try:
        app = build_service(a)
    except (ConfigError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    import uvicorn
    if not (a.admin_token or os.environ.get("INTENTGUARD_ADMIN_TOKEN")):
        print("warning: no admin token, so anyone who can reach this port can approve actions "
              "(fine on localhost only)", file=sys.stderr)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["mcp"]:  # the MCP gateway has its own option set
        from .mcp_gateway import main as mcp_main
        mcp_main(argv[1:])
        return 0
    ap = argparse.ArgumentParser(prog="intentguard", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="write a documented config file")
    p.add_argument("path", nargs="?", default="intentguard.toml")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)
    p = sub.add_parser("check-config", help="validate a config file")
    p.add_argument("path")
    p.set_defaults(fn=cmd_check_config)
    p = sub.add_parser("verify-audit", help="check an audit log's hash chain")
    p.add_argument("path")
    p.set_defaults(fn=cmd_verify_audit)
    p = sub.add_parser("report", help="readable summary of an audit log, per session")
    p.add_argument("path")
    p.add_argument("--session", help="only this session")
    p.set_defaults(fn=cmd_report)
    p = sub.add_parser("serve", help="run the HTTP service")
    p.add_argument("--demo", action="store_true", help="serve the mock tools (synthetic data)")
    p.add_argument("--upstream", help="command that starts the MCP server to put the service in front of")
    p.add_argument("--config")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--audit-file")
    p.add_argument("--db", help="SQLite file that keeps sessions across restarts (or INTENTGUARD_DB)")
    p.add_argument("--agent-token")
    p.add_argument("--admin-token")
    p.set_defaults(fn=cmd_serve)
    sub.add_parser("mcp", help="run the MCP gateway (see `intentguard mcp --help`)")
    a = ap.parse_args(argv)
    if a.cmd == "serve" and a.demo == bool(a.upstream):
        ap.error("serve: choose exactly one of --demo or --upstream")
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
