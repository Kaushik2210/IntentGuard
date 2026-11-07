"""An MCP server that puts IntentGuard in front of tools (standard library only).

Two modes, both over the stdio transport (newline-delimited JSON-RPC 2.0):

    python -m intentguard.mcp_gateway --demo --task "Read research/paper.pdf and summarize it." --grants grants.json
    python -m intentguard.mcp_gateway --upstream "python some_mcp_server.py" --config proxy.json \\
        --task "..." --grants grants.json

Demo mode serves the mock tools (synthetic data). Proxy mode starts an existing MCP server as a child process
and re-exposes only the tools named in the config; each call is authorized by the policy engine before it is
forwarded. A tool that is not in the config is not listed, and a call to it is blocked and audited (fail closed).

Implemented: initialize, notifications/initialized, ping, tools/list, tools/call. Not implemented: resources,
prompts, sampling, HTTP transport, pagination, list-changed notifications. A call that needs human approval
(REVIEW) is reported to the model as not executed; there is no approval channel over stdio, so approvals need
the HTTP service and dashboard.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import shlex
import subprocess
import sys
import threading
import time
from dataclasses import replace
from typing import Any, TextIO

from .audit import AuditLog
from .client import InProcessSession, Session, ToolResult
from .config import Config, ConfigError, load_config
from .engine import PolicyEngine
from .gateway import Catalog, Gateway, Tool
from .mock_env import MockEnv
from .models import ActionRequest, Classification, Decision, Op, Trust, Verdict
from .models import Session as PolicySession
from .scope import compile_scope

SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
SERVER_INFO = {"name": "intentguard-gateway", "version": "0.1.0"}


def _schema(props: dict[str, str], required: list[str]) -> dict:
    return {"type": "object", "properties": {k: {"type": "string", "description": v} for k, v in props.items()},
            "required": required}


# Tool descriptors served in demo mode (names match the mock tools).
DEMO_TOOLS = [
    {"name": "read_file", "description": "Read a file by path", "inputSchema": _schema({"path": "File path"}, ["path"])},
    {"name": "search_files", "description": "Search files for text",
     "inputSchema": _schema({"query": "Text to search for"}, ["query"])},
    {"name": "send_email", "description": "Send an email",
     "inputSchema": _schema({"to": "Recipient", "body": "Message body", "attachment": "Optional file to attach"},
                            ["to", "body"])},
    {"name": "upload", "description": "Upload data to a URL",
     "inputSchema": _schema({"url": "Destination URL", "data": "Data to upload"}, ["url", "data"])},
    {"name": "run_shell", "description": "Run a shell command", "inputSchema": _schema({"cmd": "Command"}, ["cmd"])},
    {"name": "db_query", "description": "Run a database query", "inputSchema": _schema({"sql": "SQL"}, ["sql"])},
]


def _text(output: Any) -> str:
    return output if isinstance(output, str) else json.dumps(output, default=str)


class _AllowAll:
    """Demo-only comparison baseline (`--no-policy`): every call is allowed. Never use for real tools."""

    def evaluate(self, req: ActionRequest, s: PolicySession) -> Decision:
        return Decision(req.action_id, Verdict.ALLOW, 0.0, [], [], "no policy", "allow", replace(s.caps))


class McpGateway:
    """Speaks MCP to a client and authorizes each tool call through an IntentGuard session."""

    def __init__(self, session: Session, tools: list[dict]):
        self.session = session
        self.tools = tools
        self.calls: list[ToolResult] = []

    # -- protocol ---------------------------------------------------------------
    def handle(self, msg: dict) -> dict | None:
        method, mid = msg.get("method"), msg.get("id")
        if mid is None:  # notification: no response
            return None
        try:
            if method == "initialize":
                want = (msg.get("params") or {}).get("protocolVersion")
                return self._ok(mid, {"protocolVersion": want if want in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0],
                                      "capabilities": {"tools": {"listChanged": False}},
                                      "serverInfo": SERVER_INFO,
                                      "instructions": "Every tool call is authorized by IntentGuard against the "
                                                      "user's task before it runs."})
            if method == "ping":
                return self._ok(mid, {})
            if method == "tools/list":
                return self._ok(mid, {"tools": self.tools})
            if method == "tools/call":
                p = msg.get("params") or {}
                if not isinstance(p.get("name"), str):
                    return self._err(mid, -32602, "tools/call needs a tool name")
                return self._ok(mid, self._call(p["name"], p.get("arguments") or {}))
            return self._err(mid, -32601, f"method not found: {method}")
        except Exception as exc:  # never leave a request unanswered
            return self._err(mid, -32603, f"internal error: {exc}")

    def _call(self, name: str, args: dict) -> dict:
        res = self.session.call(name, **args)
        self.calls.append(res)
        if res.allowed and not res.error:
            return {"content": [{"type": "text", "text": _text(res.output)}], "isError": False}
        return {"content": [{"type": "text", "text": res.message()}], "isError": True}

    @staticmethod
    def _ok(mid: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    @staticmethod
    def _err(mid: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

    # -- transport --------------------------------------------------------------
    def serve(self, stdin: TextIO = sys.stdin, stdout: TextIO = sys.stdout) -> None:
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                out = self._err(None, -32700, "parse error")
            else:
                out = self.handle(msg) if isinstance(msg, dict) else self._err(None, -32600, "invalid request")
            if out is not None:
                stdout.write(json.dumps(out) + "\n")
                stdout.flush()


class ApprovalSession:
    """Routes calls through the HTTP service app, so the dashboard sees them, and waits for a human on REVIEW.

    A call that needs approval blocks here until someone approves or rejects it through the service
    (`/pending/{id}/approve` or `/reject`, which the dashboard uses). If nobody answers within `timeout`
    seconds the pending action is cancelled, so it cannot run later after the agent has been told it failed.
    """

    def __init__(self, app: Any, gateway: Gateway, session_id: str, timeout: float = 45.0, poll: float = 0.1):
        self._app, self._gw, self._sid, self._timeout, self._poll = app, gateway, session_id, timeout, poll

    def call(self, tool: str, **args: Any) -> ToolResult:
        res = self._app.state.do_call(self._sid, tool, args)
        d = res.decision
        out = ToolResult(d.decision.value, d.explanation, list(d.fired_rules), res.output, d.action_id, d.risk_score,
                         res.error)
        if d.decision != Verdict.REVIEW:
            return out
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            done = self._gw.resolved.get(d.action_id)
            if done:
                kind, value = done
                if kind == "approved":
                    return ToolResult("ALLOW", "approved by a human", out.rules, value, d.action_id, out.risk)
                if kind == "rejected":
                    return ToolResult("BLOCK", "A human rejected this action.", out.rules, None, d.action_id, out.risk)
                return ToolResult("BLOCK", f"A human approved it but the tool failed: {value}", out.rules, None,
                                  d.action_id, out.risk)
            time.sleep(self._poll)
        if d.action_id in self._gw.pending:  # cancel, so a late approval cannot run it behind the agent's back
            self._gw.reject(d.action_id, "timeout")
        return ToolResult("BLOCK", f"No human answered within {self._timeout:.0f}s, so the action was cancelled "
                                   "and not executed.", out.rules, None, d.action_id, out.risk)


# -- proxy mode: wrap an existing MCP server ----------------------------------------
class StdioUpstream:
    """Minimal MCP client for a child process (initialize, tools/list, tools/call)."""

    def __init__(self, command: list[str], timeout: float = 30.0):
        self.timeout = timeout
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)
        self._q: queue.Queue = queue.Queue()
        self._n = 0
        threading.Thread(target=self._pump, daemon=True).start()
        self._request("initialize", {"protocolVersion": SUPPORTED_VERSIONS[1], "capabilities": {},
                                     "clientInfo": {"name": "intentguard-proxy", "version": "0.1.0"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _pump(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            try:
                self._q.put(json.loads(line))
            except json.JSONDecodeError:
                continue

    def _send(self, msg: dict) -> None:
        assert self.proc.stdin
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def _request(self, method: str, params: dict) -> dict:
        self._n += 1
        mid = self._n
        self._send({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
        while True:
            try:
                msg = self._q.get(timeout=self.timeout)
            except queue.Empty as exc:
                raise TimeoutError(f"upstream did not answer {method}") from exc
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"upstream error: {msg['error']}")
                return msg["result"]

    def list_tools(self) -> list[dict]:
        return self._request("tools/list", {})["tools"]

    def call_tool(self, name: str, args: dict) -> str:
        res = self._request("tools/call", {"name": name, "arguments": args})
        text = "\n".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
        if res.get("isError"):
            raise RuntimeError(text or "upstream tool error")
        return text

    def close(self) -> None:
        self.proc.terminate()


def build_proxy(upstream: Any, config: dict, engine: Any = None) -> tuple[Gateway, list[dict]]:
    """Gateway whose tools forward to `upstream`. `config`:

        {"tools":   {"read_note": {"op": "read", "resource_arg": "path"},
                     "send":      {"op": "send", "dest_arg": "to", "resource_arg": "attachment",
                                   "resource_optional": true}},   # "" or "null" then means no attachment
         "classes": {"notes/a.txt": "CONFIDENTIAL"},   # resource -> PUBLIC|INTERNAL|CONFIDENTIAL|SECRET (default INTERNAL)
         "trust":   {"bob@example.org": "approved"},     # destination -> local|approved|unknown|denylisted
         "tables":  {"salaries": "CONFIDENTIAL"}}
    Only upstream tools named under "tools" are exposed.
    """
    mapping = config.get("tools", {})
    listed = {t["name"]: t for t in upstream.list_tools()}
    tools: list[Tool] = []
    exposed: list[dict] = []
    for name, spec in mapping.items():
        if name not in listed:
            continue

        def fn(_name: str = name, **kw: Any) -> str:
            return upstream.call_tool(_name, kw)

        tools.append(Tool(name, Op(spec["op"]), fn, spec.get("resource_arg"), spec.get("dest_arg"),
                          spec.get("resource_optional", False)))
        exposed.append(listed[name])
    catalog = Catalog({k: Classification[v] for k, v in config.get("classes", {}).items()},
                      {k: Trust(v) for k, v in config.get("trust", {}).items()},
                      {k: Classification[v] for k, v in config.get("tables", {}).items()})
    return Gateway(tools, catalog, engine or PolicyEngine()), exposed


def split_command(cmd: str) -> list[str]:
    """Split a command line into arguments. On Windows a backslash is a path separator, not an escape, so the
    plain POSIX rules would mangle a path such as C:/dir/python.exe written with backslashes; quotes still work."""
    parts = shlex.split(cmd, posix=os.name != "nt")
    return [p[1:-1] if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'" else p for p in parts]


def _load(arg: str) -> dict:
    return json.loads(arg) if arg.lstrip().startswith("{") else json.load(open(arg, encoding="utf-8"))


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="MCP server that authorizes every tool call with IntentGuard")
    ap.add_argument("--task", required=True, help="the user's task, which defines what the agent may do")
    ap.add_argument("--grants", help="JSON file or inline JSON: resources, destinations, ceiling "
                                     "(default: the [grants] section of --config)")
    ap.add_argument("--demo", action="store_true", help="serve the mock tools (synthetic data)")
    ap.add_argument("--extra-docs", help="demo mode: JSON file {path: text} of extra synthetic documents (INTERNAL)")
    ap.add_argument("--upstream", help="command that starts the MCP server to protect")
    ap.add_argument("--config", help="intentguard.toml (or .json): engine settings, catalog and, for proxy mode, "
                                     "which upstream tools to expose")
    ap.add_argument("--agent-id", default="mcp-client")
    ap.add_argument("--no-policy", action="store_true", help="demo only: allow every call (comparison baseline)")
    ap.add_argument("--action-risk-cap", type=float, help="most risk a single action can add (experiment; default none)")
    ap.add_argument("--lockout-review", action="store_true",
                    help="experiment: capability locks and quarantine send the action to a human instead of blocking")
    ap.add_argument("--audit-file", help="persist the hash-chained audit log here")
    ap.add_argument("--approvals-port", type=int, help="serve the approval API and dashboard backend on 127.0.0.1:PORT; "
                                                       "calls that need approval wait for a human")
    ap.add_argument("--approval-timeout", type=float, default=45.0, help="seconds to wait for a human (default 45)")
    ap.add_argument("--admin-token", help="bearer token for the approval API (default: none, local use only)")
    a = ap.parse_args(argv)
    if a.demo == bool(a.upstream):
        ap.error("choose exactly one of --demo or --upstream")
    try:
        cfg = load_config(a.config) if a.config else Config()
    except ConfigError as exc:
        ap.error(str(exc))
    engine_cfg = replace(cfg.engine, **{k: v for k, v in (("action_risk_cap", a.action_risk_cap),
                                                          ("lockout_review", a.lockout_review or None)) if v})
    audit = AuditLog(a.audit_file)
    if a.demo:
        if a.extra_docs:  # e.g. a poisoned document for demos; must be loaded before the catalog is built
            from . import mock_env
            for path, body in _load(a.extra_docs).items():
                mock_env.FILES[path] = (body, Classification.INTERNAL)
        env = MockEnv()
        engine = _AllowAll() if a.no_policy else PolicyEngine(engine_cfg)
        has_catalog = cfg.classes or cfg.trust or cfg.tables
        gw, exposed = Gateway(env.tools(), cfg.catalog() if has_catalog else env.catalog(), engine, audit), DEMO_TOOLS
    else:
        if not cfg.tools:
            ap.error("--upstream needs --config with at least one [tools.<name>] section")
        gw, exposed = build_proxy(StdioUpstream(split_command(a.upstream)), cfg.proxy_dict(), PolicyEngine(engine_cfg))
        gw.audit = audit
    grants = _load(a.grants) if a.grants else cfg.grants
    if not grants:
        ap.error("no grants: pass --grants or add a [grants] section to --config")
    session: Session
    if a.approvals_port:
        from .service.app import NewSession, create_app  # needs the 'api' extra (fastapi, uvicorn)
        app = create_app(gw, None, a.admin_token)
        app.state.do_open(NewSession(session_id="mcp", agent_id=a.agent_id, task=a.task, grants=grants))
        import uvicorn
        server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=a.approvals_port, log_level="warning"))
        threading.Thread(target=server.run, daemon=True).start()
        session = ApprovalSession(app, gw, "mcp", a.approval_timeout)
        print(f"approval API on http://127.0.0.1:{a.approvals_port} "
              f"({'token required' if a.admin_token else 'NO TOKEN: local use only'})", file=sys.stderr)
    else:
        session = InProcessSession(gw.open_session("mcp", a.agent_id, compile_scope(a.task, grants)))
    print("intentguard MCP gateway ready", file=sys.stderr)
    McpGateway(session, exposed).serve()


if __name__ == "__main__":
    main()
