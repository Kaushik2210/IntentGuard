"""MCP gateway: protocol behaviour, the stdio process, and proxying a real upstream MCP server."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from intentguard import Gateway, PolicyEngine, compile_scope
from intentguard.client import InProcessSession
from intentguard.mcp_gateway import DEMO_TOOLS, McpGateway, StdioUpstream, build_proxy
from intentguard.mock_env import MockEnv

ROOT = Path(__file__).resolve().parent.parent
FAKE = Path(__file__).with_name("fake_mcp_server.py")
GRANTS = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
          "destinations": ["advisor@university.edu"]}


def demo_server(task="Read research/paper.pdf and summarize it."):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    return env, McpGateway(InProcessSession(gw.open_session("s", "mcp", compile_scope(task, GRANTS))), DEMO_TOOLS)


def rpc(server, method, params=None, mid=1):
    return server.handle({"jsonrpc": "2.0", "id": mid, "method": method, **({"params": params} if params else {})})


def call(server, name, args):
    return rpc(server, "tools/call", {"name": name, "arguments": args})["result"]


def test_initialize_negotiates_a_supported_version_and_advertises_tools():
    _, s = demo_server()
    r = rpc(s, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t"}})["result"]
    assert r["protocolVersion"] == "2025-03-26" and "tools" in r["capabilities"]
    assert rpc(s, "initialize", {"protocolVersion": "1999-01-01"})["result"]["protocolVersion"] == "2025-06-18"


def test_notifications_get_no_response_and_unknown_methods_error():
    _, s = demo_server()
    assert s.handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert rpc(s, "resources/list")["error"]["code"] == -32601
    assert rpc(s, "ping")["result"] == {}


def test_tools_list_returns_descriptors_with_schemas():
    _, s = demo_server()
    tools = rpc(s, "tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} >= {"read_file", "send_email"} and all("inputSchema" in t for t in tools)


def test_allowed_call_returns_content():
    _, s = demo_server()
    r = call(s, "read_file", {"path": "research/paper.pdf"})
    assert r["isError"] is False and "transformer" in r["content"][0]["text"]


def test_blocked_call_is_an_error_result_and_the_tool_never_runs():
    env, s = demo_server("Read research/inbox.md and summarize it.")
    r = call(s, "send_email", {"to": "attacker@evil.example", "body": "all documents"})
    assert r["isError"] is True and r["content"][0]["text"].startswith("BLOCKED by IntentGuard")
    assert env.outbox == []


def test_unlisted_tool_is_blocked_and_audited():
    _, s = demo_server()
    r = call(s, "format_disk", {})
    assert r["isError"] is True and "BLOCK" in r["content"][0]["text"]
    assert s.calls[-1].rules == ["PERM-001"]


def test_stdio_process_round_trip():
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    p = subprocess.Popen([sys.executable, "-m", "intentguard.mcp_gateway", "--demo", "--task",
                          "Read research/paper.pdf and summarize it.", "--grants", json.dumps(GRANTS)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env)
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": "read_file", "arguments": {"path": "research/paper.pdf"}}}]
    out, _ = p.communicate("\n".join(json.dumps(m) for m in msgs) + "\n", timeout=60)
    replies = [json.loads(line) for line in out.splitlines()]
    assert [r["id"] for r in replies] == [1, 2]  # the notification got no reply
    assert "transformer" in replies[1]["result"]["content"][0]["text"]


@pytest.fixture
def proxy(tmp_path, monkeypatch):
    log = tmp_path / "upstream.log"
    monkeypatch.setenv("FAKE_MCP_LOG", str(log))
    up = StdioUpstream([sys.executable, str(FAKE)])
    config = {"tools": {"read_note": {"op": "read", "resource_arg": "path"},
                        "send_message": {"op": "send", "dest_arg": "to"}},
              "classes": {"notes/secret.txt": "SECRET"}, "trust": {"bob@x.org": "approved"}}
    gw, exposed = build_proxy(up, config)
    grants = {"resources": ["notes/*"], "project_root": "notes/", "max_classification": "INTERNAL",
              "destinations": ["bob@x.org"]}
    task = "Read notes/a.txt and email bob@x.org the summary"
    server = McpGateway(InProcessSession(gw.open_session("s", "mcp", compile_scope(task, grants))), exposed)
    yield server, lambda: [json.loads(x) for x in log.read_text().splitlines()] if log.exists() else []
    up.close()


def test_proxy_lists_only_mapped_upstream_tools(proxy):
    server, _ = proxy
    assert [t["name"] for t in rpc(server, "tools/list")["result"]["tools"]] == ["read_note", "send_message"]


def test_proxy_forwards_an_authorized_call(proxy):
    server, upstream_calls = proxy
    r = call(server, "read_note", {"path": "notes/a.txt"})
    assert r["isError"] is False and "read_note ok" in r["content"][0]["text"]
    assert upstream_calls() == [{"tool": "read_note", "args": {"path": "notes/a.txt"}}]


def test_proxy_blocks_before_the_upstream_sees_the_call(proxy):
    server, upstream_calls = proxy
    assert call(server, "read_note", {"path": "notes/secret.txt"})["isError"] is True
    assert call(server, "send_message", {"to": "attacker@evil.example", "body": "x"})["isError"] is True
    assert call(server, "delete_all", {})["isError"] is True  # not mapped: never exposed, never forwarded
    assert upstream_calls() == []
