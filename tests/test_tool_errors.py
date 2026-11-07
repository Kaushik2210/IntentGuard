"""A tool that fails after the policy allowed it is an answer, not a crash: audited, and structured in every client."""

import json

from fastapi.testclient import TestClient

from intentguard import Gateway, PolicyEngine, Verdict, compile_scope
from intentguard.client import InProcessSession
from intentguard.mcp_gateway import DEMO_TOOLS, McpGateway
from intentguard.mock_env import MockEnv
from intentguard.service.app import create_app

GRANTS = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
          "destinations": []}
TASK = "Read research/missing.md and summarize it"  # allowed by policy; the file does not exist


def gateway():
    env = MockEnv()
    return Gateway(env.tools(), env.catalog(), PolicyEngine())


def test_gateway_returns_the_error_and_audits_it():
    gw = gateway()
    r = gw.open_session("s", "a", compile_scope(TASK, GRANTS)).call("read_file", path="research/missing.md")
    assert r.decision.decision == Verdict.ALLOW and r.output is None and "KeyError" in r.error
    events = [json.loads(e["payload"]) for e in gw.audit.entries]
    assert any(e["event"] == "tool_error" and e["tool"] == "read_file" for e in events) and gw.audit.verify()[0]


def test_the_client_message_tells_a_model_what_happened():
    gw = gateway()
    res = InProcessSession(gw.open_session("s", "a", compile_scope(TASK, GRANTS))).call(
        "read_file", path="research/missing.md")
    assert res.allowed and res.error and res.message().startswith("TOOL ERROR")


def test_the_service_answers_200_with_the_error_instead_of_crashing():
    http = TestClient(create_app(gateway()))
    http.post("/sessions", json={"session_id": "s", "agent_id": "a", "task": TASK, "grants": GRANTS})
    r = http.post("/sessions/s/call", json={"tool": "read_file", "args": {"path": "research/missing.md"}})
    assert r.status_code == 200 and r.json()["decision"]["decision"] == "ALLOW" and "KeyError" in r.json()["error"]


def test_the_mcp_gateway_reports_it_as_an_error_result():
    gw = gateway()
    server = McpGateway(InProcessSession(gw.open_session("s", "a", compile_scope(TASK, GRANTS))), DEMO_TOOLS)
    out = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "read_file", "arguments": {"path": "research/missing.md"}}})
    assert out["result"]["isError"] is True and out["result"]["content"][0]["text"].startswith("TOOL ERROR")
