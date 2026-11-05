"""Approval channel for REVIEW calls: the agent's call waits while a human decides through the service API."""

import threading
import time

from fastapi.testclient import TestClient

from intentguard import Gateway, PolicyEngine
from intentguard.mcp_gateway import DEMO_TOOLS, ApprovalSession, McpGateway
from intentguard.mock_env import MockEnv
from intentguard.service.app import NewSession, create_app

GRANTS = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
          "destinations": ["advisor@university.edu"]}
TASK = "Summarize research/notes.md and email bob@newlab.org"  # bob is not a granted recipient: REVIEW


def setup(timeout=3.0):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    app = create_app(gw)
    app.state.do_open(NewSession(session_id="s", agent_id="mcp", task=TASK, grants=GRANTS))
    return env, gw, TestClient(app), ApprovalSession(app, gw, "s", timeout=timeout, poll=0.02)


def human(client, gw, verb, seen=None):
    """A thread that waits for a pending action and approves or rejects it through the API."""
    def run():
        for _ in range(300):
            if gw.pending:
                aid = next(iter(gw.pending))
                if seen is not None:
                    seen.extend(client.get("/pending").json())
                client.post(f"/pending/{aid}/{verb}", json={"approver": "alice"})
                return
            time.sleep(0.01)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def test_approved_call_runs_and_returns_its_output():
    env, gw, client, sess = setup()
    human(client, gw, "approve")
    r = sess.call("send_email", to="bob@newlab.org", body="summary")
    assert r.allowed and r.output == "sent" and len(env.outbox) == 1


def test_rejected_call_does_not_run():
    env, gw, client, sess = setup()
    human(client, gw, "reject")
    r = sess.call("send_email", to="bob@newlab.org", body="summary")
    assert r.decision == "BLOCK" and "rejected" in r.explanation and env.outbox == []


def test_unanswered_call_is_cancelled_and_cannot_run_later():
    env, gw, client, sess = setup(timeout=0.3)
    r = sess.call("send_email", to="bob@newlab.org", body="summary")
    assert r.decision == "BLOCK" and "No human answered" in r.explanation
    assert not gw.pending
    late = client.post(f"/pending/{r.action_id}/approve", json={"approver": "alice"})
    assert late.status_code == 404 and env.outbox == []  # a late approval has nothing to run


def test_dashboard_sees_the_waiting_call():
    _, gw, client, sess = setup()
    seen: list = []
    human(client, gw, "approve", seen)
    sess.call("send_email", to="bob@newlab.org", body="summary")
    assert seen and seen[0]["tool"] == "send_email" and seen[0]["decision"]["decision"] == "REVIEW"


def test_approval_is_remembered_so_the_next_call_does_not_wait():
    _, gw, client, sess = setup(timeout=0.3)
    human(client, gw, "approve")
    assert sess.call("send_email", to="bob@newlab.org", body="part 1").allowed
    started = time.monotonic()
    assert sess.call("send_email", to="bob@newlab.org", body="part 2").allowed
    assert time.monotonic() - started < 0.25  # no second wait


def test_allowed_and_blocked_calls_never_wait():
    _, gw, client, sess = setup(timeout=5.0)
    started = time.monotonic()
    assert sess.call("read_file", path="research/notes.md").allowed
    assert sess.call("send_email", to="attacker@evil.example", body="x").decision == "BLOCK"
    assert time.monotonic() - started < 1.0


def test_mcp_tools_call_waits_for_the_human_then_returns_the_result():
    env, gw, client, sess = setup()
    server = McpGateway(sess, DEMO_TOOLS)
    human(client, gw, "approve")
    r = server.handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "send_email", "arguments": {"to": "bob@newlab.org", "body": "summary"}}})
    assert r["result"]["isError"] is False and r["result"]["content"][0]["text"] == "sent"
    assert len(env.outbox) == 1


def test_real_process_waits_for_an_http_approval():
    import json
    import os
    import socket
    import subprocess
    import sys
    import urllib.request
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    p = subprocess.Popen(
        [sys.executable, "-m", "intentguard.mcp_gateway", "--demo", "--task", TASK, "--grants", json.dumps(GRANTS),
         "--approvals-port", str(port), "--approval-timeout", "30"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        env={**os.environ, "PYTHONPATH": str(root / "src")})
    try:
        for m in ({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}},
                  {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": "send_email", "arguments": {"to": "bob@newlab.org", "body": "summary"}}}):
            p.stdin.write(json.dumps(m) + "\n")
        p.stdin.flush()
        base, pending = f"http://127.0.0.1:{port}", []
        for _ in range(300):  # wait for the service to come up and the call to appear as pending
            try:
                pending = json.load(urllib.request.urlopen(base + "/pending", timeout=2))
            except OSError:
                pending = []
            if pending:
                break
            time.sleep(0.1)
        assert pending and pending[0]["tool"] == "send_email"
        req = urllib.request.Request(f"{base}/pending/{pending[0]['decision']['action_id']}/approve",
                                     json.dumps({"approver": "alice"}).encode(),
                                     {"Content-Type": "application/json"})
        assert json.load(urllib.request.urlopen(req, timeout=5))["output"] == "sent"
        p.stdin.close()
        replies = [json.loads(line) for line in p.stdout.read().splitlines()]
    finally:
        p.kill()
    assert replies[-1]["id"] == 2 and replies[-1]["result"]["isError"] is False
    assert replies[-1]["result"]["content"][0]["text"] == "sent"
