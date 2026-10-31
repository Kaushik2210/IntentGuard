from fastapi.testclient import TestClient

from intentguard.service.app import demo_app

GRANTS = {"resources": ["research/*"], "project_root": "research/",
          "max_classification": "INTERNAL", "destinations": ["advisor@university.edu"]}


def start():
    c = TestClient(demo_app())
    r = c.post("/sessions", json={"session_id": "s1", "agent_id": "a",
                                  "task": "Summarize notes and email my advisor", "grants": GRANTS})
    assert r.status_code == 200
    return c


def test_allow_block_and_stats():
    c = start()
    ok = c.post("/sessions/s1/call", json={"tool": "read_file", "args": {"path": "research/notes.md"}})
    assert ok.json()["decision"]["decision"] == "ALLOW" and ok.json()["output"]
    bad = c.post("/sessions/s1/call", json={"tool": "read_file", "args": {"path": "hr/salary.xlsx"}})
    assert bad.json()["decision"]["decision"] == "BLOCK" and bad.json()["output"] is None
    s = c.get("/stats").json()
    assert s["inspected"] == 2 and s["by_decision"]["BLOCK"] == 1


def test_review_flow_and_audit_verify():
    c = start()
    r = c.post("/sessions/s1/call", json={"tool": "send_email",
                                          "args": {"to": "other@x.org", "body": "hi"}}).json()
    aid = r["decision"]["action_id"]
    assert r["decision"]["decision"] == "REVIEW"
    assert [e["decision"]["action_id"] for e in c.get("/pending").json()] == [aid]
    assert c.post(f"/pending/{aid}/approve", json={"approver": "kaushik"}).status_code == 200
    assert c.get("/pending").json() == []
    assert c.get("/audit/verify").json() == {"ok": True, "first_bad_seq": None}


def test_errors():
    c = start()
    assert c.post("/sessions/nope/call", json={"tool": "x"}).status_code == 404
    assert c.post("/sessions", json={"session_id": "s1", "agent_id": "a", "task": "t"}).status_code == 409
    assert c.post("/pending/zzz/approve", json={"approver": "k"}).status_code == 404


def test_events_and_seed():
    c = TestClient(demo_app())
    assert c.post("/demo/seed").json()["seeded"] == 3
    ev = c.get("/events?limit=5").json()
    assert len(ev) == 5 and ev[0]["ts"] >= ev[-1]["ts"]
    assert c.get("/stats").json()["inspected"] == 12


def test_tokens_separate_agent_and_admin():
    from intentguard import AuditLog, Gateway, PolicyEngine
    from intentguard.mock_env import MockEnv
    from intentguard.service.app import create_app
    env = MockEnv()
    c = TestClient(create_app(Gateway(env.tools(), env.catalog(), PolicyEngine(), AuditLog()),
                              agent_token="agent-secret", admin_token="admin-secret"))
    body = {"session_id": "s1", "agent_id": "a", "task": "Summarize notes and email my advisor", "grants": GRANTS}
    assert c.post("/sessions", json=body).status_code == 401
    ag, ad = {"Authorization": "Bearer agent-secret"}, {"Authorization": "Bearer admin-secret"}
    assert c.post("/sessions", json=body, headers=ag).status_code == 200
    call = {"tool": "send_email", "args": {"to": "other@x.org", "body": "hi"}}
    r = c.post("/sessions/s1/call", json=call, headers=ag)
    aid = r.json()["decision"]["action_id"]
    # an agent must not be able to approve its own action or read the audit trail
    assert c.post(f"/pending/{aid}/approve", json={"approver": "x"}, headers=ag).status_code == 401
    assert c.get("/audit", headers=ag).status_code == 401
    assert c.post(f"/pending/{aid}/approve", json={"approver": "x"}, headers=ad).status_code == 200
