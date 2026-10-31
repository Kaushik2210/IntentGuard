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
    assert [d["action_id"] for d in c.get("/pending").json()] == [aid]
    assert c.post(f"/pending/{aid}/approve", json={"approver": "kaushik"}).status_code == 200
    assert c.get("/pending").json() == []
    assert c.get("/audit/verify").json() == {"ok": True, "first_bad_seq": None}


def test_errors():
    c = start()
    assert c.post("/sessions/nope/call", json={"tool": "x"}).status_code == 404
    assert c.post("/sessions", json={"session_id": "s1", "agent_id": "a", "task": "t"}).status_code == 409
    assert c.post("/pending/zzz/approve", json={"approver": "k"}).status_code == 404
