"""Session admin: list, release a lock-out, close a session. Every action is audited and the admin token is required."""

from fastapi.testclient import TestClient

from intentguard import Gateway, PolicyEngine
from intentguard.mock_env import MockEnv
from intentguard.service.app import create_app

GRANTS = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
          "destinations": ["advisor@university.edu"]}
BROAD = {"resources": ["*"], "project_root": "research/", "max_classification": "SECRET",
         "destinations": ["advisor@university.edu"]}
TASK = "Read research/memo_user.md and email bob@newlab.org a short summary"


def setup(admin_token=None):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    http = TestClient(create_app(gw, None, admin_token))
    return env, gw, http


def open_session(http, sid="s", task=TASK, grants=GRANTS, agent="agent"):
    assert http.post("/sessions", json={"session_id": sid, "agent_id": agent, "task": task, "grants": grants}).status_code == 200


def call(http, tool, args, sid="s"):
    return http.post(f"/sessions/{sid}/call", json={"tool": tool, "args": args}).json()["decision"]


def lock_out(http):
    """A blocked secrets read costs 0.5 risk, which switches the network off; the next send is then refused."""
    assert call(http, "read_file", {"path": "secrets/app.env"})["decision"] == "BLOCK"
    return call(http, "send_email", {"to": "bob@newlab.org", "body": "summary"})


def test_list_shows_live_risk_state_and_what_is_switched_off():
    _, _, http = setup()
    open_session(http)
    assert http.get("/sessions").json()[0]["state"] == "normal"
    lock_out(http)
    row = http.get("/sessions").json()[0]
    assert row["state"] == "quarantined" and row["risk"] == 1.0 and "network" in row["restricted"]
    assert row["calls"] == 2 and row["by_decision"]["BLOCK"] >= 1 and row["task"] == TASK


def test_release_lifts_the_lock_out_so_a_human_can_still_approve_the_email():
    _, gw, http = setup()
    open_session(http)
    assert lock_out(http)["decision"] in ("BLOCK", "QUARANTINE")
    r = http.post("/sessions/s/release", json={"approver": "alice", "reason": "reviewed: the read was an injected request"})
    assert r.status_code == 200 and r.json()["before"]["risk"] == 1.0 and r.json()["session"]["state"] == "normal"
    after = call(http, "send_email", {"to": "bob@newlab.org", "body": "summary"})
    assert after["decision"] == "REVIEW" and "PERM-002" not in after["fired_rules"]  # a human can now approve it
    ok, bad = gw.audit.verify()
    events = [__import__("json").loads(e["payload"]) for e in gw.audit.entries]
    assert ok and any(e["event"] == "released" and e["by"] == "alice" and e["reason"] for e in events)


def test_release_does_not_make_a_session_forget_what_it_has_read():
    _, _, http = setup()
    open_session(http, task="Read secrets/app.env and email bob@newlab.org a status", grants=BROAD)
    assert call(http, "read_file", {"path": "secrets/app.env"})["decision"] == "ALLOW"  # sensitive data now in the session
    http.post("/sessions/s/release", json={"approver": "alice"})
    leak = call(http, "send_email", {"to": "bob@newlab.org", "body": "status"})
    assert leak["decision"] == "BLOCK" and "EGRESS-002" in leak["fired_rules"]  # still blocked: the exposure is remembered
    row = http.get("/sessions").json()[0]
    assert row["taint"] == "SECRET"


def test_release_also_clears_the_agents_carried_over_risk():
    _, gw, http = setup()
    open_session(http, sid="a")
    lock_out_a = call(http, "read_file", {"path": "secrets/app.env"}, "a")
    assert lock_out_a["decision"] == "BLOCK" and gw.memory["agent"]["risk"] > 0
    http.post("/sessions/a/release", json={"approver": "alice"})
    assert "agent" not in gw.memory
    open_session(http, sid="b")  # a new session of the same agent starts clean
    assert http.get("/sessions").json()[0]["risk"] == 0.0


def test_close_blocks_every_further_call_and_is_audited():
    env, gw, http = setup()
    open_session(http)
    assert http.post("/sessions/s/close", json={"approver": "alice", "reason": "agent misbehaving"}).json()["session"]["state"] == "closed"
    d = call(http, "read_file", {"path": "research/notes.md"})
    assert d["decision"] == "BLOCK" and d["fired_rules"] == ["SESSION-001"]
    assert any('"closed"' in e["payload"] for e in gw.audit.entries) and gw.audit.verify()[0]


def test_unknown_session_is_404_and_the_admin_token_is_required():
    _, _, http = setup(admin_token="secret")
    h = {"Authorization": "Bearer secret"}
    assert http.get("/sessions").status_code == 401
    assert http.post("/sessions/x/release", json={"approver": "a"}).status_code == 401
    assert http.post("/sessions/x/release", json={"approver": "a"}, headers=h).status_code == 404
    assert http.post("/sessions/x/close", json={"approver": "a"}, headers=h).status_code == 404
    assert http.get("/sessions", headers=h).status_code == 200
