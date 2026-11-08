"""The SDK: guard your own functions with a decorator."""

import pytest

from intentguard.sdk import Guard

GRANTS = {"resources": ["notes/*"], "destinations": ["bob@x.org"]}
TASK = "Read notes/a.txt and email bob@x.org a short summary"


def make(**kw):
    sent = []
    guard = Guard(classes={"hr/salary.csv": "CONFIDENTIAL"},
                  trust={"bob@x.org": "approved", "evil@x.org": "denylisted"}, **kw)

    @guard.tool("read", resource_arg="path")
    def read_file(path):
        return {"notes/a.txt": "ship on friday", "hr/salary.csv": "alice,120000"}[path]

    @guard.tool("send", resource_arg="attachment", dest_arg="to", resource_optional=True)
    def send_email(to, body, attachment=None):
        sent.append((to, body))
        return "sent"

    return guard, sent


def test_allowed_calls_run_and_return_output():
    guard, sent = make()
    s = guard.session(TASK, GRANTS)
    assert s.call("read_file", path="notes/a.txt").output == "ship on friday"
    assert s.call("send_email", to="bob@x.org", body="ok").allowed and sent == [("bob@x.org", "ok")]


def test_out_of_scope_calls_are_blocked_and_never_run():
    guard, sent = make()
    s = guard.session(TASK, GRANTS)
    r = s.call("read_file", path="hr/salary.csv")
    assert not r.allowed and r.explanation
    r = s.call("send_email", to="evil@x.org", body="x")
    assert not r.allowed and sent == []


def test_unregistered_tool_fails_closed():
    guard, _ = make()
    assert not guard.session(TASK, GRANTS).call("delete_everything").allowed


def test_decorator_returns_the_function_unchanged():
    guard = Guard()

    @guard.tool("read", resource_arg="p")
    def f(p):
        return p

    assert f("x") == "x"


def test_bad_registrations_fail_early():
    guard = Guard()
    with pytest.raises(ValueError, match="not a parameter"):
        guard.tool("read", resource_arg="nope")(lambda path: path)
    with pytest.raises(ValueError, match="unknown operation"):
        guard.tool("teleport")
    guard.tool("read", name="a")(lambda: 1)
    with pytest.raises(ValueError, match="already registered"):
        guard.tool("read", name="a")(lambda: 2)
    with pytest.raises(ValueError, match="unknown trust"):
        Guard(trust={"x": "friendly"})


def test_register_after_first_session_is_refused_and_no_tools_is_an_error():
    with pytest.raises(RuntimeError, match="no tools"):
        Guard().session("task")
    guard, _ = make()
    guard.session(TASK, GRANTS)
    with pytest.raises(RuntimeError, match="before the first session"):
        guard.tool("read")(lambda: 1)


def test_sessions_persist_with_db(tmp_path):
    db = str(tmp_path / "s.db")
    guard, _ = make(db=db)
    s = guard.session(TASK, GRANTS, session_id="s1")
    s.call("read_file", path="hr/salary.csv")  # blocked: raises risk
    risk = guard.gateway.sessions["s1"].risk
    guard2, _ = make(db=db)
    assert guard2.gateway.sessions["s1"].risk == pytest.approx(risk) and risk > 0


def test_report_summarises_a_session_and_flags_a_tampered_log(tmp_path):
    from intentguard import AuditLog
    from intentguard.cli import main
    path = tmp_path / "audit.jsonl"
    guard, _ = make(audit=AuditLog(path))
    s = guard.session(TASK, GRANTS, session_id="s1")
    s.call("read_file", path="notes/a.txt")
    s.call("read_file", path="hr/salary.csv")
    guard.gateway.release("s1", "admin", "looked fine")
    from intentguard.report import build_report
    text = build_report(AuditLog(path))
    assert "Session s1" in text and "hash chain intact" in text and "hr/salary.csv" in text
    assert "released by admin (looked fine)" in text and "ALLOW=1" in text
    assert main(["report", str(path)]) == 0
    path.write_text(path.read_text().replace("salary", "salarz", 1))
    assert main(["report", str(path)]) == 1  # a tampered log is reported and exits non-zero
    assert main(["report", str(tmp_path / "missing.jsonl")]) == 2
