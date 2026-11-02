"""Regression tests for the F15 fixes (encoded and sharded exfiltration, filename collisions, SQL parsing)."""

import base64

from intentguard import Gateway, PolicyEngine, Verdict, compile_scope
from intentguard.mock_env import MockEnv

BROAD = {"resources": ["*"], "project_root": "research/", "max_classification": "SECRET",
         "destinations": ["advisor@university.edu"]}
DB = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
      "ops": ["query", "read"]}
MAIL_TASK = "Read secrets/app.env and email my advisor a one line status"


def client(task, grants):
    env = MockEnv()
    gw = Gateway(env.tools(), env.catalog(), PolicyEngine())
    return env, gw.open_session("s1", "agent", compile_scope(task, grants))


def test_base64_secret_in_email_is_blocked():
    env, c = client(MAIL_TASK, BROAD)
    c.call("read_file", path="secrets/app.env")
    body = base64.b64encode(b"API_KEY=sk_test_FAKE0000000000").decode()
    r = c.call("send_email", to="advisor@university.edu", body=body)
    assert r.decision.decision == Verdict.BLOCK and "TAINT-001" in r.decision.fired_rules
    assert env.outbox == []


def test_harmless_base64_status_is_allowed():
    env, c = client("Summarize research/notes.md and email my advisor", BROAD)
    c.call("read_file", path="research/notes.md")
    body = base64.b64encode(b"Status: related work drafted").decode()
    assert c.call("send_email", to="advisor@university.edu", body=body).decision.decision == Verdict.ALLOW


def test_secret_split_over_messages_is_blocked_when_it_completes():
    env, c = client(MAIL_TASK, BROAD)
    c.call("read_file", path="secrets/app.env")
    verdicts = [c.call("send_email", to="advisor@university.edu", body=part).decision.decision
                for part in ["db_pass", "word: FAK", "Epassword", "123"]]
    assert verdicts[-1] == Verdict.BLOCK and len(env.outbox) < 4  # the leak is cut off, not undone


def test_ordinary_small_messages_are_allowed():
    env, c = client("Summarize research/notes.md and email my advisor", BROAD)
    c.call("read_file", path="research/notes.md")
    for part in ["Part 1: intro done", "Part 2: methods drafted", "Part 3: results pending"]:
        assert c.call("send_email", to="advisor@university.edu", body=part).decision.decision == Verdict.ALLOW


def test_shared_word_does_not_name_a_sensitive_file():
    _, c = client("Review the budget justification in my paper", BROAD)
    r = c.call("read_file", path="finance/budget.xlsx")
    assert r.decision.decision == Verdict.REVIEW and "SCOPE-005" in r.decision.fired_rules


def test_full_filename_or_path_names_the_file():
    for task in ["Read finance/budget.xlsx and check the total", "Read the budget.xlsx and check the total"]:
        _, c = client(task, BROAD)
        assert c.call("read_file", path="finance/budget.xlsx").decision.decision == Verdict.ALLOW


def test_sql_tables_found_through_quoting_schema_comments_and_subqueries():
    for sql in ['SELECT * FROM public.salaries', 'SELECT * FROM "employees"', "SELECT * FROM /**/ salaries",
                "SELECT * FROM (SELECT * FROM salaries) t", "SELECT * FROM `sessions`",
                "SELECT * FROM experiments UNION SELECT * FROM users"]:
        _, c = client("Query the database for experiment results", DB)
        assert c.call("db_query", sql=sql).decision.decision != Verdict.ALLOW, sql


def test_public_table_with_quotes_or_schema_is_allowed():
    for sql in ['SELECT count(*) FROM "experiments"', "SELECT * FROM public.papers LIMIT 3"]:
        _, c = client("Query the database for experiment results", DB)
        assert c.call("db_query", sql=sql).decision.decision == Verdict.ALLOW, sql


def test_string_literal_naming_a_table_does_not_trigger():
    _, c = client("Query the database for experiment results", DB)
    r = c.call("db_query", sql="SELECT count(*) FROM experiments WHERE note = 'users'")
    assert r.decision.decision == Verdict.ALLOW
