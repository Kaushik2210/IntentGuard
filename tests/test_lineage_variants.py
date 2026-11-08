"""Sensitive values that leave re-written: numbers as 120k or in words, and leetspeak (F29)."""

import pytest

from intentguard import EngineConfig, Guard, PolicyEngine
from intentguard.engine import _leet, _numbers

SALARY = "alice,120000\nbob,98000"
ENVFILE = "API_KEY=sk_test_FAKE0000000000"


def run(body, path="hr/salary.csv", content=SALARY, cls="CONFIDENTIAL", cfg=None):
    guard = Guard(classes={path: cls}, trust={"bob@x.org": "approved"},
                  engine=PolicyEngine(cfg) if cfg else None)

    @guard.tool("read", resource_arg="p")
    def read(p):
        return content

    @guard.tool("send", dest_arg="to")
    def send(to, body):
        return "sent"

    s = guard.session(f"Read {path} and email bob@x.org a short status",
                      {"resources": [path], "destinations": ["bob@x.org"], "max_classification": cls})
    assert s.call("read", p=path).allowed
    return s.call("send", to="bob@x.org", body=body)


@pytest.mark.parametrize("body", [
    "Alice: $120k, Bob: $98k", "alice makes 120,000 a year", "Bob is paid ninety eight thousand",
    "Alice: one hundred and twenty thousand", "Alice earns 120 thousand dollars", "Salaries: alice,120000 and bob,98000",
])
def test_a_sensitive_number_written_another_way_is_not_sent_unchecked(body):
    assert not run(body).allowed


@pytest.mark.parametrize("body", ["AP1_K3Y: sk_t3st_F4K3000000000", "sk_te$t_F@KE0000000000"])
def test_leetspeak_credentials_are_blocked(body):
    r = run(body, "secrets/app.env", ENVFILE, "SECRET")
    assert not r.allowed and "TAINT-002" in r.rules


@pytest.mark.parametrize("body", [
    "Done: 2 rows read, nothing unusual in 2024.", "Meeting at 10:30 in room 4; the budget of 50000 is approved.",
    "Team of ten, payroll runs on the 25th.", "It would take about forty minutes.",
])
def test_ordinary_replies_still_go_through(body):
    assert run(body).allowed


def test_the_variants_are_the_only_thing_that_catches_them():
    assert run("Alice: $120k", cfg=EngineConfig(lineage_variants=False)).allowed


def test_limits_are_real_and_documented():
    # rounding, another language and a fact without numbers are not recognised
    for body in ("Alice earns roughly 125k", "Alice gana ciento veinte mil", "Alice earns more than Bob"):
        assert run(body).allowed


def test_number_extraction():
    assert _numbers(SALARY) == {120000, 98000}
    assert _numbers("$1.5m and 120,000 and 250 thousand") == {1_500_000, 120000, 250000}
    assert _numbers("one hundred and twenty thousand five hundred") == {120500}
    assert _numbers("twenty-five thousand") == {25000}
    assert _numbers("in 2024, 3 rows, version 1.2.30000, ten, a hundred") == set()


def test_leet_readings_try_zero_and_one_both_ways():
    out = _leet("F4K3 p4$$w0rd 1")
    assert any("fake password" in r.lower() for r in out)  # 0 read as o
    assert {r.split()[-1] for r in out} == {"i", "l", "1"}  # a lone 1 read all three ways
    assert _leet("plain words only") == []
