"""The config file: valid files load, mistakes give clear errors, and settings really change the engine."""

from pathlib import Path

import pytest

from intentguard import Classification, Gateway, PolicyEngine, Trust, compile_scope
from intentguard.config import ConfigError, load_config, parse
from intentguard.mock_env import MockEnv

EXAMPLE = Path(__file__).resolve().parent.parent / "src" / "intentguard" / "sample_config.toml"
GRANTS = {"resources": ["research/*"], "project_root": "research/", "max_classification": "INTERNAL",
          "destinations": ["advisor@university.edu"]}


def test_example_file_loads_with_the_documented_values():
    c = load_config(EXAMPLE)
    assert c.engine.quarantine_at == 1.0 and c.engine.lineage_k == 12 and c.engine.action_risk_cap is None
    assert dict((cap, at) for at, cap in c.engine.ladder) == {"network": 0.4, "shell": 0.6, "files_locked": 0.6,
                                                               "db_needs_review": 0.8}
    assert c.classes["secrets/app.env"] == Classification.SECRET
    assert c.trust["advisor@university.edu"] == Trust.APPROVED
    assert c.tools["send_email"]["resource_optional"] is True
    assert c.grants["destinations"] == ["advisor@university.edu"]
    cat = c.catalog()
    assert cat.classify("hr/salary.xlsx") == Classification.CONFIDENTIAL and cat.table_class("salaries") == Classification.CONFIDENTIAL


def test_proxy_dict_has_the_shape_the_mcp_gateway_takes():
    p = load_config(EXAMPLE).proxy_dict()
    assert p["classes"]["secrets/app.env"] == "SECRET" and p["trust"]["advisor@university.edu"] == "approved"
    assert p["tools"]["read_file"] == {"op": "read", "resource_arg": "path"}


def test_whole_numbers_are_accepted_for_float_settings():
    assert parse({"engine": {"quarantine_at": 1}}).engine.quarantine_at == 1.0


@pytest.mark.parametrize("raw, where", [
    ({"enginee": {}}, "unknown section"),
    ({"engine": {"quarantine": 1.0}}, "[engine]: unknown setting 'quarantine'"),
    ({"engine": {"quarantine_at": "high"}}, "[engine].quarantine_at must be float"),
    ({"engine": {"quarantine_at": 2.0}}, "must be in (0, 1]"),
    ({"engine": {"ladder": {"internet": 0.4}}}, "unknown capability"),
    ({"engine": {"ladder": {"network": 1.5}}}, "[engine.ladder].network must be a number in (0, 1]"),
    ({"classes": {"x": "TOP_SECRET"}}, "[classes].x: 'TOP_SECRET' is not one of"),
    ({"trust": {"a@b.c": "friendly"}}, "[trust].a@b.c: 'friendly' is not one of"),
    ({"tools": {"t": {"op": "teleport"}}}, "[tools.t].op: 'teleport' is not one of"),
    ({"tools": {"t": {"resource_arg": "p"}}}, "[tools.t] needs an 'op'"),
    ({"tools": {"t": {"op": "read", "colour": "red"}}}, "unknown key(s) ['colour']"),
    ({"grants": {"max_classification": "HUGE"}}, "[grants].max_classification"),
])
def test_mistakes_give_a_clear_error(raw, where):
    with pytest.raises(ConfigError) as exc:
        parse(raw)
    assert where in str(exc.value)


def test_unreadable_and_invalid_files_say_what_is_wrong(tmp_path):
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path / "missing.toml")
    bad = tmp_path / "bad.toml"
    bad.write_text("[engine\nquarantine_at = 1")
    with pytest.raises(ConfigError, match="not valid toml"):
        load_config(bad)


def test_a_raised_ladder_threshold_changes_what_the_engine_does():
    def second_call(engine):
        env = MockEnv()
        c = Gateway(env.tools(), env.catalog(), engine).open_session(
            "s", "a", compile_scope("Read research/memo_user.md and email bob@newlab.org a short summary", GRANTS))
        assert c.call("read_file", path="secrets/app.env").decision.decision.value == "BLOCK"  # costs 0.5 risk
        return c.call("send_email", to="bob@newlab.org", body="summary").decision.fired_rules

    default = second_call(PolicyEngine())
    relaxed = second_call(PolicyEngine(parse({"engine": {"ladder": {"network": 0.9}}}).engine))
    assert "PERM-002" in default and "PERM-002" not in relaxed  # the network stays on at 0.5 risk
