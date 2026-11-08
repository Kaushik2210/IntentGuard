"""The `intentguard` command: init, check-config, verify-audit, and the service built from a config file."""

import argparse
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from intentguard.audit import AuditLog
from intentguard.cli import build_service, main
from intentguard.config import load_config

FAKE = Path(__file__).with_name("fake_mcp_server.py")


def ns(**kw):
    base = dict(config=None, demo=False, upstream=None, host="127.0.0.1", port=8000, audit_file=None,
                agent_token=None, admin_token=None)
    return argparse.Namespace(**{**base, **kw})


def test_init_writes_a_config_that_validates_and_refuses_to_overwrite(tmp_path, capsys):
    target = tmp_path / "intentguard.toml"
    assert main(["init", str(target)]) == 0 and load_config(target).grants["resources"] == ["research/*"]
    assert main(["init", str(target)]) == 1 and "already exists" in capsys.readouterr().err
    target.write_text("junk")
    assert main(["init", str(target), "--force"]) == 0 and load_config(target)  # overwritten with the sample


def test_check_config_summarises_a_good_file_and_names_the_problem_in_a_bad_one(tmp_path, capsys):
    good = tmp_path / "good.toml"
    main(["init", str(good)])
    capsys.readouterr()
    assert main(["check-config", str(good)]) == 0
    out = capsys.readouterr().out
    assert "ok:" in out and "network at 0.4" in out and "tools: read_file, send_email" in out
    bad = tmp_path / "bad.toml"
    bad.write_text('[classes]\n"x" = "TOP_SECRET"\n')
    assert main(["check-config", str(bad)]) == 1
    assert "[classes].x" in capsys.readouterr().err


def test_verify_audit_detects_tampering(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(4):
        log.append({"event": "action", "n": i})
    assert main(["verify-audit", str(path)]) == 0 and "4 entries" in capsys.readouterr().out
    lines = path.read_text().splitlines()
    entry = json.loads(lines[1])
    entry["payload"] = entry["payload"].replace('"n": 1', '"n": 9')
    lines[1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n")
    assert main(["verify-audit", str(path)]) == 1 and "breaks at entry 1" in capsys.readouterr().err
    assert main(["verify-audit", str(tmp_path / "missing.jsonl")]) == 1


def test_serve_demo_uses_the_default_grants_from_the_config(tmp_path):
    cfg = tmp_path / "c.toml"
    main(["init", str(cfg)])
    http = TestClient(build_service(ns(config=str(cfg), demo=True)))
    r = http.post("/sessions", json={"session_id": "s", "agent_id": "a", "task": "Read research/paper.pdf"})
    assert r.status_code == 200  # no grants in the request: the config's [grants] applied
    ok = http.post("/sessions/s/call", json={"tool": "read_file", "args": {"path": "research/paper.pdf"}}).json()
    bad = http.post("/sessions/s/call", json={"tool": "read_file", "args": {"path": "hr/salary.xlsx"}}).json()
    assert ok["decision"]["decision"] == "ALLOW" and bad["decision"]["decision"] == "BLOCK"
    assert http.post("/demo/seed").status_code == 200  # the dashboard's sample-data button still works


def test_serve_refuses_to_listen_on_a_network_address_without_tokens():
    with pytest.raises(ValueError, match="refusing to listen"):
        build_service(ns(demo=True, host="0.0.0.0"))
    with pytest.raises(ValueError, match="refusing to listen"):
        build_service(ns(demo=True, host="0.0.0.0", agent_token="a"))  # both tokens are needed
    app = build_service(ns(demo=True, host="0.0.0.0", agent_token="a", admin_token="b"))
    assert TestClient(app).get("/stats").status_code == 401  # and the admin endpoints really are protected


def test_serve_in_front_of_an_upstream_mcp_server(tmp_path, monkeypatch):
    log = tmp_path / "upstream.log"
    monkeypatch.setenv("FAKE_MCP_LOG", str(log))
    cfg = tmp_path / "proxy.toml"
    cfg.write_text('[tools.read_note]\nop = "read"\nresource_arg = "path"\n'
                   '[grants]\nresources = ["notes/*"]\nproject_root = "notes/"\n')
    http = TestClient(build_service(ns(config=str(cfg), upstream=f"{sys.executable} {FAKE}")))
    http.post("/sessions", json={"session_id": "s", "agent_id": "a", "task": "Read notes/a.txt"})
    ok = http.post("/sessions/s/call", json={"tool": "read_note", "args": {"path": "notes/a.txt"}}).json()
    out = http.post("/sessions/s/call", json={"tool": "read_note", "args": {"path": "elsewhere/b.txt"}}).json()
    unmapped = http.post("/sessions/s/call", json={"tool": "delete_all", "args": {}}).json()
    assert ok["decision"]["decision"] == "ALLOW" and "read_note ok" in ok["output"]
    assert out["decision"]["decision"] == "BLOCK" and unmapped["decision"]["decision"] == "BLOCK"
    assert [json.loads(x)["tool"] for x in log.read_text().splitlines()] == ["read_note"]  # only the allowed call


def test_serve_needs_exactly_one_backend():
    with pytest.raises(SystemExit):
        main(["serve"])
    with pytest.raises(ValueError, match="at least one"):
        build_service(ns(upstream=f"{sys.executable} {FAKE}"))


def test_serve_db_restores_sessions_after_a_restart(tmp_path):
    a = argparse.Namespace(demo=True, upstream=None, config=None, host="127.0.0.1", port=8000,
                           audit_file=None, agent_token=None, admin_token=None, db=str(tmp_path / "s.db"))
    body = {"session_id": "s", "agent_id": "agent", "task": "Read research/paper.pdf.",
            "grants": {"resources": ["research/*"]}}
    assert TestClient(build_service(a)).post("/sessions", json=body).status_code == 200
    again = TestClient(build_service(a))  # a second service on the same file = a restart
    assert [r["session_id"] for r in again.get("/sessions").json()] == ["s"]
