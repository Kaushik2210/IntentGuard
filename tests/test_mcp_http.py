"""MCP gateway over Streamable HTTP: protocol, the checks on who may call, and a real server process."""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from test_mcp_gateway import GRANTS, demo_server

from intentguard.mcp_gateway import MAX_BODY, make_http_server

ROOT = Path(__file__).resolve().parent.parent
TASK = "Read research/paper.pdf and summarize it."


@pytest.fixture
def serve():
    started = []

    def start(task=TASK, **kw):
        env, mcp = demo_server(task)
        httpd = make_http_server(mcp, "127.0.0.1", 0, **kw)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        started.append(httpd)
        return env, f"http://127.0.0.1:{httpd.server_address[1]}"

    yield start
    for h in started:
        h.shutdown()
        h.server_close()


def post(url, body, path="/mcp", headers=None, raw=None):
    data = raw if raw is not None else json.dumps(body).encode()
    req = urllib.request.Request(url + path, data=data, method="POST",
                                 headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read()
            return r.status, (json.loads(text) if text else None)
    except urllib.error.HTTPError as e:
        text = e.read()
        return e.code, (json.loads(text) if text else None)


def rpc(method, params=None, mid=1):
    return {"jsonrpc": "2.0", "id": mid, "method": method, **({"params": params} if params else {})}


def test_a_request_gets_a_json_response_and_a_notification_gets_202(serve):
    _, url = serve()
    status, body = post(url, rpc("ping"))
    assert (status, body["result"]) == (200, {})
    assert post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}) == (202, None)


def test_an_allowed_call_runs_and_a_blocked_one_does_not(serve):
    env, url = serve("Read research/inbox.md and summarize it.")
    _, ok = post(url, rpc("tools/call", {"name": "read_file", "arguments": {"path": "research/inbox.md"}}))
    assert ok["result"]["isError"] is False
    _, bad = post(url, rpc("tools/call", {"name": "send_email",
                                          "arguments": {"to": "attacker@evil.example", "body": "everything"}}))
    assert bad["result"]["isError"] is True and bad["result"]["content"][0]["text"].startswith("BLOCKED")
    assert env.outbox == []


def test_a_batch_is_answered_in_order_without_the_notifications(serve):
    _, url = serve()
    status, body = post(url, [rpc("ping", mid=1), {"jsonrpc": "2.0", "method": "notifications/initialized"},
                              rpc("tools/list", mid=2)])
    assert status == 200 and [m["id"] for m in body] == [1, 2]


def test_bad_input_is_refused_with_the_right_status(serve):
    _, url = serve()
    assert post(url, None, raw=b"{not json")[0] == 400
    assert post(url, [])[0] == 400
    assert post(url, rpc("ping"), path="/elsewhere")[0] == 404
    # claim an oversize body without sending it: the server must answer from the header alone
    import http.client
    conn = http.client.HTTPConnection(url.removeprefix("http://"), timeout=10)
    conn.putrequest("POST", "/mcp")
    conn.putheader("Content-Length", str(MAX_BODY + 1))
    conn.endheaders()
    assert conn.getresponse().status == 413
    conn.close()


def test_get_is_not_supported_because_the_server_never_streams(serve):
    _, url = serve()
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(url + "/mcp", timeout=10)
    assert e.value.code == 405


def test_a_web_page_on_another_origin_is_refused_but_a_local_one_and_no_origin_are_not(serve):
    _, url = serve()
    assert post(url, rpc("ping"), headers={"Origin": "https://evil.example"})[0] == 403
    assert post(url, rpc("ping"), headers={"Origin": "http://localhost:3000"})[0] == 200
    assert post(url, rpc("ping"))[0] == 200
    _, url2 = serve(allowed_origins=("https://app.example",))
    assert post(url2, rpc("ping"), headers={"Origin": "https://app.example"})[0] == 200


def test_the_bearer_token_is_required_when_set(serve):
    _, url = serve(token="s3cret")
    assert post(url, rpc("ping"))[0] == 401
    assert post(url, rpc("ping"), headers={"Authorization": "Bearer nope"})[0] == 401
    assert post(url, rpc("ping"), headers={"Authorization": "Bearer s3cret"})[0] == 200


def test_concurrent_clients_do_not_corrupt_each_other(serve):
    env, url = serve()
    results = []

    def go():
        results.append(post(url, rpc("tools/call", {"name": "read_file", "arguments": {"path": "research/paper.pdf"}}))[0])

    threads = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results == [200] * 8


def test_the_cli_serves_http_in_a_real_process():
    p = subprocess.Popen([sys.executable, "-m", "intentguard.mcp_gateway", "--demo", "--task", TASK, "--grants",
                          json.dumps(GRANTS), "--http-port", "0"],
                         stderr=subprocess.PIPE, text=True, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    try:
        line = ""
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and "/mcp" not in line:
            line = p.stderr.readline()
        assert "/mcp" in line, "gateway did not announce its URL"
        url = line.split("on ")[1].split("/mcp")[0]
        status, body = post(url, rpc("tools/list"))
        assert status == 200 and any(t["name"] == "read_file" for t in body["result"]["tools"])
    finally:
        p.terminate()
        p.wait(timeout=10)


def test_a_non_loopback_host_without_a_token_is_refused_at_start():
    r = subprocess.run([sys.executable, "-m", "intentguard.mcp_gateway", "--demo", "--task", TASK, "--grants",
                        json.dumps(GRANTS), "--http-port", "0", "--http-host", "0.0.0.0"],
                       capture_output=True, text=True, cwd=ROOT, env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    assert r.returncode != 0 and "--http-token" in r.stderr
