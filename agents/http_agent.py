"""Scripted agent that talks to the gateway over HTTP only (stdlib, no intentguard import).

It holds no tool handles: every action is a POST to the gateway. Run as a separate process (or
container) so tools are reachable only through the service.

    python agents/http_agent.py http://localhost:8000 episode.json
"""

import json
import sys
import urllib.error
import urllib.request


def post(base: str, path: str, body: dict) -> dict:
    req = urllib.request.Request(base + path, json.dumps(body).encode(),
                                 {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        return {"error": e.code}


def main(base: str, episode_file: str) -> None:
    ep = json.load(open(episode_file))
    post(base, "/sessions", {"session_id": ep["id"], "agent_id": "http-agent",
                             "task": ep["task"], "grants": ep["grants"]})
    out = []
    for step in ep["steps"]:
        r = post(base, f"/sessions/{ep['id']}/call", {"tool": step["tool"], "args": step["args"]})
        out.append({"tool": step["tool"], "decision": r.get("decision", {}).get("decision"),
                    "output": r.get("output")})
    print(json.dumps({"steps": out, "imported_intentguard": "intentguard" in sys.modules}))


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
