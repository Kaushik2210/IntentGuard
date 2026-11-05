"""Small client for the gateway, in-process or over HTTP (standard library only).

An agent framework needs one thing: `session.call(tool, **args) -> ToolResult`. `ToolResult.allowed` says
whether the tool ran; otherwise `decision`, `explanation` and `rules` say why not, in words the model can
read. The agent never gets a handle to a tool, only to this session.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class ToolResult:
    decision: str  # ALLOW | REVIEW | BLOCK | QUARANTINE
    explanation: str = ""
    rules: list[str] = field(default_factory=list)
    output: Any = None
    action_id: str = ""
    risk: float = 0.0

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"

    def message(self) -> str:
        """What a model should be told when the call did not run."""
        if self.decision == "REVIEW":
            return (f"NEEDS HUMAN APPROVAL (IntentGuard, action {self.action_id}): {self.explanation} "
                    "Do not retry the same call. Tell the user it is waiting for approval.")
        return (f"BLOCKED by IntentGuard ({self.decision}): {self.explanation} "
                "Do not retry or look for another way around it. Tell the user what was blocked and why.")


class Session(Protocol):
    def call(self, tool: str, **args: Any) -> ToolResult: ...


class InProcessSession:
    """Wraps a `GatewayClient` (the object `Gateway.open_session` returns)."""

    def __init__(self, client: Any):
        self._client = client

    def call(self, tool: str, **args: Any) -> ToolResult:
        res = self._client.call(tool, **args)
        d = res.decision
        return ToolResult(d.decision.value, d.explanation, list(d.fired_rules), res.output, d.action_id,
                          d.risk_score)


Transport = Callable[[str, str, dict, dict], dict]  # (method, path, body, headers) -> json


def _urllib_transport(base: str, timeout: float = 30.0) -> Transport:
    def send(method: str, path: str, body: dict, headers: dict) -> dict:
        req = urllib.request.Request(base.rstrip("/") + path, json.dumps(body).encode(),
                                     {"Content-Type": "application/json", **headers}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"gateway returned HTTP {exc.code} for {path}") from exc
    return send


class HTTPSession:
    """A session on a running IntentGuard service. `transport` can be swapped (tests use an in-memory one)."""

    def __init__(self, session_id: str, transport: Transport, token: str | None = None):
        self.session_id = session_id
        self._send = transport
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}

    def call(self, tool: str, **args: Any) -> ToolResult:
        r = self._send("POST", f"/sessions/{self.session_id}/call", {"tool": tool, "args": args}, self._headers)
        d = r["decision"]
        return ToolResult(d["decision"], d.get("explanation", ""), list(d.get("fired_rules", [])),
                          r.get("output"), d.get("action_id", ""), d.get("risk_score", 0.0))


def open_http_session(base_url: str, task: str, grants: dict, agent_id: str = "agent",
                      session_id: str | None = None, token: str | None = None,
                      transport: Transport | None = None) -> HTTPSession:
    send = transport or _urllib_transport(base_url)
    sid = session_id or f"s-{uuid.uuid4().hex[:8]}"
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    send("POST", "/sessions", {"session_id": sid, "agent_id": agent_id, "task": task, "grants": grants}, headers)
    return HTTPSession(sid, send, token)
