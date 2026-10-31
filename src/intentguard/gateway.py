"""The gateway is the only holder of the tools. Agents get a GatewayClient with one method."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .engine import PolicyEngine
from .models import (
    ActionRequest,
    Classification,
    Decision,
    Evidence,
    Op,
    Session,
    TaskScope,
    Trust,
    Verdict,
)


@dataclass
class Tool:
    name: str
    op: Op
    fn: Callable[..., Any]
    resource_arg: str | None = None
    dest_arg: str | None = None


@dataclass
class Result:
    decision: Decision
    output: Any = None


class Catalog:
    """Ground truth about resources and destinations. The agent cannot influence it."""

    def __init__(self, classes: dict[str, Classification] | None = None,
                 trust: dict[str, Trust] | None = None):
        self.classes = classes or {}
        self.trust = trust or {}

    def classify(self, resource: str) -> Classification:
        return self.classes.get(resource, Classification.INTERNAL)  # unknown -> not public

    def trust_of(self, dest: str) -> Trust:
        return self.trust.get(dest, Trust.UNKNOWN)


class Gateway:
    def __init__(self, tools: list[Tool], catalog: Catalog, engine: PolicyEngine | None = None,
                 audit: AuditLog | None = None):
        self.__tools = {t.name: t for t in tools}
        self.catalog = catalog
        self.engine = engine or PolicyEngine()
        self.audit = audit or AuditLog()
        self.sessions: dict[str, Session] = {}
        self.pending: dict[str, tuple[Session, Tool, dict]] = {}

    def open_session(self, session_id: str, agent_id: str, scope: TaskScope) -> GatewayClient:
        self.sessions[session_id] = Session(session_id, agent_id, scope)
        self.audit.append({"event": "session_open", "session": session_id, "agent": agent_id,
                           "task": scope.task_text})
        return GatewayClient(self, session_id)

    def call(self, session_id: str, tool_name: str, **args) -> Result:
        s = self.sessions[session_id]
        tool = self.__tools.get(tool_name)
        if tool is None:  # fail closed
            req = ActionRequest(session_id, s.agent_id, tool_name, Op.EXEC, args=args)
            d = Decision(req.action_id, Verdict.BLOCK, s.risk, ["PERM-001"],
                         [Evidence("PERM-001", "Tool is not registered for this agent", tool_name)],
                         "- Tool is not registered for this agent", "block", s.caps)
            self._log(req, d)
            return Result(d)
        res = args.get(tool.resource_arg) if tool.resource_arg else None
        dest = args.get(tool.dest_arg) if tool.dest_arg else None
        req = ActionRequest(
            session_id, s.agent_id, tool.name, tool.op, resource=res,
            classification=self.catalog.classify(res) if res else Classification.PUBLIC,
            destination=dest, trust=self.catalog.trust_of(dest) if dest else None, args=args)
        try:
            d = self.engine.evaluate(req, s)
        except Exception as exc:  # fail closed on engine error
            d = Decision(req.action_id, Verdict.BLOCK, s.risk, ["ENGINE-ERR"], [],
                         f"engine error: {exc!r}", "block", s.caps)
        self._log(req, d)
        if d.decision == Verdict.ALLOW:
            return Result(d, tool.fn(**args))
        if d.decision == Verdict.REVIEW:
            self.pending[req.action_id] = (s, tool, args)
        return Result(d)

    def approve(self, action_id: str, approver: str) -> Any:
        s, tool, args = self.pending.pop(action_id)
        self.audit.append({"event": "approved", "action": action_id, "by": approver})
        return tool.fn(**args)

    def reject(self, action_id: str, approver: str) -> None:
        self.pending.pop(action_id)
        self.audit.append({"event": "rejected", "action": action_id, "by": approver})

    def _log(self, req: ActionRequest, d: Decision) -> None:
        self.audit.append({
            "event": "action", "action": req.action_id, "session": req.session_id,
            "agent": req.agent_id, "tool": req.tool, "op": req.op.value, "resource": req.resource,
            "destination": req.destination, "decision": d.decision.value, "risk": d.risk_score,
            "rules": d.fired_rules, "latency_ms": round(d.latency_ms, 3)})


class GatewayClient:
    """What the agent holds: no tool handles, only call()."""

    __slots__ = ("_gw", "_sid")

    def __init__(self, gw: Gateway, sid: str):
        self._gw, self._sid = gw, sid

    def call(self, tool: str, **args) -> Result:
        return self._gw.call(self._sid, tool, **args)
