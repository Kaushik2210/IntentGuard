"""The gateway is the only holder of the tools. Agents get a GatewayClient with one method."""

from __future__ import annotations

import posixpath
import re
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
                 trust: dict[str, Trust] | None = None,
                 tables: dict[str, Classification] | None = None):
        self.classes = classes or {}
        self.trust = trust or {}
        self.tables = tables or {}

    def table_class(self, table: str) -> Classification:
        return self.tables.get(table.lower(), Classification.INTERNAL)

    def classify(self, resource: str) -> Classification:
        return self.classes.get(resource, Classification.INTERNAL)  # unknown -> not public

    def trust_of(self, dest: str) -> Trust:
        return self.trust.get(dest, Trust.UNKNOWN)


def canonical(path: str) -> str:
    """Normalise before any policy check so 'research/../hr/x' is judged as 'hr/x'."""
    return posixpath.normpath(str(path).replace("\\", "/"))


class Gateway:
    def __init__(self, tools: list[Tool], catalog: Catalog, engine: PolicyEngine | None = None,
                 audit: AuditLog | None = None):
        self.__tools = {t.name: t for t in tools}
        self.catalog = catalog
        self.engine = engine or PolicyEngine()
        self.audit = audit or AuditLog()
        self.sessions: dict[str, Session] = {}
        self.pending: dict[str, tuple[Session, Tool, dict]] = {}
        self.memory: dict[str, dict] = {}  # per-agent risk and tags carried across sessions

    def open_session(self, session_id: str, agent_id: str, scope: TaskScope) -> GatewayClient:
        s = Session(session_id, agent_id, scope)
        carry = getattr(self.engine, "carry", None)
        if carry and agent_id in self.memory:
            carry(s, self.memory[agent_id])
        self.sessions[session_id] = s
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
        if tool.resource_arg and args.get(tool.resource_arg) is not None:
            args = {**args, tool.resource_arg: canonical(args[tool.resource_arg])}
        res = args.get(tool.resource_arg) if tool.resource_arg else None
        if tool.op == Op.EXEC:  # files named inside a shell command are resources too
            paths = [canonical(w) for w in str(args.get("cmd", "")).split()[1:]
                     if not w.startswith("-") and ("/" in w or "." in w)]
            if paths:
                res = max(paths, key=self.catalog.classify)
        dest = args.get(tool.dest_arg) if tool.dest_arg else None
        req = ActionRequest(
            session_id, s.agent_id, tool.name, tool.op, resource=res,
            classification=self.catalog.classify(res) if res else Classification.PUBLIC,
            destination=dest, trust=self.catalog.trust_of(dest) if dest else None, args=args)
        if tool.op == Op.QUERY:  # classify the tables a query touches, not just the tool
            req.tables = re.findall(r"\b(?:from|join|into|update|table)\s+([A-Za-z_][A-Za-z0-9_]*)",
                                    str(args.get("sql", "")), re.I)
            if req.tables:
                req.classification = max(self.catalog.table_class(t) for t in req.tables)
            if re.search(r"\b(drop|delete|truncate|alter|update|insert)\b", str(args.get("sql", "")), re.I):
                req.op = Op.WRITE  # a destructive statement is a write, not a read-only query
        try:
            d = self.engine.evaluate(req, s)
        except Exception as exc:  # fail closed on engine error
            d = Decision(req.action_id, Verdict.BLOCK, s.risk, ["ENGINE-ERR"], [],
                         f"engine error: {exc!r}", "block", s.caps)
        self._log(req, d)
        if d.decision == Verdict.ALLOW:
            return Result(d, self._run(s, tool, args))
        if d.decision == Verdict.REVIEW:
            self.pending[req.action_id] = (s, tool, args)
        return Result(d)

    def approve(self, action_id: str, approver: str) -> Any:
        s, tool, args = self.pending.pop(action_id)
        self.audit.append({"event": "approved", "action": action_id, "by": approver})
        return self._run(s, tool, args)

    def reject(self, action_id: str, approver: str) -> None:
        self.pending.pop(action_id)
        self.audit.append({"event": "rejected", "action": action_id, "by": approver})

    def _run(self, s: Session, tool: Tool, args: dict) -> Any:
        out = tool.fn(**args)
        observe = getattr(self.engine, "observe", None)
        if observe and observe(s, out):
            self.audit.append({"event": "injection_flag", "session": s.session_id, "tool": tool.name,
                               "risk": round(s.risk, 3)})
        return out

    def _log(self, req: ActionRequest, d: Decision) -> None:
        sess = self.sessions[req.session_id]
        self.memory[req.agent_id] = {"risk": sess.risk, "tags": set(sess.tags)}
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
