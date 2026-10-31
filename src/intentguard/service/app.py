"""FastAPI front for the gateway: session control, tool calls, approvals, audit, stats.

Run the demo service (mock tools, synthetic data only):
    uvicorn intentguard.service.app:demo_app --factory --reload
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from ..audit import AuditLog
from ..engine import PolicyEngine
from ..gateway import Gateway
from ..mock_env import MockEnv
from ..models import Decision, Verdict
from ..scope import compile_scope


class NewSession(BaseModel):
    session_id: str
    agent_id: str
    task: str
    grants: dict = Field(default_factory=dict)


class ToolCall(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)


class Approver(BaseModel):
    approver: str


def create_app(gateway: Gateway) -> FastAPI:
    app = FastAPI(title="IntentGuard", version="0.1.0")
    clients: dict[str, Any] = {}
    review_decisions: dict[str, Decision] = {}

    @app.post("/sessions")
    def open_session(body: NewSession):
        if body.session_id in gateway.sessions:
            raise HTTPException(409, "session exists")
        try:
            scope = compile_scope(body.task, body.grants)
        except (KeyError, ValueError) as exc:
            raise HTTPException(422, f"bad grants: {exc}") from exc
        clients[body.session_id] = gateway.open_session(body.session_id, body.agent_id, scope)
        return jsonable_encoder({"session_id": body.session_id, "scope": scope})

    @app.get("/sessions/{sid}")
    def get_session(sid: str):
        s = gateway.sessions.get(sid)
        if not s:
            raise HTTPException(404, "no such session")
        return jsonable_encoder(s)

    @app.post("/sessions/{sid}/call")
    def call(sid: str, body: ToolCall):
        if sid not in clients:
            raise HTTPException(404, "no such session")
        res = clients[sid].call(body.tool, **body.args)
        d = res.decision
        if d.decision == Verdict.REVIEW:
            review_decisions[d.action_id] = d
        return jsonable_encoder({"decision": d, "output": res.output})

    @app.get("/pending")
    def pending():
        return jsonable_encoder([review_decisions[a] for a in gateway.pending
                                 if a in review_decisions])

    @app.post("/pending/{action_id}/approve")
    def approve(action_id: str, body: Approver):
        if action_id not in gateway.pending:
            raise HTTPException(404, "not pending")
        return jsonable_encoder({"output": gateway.approve(action_id, body.approver)})

    @app.post("/pending/{action_id}/reject")
    def reject(action_id: str, body: Approver):
        if action_id not in gateway.pending:
            raise HTTPException(404, "not pending")
        gateway.reject(action_id, body.approver)
        return {"rejected": action_id}

    @app.get("/audit")
    def audit(offset: int = 0, limit: int = 100):
        limit = max(1, min(limit, 500))
        rows = gateway.audit.entries[offset:offset + limit]
        return {"total": len(gateway.audit.entries),
                "entries": [{**e, "payload": json.loads(e["payload"])} for e in rows]}

    @app.get("/audit/verify")
    def verify():
        ok, bad = gateway.audit.verify()
        return {"ok": ok, "first_bad_seq": bad}

    @app.get("/stats")
    def stats():
        acts = [json.loads(e["payload"]) for e in gateway.audit.entries]
        acts = [a for a in acts if a.get("event") == "action"]
        c = Counter(a["decision"] for a in acts)
        return {"inspected": len(acts), "by_decision": dict(c),
                "pending": len(gateway.pending), "sessions": len(gateway.sessions)}

    return app


def demo_app() -> FastAPI:
    env = MockEnv()
    return create_app(Gateway(env.tools(), env.catalog(), PolicyEngine(), AuditLog()))
