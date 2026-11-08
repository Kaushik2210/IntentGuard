"""Guard your own Python functions in a few lines.

    from intentguard.sdk import Guard

    guard = Guard(classes={"hr/salary.csv": "CONFIDENTIAL"}, trust={"bob@x.org": "approved"})

    @guard.tool("read", resource_arg="path")
    def read_file(path): ...

    @guard.tool("send", resource_arg="attachment", dest_arg="to", resource_optional=True)
    def send_email(to, body, attachment=None): ...

    session = guard.session("Read notes/a.txt and email bob@x.org a summary",
                            grants={"resources": ["notes/*"], "destinations": ["bob@x.org"]})
    session.call("read_file", path="notes/a.txt")      # -> ToolResult (allowed, with output)
    session.call("send_email", to="evil@x.org", body="...")   # -> ToolResult (BLOCK, with the reason)

The decorated function is returned unchanged, so you can still unit-test it. The agent should only ever hold the session:
give it `guarded_tools(session)` (LangChain) or call `session.call` yourself, and never the functions.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any

from .audit import AuditLog
from .client import InProcessSession
from .engine import PolicyEngine
from .gateway import Catalog, Gateway, Tool
from .models import Classification, Op, Trust
from .scope import compile_scope


def _enum(kind, value, what: str):
    if isinstance(value, kind):
        return value
    try:
        return kind[str(value).upper()] if kind is Classification else kind(str(value).lower())
    except (KeyError, ValueError):
        raise ValueError(f"unknown {what} {value!r}") from None


class Guard:
    def __init__(self, classes: dict[str, Any] | None = None, trust: dict[str, Any] | None = None,
                 tables: dict[str, Any] | None = None, engine: PolicyEngine | None = None,
                 audit: AuditLog | None = None, db: str | None = None):
        """`classes` maps a resource to PUBLIC/INTERNAL/CONFIDENTIAL/SECRET; `trust` maps a destination to
        local/approved/unknown/denylisted; `tables` classifies database tables. Anything not listed is treated as
        INTERNAL (a resource) or unknown (a destination). `db` is an optional SQLite file that keeps sessions
        across restarts."""
        self._catalog = Catalog({k: _enum(Classification, v, "classification") for k, v in (classes or {}).items()},
                                {k: _enum(Trust, v, "trust level") for k, v in (trust or {}).items()},
                                {k.lower(): _enum(Classification, v, "classification") for k, v in (tables or {}).items()})
        self._engine, self._audit, self._db = engine, audit, db
        self._tools: list[Tool] = []
        self._gateway: Gateway | None = None

    def tool(self, op: Op | str, *, resource_arg: str | None = None, dest_arg: str | None = None,
             name: str | None = None, resource_optional: bool = False) -> Callable[[Callable], Callable]:
        """Register a function. `op` is read, write, send, upload, query, exec or summarize. Name the argument that
        carries the file (`resource_arg`) and the one that carries the recipient or URL (`dest_arg`) so the policy can
        judge them."""
        operation = _enum(Op, op, "operation")

        def register(fn: Callable) -> Callable:
            if self._gateway is not None:
                raise RuntimeError("register tools before the first session is opened")
            params = inspect.signature(fn).parameters
            for label, arg in (("resource_arg", resource_arg), ("dest_arg", dest_arg)):
                if arg is not None and arg not in params:
                    raise ValueError(f"{fn.__name__}: {label}={arg!r} is not a parameter of the function")
            tool_name = name or fn.__name__
            if any(t.name == tool_name for t in self._tools):
                raise ValueError(f"a tool named {tool_name!r} is already registered")
            self._tools.append(Tool(tool_name, operation, fn, resource_arg, dest_arg, resource_optional))
            return fn

        return register

    @property
    def gateway(self) -> Gateway:
        """The underlying Gateway (approvals: `guard.gateway.pending`, `.approve(id, who)`, `.reject(id, who)`)."""
        if self._gateway is None:
            if not self._tools:
                raise RuntimeError("no tools registered: decorate at least one function with @guard.tool(...)")
            self._gateway = Gateway(self._tools, self._catalog, self._engine, self._audit)
            if self._db:
                from .store import SessionStore
                self._gateway.attach_store(SessionStore(self._db))
        return self._gateway

    def session(self, task: str, grants: dict | None = None, agent_id: str = "agent",
                session_id: str | None = None) -> InProcessSession:
        """Open a session for one user task. `grants` is what the user allows at most: resources (globs),
        destinations, ops, max_classification, project_root. With no grants the session can only do what the task
        text implies, on nothing: grant resources and destinations explicitly."""
        import uuid
        sid = session_id or f"s-{uuid.uuid4().hex[:8]}"
        client = self.gateway.open_session(sid, agent_id, compile_scope(task, grants or {}))
        return InProcessSession(client)
