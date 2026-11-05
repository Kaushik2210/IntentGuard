from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, IntEnum


class Op(str, Enum):
    READ = "read"
    SUMMARIZE = "summarize"
    WRITE = "write"
    SEND = "send"
    UPLOAD = "upload"
    QUERY = "query"
    EXEC = "exec"


EGRESS_OPS = {Op.SEND, Op.UPLOAD}


class Classification(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    SECRET = 3


class Trust(str, Enum):
    LOCAL = "local"
    APPROVED = "approved"
    UNKNOWN = "unknown"
    DENYLISTED = "denylisted"


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"


SEVERITY = {Verdict.ALLOW: 0, Verdict.REVIEW: 1, Verdict.BLOCK: 2, Verdict.QUARANTINE: 3}


@dataclass
class TaskScope:
    task_text: str
    allowed_ops: set[Op]
    allowed_resources: list[str]  # fnmatch globs
    allowed_destinations: list[str] = field(default_factory=list)
    max_classification: Classification = Classification.INTERNAL
    project_root: str | None = None
    confidence: float = 1.0
    source: str = "template"


@dataclass
class Capabilities:
    network: bool = True
    shell: bool = True
    files_locked: bool = False
    db_needs_review: bool = False


@dataclass
class ActionRequest:
    session_id: str
    agent_id: str
    tool: str
    op: Op
    resource: str | None = None
    classification: Classification = Classification.PUBLIC
    destination: str | None = None
    trust: Trust | None = None
    tables: list[str] = field(default_factory=list)
    args: dict = field(default_factory=dict)
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    ts: float = field(default_factory=time.time)


@dataclass
class Evidence:
    rule_id: str
    message: str
    observed: str = ""
    expected: str = ""


@dataclass
class Decision:
    action_id: str
    decision: Verdict
    risk_score: float
    fired_rules: list[str]
    evidence: list[Evidence]
    explanation: str
    recommended: str
    capabilities_after: Capabilities
    latency_ms: float = 0.0


@dataclass
class Session:
    session_id: str
    agent_id: str
    scope: TaskScope
    risk: float = 0.0
    taint: Classification = Classification.PUBLIC
    taint_sources: set[str] = field(default_factory=set)
    tags: list[str] = field(default_factory=list)
    denied: int = 0
    quarantined: bool = False
    caps: Capabilities = field(default_factory=Capabilities)
    outbound: str = ""  # recent outbound text, so a secret split across several sends is still seen
    lineage: list = field(default_factory=list)  # (classification, n-grams) of sensitive content read here
