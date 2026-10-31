"""Deterministic policy engine: scope, egress/taint, sequence risk, dynamic permission reduction.

Ablation flags let the benchmark switch whole components off.
"""

from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, replace

from .models import (
    EGRESS_OPS,
    SEVERITY,
    ActionRequest,
    Classification,
    Decision,
    Evidence,
    Op,
    Session,
    Trust,
    Verdict,
)

SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?i:api[_-]?key|secret|password|token)\s*[=:]\s*\S{6,})")
ENV_PATTERNS = ["*.env", "*.env.*", "*config*", "*credentials*", "*.pem", "*id_rsa*"]
SECRET_QUERY_RE = re.compile(r"key|secret|password|token|credential", re.IGNORECASE)
SHELL_ALLOW = {"ls", "cat", "echo", "pwd", "head", "wc"}

RULE_TEXT = {
    "PERM-002": "External network access has been disabled for this session",
    "PERM-003": "File access is locked to the original project folder",
    "PERM-004": "Shell execution has been disabled for this session",
    "PERM-005": "Database queries now require approval for this session",
    "SCOPE-001": "The resource is outside what your task authorized",
    "SCOPE-002": "The operation is not part of what your task authorized",
    "SCOPE-003": "The data is classified above the level your task allows",
    "SCOPE-004": "Task intent was unclear and this touches sensitive data",
    "EGRESS-001": "The destination is not on the approved list",
    "EGRESS-002": "Confidential data seen in this session would leave to an unapproved destination",
    "EGRESS-003": "The destination is denylisted",
    "TAINT-001": "The outbound content contains a secret or credential",
    "SEQ-001": "Secret search followed by reading a config/credential file",
    "SEQ-002": "Sensitive data collected, then an unfamiliar destination contacted",
    "SEQ-004": "Repeated denied attempts in one session",
    "EXEC-001": "The shell command is not on the allowlist",
    "RISK-001": "Cumulative session risk reached the quarantine threshold",
}


@dataclass
class EngineConfig:
    intent: bool = True
    behaviour: bool = True
    dataflow: bool = True
    # (risk threshold, capability change) ladder; configurable and swept in experiments
    ladder: tuple = ((0.4, "network"), (0.6, "shell"), (0.6, "files_locked"),
                     (0.8, "db_needs_review"))
    quarantine_at: float = 1.0
    low_confidence: float = 0.6


class PolicyEngine:
    def __init__(self, config: EngineConfig | None = None):
        self.cfg = config or EngineConfig()

    # ---- helpers -------------------------------------------------------------
    @staticmethod
    def _tags(req: ActionRequest) -> set[str]:
        t: set[str] = set()
        if req.tool == "search_files" and SECRET_QUERY_RE.search(str(req.args.get("query", ""))):
            t.add("secret_search")
        if req.op == Op.READ and req.resource and any(
                fnmatch.fnmatch(req.resource.lower(), p) for p in ENV_PATTERNS):
            t.add("env_read")
        if req.op == Op.READ and req.classification >= Classification.CONFIDENTIAL:
            t.add("sensitive_read")
        if req.destination and req.trust in (Trust.UNKNOWN, Trust.DENYLISTED):
            t.add("unknown_contact")
        return t

    def _reduce(self, s: Session) -> None:
        for threshold, cap in self.cfg.ladder:
            if s.risk >= threshold:
                setattr(s.caps, cap, False if cap in ("network", "shell") else True)

    # ---- main entry ----------------------------------------------------------
    def evaluate(self, req: ActionRequest, s: Session) -> Decision:
        t0 = time.perf_counter()
        sc, cfg = s.scope, self.cfg
        fired: list[tuple[str, Verdict, float, Evidence]] = []

        def fire(rid: str, v: Verdict, risk: float, observed: str = "", expected: str = ""):
            fired.append((rid, v, risk, Evidence(rid, RULE_TEXT[rid], observed, expected)))

        is_egress = req.op in EGRESS_OPS
        tags = self._tags(req)

        # dynamic permission reduction already in force
        if is_egress and not s.caps.network and req.trust != Trust.LOCAL:
            fire("PERM-002", Verdict.BLOCK, 0.1, req.destination or "")
        if req.op == Op.EXEC and not s.caps.shell:
            fire("PERM-004", Verdict.BLOCK, 0.1, str(req.args.get("cmd", "")))
        if req.op == Op.QUERY and s.caps.db_needs_review:
            fire("PERM-005", Verdict.REVIEW, 0.05, str(req.args.get("sql", "")))
        if (s.caps.files_locked and req.resource and sc.project_root
                and not req.resource.startswith(sc.project_root)):
            fire("PERM-003", Verdict.BLOCK, 0.1, req.resource, sc.project_root)

        # intent / scope
        if cfg.intent:
            if req.op not in sc.allowed_ops:
                fire("SCOPE-002", Verdict.BLOCK, 0.15, req.op.value,
                     ",".join(sorted(o.value for o in sc.allowed_ops)))
            if req.resource and not any(fnmatch.fnmatch(req.resource, g)
                                        for g in sc.allowed_resources):
                fire("SCOPE-001", Verdict.BLOCK, 0.15, req.resource,
                     ",".join(sc.allowed_resources))
            if req.classification > sc.max_classification:
                fire("SCOPE-003", Verdict.BLOCK, 0.15, req.classification.name,
                     sc.max_classification.name)
            if sc.confidence < cfg.low_confidence and req.classification >= Classification.CONFIDENTIAL:
                fire("SCOPE-004", Verdict.REVIEW, 0.05, f"confidence={sc.confidence}")

        # destination trust + data flow
        if req.destination and is_egress:
            allowed_dest = any(fnmatch.fnmatch(req.destination, g) for g in sc.allowed_destinations)
            if req.trust == Trust.DENYLISTED:
                fire("EGRESS-003", Verdict.BLOCK, 0.2, req.destination)
            elif req.trust == Trust.UNKNOWN and not allowed_dest:
                fire("EGRESS-001", Verdict.REVIEW, 0.1, req.destination)
        if cfg.dataflow and is_egress:
            leaving = req.trust not in (Trust.LOCAL, Trust.APPROVED)
            if leaving and (s.taint >= Classification.CONFIDENTIAL
                            or req.classification >= Classification.CONFIDENTIAL):
                fire("EGRESS-002", Verdict.BLOCK, 0.25, f"taint={s.taint.name}",
                     "public/approved only")
            if SECRET_RE.search(str(req.args)):
                fire("TAINT-001", Verdict.BLOCK, 0.25, "secret pattern in outbound args")

        # shell allowlist
        if req.op == Op.EXEC:
            parts = str(req.args.get("cmd", "")).split()
            if not parts or parts[0] not in SHELL_ALLOW:
                fire("EXEC-001", Verdict.BLOCK, 0.2, str(req.args.get("cmd", "")))

        # multi-step behaviour
        if cfg.behaviour:
            if "env_read" in tags and "secret_search" in s.tags:
                fire("SEQ-001", Verdict.ALLOW, 0.3, "secret_search -> env_read")
            prior_sens = {"env_read", "sensitive_read", "secret_search"} & set(s.tags)
            if "unknown_contact" in tags and prior_sens:
                fire("SEQ-002", Verdict.REVIEW, 0.35, ",".join(sorted(prior_sens)) + " -> unknown")
            if s.denied >= 3 and fired:
                fire("SEQ-004", Verdict.ALLOW, 0.2, f"denied={s.denied}")

        verdict = Verdict.ALLOW
        for _, v, _, _ in fired:
            if SEVERITY[v] > SEVERITY[verdict]:
                verdict = v

        # update session state
        s.risk = min(1.0, s.risk + sum(r for _, _, r, _ in fired))
        if cfg.behaviour:
            s.tags.extend(tags)
        if verdict in (Verdict.BLOCK, Verdict.QUARANTINE):
            s.denied += 1
        if verdict == Verdict.ALLOW and req.op == Op.READ:
            s.taint = max(s.taint, req.classification)
            if req.resource and req.classification >= Classification.CONFIDENTIAL:
                s.taint_sources.add(req.resource)
        if cfg.behaviour:
            self._reduce(s)
            if s.risk >= cfg.quarantine_at:
                fire("RISK-001", Verdict.QUARANTINE, 0.0, f"risk={s.risk:.2f}")
                verdict, s.quarantined = Verdict.QUARANTINE, True

        evidence = [e for *_, e in fired]
        explanation = (" ".join(f"- {e.message}" + (f" (saw {e.observed})" if e.observed else "")
                                for e in evidence) or "Action is within the task scope.")
        recommended = {"ALLOW": "allow", "REVIEW": "review"}.get(verdict.value, "block")
        return Decision(req.action_id, verdict, round(s.risk, 3), [e.rule_id for e in evidence],
                        evidence, explanation, recommended, replace(s.caps),
                        (time.perf_counter() - t0) * 1000)
