"""Comparison systems that share the PolicyEngine.evaluate interface."""

from __future__ import annotations

from dataclasses import replace

from intentguard import EngineConfig, PolicyEngine, Verdict
from intentguard.models import ActionRequest, Decision, Session


class AllowAllEngine:
    """Configuration 1: unprotected agent."""

    def evaluate(self, req: ActionRequest, s: Session) -> Decision:
        return Decision(req.action_id, Verdict.ALLOW, 0.0, [], [], "unprotected", "allow",
                        replace(s.caps))


class StaticPermissionEngine:
    """Configuration 2: conventional RBAC. Role = fixed tool allowlist, whole filesystem readable,
    no knowledge of the user's task, data sensitivity or session history."""

    ROLE_TOOLS = {"read_file", "search_files", "send_email", "db_query"}

    def evaluate(self, req: ActionRequest, s: Session) -> Decision:
        ok = req.tool in self.ROLE_TOOLS
        return Decision(req.action_id, Verdict.ALLOW if ok else Verdict.BLOCK, 0.0,
                        [] if ok else ["RBAC-001"], [], "static role check",
                        "allow" if ok else "block", replace(s.caps))


class KeywordGuardrailEngine:
    """Stand-in for a content/keyword guardrail (NOT a published tool): blocks denylisted
    destinations, secret patterns in arguments, and obviously dangerous shell strings. It has no
    notion of the user's task, data classification or session history."""

    BAD_SHELL = ("curl", "wget", "nc ", "env", "/etc/passwd", "chmod", "| sh", "rm -")

    def evaluate(self, req: ActionRequest, s: Session) -> Decision:
        from intentguard.engine import SECRET_RE
        from intentguard.models import Trust
        hit = (req.trust == Trust.DENYLISTED or bool(SECRET_RE.search(str(req.args)))
               or any(b in str(req.args.get("cmd", "")) for b in self.BAD_SHELL))
        return Decision(req.action_id, Verdict.BLOCK if hit else Verdict.ALLOW, 0.0,
                        ["KW-001"] if hit else [], [], "keyword guardrail",
                        "block" if hit else "allow", replace(s.caps))


SYSTEMS = {
    "unprotected": AllowAllEngine,
    "static_rbac": StaticPermissionEngine,
    "keyword_guardrail_standin": KeywordGuardrailEngine,
    "intentguard_full": lambda: PolicyEngine(EngineConfig()),
    "ablate_no_intent": lambda: PolicyEngine(EngineConfig(intent=False)),
    "ablate_no_behaviour": lambda: PolicyEngine(EngineConfig(behaviour=False)),
    "ablate_no_dataflow": lambda: PolicyEngine(EngineConfig(dataflow=False)),
}
# Configuration 3 (external guardrail baseline, e.g. NeMo Guardrails / LlamaFirewall) is NOT
# implemented yet; the results table reports it as TO MEASURE.
