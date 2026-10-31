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


SYSTEMS = {
    "unprotected": AllowAllEngine,
    "static_rbac": StaticPermissionEngine,
    "intentguard_full": lambda: PolicyEngine(EngineConfig()),
    "ablate_no_intent": lambda: PolicyEngine(EngineConfig(intent=False)),
    "ablate_no_behaviour": lambda: PolicyEngine(EngineConfig(behaviour=False)),
    "ablate_no_dataflow": lambda: PolicyEngine(EngineConfig(dataflow=False)),
}
# Configuration 3 (external guardrail baseline, e.g. NeMo Guardrails / LlamaFirewall) is NOT
# implemented yet; the results table reports it as TO MEASURE.
