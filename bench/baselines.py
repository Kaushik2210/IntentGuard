"""Comparison systems that share the PolicyEngine.evaluate interface."""

from __future__ import annotations

import json
from dataclasses import replace

from intentguard import EngineConfig, PolicyEngine, Verdict
from intentguard.models import ActionRequest, Decision, Op, Session


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


class LlamaFirewallEngine:
    """Meta LlamaFirewall 1.0.3, local scanners only (REGEX + HIDDEN_ASCII).

    Adaptation (an assumption, stated in the paper): each proposed tool call is scanned as an
    assistant message "tool({args})", and for reads the file content is scanned as a tool output.
    NOT run: PROMPT_GUARD (gated Hugging Face model, no token on this machine), AGENT_ALIGNMENT
    (needs an external LLM API), CODE_SHIELD (needs semgrep-core, unavailable on Windows).
    Default REGEX patterns include email addresses, so benign emails are flagged: that is the
    published default configuration, not a tuned one.
    """

    def __init__(self):
        from llamafirewall import LlamaFirewall, Role, ScannerType
        scanners = [ScannerType.REGEX, ScannerType.HIDDEN_ASCII]
        self.fw = LlamaFirewall(scanners={Role.ASSISTANT: scanners, Role.TOOL: scanners})

    def evaluate(self, req: ActionRequest, s: Session) -> Decision:
        import time

        from llamafirewall import AssistantMessage, ScanDecision, ToolMessage

        from intentguard.mock_env import FILES
        t0 = time.perf_counter()
        msgs = [AssistantMessage(content=f"{req.tool}({json.dumps(req.args, default=str)})")]
        if req.op == Op.READ and req.resource in FILES:
            msgs.append(ToolMessage(content=FILES[req.resource][0]))
        hit = any(self.fw.scan(m).decision != ScanDecision.ALLOW for m in msgs)
        d = Decision(req.action_id, Verdict.BLOCK if hit else Verdict.ALLOW, 0.0,
                     ["LF-001"] if hit else [], [], "llamafirewall local scanners",
                     "block" if hit else "allow", replace(s.caps))
        d.latency_ms = (time.perf_counter() - t0) * 1000
        return d


def _optional_systems() -> dict:
    try:
        import llamafirewall  # noqa: F401
    except ImportError:
        return {}
    return {"llamafirewall_local_scanners": LlamaFirewallEngine}


SYSTEMS = {
    "unprotected": AllowAllEngine,
    "static_rbac": StaticPermissionEngine,
    "keyword_guardrail_standin": KeywordGuardrailEngine,
    "intentguard_full": lambda: PolicyEngine(EngineConfig()),
    "ablate_no_mention_check": lambda: PolicyEngine(EngineConfig(mention_check=False)),
    "ablate_no_intent": lambda: PolicyEngine(EngineConfig(intent=False)),
    "ablate_no_behaviour": lambda: PolicyEngine(EngineConfig(behaviour=False)),
    "ablate_no_dataflow": lambda: PolicyEngine(EngineConfig(dataflow=False)),
}
# Configuration 3 (external guardrail baseline, e.g. NeMo Guardrails / LlamaFirewall) is NOT
# implemented yet; the results table reports it as TO MEASURE.
SYSTEMS.update(_optional_systems())
