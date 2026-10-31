# Paper outline (working draft, not for submission)

Working title: Intent-Aware and Behavioural Authorization for Autonomous AI Agents: A Runtime
Framework for Preventing Unauthorized Tool Execution and Sensitive Data Exfiltration

Numbers in this file are never typed by hand. Run `python -m bench.run` then
`python -m bench.paper_tables > paper/tables.md` and cite from that file.

## 1. Introduction
- Agents hold tool permissions broader than any single task. Tool-level access control cannot say
  whether *this call* is justified by *this task*.
- Contribution list (only what the evidence currently supports):
  1. A deterministic authorization model combining task scope, data classification, destination trust,
     taint, and cumulative session risk with dynamic permission reduction.
  2. A hash-chained audit design and explanation-carrying decisions.
  3. IntentGuardBench: a seeded, labelled episode generator plus a hand-written adversarial set.
  4. Ablations and an honest failure analysis.
- Do not claim: complete protection, superiority over published tools (no such baseline measured yet).

## 2. Threat model
- Attacker capability: injected content in documents/tool output, malicious or lookalike destinations,
  over-broad user grants. Out of model: attacker controls the user's task text, compromised gateway
  host, side channels, model weights.
- Trusted: gateway, catalog (classification and destination trust), policy rules.
- Assumption to state plainly: the agent has no direct handle to tools (needs process isolation;
  the current prototype demonstrates the API shape only).

## 3. Design
Scope compiler, policy engine (rule catalogue), taint ledger and egress policy, session risk and
reduction ladder, approval queue with evidence-based explanations, audit chain. LLM is optional and
never the final authority.

## 4. IntentGuardBench
Generator templates, label definitions (harmful step vs clean step), sets (core, seq, generated dev /
held-out / fresh, adversarial), dev/held-out discipline from `docs/findings.md`.
Limitation: author of engine = author of benchmark. Needs an independent episode set.

## 5. Evaluation
Metrics: ASR, detection, benign block rate, review friction, precision, exfil rate, task completion,
latency, Wilson 95% intervals. Systems: unprotected, static RBAC, keyword stand-in, IntentGuard,
ablations. External published guardrail: TO MEASURE.
RQ1 intent-to-policy, RQ2 multi-step, RQ3 dynamic reduction, RQ4 overhead.
Report negative and mixed results: the hand-written-set number (11.4%) did not transfer to held-out
data (43.2%) before SCOPE-005; SCOPE-005 results are partly circular (see F5).

## 6. Failure analysis
From findings F2, F5, F6: broad grants, token-collision on SCOPE-005, DB result classification,
review friction on loosely worded tasks, shell and path handling bugs found by adversarial testing.

## 7. Related work to read and cite (verify each before citing)
OWASP Top 10 for Agentic Applications (2026), AgentDojo, NeMo Guardrails, LlamaFirewall,
Llama Guard, MCP security work, taint tracking and information-flow control literature.

## 8. Limitations and ethics
Synthetic data and mock services only, no real attack traffic, small and author-written benchmark,
deterministic scripted agent (no LLM variance measured), no authentication in the demo service.

## Before submission checklist
- [ ] Independent episode set (someone else writes attacks and labels)
- [ ] Published baseline guardrail actually run
- [ ] LLM-driven agent runs (variance across seeds)
- [ ] Process-level isolation of the agent from tools
- [ ] Reproduction script and archived release (Zenodo DOI)
- [ ] Supervisor review
