# IntentGuard: architecture proposal (step 8.1, no code yet)

## 1. Request flow

1. User submits a task plus granted permissions. The **Scope Compiler** turns it into a `TaskScope` (deterministic templates first; an optional LLM parser may only *narrow or propose*, and a human or the deterministic validator confirms).
2. The agent proposes a tool call. The **Interceptor** normalises it into an `ActionRequest`.
3. The **Decision Pipeline** runs in a fixed order: static permission check, intent/scope check, taint/egress check, session-risk update, rule aggregation, decision.
4. **Enforcement** executes the tool (ALLOW), refuses it (BLOCK), parks it for a human (REVIEW), or isolates the session (QUARANTINE).
5. Every step appends to the hash-chained **Audit Log**. Any ALLOW result that touches data updates the **Taint Ledger**.

Decision precedence: any hard-deny rule wins; otherwise the highest-severity soft rule decides; otherwise ALLOW only if the action is inside `TaskScope`. Unknown tool, unknown resource class, or engine error means BLOCK or REVIEW (fail closed).

## 2. Data model (pydantic v2)

```python
class TaskScope:
    scope_id: str
    task_text: str
    allowed_ops: set[Op]                 # READ, SUMMARIZE, WRITE, SEND, UPLOAD, QUERY, EXEC
    allowed_resources: list[ResourceMatcher]   # glob / prefix / tag
    allowed_destinations: list[DestMatcher]    # domain / email / service id
    max_classification: Classification   # PUBLIC < INTERNAL < CONFIDENTIAL < SECRET
    source: Literal["template", "llm_proposed_validated", "manual"]
    confidence: float                    # <1.0 forces stricter fallbacks

class ActionRequest:
    action_id, session_id, agent_id, ts
    tool: str; op: Op
    args: dict                           # redacted copy stored in audit
    resource: ResourceRef | None         # path/uri, classification, labels
    destination: DestRef | None          # domain/email, trust_tier
    prior_action_ids: list[str]

class Decision:
    action_id
    decision: Literal["ALLOW","BLOCK","REVIEW","QUARANTINE"]
    risk_score: float                    # 0..1 session-cumulative after this action
    fired_rules: list[str]               # e.g. ["SCOPE-001","EGRESS-002"]
    evidence: list[Evidence]             # {rule_id, field, observed, expected}
    explanation: str                     # rendered from evidence, not free-form LLM text
    recommended: Literal["allow","block","review"]
    permissions_after: CapabilitySet     # result of dynamic reduction
    latency_ms: float

class AuditEntry:
    seq: int; prev_hash: str; payload_hash: str; entry_hash: str  # sha256(prev_hash||payload)
```

Trust tiers for destinations: `LOCAL`, `APPROVED`, `UNKNOWN`, `DENYLISTED`.

## 3. v0 rule catalogue

| ID | Rule | Default |
|---|---|---|
| PERM-001 | Tool not granted to agent | BLOCK |
| SCOPE-001 | Resource outside `allowed_resources` | BLOCK |
| SCOPE-002 | Operation not in `allowed_ops` | BLOCK |
| SCOPE-003 | Resource classification above `max_classification` | BLOCK |
| SCOPE-004 | Scope confidence < threshold and action touches sensitive resource | REVIEW |
| SCOPE-005 | CONFIDENTIAL+ file or table not named by the task (path or full file name; table name as a word) | REVIEW |
| EGRESS-001 | Destination `UNKNOWN` | REVIEW |
| EGRESS-002 | Tainted (CONFIDENTIAL+) data to non-approved destination | BLOCK |
| EGRESS-003 | Destination `DENYLISTED` | BLOCK |
| TAINT-001 | Secret pattern (key, token, private key) in outbound args, also after rot13, reversal, URL, base64, base32 or hex decoding and across recent outbound messages | BLOCK |
| TAINT-002 | Outbound content contains data read from a CONFIDENTIAL+ file or table in this session (fingerprint match, 12 letters/digits, same decodings) | BLOCK for SECRET data, REVIEW for CONFIDENTIAL |
| SEQ-001 | Secret search followed by env/config read | +risk |
| SEQ-002 | Sensitive read followed by unfamiliar-domain contact | +risk |
| SEQ-003 | Collected sensitive data followed by upload/send | BLOCK |
| SEQ-004 | Repeated denied attempts in one session | +risk, escalate |
| SEQ-005 | Egress, shell or database action after injection-like text was seen in tool output | REVIEW |
| INJ-001 | Instruction-like text in tool *output* that changes the task (flag, never trust) | +risk |
| EXEC-001 | Shell command outside allowlist | BLOCK |
| EXEC-002 | Shell command with network or credential access | REVIEW |
| ESC-001 | Attempt to modify own policy/permissions | QUARANTINE |

Dynamic reduction ladder driven by cumulative risk: `>=0.4` disable external network; `>=0.6` restrict files to the original project folder and disable shell; `>=0.8` all DB and send actions require approval; `>=1.0` QUARANTINE. Thresholds are config values and are ablation/sweep parameters in the paper.

## 4. Repo layout and key interfaces

Layout as in the kickoff prompt. Key interfaces: `PolicyEngine.evaluate(ActionRequest, TaskScope, SessionState) -> Decision` (implementations: `PythonRulesEngine`, later `OpaEngine`), `ScopeCompiler.compile(task, grants) -> TaskScope`, `RiskEngine.update(session, action, decision)`, `TaintLedger.mark/propagate/check`, `AuditLog.append/verify`. Benchmark ablation switches are plain config flags: `intent=False`, `behaviour=False`, `dataflow=False`, `mention_check=False`, `cross_session=False`, `lineage=False`.

Isolation: the agent runs in its own process or container with only the gateway's HTTP/MCP endpoint reachable; protected tools live behind the gateway on an internal network with no route out.

## 5. Milestones

M0 scaffold and threat model, M1 mock tools plus gateway passthrough plus bypass test, M2 TaskScope and intent authorization plus audit chain, M3 taint and egress, M4 risk engine plus dynamic reduction, M5 approval flow and explanations, M6 IntentGuardBench v0 (about 60 episodes) plus baselines and ablations, M7 dashboard, M8 benchmark scale-up plus OPA plus LangGraph plus AgentDojo, M9 paper tables and reproduction script.

## 6. Open questions for you

1. **Folder:** where should the repo live (suggest `Desktop\IntentGuard`)?
2. **Baseline:** which existing guardrail to compare against (NeMo Guardrails, LlamaFirewall, Llama Guard)? "Adrian" in your notes is unidentified.
3. **Services:** may the dev setup require Docker, or should M0 to M6 run on SQLite and in-memory only until you confirm?
4. **LLM:** which model may the optional intent parser and the LangGraph demo agent use, and is a paid API acceptable? The core works with none.
5. **Publication:** target venue or journal and the supervisor's deadline, so the benchmark size and AgentDojo scope fit the timeline.
6. **License:** Apache-2.0 assumed; confirm.

## 7. Where the code stands now (additions since the milestones above)

| Module | What it adds |
|---|---|
| `store.py` | SQLite persistence of sessions, per-agent memory and lineage; lineage hashes are keyed with `<db>.key` (F28, F30) |
| `sdk.py` | `Guard`: decorate your own Python functions, open a session per task, give the agent only the session |
| `report.py` | `intentguard report`: readable per-session summary of an audit log, non-zero exit if the chain is broken |
| `mcp_gateway.py` | MCP over stdio or Streamable HTTP (`--http-port`, origin and bearer-token checks), demo and proxy modes, approval channel |
| `engine.py` lineage | 12-character fingerprints plus large numbers (digits, `120k`, words) and leetspeak readings (F17, F29) |
| `bench/baselines.py` | unprotected, RBAC, keyword, LlamaFirewall, Prompt Guard 2 and stand-ins for Progent and The Task Shield (F27) |

Not persisted by design: actions waiting for a human, the recent outbound text buffer, and the dashboard event list.

