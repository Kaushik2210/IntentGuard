# IntentGuard

Intent-aware and behavioural runtime authorization for autonomous AI agents. Research prototype.

Every tool call goes through a gateway that decides ALLOW / REVIEW / BLOCK / QUARANTINE using
deterministic rules over: the user's task scope, resource classification, destination trust,
data taint, and accumulated session risk. Risk crossing thresholds automatically shrinks the
session's permissions. All decisions go into a hash-chained audit log.

```
pip install -e .[dev]
pytest
```

## Status (v0.1, core only)

Implemented: TaskScope compiler (template), policy engine with ablation flags, taint/egress rules,
multi-step rules SEQ-001/002/004, dynamic permission ladder, approval queue, audit chain, mock env.

Not yet: benchmark and baselines, dashboard, FastAPI service, OPA backend, LangGraph agent,
Postgres/Redis, process-level isolation (the in-process `GatewayClient` only shows the API shape;
real enforcement needs the agent and tools in separate processes/containers).

No benchmark results exist yet. Do not quote any numbers from this repo until `bench/` produces them.
