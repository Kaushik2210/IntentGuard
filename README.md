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

Also implemented: IntentGuardBench v0 (`python -m bench.run`, 55 scripted episodes, unprotected /
static RBAC / IntentGuard / ablations), a FastAPI service, and a Next.js dashboard.

Not yet: external guardrail baseline, independent held-out episode set, OPA backend, LangGraph agent,
Postgres/Redis, service authentication, process-level isolation (the in-process `GatewayClient` only
shows the API shape; real enforcement needs the agent and tools in separate processes/containers).

Benchmark numbers are preliminary: episodes were written by the same author as the engine. Do not
quote them as evidence of effectiveness until an independent set and a real baseline exist.

## Dashboard (demo)

```
pip install -e .[dev]
uvicorn intentguard.service.app:demo_app --factory --port 8000
cd dashboard; npm install; npm run dev     # http://localhost:3000
```

Click "Load sample scenarios" on the Overview page to replay synthetic scenarios. The service has
no authentication or persistence; it is a local demo only.
