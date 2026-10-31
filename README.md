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

## Status (research prototype)

Implemented: deterministic policy engine (scope, taint/egress, sequence risk, injection-aware output
scan, dynamic permission reduction), hash-chained audit log, approval queue, FastAPI service with
agent/admin bearer tokens, Next.js dashboard, HTTP-only agent process, IntentGuardBench (hand-written,
seeded-generated and adversarial sets, ablations, baselines incl. LlamaFirewall local scanners).

Not done: published-guardrail comparison with PromptGuard/AlignmentCheck, LLM-driven agent runs,
independent (non-author) episode set, verified network-level isolation (Docker draft untested), OPA
backend, Postgres/Redis, cross-session risk, DB result classification.

Read `docs/findings.md` before quoting any number: results are preliminary, same-author benchmarks,
and several weaknesses are documented there (F2, F5 to F9). `python -m bench.run` regenerates them;
run it with `.venv-lf/Scripts/python` to include the LlamaFirewall row.

## Dashboard (demo)

```
pip install -e .[dev]
uvicorn intentguard.service.app:demo_app --factory --port 8000
cd dashboard; npm install; npm run dev     # http://localhost:3000
```

Click "Load sample scenarios" on the Overview page to replay synthetic scenarios. With no tokens set
the service is open and keeps sessions in memory; it is a local demo only.

Auth: set `INTENTGUARD_AGENT_TOKEN` and `INTENTGUARD_ADMIN_TOKEN` on the service (and
`NEXT_PUBLIC_ADMIN_TOKEN` for the dashboard, local demo only). `INTENTGUARD_AUDIT_FILE` persists the
audit chain.
