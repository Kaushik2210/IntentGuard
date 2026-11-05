# IntentGuard

Intent-aware and behavioural runtime authorization for autonomous AI agents. Research prototype.
Paper working title: *Intent-Aware Authorization for AI Agents*.

Every tool call goes through a gateway that decides ALLOW / REVIEW / BLOCK / QUARANTINE using
deterministic rules over: the user's task scope, resource classification, destination trust,
data taint, and accumulated session risk. Risk crossing thresholds automatically shrinks the
session's permissions. All decisions go into a hash-chained audit log.

```
pip install -e .[dev]
pytest
```

## Status (research prototype)

Implemented: deterministic policy engine (task scope, taint/egress, content lineage of sensitive data,
sequence risk, injection-aware output scan, dynamic permission reduction, cross-session risk carry-over,
database table classification), hash-chained audit log, approval queue, FastAPI service with agent/admin
bearer tokens, Next.js dashboard, HTTP-only agent process, IntentGuardBench (hand-written, seeded-generated,
adversarial and red-team sets with dev and held-out halves, ablations, baselines incl. LlamaFirewall local
scanners and Llama Prompt Guard 2), and an LLM-driven agent harness for local Ollama models.

Not done: an independent (non-author) episode set, LlamaFirewall AlignmentCheck (needs an external LLM),
comparison runs of Progent or CaMeL, verified network-level isolation (Docker draft untested), OPA backend,
Postgres/Redis. Known open weaknesses: paraphrased or substituted exfiltration, split secrets whose first
piece is short, and review friction on legitimate tasks (see F16 to F18).

Read `docs/findings.md` before quoting any number: results are preliminary, the engine and benchmarks share
an author, and several weaknesses are documented there (F2, F5 to F18). `python -m bench.run` regenerates
the results; run it with `.venv-lf/Scripts/python` (Hugging Face access to Llama Prompt Guard 2 needed) to
include the LlamaFirewall rows. `docs/literature-review.md` and the spreadsheets next to it hold the
literature survey. Tests: `python -m pytest -q` (43 passing).

## Use it with an agent framework (LangChain / LangGraph)

The agent gets tools that hold no capability; every call goes to the gateway, which allows it, sends it to a
human, or explains why not, in text the model can read.

```python
from langchain.agents import create_agent
from intentguard.client import open_http_session           # or InProcessSession(gateway.open_session(...))
from intentguard.integrations.langchain import guarded_tools

session = open_http_session("http://localhost:8000", task, grants)   # grants: resources, destinations, ceiling
agent = create_agent(model, guarded_tools(session))
```

`pip install -e ".[langchain]"`. `agents/langgraph_agent.py` runs a real local model (Ollama) this way, with
`--poison` to add forceful injected documents and `--unprotected` for the same agent without the gateway.
`tests/test_langchain.py` drives the loop with a scripted model so CI stays deterministic.

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
