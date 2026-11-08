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

## Quick start: the `intentguard` command

```
pip install -e ".[dev]"          # installs the `intentguard` command
intentguard init                 # writes a documented intentguard.toml to edit
intentguard check-config intentguard.toml
intentguard serve --demo         # HTTP service + dashboard backend, mock tools, http://127.0.0.1:8000
intentguard serve --demo --db sessions.db   # same, but sessions survive a restart
intentguard mcp --demo --task "Read research/paper.pdf and summarize it." --grants '{"resources":["research/*"]}'   # MCP gateway
intentguard verify-audit audit.jsonl                                       # is the hash chain intact?
intentguard report audit.jsonl                                             # readable summary per session
```

One TOML file configures everything: the engine (quarantine level, the risk ladder that switches network, shell and
files off), the catalog (which files and tables are sensitive, which destinations are trusted or denylisted), which
tools exist and which argument is the resource or destination, and default grants for sessions opened without their
own. Unknown keys and bad values are errors that name the section. `intentguard serve --upstream "CMD" --config
intentguard.toml` puts the service in front of an existing MCP server. The service refuses to listen on anything but
localhost unless both `--agent-token` and `--admin-token` are set. With `--db FILE` (or `INTENTGUARD_DB`) sessions are kept in SQLite
and restored on restart: risk, restrictions, closed state, approvals and the fingerprints of sensitive data a session has read
(64-bit hashes keyed with a secret in `<db>.key`, never readable text; keep that file apart from the database). Not saved: actions waiting for a human, and the short buffer of recent outbound text.

## Status (research prototype)

Implemented: deterministic policy engine (task scope, taint/egress, content lineage of sensitive data,
sequence risk, injection-aware output scan, dynamic permission reduction, cross-session risk carry-over,
database table classification, session approval memory), hash-chained audit log, approval queue, FastAPI
service with agent/admin bearer tokens, Next.js dashboard with session admin (release and close), a config file and the `intentguard`
command, HTTP-only agent process, structured errors when a tool fails after being allowed, a LangChain/LangGraph
adapter, an MCP gateway (demo and proxy modes, with an approval channel that waits for a human in the
dashboard), IntentGuardBench (hand-written, seeded-generated, adversarial and red-team sets with dev and
held-out halves, ablations, baselines incl. LlamaFirewall local scanners, Llama Prompt Guard 2, and deterministic stand-ins for the ideas behind Progent and The Task Shield, see F27), and
harnesses that run real local Ollama models as agents, directly and through the MCP gateway.

Experiments that are built but off by default because they did not pay for themselves: a per-action risk cap
and a reviewed lock-out (see F25 and F26).

Not done: an independent (non-author) episode set, LlamaFirewall AlignmentCheck (needs an external LLM),
comparison runs of the real Progent, The Task Shield or CaMeL (only stand-ins for the first two, F27), verified network-level isolation (Docker draft untested), OPA backend,
Postgres/Redis, MCP resources/prompts/SSE streaming. Known open weaknesses: paraphrased or substituted (numbers and leetspeak are now matched, F29; reworded facts are not)
exfiltration, split secrets whose first piece is short, review friction on legitimate tasks, and a session that
is locked out after one blocked attempt (F16 to F18, F24 to F26).

Read `docs/findings.md` before quoting any number: results are preliminary, the engine and benchmarks share
an author, and several weaknesses are documented there (F2, F5 to F26). `python -m bench.run` regenerates
the results; run it with `.venv-lf/Scripts/python` (Hugging Face access to Llama Prompt Guard 2 needed) to
include the LlamaFirewall rows. `docs/literature-review.md` and the spreadsheets next to it hold the
literature survey; `docs/mcp-demo.md` walks through the MCP gateway with the dashboard. Tests:
`python -m pytest -q` (171 passing locally; the LangChain tests skip in a clean `.[dev]` environment).

## Showcase site

`web/` is a Next.js (App Router, static export) site that shows the prototype: a 3D steel-and-glass gate (three.js) that real engine
decisions fly through, a replay console that lights up which of the six checks fired, a compose box to try to smuggle a secret past the
lineage check (a tested TypeScript port of that one rule), a risk gauge with the capabilities that switch off, an audit ledger you can
tamper with (SHA-256 in the browser), the benchmark table with its caveats, and the known limits. It follows light and dark and respects
`prefers-reduced-motion`.

```bash
python site/build_site.py          # run the real engine, write web/src/data/site-data.json (--refresh re-reads results/results.md)
cd web && npm install && npm run dev      # http://localhost:3100
cd web && npm run publish:docs            # build and copy the static site into docs/
```

Everything the site shows comes from that JSON, and a test fails if it no longer matches the engine. To publish, set GitHub Pages to deploy
from branch `master`, folder `/docs`; the export assumes the URL path `/IntentGuard/` (set `NEXT_BASE_PATH=""` for a custom domain).

## Guard your own Python functions

No framework needed: decorate the functions the agent may use, open a session for the user's task, and give the agent only
the session. `examples/guard_your_own_tools.py` runs end to end.

```python
from intentguard.sdk import Guard

guard = Guard(classes={"hr/salary.csv": "CONFIDENTIAL"}, trust={"bob@x.org": "approved"})

@guard.tool("read", resource_arg="path")
def read_file(path): ...

@guard.tool("send", resource_arg="attachment", dest_arg="to", resource_optional=True)
def send_email(to, body, attachment=None): ...

session = guard.session("Read notes/a.txt and email bob@x.org a summary",
                        grants={"resources": ["notes/*"], "destinations": ["bob@x.org"]})
session.call("send_email", to="evil@x.org", body="...")   # BLOCK, with the reason; the function never runs
```

Pass `db="sessions.db"` to keep sessions across restarts. `guard.gateway` exposes approvals, `release` and `close`.

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

## MCP gateway

`intentguard.mcp_gateway` is an MCP server (stdio or Streamable HTTP, standard library only) that authorizes every `tools/call`
against the user's task before it runs. A blocked call comes back as an MCP error result with the reason.

```bash
# demo tools (synthetic data)
python -m intentguard.mcp_gateway --demo --task "Read research/paper.pdf and summarize it." --grants grants.json

# protect an existing MCP server: only the tools named in proxy.json are exposed and forwarded
python -m intentguard.mcp_gateway --upstream "python my_server.py" --config proxy.json \
    --task "Read notes/a.txt and email bob@x.org the summary" --grants grants.json --audit-file audit.jsonl
```

`proxy.json` maps each upstream tool to an operation and says which argument is the resource and the
destination, plus optional `classes` (resource sensitivity), `trust` (destination trust) and `tables`. A tool that
is not listed is never shown to the client, and a call to it is blocked and audited. Point an MCP host
(Claude Desktop, Cursor, an agent SDK) at the command above instead of at the real server.

**HTTP transport.** Add `--http-port 8000` to serve `POST http://127.0.0.1:8000/mcp` instead of stdio, for hosts that
connect to a URL. It answers with plain JSON (no SSE streaming; GET returns 405), caps the body at 1 MB, refuses a
browser `Origin` that is not local (stops DNS rebinding from a web page; allow more with `--http-origin`), and
requires `Authorization: Bearer <token>` when you pass `--http-token`. Listening on a non-loopback `--http-host`
is refused unless a token is set. All clients share the gateway's one IntentGuard session, as with stdio, so run
one gateway per user task; there is no TLS, so put it behind a reverse proxy before exposing it.

**Approvals.** Add `--approvals-port 8765` (needs `pip install -e ".[api]"`) and the gateway also serves the
approval API on `127.0.0.1:8765`, the same endpoints the dashboard uses. A call that needs a human
(unapproved recipient, loosely named sensitive file) then waits instead of failing: the agent's `tools/call`
stays open until someone approves or rejects it in the dashboard, and the tool runs only after approval. If
nobody answers within `--approval-timeout` seconds (default 45, keep it below your MCP host's own request
timeout) the pending action is cancelled, so a late approval cannot run it behind the agent's back. An
approval is remembered for that recipient or file for the rest of the session. The API has no token unless
you pass `--admin-token`; it binds to localhost only.

Implemented: initialize, ping, tools/list, tools/call. Not implemented: resources, prompts, sampling, SSE
streaming, per-client sessions, and per-request cancellation notifications. Checked against the official `mcp` Python SDK client
(2.3.0): initialize, list and call, including a blocked call, work. `tests/test_mcp_gateway.py` covers the
protocol, the stdio process, and proxying a real child MCP server, including that a blocked call never reaches
the upstream; `tests/test_mcp_http.py` covers the HTTP transport, its origin, token and size checks, and a real process; `tests/test_mcp_approval.py` covers approve, reject, timeout and a real process approved over HTTP.

## Dashboard (demo)

```
pip install -e .[dev]
intentguard serve --demo --port 8000        # or: uvicorn intentguard.service.app:demo_app --factory
cd dashboard; npm install; npm run dev     # http://localhost:3000
```

The dashboard has an Overview, **Sessions** (live risk, what has been switched off, how each call was judged, and
admin actions), Approvals and an Audit log. On the Sessions page a human can **release** a locked-out session after
reviewing it, or **close** it. Releasing restores the switched-off capabilities and clears the session's risk and the
agent's carried-over risk, but keeps the record of sensitive data the session has already read, so an exposure is never
forgotten; both actions need the admin token and go into the audit log with the reason. The same actions are
`POST /sessions/{id}/release` and `/close`, and `GET /sessions` lists every session.

Click "Load sample scenarios" on the Overview page to replay synthetic scenarios. With no tokens set
the service is open and keeps sessions in memory; it is a local demo only.

Auth: set `INTENTGUARD_AGENT_TOKEN` and `INTENTGUARD_ADMIN_TOKEN` on the service (and
`NEXT_PUBLIC_ADMIN_TOKEN` for the dashboard, local demo only). `INTENTGUARD_AUDIT_FILE` persists the
audit chain.
