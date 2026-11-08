"""Turn an audit log into a readable report: per session, what was asked, what was allowed, what was stopped and why.

    intentguard report audit.jsonl [--session ID]
"""

from __future__ import annotations

import json
from collections import Counter

from .audit import AuditLog


def _events(log: AuditLog) -> list[dict]:
    return [json.loads(e["payload"]) for e in log.entries]


def build_report(log: AuditLog, session: str | None = None) -> str:
    ok, bad = log.verify()
    events = _events(log)
    sessions: dict[str, dict] = {}
    order: list[str] = []
    for ev in events:
        sid = ev.get("session")
        if sid is None or (session and sid != session):
            continue
        if sid not in sessions:
            sessions[sid] = {"task": "", "agent": ev.get("agent", ""), "decisions": Counter(), "stopped": [],
                             "notes": []}
            order.append(sid)
        r = sessions[sid]
        kind = ev.get("event")
        if kind == "session_open":
            r["task"], r["agent"] = ev.get("task", ""), ev.get("agent", "")
        elif kind == "action":
            r["decisions"][ev["decision"]] += 1
            if ev["decision"] != "ALLOW":
                target = ev.get("destination") or ev.get("resource") or ""
                r["stopped"].append(f"{ev['decision']:10} {ev['tool']}({target}) rules={','.join(ev['rules']) or '-'} "
                                    f"risk={ev['risk']:.2f}")
        elif kind == "tool_error":
            r["notes"].append(f"tool error in {ev['tool']}: {ev['error']}")
        elif kind == "injection_flag":
            r["notes"].append(f"instruction-like text found in output of {ev['tool']} (risk {ev['risk']})")
        elif kind in ("approved", "rejected", "released", "closed"):
            who = ev.get("by", "?")
            why = f" ({ev['reason']})" if ev.get("reason") else ""
            r["notes"].append(f"{kind} by {who}{why}")
    out = ["# IntentGuard audit report", "",
           f"Audit log: {len(log.entries)} entries, hash chain "
           + ("intact." if ok else f"BROKEN at entry {bad}: the log was altered or truncated."), ""]
    if not order:
        out.append("No matching sessions.")
    for sid in order:
        r = sessions[sid]
        c = r["decisions"]
        out += [f"## Session {sid} (agent {r['agent']})", f"Task: {r['task'] or '(not recorded)'}",
                f"Calls: {sum(c.values())}  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())), ""]
        if r["stopped"]:
            out += ["Not allowed:"] + [f"  - {line}" for line in r["stopped"]] + [""]
        if r["notes"]:
            out += ["Events:"] + [f"  - {n}" for n in r["notes"]] + [""]
    return "\n".join(out).rstrip() + "\n"
