"use client";

import { useMemo, useState } from "react";
import { data, type ChainEntry } from "@/lib/data";
import { GENESIS, sha256 } from "@/lib/sha256";

function label(payload: string): string {
  try {
    const o = JSON.parse(payload) as { event?: string; tool?: string; decision?: string };
    return [o.event, o.tool, o.decision].filter(Boolean).join(" ");
  } catch {
    return "edited entry";
  }
}

/** Same check as AuditLog.verify in src/intentguard/audit.py. Returns the first bad index, or -1. */
function firstBad(entries: ChainEntry[]): number {
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i || e.prev_hash !== prev || e.entry_hash !== sha256(prev + e.payload)) return i;
    prev = e.entry_hash;
  }
  return -1;
}

export default function Ledger() {
  const [entries, setEntries] = useState<ChainEntry[]>(() => data.chain.map((e) => ({ ...e })));
  const bad = useMemo(() => firstBad(entries), [entries]);

  return (
    <div>
      <div className="verdictbar">
        <p className={`vmsg ${bad < 0 ? "ok" : "bad"}`} role="status" data-testid="chainmsg">
          {bad < 0
            ? "Chain intact: every block matches the one before it."
            : `Tampering detected at block #${bad}. Everything after it can no longer be trusted. This is the same check as the verify-audit command.`}
        </p>
        <button type="button" className="btn" onClick={() => setEntries(data.chain.map((e) => ({ ...e })))} data-testid="repair">Repair</button>
      </div>
      <div className="ledger" aria-label="Audit log blocks" tabIndex={0}>
        {entries.map((e, i) => (
          <div key={`${e.seq}-${i}`} className={`blk ${bad < 0 ? "ok" : i === bad ? "bad" : i > bad ? "after" : "ok"}`} data-testid="blk">
            <span className="seq">#{e.seq}</span>
            <span className="lab">{label(e.payload)}</span>
            <code>{e.payload.length > 96 ? e.payload.slice(0, 96) + "…" : e.payload}</code>
            <span className="lab">prev</span>
            <code>{e.prev_hash.slice(0, 20)}&hellip;</code>
            <span className="lab">hash</span>
            <code>{e.entry_hash.slice(0, 20)}&hellip;</code>
            <div className="row" style={{ marginTop: 6 }}>
              <button type="button" className="btn sm" onClick={() => setEntries(entries.map((x, j) => (j === i ? { ...x, payload: x.payload + " " } : x)))}>Edit</button>
              <button type="button" className="btn sm" onClick={() => setEntries(entries.filter((_, j) => j !== i))}>Delete</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
