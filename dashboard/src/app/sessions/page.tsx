"use client";

import { useState } from "react";
import { Btn, ErrorBar, Kpi, Panel, RiskBar, StateBadge, when } from "@/components/ui";
import { COLOR, SessionRow, Verdict, post, usePoll } from "@/lib/api";

const CAP_LABEL: Record<string, string> = {
  network: "network off",
  shell: "shell off",
  files_locked: "files locked to project",
  db_needs_review: "database needs review",
};

function SessionCard({ s, refresh }: { s: SessionRow; refresh: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const act = async (verb: "release" | "close") => {
    if (verb === "close" && !window.confirm(`Close session ${s.session_id}? Every further call in it will be blocked.`)) return;
    setBusy(true);
    try {
      await post(`/sessions/${s.session_id}/${verb}`, { approver: "dashboard-user", reason });
      setReason("");
      refresh();
    } finally {
      setBusy(false);
    }
  };
  const canRelease = s.state === "restricted" || s.state === "quarantined";
  return (
    <Panel title={`${s.agent_id} · ${s.session_id}`} right={<StateBadge s={s.state} />}>
      <div className="space-y-3 p-4">
        <p className="text-[13px]">{s.task}</p>
        <div>
          <div className="mb-1.5 flex justify-between text-[12px] text-muted">
            <span>Risk</span>
            <span className="font-mono tabular-nums text-fg">{s.risk.toFixed(2)} / 1.00</span>
          </div>
          <RiskBar risk={s.risk} />
        </div>
        <div className="flex flex-wrap items-center gap-1.5 text-[12px]">
          {s.restricted.map((c) => (
            <span key={c} className="rounded-md bg-panel2 px-2 py-0.5 text-review">{CAP_LABEL[c] ?? c}</span>
          ))}
          {(s.taint === "CONFIDENTIAL" || s.taint === "SECRET") && (
            <span className="rounded-md bg-panel2 px-2 py-0.5 text-block">has read {s.taint.toLowerCase()} data</span>
          )}
          {(Object.entries(s.by_decision) as [Verdict, number][]).map(([v, n]) => (
            <span key={v} className="rounded-md bg-panel2 px-2 py-0.5 font-mono" style={{ color: COLOR[v] }}>{v} {n}</span>
          ))}
          <span className="ml-auto text-muted">
            {s.calls} calls{s.last_ts ? ` · last ${when(s.last_ts)}` : ""}
          </span>
        </div>
        {s.state !== "closed" && (
          <div className="flex flex-wrap items-center gap-2 border-t border-line pt-3">
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Reason (kept in the audit log)"
              aria-label="Reason"
              className="min-h-9 min-w-0 flex-1 rounded-lg border border-line bg-panel2 px-3 text-[13px] outline-none focus:border-accent"
            />
            {canRelease && <Btn tone="primary" onClick={() => !busy && act("release")}>Release lock-out</Btn>}
            <Btn tone="danger" onClick={() => !busy && act("close")}>Close session</Btn>
          </div>
        )}
        {canRelease && (
          <p className="text-[12px] text-muted">
            Releasing restores the switched-off capabilities and clears this session&apos;s risk. It keeps the record of
            sensitive data the session has already read, so an exposure is never forgotten.
          </p>
        )}
      </div>
    </Panel>
  );
}

export default function Sessions() {
  const { data, error, refresh } = usePoll<SessionRow[]>("/sessions", 2500);
  const count = (st: string) => data?.filter((s) => s.state === st).length ?? 0;
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-lg font-semibold tracking-tight">Sessions</h1>
      <ErrorBar msg={error} />
      <div className="grid grid-cols-3 gap-3">
        <Kpi label="Normal" value={count("normal")} color="var(--allow)" />
        <Kpi label="Restricted" value={count("restricted")} color="var(--review)" />
        <Kpi label="Quarantined" value={count("quarantined")} color="var(--quarantine)" />
      </div>
      {data?.length === 0 && (
        <Panel><p className="px-4 py-10 text-center text-muted">No sessions yet.</p></Panel>
      )}
      {data?.map((s) => <SessionCard key={s.session_id} s={s} refresh={refresh} />)}
    </div>
  );
}
