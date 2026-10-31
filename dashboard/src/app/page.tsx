"use client";

import { useMemo } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Badge, Btn, ErrorBar, Kpi, Panel, brief, when } from "@/components/ui";
import { COLOR, Event, Stats, Verdict, post, usePoll } from "@/lib/api";

const ORDER: Verdict[] = ["ALLOW", "REVIEW", "BLOCK", "QUARANTINE"];

export default function Overview() {
  const stats = usePoll<Stats>("/stats");
  const ev = usePoll<Event[]>("/events?limit=200");
  const events = useMemo(() => ev.data ?? [], [ev.data]);

  const byAgent = useMemo(() => {
    const m = new Map<string, Record<string, number | string>>();
    for (const e of events) {
      const row = m.get(e.agent) ?? { agent: e.agent };
      row[e.decision.decision] = ((row[e.decision.decision] as number) ?? 0) + 1;
      m.set(e.agent, row);
    }
    return [...m.values()];
  }, [events]);

  const sessions = useMemo(() => {
    const m = new Map<string, Event>();
    for (const e of [...events].reverse()) m.set(e.session, e); // last event wins
    return [...m.values()];
  }, [events]);

  const d = stats.data?.by_decision ?? {};
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold tracking-tight">Security Centre</h1>
        <Btn tone="primary" onClick={async () => { await post("/demo/seed"); stats.refresh(); ev.refresh(); }}>
          Load sample scenarios
        </Btn>
      </div>
      <ErrorBar msg={stats.error ?? ev.error} />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        <Kpi label="Actions inspected" value={stats.data?.inspected ?? 0} />
        <Kpi label="Allowed" value={d.ALLOW ?? 0} color="var(--allow)" />
        <Kpi label="Blocked" value={(d.BLOCK ?? 0) + (d.QUARANTINE ?? 0)} color="var(--block)" />
        <Kpi label="Pending approval" value={stats.data?.pending ?? 0} color="var(--review)" />
        <Kpi label="Sessions" value={stats.data?.sessions ?? 0} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Decisions by agent">
          <div className="h-64 p-3">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={byAgent}>
                <CartesianGrid stroke="var(--line)" vertical={false} />
                <XAxis dataKey="agent" stroke="var(--muted)" tickLine={false} fontSize={12} />
                <YAxis stroke="var(--muted)" tickLine={false} axisLine={false} allowDecimals={false} fontSize={12} />
                <Tooltip contentStyle={{ background: "var(--panel-2)", border: "1px solid var(--line)", borderRadius: 8 }} cursor={{ fill: "var(--panel-2)" }} />
                <Legend />
                {ORDER.map((v) => (
                  <Bar key={v} dataKey={v} stackId="a" fill={COLOR[v]} isAnimationActive={false} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>

        <Panel title="Session risk and permissions">
          <ul className="divide-y divide-line">
            {sessions.length === 0 && <li className="px-4 py-6 text-muted">No sessions yet.</li>}
            {sessions.slice(0, 8).map((e) => {
              const c = e.decision.capabilities_after;
              const r = e.decision.risk_score;
              return (
                <li key={e.session} className="px-4 py-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-[12px]">{e.session}</span>
                    <span className="font-mono text-[12px] tabular-nums">{r.toFixed(2)}</span>
                  </div>
                  <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-panel2">
                    <div className="h-full rounded-full" style={{ width: `${Math.min(100, r * 100)}%`, background: r >= 0.8 ? COLOR.BLOCK : r >= 0.4 ? COLOR.REVIEW : COLOR.ALLOW }} />
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1.5 text-[11px] text-muted">
                    {!c.network && <span className="rounded bg-panel2 px-1.5 py-0.5">network off</span>}
                    {!c.shell && <span className="rounded bg-panel2 px-1.5 py-0.5">shell off</span>}
                    {c.files_locked && <span className="rounded bg-panel2 px-1.5 py-0.5">files locked</span>}
                    {c.db_needs_review && <span className="rounded bg-panel2 px-1.5 py-0.5">db needs approval</span>}
                    {c.network && c.shell && !c.files_locked && !c.db_needs_review && <span>full session permissions</span>}
                  </div>
                </li>
              );
            })}
          </ul>
        </Panel>
      </div>

      <Panel title="Recent security events">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-[13px]">
            <thead className="text-[12px] text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Agent</th>
                <th className="px-4 py-2 font-medium">Action</th>
                <th className="px-4 py-2 font-medium">Decision</th>
                <th className="px-4 py-2 font-medium">Rules</th>
              </tr>
            </thead>
            <tbody>
              {events.slice(0, 25).map((e) => (
                <tr key={e.decision.action_id} className="border-t border-line">
                  <td className="px-4 py-2 font-mono text-[12px] text-muted">{when(e.ts)}</td>
                  <td className="px-4 py-2">{e.agent}</td>
                  <td className="px-4 py-2"><span className="font-mono text-[12px]">{e.tool}</span> <span className="text-muted">{brief(e.args)}</span></td>
                  <td className="px-4 py-2"><Badge v={e.decision.decision} /></td>
                  <td className="px-4 py-2 font-mono text-[11px] text-muted">{e.decision.fired_rules.join(" ") || "-"}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-muted">No events yet. Load sample scenarios to see decisions.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
