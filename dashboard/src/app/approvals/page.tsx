"use client";

import { Badge, Btn, ErrorBar, Panel, brief } from "@/components/ui";
import { Event, post, usePoll } from "@/lib/api";

export default function Approvals() {
  const { data, error, refresh } = usePoll<Event[]>("/pending");
  const act = async (id: string, verb: "approve" | "reject") => {
    await post(`/pending/${id}/${verb}`, { approver: "dashboard-user" });
    refresh();
  };
  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <h1 className="text-lg font-semibold tracking-tight">Approval centre</h1>
      <ErrorBar msg={error} />
      {data?.length === 0 && (
        <Panel><p className="px-4 py-10 text-center text-muted">Nothing waiting for review.</p></Panel>
      )}
      {data?.map((e) => (
        <Panel key={e.decision.action_id} title={`${e.agent} · ${e.session}`} right={<Badge v={e.decision.decision} />}>
          <div className="space-y-3 p-4">
            <p>
              Requested: <span className="font-mono text-[13px]">{e.tool}</span>{" "}
              <span className="text-muted">{brief(e.args)}</span>
            </p>
            <div>
              <div className="mb-1.5 text-[12px] font-medium text-muted">Why this was flagged</div>
              <ul className="space-y-1.5">
                {e.decision.evidence.map((ev) => (
                  <li key={ev.rule_id} className="rounded-lg bg-panel2 px-3 py-2">
                    <span className="mr-2 font-mono text-[11px] text-muted">{ev.rule_id}</span>
                    {ev.message}
                    {ev.observed && <span className="ml-1 font-mono text-[12px] text-muted">({ev.observed})</span>}
                  </li>
                ))}
              </ul>
            </div>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[12px] text-muted">
                Risk {e.decision.risk_score.toFixed(2)} · recommended: <b className="text-fg">{e.decision.recommended}</b>
              </span>
              <div className="flex gap-2">
                <Btn tone="danger" onClick={() => act(e.decision.action_id, "reject")}>Reject</Btn>
                <Btn tone="primary" onClick={() => act(e.decision.action_id, "approve")}>Approve</Btn>
              </div>
            </div>
          </div>
        </Panel>
      ))}
    </div>
  );
}
