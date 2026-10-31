"use client";

import { useState } from "react";
import { Btn, ErrorBar, Panel } from "@/components/ui";
import { API, authHeaders, usePoll } from "@/lib/api";

interface Entry {
  seq: number;
  entry_hash: string;
  prev_hash: string;
  payload: Record<string, unknown>;
}
const PAGE = 25;

export default function Audit() {
  const [page, setPage] = useState(0);
  const [verify, setVerify] = useState<string | null>(null);
  const { data, error } = usePoll<{ total: number; entries: Entry[] }>(`/audit?offset=${page * PAGE}&limit=${PAGE}`, 4000);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE));
  const check = async () => {
    const r = await (await fetch(`${API}/audit/verify`, { headers: authHeaders() })).json();
    setVerify(r.ok ? "Chain intact: no entry has been edited, reordered or removed." : `Chain broken at entry ${r.first_bad_seq}.`);
  };
  return (
    <div className="mx-auto max-w-6xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-lg font-semibold tracking-tight">Audit log</h1>
        <Btn onClick={check}>Verify hash chain</Btn>
      </div>
      <ErrorBar msg={error} />
      {verify && <div role="status" className="rounded-lg border border-line bg-panel px-4 py-3 text-[13px]">{verify}</div>}
      <Panel title={`${data?.total ?? 0} entries`} right={
        <div className="flex items-center gap-2 text-[12px] text-muted">
          <Btn onClick={() => setPage((p) => Math.max(0, p - 1))}>Prev</Btn>
          {page + 1} / {pages}
          <Btn onClick={() => setPage((p) => Math.min(pages - 1, p + 1))}>Next</Btn>
        </div>
      }>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-[12px]">
            <thead className="text-muted">
              <tr><th className="px-4 py-2 font-medium">#</th><th className="px-4 py-2 font-medium">Event</th><th className="px-4 py-2 font-medium">Detail</th><th className="px-4 py-2 font-medium">Hash</th></tr>
            </thead>
            <tbody className="font-mono">
              {data?.entries.map((e) => (
                <tr key={e.seq} className="border-t border-line align-top">
                  <td className="px-4 py-2 text-muted">{e.seq}</td>
                  <td className="px-4 py-2">{String(e.payload.event)}</td>
                  <td className="px-4 py-2 text-muted">
                    {e.payload.event === "action"
                      ? `${e.payload.tool} ${e.payload.resource ?? e.payload.destination ?? ""} → ${e.payload.decision} [${(e.payload.rules as string[]).join(" ")}]`
                      : JSON.stringify(e.payload)}
                  </td>
                  <td className="px-4 py-2 text-muted" title={e.entry_hash}>{e.entry_hash.slice(0, 12)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}
