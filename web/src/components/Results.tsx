"use client";

import { useEffect, useState } from "react";
import { data } from "@/lib/data";

const ORDER = ["unprotected", "static_rbac", "keyword_guardrail_standin", "privilege_rules_standin", "task_alignment_standin", "intentguard_full"];
const pct = (s: string) => {
  const m = /^([\d.]+)%/.exec(s);
  return m ? parseFloat(m[1]) : 0;
};

export default function Results() {
  const [idx, setIdx] = useState(2);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const t = requestAnimationFrame(() => requestAnimationFrame(() => setReady(true)));
    return () => cancelAnimationFrame(t);
  }, [idx]);
  const set = data.sets[idx];
  const res = data.results.sets[set.id];

  return (
    <div>
      <div className="tabs" role="group" aria-label="Choose an attack set">
        {data.sets.map((s, i) => (
          <button key={s.id} type="button" aria-pressed={i === idx} onClick={() => { setReady(false); setIdx(i); }}>{s.label}</button>
        ))}
      </div>
      <p className="small muted" style={{ marginTop: 14 }}>{res?.counts.replace(/[{}']/g, "")}</p>
      <div className="panel tablewrap">
        <table>
          <caption className="sr">Harmful steps that run, and the cost to legitimate work, per system on the chosen set</caption>
          <thead>
            <tr>
              <th scope="col">System</th>
              <th scope="col">Harmful steps that run (lower is better)</th>
              <th scope="col">Legitimate steps blocked</th>
              <th scope="col">Legitimate tasks finished untouched</th>
            </tr>
          </thead>
          <tbody data-testid="restable">
            {ORDER.map((k) => {
              const r = res?.rows[k];
              if (!r) return null;
              return (
                <tr key={k} className={k === "intentguard_full" ? "me" : ""}>
                  <th scope="row">{data.labels[k]}</th>
                  <td>
                    <div className="asr">
                      <span className="track"><i style={{ width: ready ? `${pct(r.asr)}%` : 0 }} /></span>
                      <span className="num">{r.asr.split(" ")[0]}</span>
                    </div>
                  </td>
                  <td className="num">{r.fpr.split(" ")[0]}</td>
                  <td className="num">{r.completion}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
