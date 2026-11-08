"use client";

import { useEffect, useState } from "react";
import { callText, data, STAGES, stageOf, VERDICT_WORD, type Step } from "@/lib/data";
import { Tilt, VerdictPill, Window } from "./ui";

const KIND = { attack: "Attack", normal: "Normal work", limit: "Known miss" } as const;

function Pipeline({ step }: { step: Step | null }) {
  const hit = new Set<number>();
  if (step) step.rules.forEach((r) => hit.add(stageOf(r.id)));
  return (
    <ol className="pipeline" aria-label="Which of the six checks fired for the selected call" style={{ listStyle: "none", padding: 0 }}>
      {STAGES.map((s, i) => {
        const cls = !step ? "" : hit.has(i) ? `hit-${step.verdict}` : "ok";
        return (
          <li key={s.id} className={`stage ${cls}`}>
            <span className="node">{i + 1}</span>
            <b>{s.name}</b>
            <small>{hit.has(i) && step ? step.rules.filter((r) => stageOf(r.id) === i).map((r) => r.id).join(" ") : s.q}</small>
          </li>
        );
      })}
    </ol>
  );
}

export default function Replay() {
  const [cur, setCur] = useState(0);
  const [shown, setShown] = useState(0);
  const [sel, setSel] = useState(-1);
  const [say, setSay] = useState("");
  const sc = data.scenarios[cur];
  const done = shown >= sc.steps.length;

  useEffect(() => {
    if (shown > 0) {
      const s = sc.steps[shown - 1];
      setSay(`Call ${shown}: ${VERDICT_WORD[s.verdict]}.`);
    }
  }, [shown, sc]);

  const pick = (i: number) => {
    setCur(i);
    setShown(0);
    setSel(-1);
  };
  const advance = (to: number) => {
    setShown(to);
    setSel(to - 1);
  };
  const stepShown = sel >= 0 && sel < shown ? sc.steps[sel] : null;
  const stopped = sc.steps.some((s) => !s.ran);
  const hard = sc.steps.some((s) => s.verdict === "BLOCK" || s.verdict === "QUARANTINE");
  const closing =
    sc.kind === "limit"
      ? "This one gets through. It is a documented limit, not an oversight in the demo."
      : sc.kind === "normal"
        ? "Every call ran. Nothing here was slowed down."
        : sc.id === "split"
          ? "The first short piece left before the pattern was visible. The second call exposed it, and the session was then frozen."
          : hard
            ? "The harmful call was stopped before it ran."
            : stopped
              ? "The call was held for a person to approve. It did not run, and nothing leaves until someone says yes."
              : "";

  return (
    <div className="replay">
      <ul className="scn" aria-label="Situations">
        {data.scenarios.map((s, i) => (
          <li key={s.id}>
            <button type="button" aria-pressed={i === cur} onClick={() => pick(i)} data-testid={`scn-${s.id}`}>
              <span className={`tag ${s.kind}`}>{KIND[s.kind]}</span>
              <span className="t">{s.title}</span>
            </button>
          </li>
        ))}
      </ul>

      <Tilt max={2}>
        <Window title={`session site-${sc.id} · agent demo-agent`}>
          <div className="win-body" data-testid="console">
            <h3>{sc.title}</h3>
            <p className="muted" style={{ margin: "6px 0 16px" }}>{sc.blurb}</p>
            <div className="task">
              <span>What the user asked</span>
              {sc.task}
            </div>
            <div className="controls">
              <button type="button" className="btn primary" disabled={done} onClick={() => advance(shown + 1)} data-testid="next">
                {done ? "All calls run" : "Run next call"}
              </button>
              <button type="button" className="btn" disabled={done} onClick={() => advance(sc.steps.length)} data-testid="runall">Run all</button>
              <button type="button" className="btn" disabled={shown === 0} onClick={() => { setShown(0); setSel(-1); }}>Reset</button>
            </div>

            <Pipeline step={stepShown} />

            {shown === 0 ? (
              <div className="empty">The agent is about to call <span className="mono">{sc.steps[0].tool}</span>. Nothing has run yet.</div>
            ) : (
              <ol className="log">
                {sc.steps.slice(0, shown).map((s, i) => (
                  <li key={i}>
                    <button type="button" className={`entry ${s.verdict}`} aria-current={i === sel} onClick={() => setSel(i)}>
                      <span className="call">{i + 1}. {callText(s)}</span>
                      <span className="row">
                        <VerdictPill v={s.verdict} />
                        <span className="ran">{s.ran ? (s.sent ? "The email was sent." : "The tool ran.") : "The tool did not run."}</span>
                      </span>
                      {s.returned && <span className="ran">It returned: &ldquo;{s.returned.replace(/\n/g, " / ")}&rdquo;</span>}
                      {s.rules.length > 0 && (
                        <ul className="rules">
                          {s.rules.map((r) => (
                            <li key={r.id}><code>{r.id}</code>{r.text}</li>
                          ))}
                        </ul>
                      )}
                      <span className="meter">
                        <span>session risk {s.risk.toFixed(2)}</span>
                        <span className="bar" aria-hidden="true"><i style={{ width: `${Math.min(100, s.risk * 100)}%` }} /></span>
                      </span>
                    </button>
                  </li>
                ))}
              </ol>
            )}
            {done && closing && <p className="note">{closing}</p>}
            <div className="sr" role="status" aria-live="polite">{say}</div>
          </div>
        </Window>
      </Tilt>
    </div>
  );
}
