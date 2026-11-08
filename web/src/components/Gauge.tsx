"use client";

import { useState } from "react";
import { data } from "@/lib/data";
import { Tilt } from "./ui";

const CAPS: { key: string; name: string; note: string }[] = [
  { key: "network", name: "Outside network", note: "Calls to addresses outside the project" },
  { key: "shell", name: "Shell commands", note: "Running programs on the machine" },
  { key: "files_locked", name: "Files beyond the project", note: "Reading outside the task's folder" },
  { key: "db_needs_review", name: "Database queries without approval", note: "Queries run without asking a person" },
  { key: "quarantine", name: "The session itself", note: "Whether the agent can act at all" },
];

const CX = 160;
const CY = 165;
const R = 118;
const START = 150;
const SWEEP = 240;
const pt = (deg: number, r = R) => [CX + r * Math.cos((deg * Math.PI) / 180), CY + r * Math.sin((deg * Math.PI) / 180)] as const;
function arc(v0: number, v1: number, r = R) {
  const [x0, y0] = pt(START + v0 * SWEEP, r);
  const [x1, y1] = pt(START + v1 * SWEEP, r);
  return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${(v1 - v0) * SWEEP > 180 ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

export default function Gauge() {
  const [risk, setRisk] = useState(0);
  const th: Record<string, number> = {};
  data.ladder.forEach((r) => (th[r.off] = r.at));
  const v = Math.max(0, Math.min(1, risk));
  const angle = START + v * SWEEP;
  const mood = v >= 1 ? "Session frozen. A person has to look." : v >= 0.8 ? "Alarmed. Almost everything needs approval." : v >= 0.6 ? "Worried. Shell and files are shut." : v >= 0.4 ? "Wary. The outside network is off." : "Calm. Everything is open.";
  const zone = v >= 0.8 ? "var(--red)" : v >= 0.4 ? "var(--amber)" : "var(--accent)";

  return (
    <div className="gauge-grid">
      <Tilt max={3}>
        <div className="panel pad dial">
          <svg viewBox="0 0 320 322" role="img" aria-label={`Session risk gauge reading ${v.toFixed(2)}`}>
            <defs>
              <radialGradient id="face" cx="50%" cy="45%" r="70%">
                <stop offset="0" stopColor="#1a2230" />
                <stop offset="1" stopColor="#0a0e15" />
              </radialGradient>
              <filter id="needleShadow" x="-20%" y="-20%" width="140%" height="140%"><feDropShadow dx="0" dy="3" stdDeviation="3" floodOpacity=".6" /></filter>
            </defs>
            <circle cx={CX} cy={CY} r="146" fill="url(#face)" stroke="rgba(255,255,255,.22)" strokeWidth="2" />
            <circle cx={CX} cy={CY} r="138" fill="none" stroke="rgba(0,0,0,.6)" strokeWidth="2" />
            <path d={arc(0, 0.4)} stroke="var(--accent)" strokeWidth="12" fill="none" opacity=".85" />
            <path d={arc(0.4, 0.8)} stroke="var(--amber)" strokeWidth="12" fill="none" opacity=".85" />
            <path d={arc(0.8, 1)} stroke="var(--red)" strokeWidth="12" fill="none" opacity=".9" />
            {Array.from({ length: 21 }, (_, i) => {
              const f = i / 20;
              const [x0, y0] = pt(START + f * SWEEP, R - 12);
              const [x1, y1] = pt(START + f * SWEEP, R - (i % 5 === 0 ? 28 : 20));
              return <line key={i} x1={x0} y1={y0} x2={x1} y2={y1} stroke="rgba(255,255,255,.7)" strokeWidth={i % 5 === 0 ? 2.2 : 1} />;
            })}
            {[0, 0.2, 0.4, 0.6, 0.8, 1].map((f) => {
              const [x, y] = pt(START + f * SWEEP, R - 46);
              return <text key={f} x={x} y={y + 4} textAnchor="middle" fontSize="12" fill="rgba(255,255,255,.75)" fontFamily="var(--mono)">{f.toFixed(1)}</text>;
            })}
            <text x={CX} y={CY + 52} textAnchor="middle" fontSize="11" letterSpacing="2" fill="rgba(255,255,255,.5)" fontFamily="var(--mono)">SESSION RISK</text>
            <text x={CX} y={CY + 80} textAnchor="middle" fontSize="26" fontWeight="650" fill={zone} fontFamily="var(--mono)">{v.toFixed(2)}</text>
            <g className="needle" style={{ transform: `rotate(${angle}deg)` }} filter="url(#needleShadow)">
              <polygon points={`${CX - 14},${CY - 3} ${CX + 98},${CY} ${CX - 14},${CY + 3}`} fill="#ff5a4f" />
              <circle cx={CX} cy={CY} r="9" fill="#cfd6e2" stroke="#0a0e15" strokeWidth="3" />
            </g>
          </svg>
          <p style={{ font: "600 18px var(--sans)", textAlign: "center", marginTop: 4 }} data-testid="mood">{mood}</p>
          <div className="range">
            <label htmlFor="risk" className="small muted">Drag, or add suspicious steps one at a time</label>
            <input id="risk" type="range" min={0} max={1} step={0.05} value={v} onChange={(e) => setRisk(parseFloat(e.target.value))} />
            <div className="row" style={{ justifyContent: "center" }}>
              <button type="button" className="btn danger sm" onClick={() => setRisk(Math.min(1, v + 0.25))} data-testid="odd">A suspicious step (+0.25)</button>
              <button type="button" className="btn sm" onClick={() => setRisk(0)}>Reset</button>
            </div>
          </div>
        </div>
      </Tilt>

      <div className="panel pad">
        <h3>What the session may still do</h3>
        <p className="muted small" style={{ marginTop: 6 }}>Thresholds come from the engine&rsquo;s own default settings. Each switch flips when risk reaches it.</p>
        <div className="caps" style={{ marginTop: 10 }}>
          {CAPS.map((c) => {
            const on = v < th[c.key] - 1e-9;
            return (
              <div className="cap" key={c.key}>
                <div>
                  <b>{c.name}</b>
                  <small>{c.note} &middot; closes at risk {th[c.key].toFixed(1)}</small>
                </div>
                <div className="row" style={{ flexWrap: "nowrap" }}>
                  <span className={`state ${on ? "on" : "offc"}`}>{on ? "On" : "Off"}</span>
                  <span className={`switch ${on ? "" : "off"}`} role="img" aria-label={`${c.name}: ${on ? "on" : "off"}`} data-testid={`cap-${c.key}`} data-on={on} />
                </div>
              </div>
            );
          })}
        </div>
        <p className="small muted" style={{ marginTop: 14 }}>In the real engine, risk is also carried over, decayed, to a new session of the same agent, so starting over does not wipe the slate. The reset button is for the demo.</p>
      </div>
    </div>
  );
}
