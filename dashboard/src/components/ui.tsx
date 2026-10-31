"use client";

import { COLOR, Verdict } from "@/lib/api";

export function Badge({ v }: { v: Verdict }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 font-mono text-[11px] font-medium"
      style={{ color: COLOR[v], background: `color-mix(in srgb, ${COLOR[v]} 14%, transparent)` }}
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: COLOR[v] }} />
      {v}
    </span>
  );
}

export function Panel({ title, children, right }: { title?: string; children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-line bg-panel">
      {title && (
        <header className="flex items-center justify-between border-b border-line px-4 py-3">
          <h2 className="text-[13px] font-medium text-muted">{title}</h2>
          {right}
        </header>
      )}
      {children}
    </section>
  );
}

export function Kpi({ label, value, color }: { label: string; value: number | string; color?: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3">
      <div className="text-[12px] text-muted">{label}</div>
      <div className="mt-1 font-mono text-2xl font-semibold tabular-nums" style={{ color }}>
        {value}
      </div>
    </div>
  );
}

export function Btn({ children, onClick, tone = "default" }: { children: React.ReactNode; onClick: () => void; tone?: "default" | "primary" | "danger" }) {
  const cls = {
    default: "border-line bg-panel2 hover:brightness-125",
    primary: "border-transparent bg-accent text-black hover:brightness-110",
    danger: "border-line bg-panel2 text-block hover:brightness-125",
  }[tone];
  return (
    <button onClick={onClick} className={`min-h-9 rounded-lg border px-3 text-[13px] font-medium transition ${cls}`}>
      {children}
    </button>
  );
}

export function ErrorBar({ msg }: { msg: string | null }) {
  if (!msg) return null;
  return (
    <div role="alert" className="mb-4 rounded-lg border border-line bg-panel px-4 py-3 text-[13px] text-review">
      {msg}. Start it with{" "}
      <code className="font-mono">uvicorn intentguard.service.app:demo_app --factory</code>.
    </div>
  );
}

export const when = (ts: number) => new Date(ts * 1000).toLocaleTimeString();
export const brief = (a: Record<string, unknown>) =>
  Object.values(a).map((x) => String(x)).join(" · ").slice(0, 80);
