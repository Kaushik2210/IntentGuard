"use client";

import { useCallback, useEffect, useState } from "react";

export const API = process.env.NEXT_PUBLIC_API ?? "http://localhost:8000";

// Local demo only: NEXT_PUBLIC_* values are visible in the browser bundle. Do not use a real secret.
const TOKEN = process.env.NEXT_PUBLIC_ADMIN_TOKEN;
export const authHeaders = (): Record<string, string> => (TOKEN ? { Authorization: `Bearer ${TOKEN}` } : {});

export type Verdict = "ALLOW" | "REVIEW" | "BLOCK" | "QUARANTINE";

export interface Evidence {
  rule_id: string;
  message: string;
  observed: string;
  expected: string;
}

export interface Decision {
  action_id: string;
  decision: Verdict;
  risk_score: number;
  fired_rules: string[];
  evidence: Evidence[];
  explanation: string;
  recommended: string;
  capabilities_after: { network: boolean; shell: boolean; files_locked: boolean; db_needs_review: boolean };
  latency_ms: number;
}

export interface Event {
  ts: number;
  session: string;
  agent: string;
  tool: string;
  args: Record<string, unknown>;
  decision: Decision;
}

export type SessionState = "normal" | "restricted" | "quarantined" | "closed";

export interface SessionRow {
  session_id: string;
  agent_id: string;
  task: string;
  state: SessionState;
  risk: number;
  restricted: string[];
  taint: string;
  tags: string[];
  denied: number;
  calls: number;
  last_ts: number | null;
  by_decision: Partial<Record<Verdict, number>>;
}

export interface Stats {
  inspected: number;
  by_decision: Partial<Record<Verdict, number>>;
  pending: number;
  sessions: number;
}

export async function post(path: string, body?: unknown) {
  const r = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...authHeaders() },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

/** Poll a GET endpoint. Returns data, error, and a manual refresh. */
export function usePoll<T>(path: string, ms = 2000) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = useCallback(async () => {
    try {
      const r = await fetch(`${API}${path}`, { cache: "no-store", headers: authHeaders() });
      if (!r.ok) throw new Error(`${r.status}`);
      setData(await r.json());
      setError(null);
    } catch {
      setError(`Cannot reach IntentGuard API at ${API}`);
    }
  }, [path]);
  useEffect(() => {
    load();
    const t = setInterval(load, ms);
    return () => clearInterval(t);
  }, [load, ms]);
  return { data, error, refresh: load };
}

export const COLOR: Record<Verdict, string> = {
  ALLOW: "var(--allow)",
  REVIEW: "var(--review)",
  BLOCK: "var(--block)",
  QUARANTINE: "var(--quarantine)",
};
