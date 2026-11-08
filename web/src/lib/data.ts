import raw from "@/data/site-data.json";

export type Verdict = "ALLOW" | "REVIEW" | "BLOCK" | "QUARANTINE";

export interface Step {
  tool: string;
  args: Record<string, string>;
  verdict: Verdict;
  risk: number;
  ran: boolean;
  sent: boolean;
  returned: string | null;
  why: string;
  rules: { id: string; text: string }[];
}

export interface Scenario {
  id: string;
  kind: "attack" | "normal" | "limit";
  title: string;
  blurb: string;
  task: string;
  steps: Step[];
}

export interface ChainEntry {
  seq: number;
  prev_hash: string;
  payload: string;
  entry_hash: string;
}

export interface ResultRow {
  asr: string;
  fpr: string;
  friction: string;
  completion: string;
}

export interface SiteData {
  repo: string;
  build: string;
  scenarios: Scenario[];
  ladder: { at: number; off: string }[];
  labels: Record<string, string>;
  sets: { id: string; label: string }[];
  results: { commit: string; sets: Record<string, { counts: string; rows: Record<string, ResultRow> }> };
  rules: Record<string, string>;
  chain: ChainEntry[];
  vault: { path: string; text: string };
}

export const data = raw as unknown as SiteData;

export const VERDICT_WORD: Record<Verdict, string> = {
  ALLOW: "Allowed",
  REVIEW: "Needs a person",
  BLOCK: "Blocked",
  QUARANTINE: "Session frozen",
};

/** The six checks, in the order the engine applies them. */
export const STAGES = [
  { id: "task", name: "Task", q: "Did they ask for this?" },
  { id: "data", name: "Data", q: "How sensitive is it?" },
  { id: "dest", name: "Destination", q: "Who receives it?" },
  { id: "lineage", name: "Lineage", q: "Where did it come from?" },
  { id: "session", name: "Session", q: "How has this run gone?" },
  { id: "record", name: "Record", q: "Written to the audit log." },
] as const;

/** Which check a rule belongs to. */
export function stageOf(ruleId: string): number {
  if (ruleId === "SCOPE-003" || ruleId === "SCOPE-005" || ruleId === "SCOPE-004") return 1;
  if (ruleId.startsWith("SCOPE") || ruleId.startsWith("PERM")) return 0;
  if (ruleId.startsWith("EGRESS")) return 2;
  if (ruleId.startsWith("TAINT")) return 3;
  return 4; // SEQ, RISK, EXEC
}

export function callText(s: Step): string {
  const parts = Object.keys(s.args).map((k) => `${k}=${JSON.stringify(s.args[k])}`);
  return `${s.tool}(${parts.join(", ")})`;
}

export function shortCall(s: Step): string {
  const a = s.args as Record<string, string | undefined>;
  const t = a.to || a.path || a.url || a.sql || a.cmd || "";
  return s.tool + (t ? ` → ${t.length > 26 ? t.slice(0, 25) + "…" : t}` : "");
}

export function allSteps(): Step[] {
  return data.scenarios.flatMap((sc) => sc.steps);
}
