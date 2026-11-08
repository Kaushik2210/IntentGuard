/* A TypeScript port of the engine's content-lineage check (TAINT-002), for the compose playground on the showcase site
   only. The replay and the audit ledger use real engine output; this re-implements one rule so a visitor can poke at it.
   tests/test_site.py runs this file under node against the Python engine on a list of strings and fails if they
   disagree. Not ported: the secret-pattern rule, the session buffer across several sends, and multi-send splitting.
   Keep to erasable TypeScript (no enums or parameter properties) so node can run it directly. */

const K = 12;
const MIN_NUMBER = 10000;

const UNITS: Record<string, number> = {};
"zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen"
  .split(" ")
  .forEach((w, i) => {
    UNITS[w] = i;
  });
const TENS: Record<string, number> = {};
"twenty thirty forty fifty sixty seventy eighty ninety".split(" ").forEach((w, i) => {
  TENS[w] = (i + 2) * 10;
});
const SCALES: Record<string, number> = { hundred: 100, thousand: 1000, million: 1000000, billion: 1000000000 };

function norm(t: string): string {
  return t.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function numbers(input: string): number[] {
  const text = input.slice(0, 20000).toLowerCase();
  const found: Record<number, boolean> = {};
  let m: RegExpExecArray | null;
  const flat = text.replace(/(\d),(?=\d{3}(?!\d))/g, "$1");
  let re = /(^|[^\d.])(\d{5,})(?![\d.]*\d)/g;
  while ((m = re.exec(flat))) found[parseInt(m[2], 10)] = true;
  re = /(^|[^\w.])(\d+(?:\.\d+)?)\s?([km])\b/g;
  while ((m = re.exec(flat))) found[Math.floor(parseFloat(m[2]) * (m[3] === "k" ? 1000 : 1000000))] = true;
  re = /(^|[^\w.])(\d+(?:\.\d+)?)\s(thousand|million|billion)\b/g;
  while ((m = re.exec(flat))) found[Math.floor(parseFloat(m[2]) * SCALES[m[3]])] = true;
  let total = 0;
  let current = 0;
  let started = false;
  const found2: string[] = text.replace(/-/g, " ").match(/[a-z]+/g) ?? [];
  const words: string[] = found2.concat([""]);
  for (const w of words) {
    if (w in UNITS || w in TENS || w in SCALES) {
      started = true;
      if (w in UNITS) current += UNITS[w];
      else if (w in TENS) current += TENS[w];
      else if (w === "hundred") current = Math.max(current, 1) * 100;
      else {
        total += Math.max(current, 1) * SCALES[w];
        current = 0;
      }
    } else if (w === "and" && started) {
      continue;
    } else {
      if (started && total + current >= MIN_NUMBER) found[total + current] = true;
      total = current = 0;
      started = false;
    }
  }
  return Object.keys(found).map(Number);
}

export function leet(text: string): string[] {
  if (!/[43571@$0]/.test(text)) return [];
  const base = text
    .replace(/4/g, "a")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
  const out: string[] = [];
  for (const one of ["i", "l", "1"]) for (const zero of ["o", "0"]) out.push(base.replace(/1/g, one).replace(/0/g, zero));
  return out;
}

function rot13(t: string): string {
  return t.replace(/[a-zA-Z]/g, (c) => {
    const b = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - b + 13) % 26) + b);
  });
}

function unquote(t: string): string {
  return t.replace(/(?:%[0-9a-fA-F]{2})+/g, (s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return s;
    }
  });
}

function utf8(bytes: number[]): string {
  try {
    return new TextDecoder("utf-8").decode(Uint8Array.from(bytes)).replace(/�/g, "");
  } catch {
    return "";
  }
}

function b64(input: string): string {
  try {
    const s = input + "=".repeat((4 - (input.length % 4)) % 4);
    const bin = atob(s);
    const a: number[] = [];
    for (let i = 0; i < bin.length; i++) a.push(bin.charCodeAt(i));
    return utf8(a);
  } catch {
    return "";
  }
}

function b32(input: string): string {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const s = input.toUpperCase().replace(/=+$/, "");
  let bits = "";
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const v = A.indexOf(s[i]);
    if (v < 0) return "";
    bits += ("00000" + v.toString(2)).slice(-5);
  }
  for (let j = 0; j + 8 <= bits.length; j += 8) out.push(parseInt(bits.slice(j, j + 8), 2));
  return utf8(out);
}

function hex(input: string): string {
  const s = input.replace(/\s/g, "");
  if (s.length % 2) return "";
  const a: number[] = [];
  for (let i = 0; i < s.length; i += 2) a.push(parseInt(s.slice(i, i + 2), 16));
  return utf8(a);
}

export function decodings(text: string, depth = 2): string[] {
  let views = [text];
  if (depth < 1) return views;
  const nxt = [rot13(text), text.split("").reverse().join(""), unquote(text)];
  let m: RegExpExecArray | null;
  let re = /[A-Za-z0-9+/]{16,}={0,2}/g;
  while ((m = re.exec(text))) nxt.push(b64(m[0]));
  re = /[A-Za-z2-7]{16,}={0,6}/g;
  while ((m = re.exec(text))) nxt.push(b32(m[0]));
  re = /(?:[0-9a-fA-F]{2}\s?){8,}/g;
  while ((m = re.exec(text))) nxt.push(hex(m[0]));
  for (const v of nxt) if (v && v !== text) views = views.concat(decodings(v, depth - 1));
  return views.filter((v, i) => views.indexOf(v) === i);
}

export type Hit = { hit: false } | { hit: true; kind: "copy" | "number"; detail: string; view: string };

/** Does `text`, going out, contain the content of `source`: copied, re-typed, encoded, or re-written as a number? */
export function check(text: string, source: string): Hit {
  let views = decodings(text);
  views = views.concat(([] as string[]).concat(...views.map(leet)));
  const s = norm(source).slice(0, 20000);
  const grams: Record<string, boolean> = {};
  for (let i = 0; i + K <= s.length; i++) grams[s.slice(i, i + K)] = true;
  const srcNums: Record<number, boolean> = {};
  numbers(source).forEach((n) => {
    srcNums[n] = true;
  });
  for (const view of views) {
    const n = norm(view);
    for (let j = 0; j + K <= n.length; j++) {
      if (grams[n.slice(j, j + K)]) return { hit: true, kind: "copy", detail: n.slice(j, j + K), view };
    }
    for (const num of numbers(view)) {
      if (srcNums[num]) return { hit: true, kind: "number", detail: String(num), view };
    }
  }
  return { hit: false };
}
