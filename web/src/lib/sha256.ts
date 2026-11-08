/* SHA-256 in plain TypeScript, so the audit ledger can re-hash entries in the browser without a secure context.
   Same construction as src/intentguard/audit.py: entry_hash = sha256(prev_hash + payload). */

function primes(n: number): number[] {
  const out: number[] = [];
  let p = 2;
  while (out.length < n) {
    let ok = true;
    for (let d = 2; d * d <= p; d++) {
      if (p % d === 0) {
        ok = false;
        break;
      }
    }
    if (ok) out.push(p);
    p++;
  }
  return out;
}

const K = primes(64).map((p) => ((Math.pow(p, 1 / 3) % 1) * 4294967296) | 0);
const H0 = primes(8).map((p) => ((Math.pow(p, 0.5) % 1) * 4294967296) | 0);
const rr = (x: number, n: number) => (x >>> n) | (x << (32 - n));

export function sha256(input: string): string {
  const H = H0.slice();
  const bytes = Array.from(new TextEncoder().encode(input));
  const bits = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  for (const v of [Math.floor(bits / 4294967296), bits >>> 0]) bytes.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
  for (let o = 0; o < bytes.length; o += 64) {
    const w: number[] = [];
    for (let i = 0; i < 16; i++) w[i] = (bytes[o + 4 * i] << 24) | (bytes[o + 4 * i + 1] << 16) | (bytes[o + 4 * i + 2] << 8) | bytes[o + 4 * i + 3];
    for (let i = 16; i < 64; i++) {
      const s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = H.slice();
    for (let i = 0; i < 64; i++) {
      const S1 = rr(a[4], 6) ^ rr(a[4], 11) ^ rr(a[4], 25);
      const ch = (a[4] & a[5]) ^ (~a[4] & a[6]);
      const t1 = (a[7] + S1 + ch + K[i] + w[i]) | 0;
      const S0 = rr(a[0], 2) ^ rr(a[0], 13) ^ rr(a[0], 22);
      const mj = (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
      const t2 = (S0 + mj) | 0;
      a = [(t1 + t2) | 0, a[0], a[1], a[2], (a[3] + t1) | 0, a[4], a[5], a[6]];
    }
    for (let j = 0; j < 8; j++) H[j] = (H[j] + a[j]) | 0;
  }
  return H.map((x) => ("00000000" + (x >>> 0).toString(16)).slice(-8)).join("");
}

export const GENESIS = "0".repeat(64);
