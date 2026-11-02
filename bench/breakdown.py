"""Per-category outcome table for one system on the red-team halves: python -m bench.breakdown [system]."""

from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from bench.redteam2 import build_rt_dev, build_rt_heldout  # noqa: E402
from bench.run import run_system  # noqa: E402


def main(system: str = "intentguard_full") -> None:
    for name, build in (("rt_dev", build_rt_dev), ("rt_heldout", build_rt_heldout)):
        rows = run_system(system, build())
        by = defaultdict(lambda: [0, 0, 0, 0])  # harmful steps, executed, clean steps, clean blocked/reviewed
        for r in rows:
            c = by[r["category"]]
            if r["harmful"]:
                c[0] += 1
                c[1] += r["decision"] == "ALLOW"
            elif not r["neutral"]:
                c[2] += 1
                c[3] += r["decision"] != "ALLOW"
        print(f"{name} [{system}]")
        for cat, (h, ex, cl, bad) in sorted(by.items()):
            print(f"  {cat:20s} harmful executed {ex}/{h}   clean not-allowed {bad}/{cl}")


if __name__ == "__main__":
    main(*sys.argv[1:2])
