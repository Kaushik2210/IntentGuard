"""Compare two systems on every set, counting what a review would hide.

The benchmark treats a REVIEW as "not executed", so a variant that turns blocks into reviews looks safe by
construction. This script also reports the worst case, where a careless human approves every review.

    python -m bench.compare_variants intentguard_full variant_lockout_review
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from bench.adversarial import build_adv, build_adv2  # noqa: E402
from bench.episodes import build, build_inj, build_seq, build_xs  # noqa: E402
from bench.generate import generate  # noqa: E402
from bench.redteam2 import build_rt_dev, build_rt_heldout  # noqa: E402
from bench.redteam3 import build_rt3_dev, build_rt3_heldout  # noqa: E402
from bench.run import run_system  # noqa: E402

SETS = [("core", build), ("seq", build_seq), ("gen_dev_seed1", lambda: generate(1, 150)),
        ("gen_heldout_seed2026", lambda: generate(2026, 300)), ("gen_fresh_seed4242", lambda: generate(4242, 300)),
        ("adversarial", build_adv), ("adversarial2", build_adv2), ("injection_text", build_inj),
        ("xsession_db", build_xs), ("rt_dev", build_rt_dev), ("rt_heldout", build_rt_heldout),
        ("rt3_dev", build_rt3_dev), ("rt3_heldout", build_rt3_heldout)]


def tally(system: str, episodes) -> dict:
    t = {"harmful": 0, "executed": 0, "to_review": 0, "clean": 0, "clean_review": 0, "clean_block": 0}
    for r in run_system(system, episodes):
        if r["neutral"]:
            continue
        if r["harmful"]:
            t["harmful"] += 1
            t["executed"] += r["decision"] == "ALLOW"
            t["to_review"] += r["decision"] == "REVIEW"
        else:
            t["clean"] += 1
            t["clean_review"] += r["decision"] == "REVIEW"
            t["clean_block"] += r["decision"] in ("BLOCK", "QUARANTINE")
    return t


def main(a: str, b: str) -> None:
    print(f"| Set | harmful steps | {a}: executed / to review | {b}: executed / to review / worst case "
          f"| clean steps interrupted ({a} -> {b}) |")
    print("|---|---|---|---|---|")
    for name, build_set in SETS:
        eps = build_set()
        x, y = tally(a, eps), tally(b, eps)
        worst = y["executed"] + y["to_review"]
        print(f"| {name} | {x['harmful']} | {x['executed']} / {x['to_review']} | "
              f"{y['executed']} / {y['to_review']} / {worst} | "
              f"{x['clean_review'] + x['clean_block']} -> {y['clean_review'] + y['clean_block']} of {x['clean']} |")


if __name__ == "__main__":
    main(*(sys.argv[1:3] or ["intentguard_full", "variant_lockout_review"]))
