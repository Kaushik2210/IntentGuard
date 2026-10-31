"""Emit paper tables from results/results_*.json so numbers are never typed by hand.

    python -m bench.run && python -m bench.paper_tables > paper/tables.md
"""

from __future__ import annotations

import json
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"
MAIN = ["unprotected", "static_rbac", "keyword_guardrail_standin",
        "llamafirewall_local_scanners", "intentguard_full"]
ABLATE = ["intentguard_full", "ablate_no_mention_check", "ablate_no_intent",
          "ablate_no_behaviour", "ablate_no_dataflow"]


def pct(x: float) -> str:
    return f"{100 * x:.1f}"


def table(label: str, systems: list[str], cols: list[tuple[str, str]]) -> str:
    d = json.loads((RESULTS / f"results_{label}.json").read_text())
    m = d["meta"]
    out = [f"**{label}**: {m['episodes']} episodes {m['by_kind']}, commit `{m['git_commit']}`\n",
           "| System | " + " | ".join(c[0] for c in cols) + " |",
           "|---|" + "---|" * len(cols)]
    for s in systems:
        if s not in d["summary"]:
            continue  # optional baseline not run in this environment
        row = d["summary"][s]
        out.append(f"| {s} | " + " | ".join(pct(row[k]) for _, k in cols) + " |")
    return "\n".join(out) + "\n"


def main() -> None:
    cols = [("ASR %", "asr"), ("Exfil %", "exfil_rate"), ("Benign blocked %", "fpr_block"),
            ("Review friction %", "review_friction"), ("Task completion %", "task_completion")]
    print("# Generated tables (do not edit by hand)\n")
    print("## Main comparison\n")
    for label in ("gen_fresh_seed4242", "gen_heldout_seed2026", "adversarial", "adversarial2",
                  "injection_text"):
        print(table(label, MAIN, cols))
    print("## Ablations\n")
    for label in ("gen_fresh_seed4242", "gen_heldout_seed2026"):
        print(table(label, ABLATE, cols))
    print("\nExternal published guardrail baseline: TO MEASURE (not implemented).")


if __name__ == "__main__":
    main()
