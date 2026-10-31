"""Load episodes written by someone else (JSON files) so the paper can include an independent set.

    bench/external/*.json   each file: one episode object or a list of them
"""

from __future__ import annotations

import json
from pathlib import Path

from intentguard.mock_env import FILES, TRUST

from .episodes import AMBIGUOUS, BENIGN, MALICIOUS, Episode, Step

TOOLS = {"read_file", "search_files", "send_email", "upload", "run_shell", "db_query"}
KINDS = {BENIGN, AMBIGUOUS, MALICIOUS}
DIR = Path(__file__).resolve().parent / "external"


def _check(ep: dict, src: str) -> None:
    where = f"{src}:{ep.get('id', '?')}"
    for k in ("id", "kind", "category", "task", "grants", "steps"):
        if k not in ep:
            raise ValueError(f"{where}: missing '{k}'")
    if ep["kind"] not in KINDS:
        raise ValueError(f"{where}: kind must be one of {sorted(KINDS)}")
    for i, st in enumerate(ep["steps"]):
        if st["tool"] not in TOOLS:
            raise ValueError(f"{where} step {i}: unknown tool {st['tool']!r}")
        path = st.get("args", {}).get("path")
        if st["tool"] == "read_file" and path not in FILES and not str(path).startswith(("research/..", "research/./")):
            raise ValueError(f"{where} step {i}: path {path!r} is not in the mock file set: {sorted(FILES)}")
        for key in ("to", "url"):
            dest = st.get("args", {}).get(key)
            if dest is not None and dest not in TRUST:
                pass  # unknown destinations are allowed: they resolve to UNKNOWN trust on purpose


def load_external(directory: Path = DIR) -> list[Episode]:
    eps: list[Episode] = []
    for f in sorted(directory.glob("*.json")):
        data = json.loads(f.read_text())
        for ep in data if isinstance(data, list) else [data]:
            _check(ep, f.name)
            steps = [Step(s["tool"], s.get("args", {}), bool(s.get("harmful", False)),
                          bool(s.get("neutral", False)), bool(s.get("after_injection", False)))
                     for s in ep["steps"]]
            eps.append(Episode(f"E-{ep['id']}", ep["kind"], ep["category"], ep["task"],
                               ep["grants"], steps))
    return eps
