"""Append-only, hash-chained audit log. Each entry commits to the previous one."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


def _h(prev: str, payload: str) -> str:
    return hashlib.sha256((prev + payload).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.entries: list[dict] = []
        if self.path and self.path.exists():
            self.entries = [json.loads(line) for line in self.path.read_text().splitlines() if line]

    def append(self, payload: dict) -> dict:
        prev = self.entries[-1]["entry_hash"] if self.entries else GENESIS
        body = json.dumps(payload, sort_keys=True, default=str)
        entry = {"seq": len(self.entries), "prev_hash": prev, "payload": body,
                 "entry_hash": _h(prev, body)}
        self.entries.append(entry)
        if self.path:
            with self.path.open("a") as f:
                f.write(json.dumps(entry) + "\n")
        return entry

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_seq). Detects edits, reordering and deletions."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            if e["seq"] != i or e["prev_hash"] != prev or e["entry_hash"] != _h(prev, e["payload"]):
                return False, i
            prev = e["entry_hash"]
        return True, None
