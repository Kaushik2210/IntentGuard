"""SQLite persistence for sessions, so a restart does not wipe what the gateway knows.

What is saved: each session's task scope, risk, restrictions, taint, approvals, closed flag, the per-agent risk carried
between sessions, and the content-lineage fingerprints (64-bit hashes, never readable text). What is NOT saved: actions
waiting for a human (they are tools bound to live callables; the audit log still records them) and the short buffer of
recent outbound text used to spot a secret split across several sends. After a restart that buffer starts empty.

The file holds task text and file names, so protect it like the audit log.

The lineage hashes are keyed with a secret that lives in a separate file (`<db>.key`, created on first use, or the hex
in INTENTGUARD_DB_KEY), so someone who gets only the database cannot recover a short value such as a salary by
hashing every candidate. Keep the key file apart from the database and from backups of it. If the database holds
lineage but the key is gone, opening it fails rather than quietly forgetting what sessions read.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import struct
import threading
from pathlib import Path

from .models import Capabilities, Classification, Op, Session, TaskScope

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (session_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS memory (agent_id TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS lineage (session_id TEXT NOT NULL, idx INTEGER NOT NULL, cls INTEGER NOT NULL,
                                    grams BLOB NOT NULL, PRIMARY KEY (session_id, idx));
"""


def _scope_to_dict(sc: TaskScope) -> dict:
    return {"task_text": sc.task_text, "allowed_ops": sorted(o.value for o in sc.allowed_ops),
            "allowed_resources": sc.allowed_resources, "allowed_destinations": sc.allowed_destinations,
            "max_classification": int(sc.max_classification), "project_root": sc.project_root,
            "confidence": sc.confidence, "source": sc.source}


def _scope_from_dict(d: dict) -> TaskScope:
    return TaskScope(d["task_text"], {Op(o) for o in d["allowed_ops"]}, list(d["allowed_resources"]),
                     list(d["allowed_destinations"]), Classification(d["max_classification"]),
                     d["project_root"], d["confidence"], d["source"])


def _session_to_dict(s: Session) -> dict:
    c = s.caps
    return {"agent_id": s.agent_id, "scope": _scope_to_dict(s.scope), "risk": s.risk, "taint": int(s.taint),
            "taint_sources": sorted(s.taint_sources), "tags": list(s.tags), "denied": s.denied,
            "quarantined": s.quarantined, "closed": s.closed,
            "caps": [c.network, c.shell, c.files_locked, c.db_needs_review],
            "approved": sorted([list(p) for p in s.approved])}


def _session_from_dict(sid: str, d: dict) -> Session:
    s = Session(sid, d["agent_id"], _scope_from_dict(d["scope"]))
    s.risk, s.taint = d["risk"], Classification(d["taint"])
    s.taint_sources, s.tags, s.denied = set(d["taint_sources"]), list(d["tags"]), d["denied"]
    s.quarantined, s.closed = d["quarantined"], d["closed"]
    s.caps = Capabilities(*d["caps"])
    s.approved = {tuple(p) for p in d["approved"]}
    return s


class StoreKeyError(ValueError):
    """The database holds lineage hashes but the key that made them is missing or wrong."""


def _load_key(path: Path, db_has_lineage: bool) -> bytes:
    env = os.environ.get("INTENTGUARD_DB_KEY")
    if env:
        try:
            key = bytes.fromhex(env)
        except ValueError:
            raise StoreKeyError("INTENTGUARD_DB_KEY must be hex") from None
        if not 16 <= len(key) <= 64:
            raise StoreKeyError("INTENTGUARD_DB_KEY must be 16 to 64 bytes (32 to 128 hex characters)")
        return key
    keyfile = path.with_name(path.name + ".key")
    if keyfile.exists():
        return bytes.fromhex(keyfile.read_text().strip())
    if db_has_lineage:
        raise StoreKeyError(f"{path} holds saved lineage but its key file {keyfile} is missing. Restore the key, or "
                            "delete the database to start clean (sessions and lineage in it are lost).")
    key = secrets.token_bytes(32)
    keyfile.write_text(key.hex())
    try:
        keyfile.chmod(0o600)  # best effort; Windows ignores most of this
    except OSError:
        pass
    return key


class SessionStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()  # the HTTP service calls from several threads
        self._db = sqlite3.connect(self.path, check_same_thread=False)
        self._db.executescript(_SCHEMA)
        has = self._db.execute("SELECT 1 FROM lineage LIMIT 1").fetchone() is not None
        try:
            self.key = _load_key(self.path, has)
        except StoreKeyError:
            self._db.close()
            raise
        self._saved_lineage: dict[str, int] = {}

    def save(self, s: Session) -> None:
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?)",
                             (s.session_id, json.dumps(_session_to_dict(s))))
            done = self._saved_lineage.get(s.session_id, 0)
            for i in range(done, len(s.lineage)):  # lineage only grows, so write just the new entries
                cls, grams = s.lineage[i]
                blob = struct.pack(f">{len(grams)}Q", *sorted(grams))
                self._db.execute("INSERT OR REPLACE INTO lineage VALUES (?, ?, ?, ?)",
                                 (s.session_id, i, int(cls), blob))
            self._saved_lineage[s.session_id] = len(s.lineage)

    def save_memory(self, agent_id: str, mem: dict) -> None:
        data = json.dumps({"risk": mem["risk"], "tags": sorted(mem["tags"])})
        with self._lock, self._db:
            self._db.execute("INSERT OR REPLACE INTO memory VALUES (?, ?)", (agent_id, data))

    def delete_memory(self, agent_id: str) -> None:
        with self._lock, self._db:
            self._db.execute("DELETE FROM memory WHERE agent_id = ?", (agent_id,))

    def load(self) -> tuple[dict[str, Session], dict[str, dict]]:
        with self._lock:
            sessions = {sid: _session_from_dict(sid, json.loads(data))
                        for sid, data in self._db.execute("SELECT session_id, data FROM sessions")}
            for sid, _idx, cls, blob in self._db.execute(
                    "SELECT session_id, idx, cls, grams FROM lineage ORDER BY session_id, idx"):
                if sid in sessions:
                    n = len(blob) // 8
                    sessions[sid].lineage.append((Classification(cls), frozenset(struct.unpack(f">{n}Q", blob))))
            for sid, s in sessions.items():
                self._saved_lineage[sid] = len(s.lineage)
            memory = {a: {"risk": m["risk"], "tags": set(m["tags"])}
                      for a, d in self._db.execute("SELECT agent_id, data FROM memory")
                      for m in [json.loads(d)]}
        return sessions, memory

    def close(self) -> None:
        self._db.close()
