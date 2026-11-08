"""Deterministic policy engine: scope, egress/taint, sequence risk, dynamic permission reduction.

Ablation flags let the benchmark switch whole components off.
"""

from __future__ import annotations

import base64
import codecs
import fnmatch
import hashlib
import re
import time
import urllib.parse
from dataclasses import dataclass, replace

from .models import (
    EGRESS_OPS,
    SEVERITY,
    ActionRequest,
    Classification,
    Decision,
    Evidence,
    Op,
    Session,
    Trust,
    Verdict,
)

SECRET_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r"|(?i:api[_-]?key|secret|password|token)\s*[=:]\s*\S{6,})")
ENV_PATTERNS = ["*.env", "*.env.*", "*config*", "*credentials*", "*.pem", "*id_rsa*"]
SECRET_QUERY_RE = re.compile(r"key|secret|password|token|credential", re.IGNORECASE)
INJ_RE = re.compile(
    r"(ignore (all |any )?(previous|prior|above) instructions|you must now|note to (the )?(ai|assistant|agent)"
    r"|disregard (the )?(user|above)|do not (tell|inform) the user|without telling the user"
    r"|forward the full|send all documents)", re.I)
SHELL_ALLOW = {"ls", "cat", "echo", "pwd", "head", "wc"}

RULE_TEXT = {
    "PERM-002": "External network access has been disabled for this session",
    "PERM-003": "File access is locked to the original project folder",
    "PERM-004": "Shell execution has been disabled for this session",
    "PERM-005": "Database queries now require approval for this session",
    "SCOPE-001": "The resource is outside what your task authorized",
    "SCOPE-002": "The operation is not part of what your task authorized",
    "SCOPE-003": "The data is classified above the level your task allows",
    "SCOPE-005": "Sensitive file is not referenced by your task",
    "SCOPE-004": "Task intent was unclear and this touches sensitive data",
    "EGRESS-001": "The destination is not on the approved list",
    "EGRESS-002": "Confidential data seen in this session would leave to an unapproved destination",
    "EGRESS-003": "The destination is denylisted",
    "TAINT-001": "The outbound content contains a secret or credential",
    "TAINT-002": "The outbound content contains data read from a sensitive file in this session",
    "SEQ-001": "Secret search followed by reading a config/credential file",
    "SEQ-002": "Sensitive data collected, then an unfamiliar destination contacted",
    "SEQ-005": "Untrusted content with instruction-like text was read earlier in this session",
    "SEQ-004": "Repeated denied attempts in one session",
    "EXEC-001": "The shell command is not on the allowlist",
    "RISK-001": "Cumulative session risk reached the quarantine threshold",
}


@dataclass
class EngineConfig:
    intent: bool = True
    behaviour: bool = True
    dataflow: bool = True
    # (risk threshold, capability change) ladder; configurable and swept in experiments
    ladder: tuple = ((0.4, "network"), (0.6, "shell"), (0.6, "files_locked"),
                     (0.8, "db_needs_review"))
    quarantine_at: float = 1.0
    low_confidence: float = 0.6
    cross_session: bool = True  # carry decayed risk and tags to a new session of the same agent
    carry_decay: float = 0.75
    mention_check: bool = True  # CONFIDENTIAL+ reads must be referenced by the task text
    lineage: bool = True  # outbound content that contains sensitive data read in this session
    lineage_k: int = 12  # shortest run of letters/digits that counts as a match
    fingerprint_key: bytes = b""  # secret that keys the lineage hashes; set by the session store (see store.py)
    lineage_variants: bool = True  # also match sensitive numbers (digits, 120k, in words) and leetspeak
    approval_memory: bool = True  # a human approval of one recipient or file is remembered for the session
    action_risk_cap: float | None = None  # most risk one action can add; None = the sum of every rule it trips
    lockout_review: bool = False  # capability locks and the quarantine threshold send an action to a human, not a freeze


def _mentioned(resource: str, task: str) -> bool:
    """A file is named by its path or its full file name; a table by its name as a whole word.
    A shared word ("budget", "app", "config") is not enough: it only collides with the file stem."""
    t = task.lower()
    r = resource.lower()
    if "/" in r or "." in r:
        return r in t or re.search(r"(?<![\w.])" + re.escape(r.rsplit("/", 1)[-1]) + r"(?![\w])", t) is not None
    return re.search(r"\b" + re.escape(r) + r"\b", t) is not None


def _decodings(text: str, depth: int = 2) -> list[str]:
    """Plain-text views of outbound content, to look through simple encodings: rot13, reversal, URL
    encoding, and base64, base32 and hex runs, decoded up to `depth` times. Not a general decoder:
    ciphers, compression, character substitution and paraphrase are not handled."""
    views = [text]
    if depth < 1:
        return views
    nxt = [codecs.decode(text, "rot13"), text[::-1], urllib.parse.unquote(text)]
    for m in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            nxt.append(base64.b64decode(m + "=" * (-len(m) % 4)).decode("utf-8", "ignore"))
        except ValueError:
            pass
    for m in re.findall(r"[A-Za-z2-7]{16,}={0,6}", text):
        try:
            nxt.append(base64.b32decode(m.upper() + "=" * (-len(m) % 8)).decode("utf-8", "ignore"))
        except ValueError:
            pass
    for m in re.findall(r"(?:[0-9a-fA-F]{2}\s?){8,}", text):
        try:
            nxt.append(bytes.fromhex(re.sub(r"\s", "", m)).decode("utf-8", "ignore"))
        except ValueError:
            pass
    for v in nxt:
        if v and v != text:
            views += _decodings(v, depth - 1)
    return list(dict.fromkeys(views))


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _fp(gram: str, key: bytes = b"") -> int:
    """64-bit fingerprint of a run of characters. Only fingerprints are kept, so the session's memory of
    sensitive data holds no readable fragments of it. With a secret `key` (the session store makes one) the hash
    cannot be reversed by guessing candidate values, which matters for short inputs such as numbers."""
    return int.from_bytes(hashlib.blake2b(gram.encode(), digest_size=8, key=key).digest(), "big")


def _grams(text: str, k: int, key: bytes = b"") -> frozenset[int]:
    t = _norm(text)[:20000]
    return frozenset(_fp(t[i:i + k], key) for i in range(len(t) - k + 1))


_UNITS = {w: i for i, w in enumerate(
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen "
    "seventeen eighteen nineteen".split())}
_TENS = {w: 10 * i for i, w in enumerate("_ _ twenty thirty forty fifty sixty seventy eighty ninety".split()) if w != "_"}
_SCALES = {"hundred": 100, "thousand": 1000, "million": 1_000_000, "billion": 1_000_000_000}
MIN_NUMBER = 10_000  # smaller numbers (years, counts, small prices) are too common to mean anything


def _numbers(text: str) -> set[int]:
    """Whole numbers of at least MIN_NUMBER written as digits (120000, 120,000), with a suffix (120k, 1.5m),
    or in English words (one hundred and twenty thousand, ninety-eight thousand). Not handled: other
    languages, fractions, approximations ("about a hundred grand"), or a number split across sentences."""
    text = text[:20000].lower()
    found: set[int] = set()
    flat = re.sub(r"(?<=\d),(?=\d{3}(?!\d))", "", text)
    found.update(int(m) for m in re.findall(r"(?<![\d.])\d{5,}(?![\d.]*\d)", flat))
    for num, suffix in re.findall(r"(?<![\w.])(\d+(?:\.\d+)?)\s?([km])\b", flat):
        found.add(int(float(num) * (1000 if suffix == "k" else 1_000_000)))
    for num, scale in re.findall(r"(?<![\w.])(\d+(?:\.\d+)?)\s(thousand|million|billion)\b", flat):
        found.add(int(float(num) * _SCALES[scale]))
    total = current = 0
    started = False
    for w in re.findall(r"[a-z]+", text.replace("-", " ")) + [""]:
        if w in _UNITS or w in _TENS or w in _SCALES:
            started = True
            if w in _UNITS:
                current += _UNITS[w]
            elif w in _TENS:
                current += _TENS[w]
            elif w == "hundred":
                current = max(current, 1) * 100
            else:
                total += max(current, 1) * _SCALES[w]
                current = 0
        elif w == "and" and started:
            continue
        else:
            if started and total + current >= MIN_NUMBER:
                found.add(total + current)
            total = current = 0
            started = False
    return found


_LEET = str.maketrans({"4": "a", "3": "e", "5": "s", "7": "t", "@": "a", "$": "s"})


def _leet(text: str) -> list[str]:
    """Plain-letter readings of leetspeak: digits and symbols swapped for the letters they imitate. Zero and one
    are ambiguous (0/o, 1/i/l), so each reading is tried both ways."""
    if not re.search(r"[43571@$0]", text):
        return []
    base = text.translate(_LEET)
    return [base.replace("1", one).replace("0", zero) for one in ("i", "l", "1") for zero in ("o", "0")]


def _overlaps(views: list[str], grams: frozenset[int], k: int, numbers: bool = False, key: bytes = b"") -> bool:
    for v in views:
        n = _norm(v)
        if any(_fp(n[i:i + k], key) in grams for i in range(len(n) - k + 1)):
            return True
        if numbers and any(_fp(f"#{x}", key) in grams for x in _numbers(v)):
            return True
    return False


class PolicyEngine:
    def __init__(self, config: EngineConfig | None = None):
        self.cfg = config or EngineConfig()

    def set_fingerprint_key(self, key: bytes) -> None:
        """Key the lineage hashes. Call before any session reads sensitive data: hashes made with another key never match."""
        self.cfg = replace(self.cfg, fingerprint_key=key)

    # ---- helpers -------------------------------------------------------------
    @staticmethod
    def _tags(req: ActionRequest) -> set[str]:
        t: set[str] = set()
        if req.tool == "search_files" and SECRET_QUERY_RE.search(str(req.args.get("query", ""))):
            t.add("secret_search")
        if req.op == Op.READ and req.resource and any(
                fnmatch.fnmatch(req.resource.lower(), p) for p in ENV_PATTERNS):
            t.add("env_read")
        if req.op == Op.READ and req.classification >= Classification.CONFIDENTIAL:
            t.add("sensitive_read")
        if req.destination and req.trust in (Trust.UNKNOWN, Trust.DENYLISTED):
            t.add("unknown_contact")
        return t

    def _reduce(self, s: Session) -> None:
        for threshold, cap in self.cfg.ladder:
            if s.risk >= threshold:
                setattr(s.caps, cap, False if cap in ("network", "shell") else True)

    CARRY_TAGS = {"secret_search", "env_read", "sensitive_read", "injection_seen"}

    def carry(self, s: Session, mem: dict) -> None:
        if not (self.cfg.cross_session and self.cfg.behaviour):
            return
        s.risk = mem["risk"] * self.cfg.carry_decay
        s.tags = sorted(set(mem["tags"]) & self.CARRY_TAGS)
        self._reduce(s)

    def remember(self, s: Session, output: object, cls: Classification) -> None:
        """Keep a fingerprint of sensitive data the session has read, to recognise it on the way out."""
        if self.cfg.lineage:
            key = self.cfg.fingerprint_key
            grams = _grams(str(output), self.cfg.lineage_k, key)
            if self.cfg.lineage_variants:  # "#" never survives _norm, so these cannot collide with text grams
                grams |= {_fp(f"#{n}", key) for n in _numbers(str(output))}
            if grams:
                s.lineage.append((cls, grams))

    def observe(self, s: Session, output: object) -> bool:
        """Scan tool output for instruction-like text. Flag and raise risk; never trusted, never obeyed."""
        if not self.cfg.behaviour:
            return False
        text = output if isinstance(output, str) else " ".join(map(str, output or []))
        if INJ_RE.search(text):
            s.tags.append("injection_seen")
            s.risk = min(1.0, s.risk + 0.25)
            self._reduce(s)
            return True
        return False

    # ---- main entry ----------------------------------------------------------
    def evaluate(self, req: ActionRequest, s: Session) -> Decision:
        t0 = time.perf_counter()
        sc, cfg = s.scope, self.cfg
        fired: list[tuple[str, Verdict, float, Evidence]] = []

        def fire(rid: str, v: Verdict, risk: float, observed: str = "", expected: str = ""):
            fired.append((rid, v, risk, Evidence(rid, RULE_TEXT[rid], observed, expected)))

        is_egress = req.op in EGRESS_OPS
        tags = self._tags(req)

        # dynamic permission reduction already in force
        lock = Verdict.REVIEW if cfg.lockout_review else Verdict.BLOCK
        if is_egress and not s.caps.network and req.trust != Trust.LOCAL:
            fire("PERM-002", lock, 0.1, req.destination or "")
        if req.op == Op.EXEC and not s.caps.shell:
            fire("PERM-004", lock, 0.1, str(req.args.get("cmd", "")))
        if req.op == Op.QUERY and s.caps.db_needs_review:
            fire("PERM-005", Verdict.REVIEW, 0.05, str(req.args.get("sql", "")))
        if (s.caps.files_locked and req.resource and sc.project_root
                and not req.resource.startswith(sc.project_root)):
            fire("PERM-003", lock, 0.1, req.resource, sc.project_root)

        # intent / scope
        if cfg.intent:
            if req.op not in sc.allowed_ops:
                fire("SCOPE-002", Verdict.BLOCK, 0.15, req.op.value,
                     ",".join(sorted(o.value for o in sc.allowed_ops)))
            if req.resource and not any(fnmatch.fnmatch(req.resource, g)
                                        for g in sc.allowed_resources):
                fire("SCOPE-001", Verdict.BLOCK, 0.15, req.resource,
                     ",".join(sc.allowed_resources))
            if req.classification > sc.max_classification:
                fire("SCOPE-003", Verdict.BLOCK, 0.15, req.classification.name,
                     sc.max_classification.name)
            if sc.confidence < cfg.low_confidence and req.classification >= Classification.CONFIDENTIAL:
                fire("SCOPE-004", Verdict.REVIEW, 0.05, f"confidence={sc.confidence}")
            names = [req.resource] if req.op == Op.READ and req.resource else (
                req.tables if req.op == Op.QUERY else [])
            if (cfg.mention_check and names and req.classification >= Classification.CONFIDENTIAL
                    and not any(_mentioned(n, sc.task_text) for n in names)
                    and not (cfg.approval_memory and all(("SCOPE-005", n) in s.approved for n in names))):
                fire("SCOPE-005", Verdict.REVIEW, 0.2, ",".join(names), "named in the task")

        # destination trust + data flow
        if req.destination and is_egress:
            allowed_dest = any(fnmatch.fnmatch(req.destination, g) for g in sc.allowed_destinations)
            if req.trust == Trust.DENYLISTED:
                fire("EGRESS-003", Verdict.BLOCK, 0.2, req.destination)
            elif (req.trust == Trust.UNKNOWN and not allowed_dest
                  and not (cfg.approval_memory and ("EGRESS-001", req.destination) in s.approved)):
                fire("EGRESS-001", Verdict.REVIEW, 0.1, req.destination)
        if cfg.dataflow and is_egress:
            leaving = req.trust not in (Trust.LOCAL, Trust.APPROVED)
            if leaving and (s.taint >= Classification.CONFIDENTIAL
                            or req.classification >= Classification.CONFIDENTIAL):
                fire("EGRESS-002", Verdict.BLOCK, 0.25, f"taint={s.taint.name}",
                     "public/approved only")
            text = " ".join(str(v) for v in req.args.values() if v != req.destination)
            s.outbound = (s.outbound + text)[-4000:]
            if (SECRET_RE.search(str(req.args))
                    or any(SECRET_RE.search(v) for v in _decodings(text) + _decodings(s.outbound))):
                fire("TAINT-001", Verdict.BLOCK, 0.25, "secret pattern in outbound content")
            if cfg.lineage and s.lineage and req.trust != Trust.LOCAL:
                views = _decodings(text) + _decodings(s.outbound)
                if cfg.lineage_variants:
                    views += [r for v in views for r in _leet(v)]
                hit = [c for c, g in s.lineage if _overlaps(views, g, cfg.lineage_k, cfg.lineage_variants, cfg.fingerprint_key)]
                if hit:  # credentials are blocked; other confidential data goes to a human
                    top = max(hit)
                    fire("TAINT-002", Verdict.BLOCK if top >= Classification.SECRET else Verdict.REVIEW, 0.3,
                         f"matches {top.name} data read earlier", "no sensitive content")

        # shell allowlist
        if req.op == Op.EXEC:
            parts = str(req.args.get("cmd", "")).split()
            if not parts or parts[0] not in SHELL_ALLOW:
                fire("EXEC-001", Verdict.BLOCK, 0.2, str(req.args.get("cmd", "")))

        # multi-step behaviour
        if cfg.behaviour:
            if "env_read" in tags and "secret_search" in s.tags:
                fire("SEQ-001", Verdict.ALLOW, 0.3, "secret_search -> env_read")
            prior_sens = {"env_read", "sensitive_read", "secret_search"} & set(s.tags)
            if "unknown_contact" in tags and prior_sens:
                fire("SEQ-002", Verdict.REVIEW, 0.35, ",".join(sorted(prior_sens)) + " -> unknown")
            if "injection_seen" in s.tags and (is_egress or req.op in (Op.EXEC, Op.QUERY)):
                fire("SEQ-005", Verdict.REVIEW, 0.2, "after instruction-like content")
            if s.denied >= 3 and fired:
                fire("SEQ-004", Verdict.ALLOW, 0.2, f"denied={s.denied}")

        verdict = Verdict.ALLOW
        for _, v, _, _ in fired:
            if SEVERITY[v] > SEVERITY[verdict]:
                verdict = v

        # update session state
        added = sum(r for _, _, r, _ in fired)
        if cfg.action_risk_cap is not None:  # one attempt that trips several rules is still one attempt
            added = min(added, cfg.action_risk_cap)
        s.risk = min(1.0, s.risk + added)
        if cfg.behaviour:
            s.tags.extend(tags)
        if verdict in (Verdict.BLOCK, Verdict.QUARANTINE):
            s.denied += 1
        if verdict == Verdict.ALLOW and req.op in (Op.READ, Op.QUERY):
            s.taint = max(s.taint, req.classification)
            if req.classification >= Classification.CONFIDENTIAL:
                s.taint_sources.add(req.resource or ",".join(req.tables))
        if cfg.behaviour:
            self._reduce(s)
            if s.risk >= cfg.quarantine_at:
                if cfg.lockout_review and verdict != Verdict.BLOCK:
                    fire("RISK-001", Verdict.REVIEW, 0.0, f"risk={s.risk:.2f}")  # a human decides; hard blocks stay
                    verdict = Verdict.REVIEW
                else:
                    fire("RISK-001", Verdict.QUARANTINE, 0.0, f"risk={s.risk:.2f}")
                    verdict, s.quarantined = Verdict.QUARANTINE, True

        evidence = [e for *_, e in fired]
        explanation = (" ".join(f"- {e.message}" + (f" (saw {e.observed})" if e.observed else "")
                                for e in evidence) or "Action is within the task scope.")
        recommended = {"ALLOW": "allow", "REVIEW": "review"}.get(verdict.value, "block")
        return Decision(req.action_id, verdict, round(s.risk, 3), [e.rule_id for e in evidence],
                        evidence, explanation, recommended, replace(s.caps),
                        (time.perf_counter() - t0) * 1000)
