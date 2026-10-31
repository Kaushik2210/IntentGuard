"""Deterministic template compiler: task text + user grants -> TaskScope.

An LLM parser may later propose a scope, but it can only narrow what the grants allow.
"""

from __future__ import annotations

import re

from .models import Classification, Op, TaskScope

_VERBS = [
    (r"\b(read|open|review|look at|list)\b", {Op.READ}),
    (r"\b(summari[sz]e|summary|digest)\b", {Op.READ, Op.SUMMARIZE}),
    (r"\b(write|save|create|draft)\b", {Op.WRITE}),
    (r"\b(email|e-mail|send|forward|reply)\b", {Op.SEND}),
    (r"\b(upload|publish|post)\b", {Op.UPLOAD}),
    (r"\b(query|database|sql|lookup)\b", {Op.QUERY}),
    (r"\b(run|execute|shell|command)\b", {Op.EXEC}),
]


def compile_scope(task: str, grants: dict) -> TaskScope:
    ops: set[Op] = set()
    for pat, o in _VERBS:
        if re.search(pat, task, re.IGNORECASE):
            ops |= o
    confidence = 1.0
    if not ops:  # unclear task -> least privilege, flag low confidence
        ops, confidence = {Op.READ}, 0.5
    granted = {Op(o) for o in grants.get("ops", [o.value for o in Op])}
    return TaskScope(
        task_text=task,
        allowed_ops=ops & granted,
        allowed_resources=list(grants.get("resources", [])),
        allowed_destinations=list(grants.get("destinations", [])),
        max_classification=Classification[grants.get("max_classification", "INTERNAL")],
        project_root=grants.get("project_root"),
        confidence=confidence,
    )
