"""One config file for IntentGuard (TOML, read with the standard library).

    [engine]                  # EngineConfig fields: quarantine_at, low_confidence, carry_decay, lineage_k, ...
    quarantine_at = 1.0
    [engine.ladder]           # risk level at which each capability is switched off
    network = 0.4
    shell = 0.6
    files_locked = 0.6
    db_needs_review = 0.8

    [classes]                 # resource -> PUBLIC | INTERNAL | CONFIDENTIAL | SECRET (default INTERNAL)
    "hr/salary.xlsx" = "CONFIDENTIAL"
    [trust]                   # destination -> local | approved | unknown | denylisted (default unknown)
    "advisor@university.edu" = "approved"
    [tables]                  # database table -> classification
    salaries = "CONFIDENTIAL"
    [tools.read_note]         # tool -> operation, and which argument is the resource / destination
    op = "read"
    resource_arg = "path"
    [grants]                  # optional default grants for sessions opened without their own
    resources = ["research/*"]
    destinations = ["advisor@university.edu"]

The `tools`, `classes`, `trust` and `tables` sections have the same shape as the proxy JSON of the MCP gateway,
so one file can drive both. Unknown keys and bad values are errors, not silently ignored.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

from .engine import EngineConfig
from .gateway import Catalog
from .models import Classification, Op, Trust

LADDER_CAPS = ("network", "shell", "files_locked", "db_needs_review")
TOOL_KEYS = {"op", "resource_arg", "dest_arg", "resource_optional"}
GRANT_KEYS = {"resources", "destinations", "max_classification", "project_root", "ops"}
TOP_KEYS = {"engine", "classes", "trust", "tables", "tools", "grants"}


class ConfigError(ValueError):
    """The config file is wrong. The message says where."""


@dataclass
class Config:
    engine: EngineConfig = field(default_factory=EngineConfig)
    classes: dict[str, Classification] = field(default_factory=dict)
    trust: dict[str, Trust] = field(default_factory=dict)
    tables: dict[str, Classification] = field(default_factory=dict)
    tools: dict[str, dict] = field(default_factory=dict)
    grants: dict = field(default_factory=dict)

    def catalog(self) -> Catalog:
        return Catalog(dict(self.classes), dict(self.trust), dict(self.tables))

    def proxy_dict(self) -> dict:
        """The dict shape `mcp_gateway.build_proxy` takes."""
        return {"tools": self.tools,
                "classes": {k: v.name for k, v in self.classes.items()},
                "trust": {k: v.value for k, v in self.trust.items()},
                "tables": {k: v.name for k, v in self.tables.items()}}


def _enum(kind: type, value: Any, where: str):
    try:
        return kind[value] if issubclass(kind, Classification) else kind(value)
    except (KeyError, ValueError):
        allowed = [m.name if issubclass(kind, Classification) else m.value for m in kind]
        raise ConfigError(f"{where}: {value!r} is not one of {allowed}") from None


def _section(raw: dict, key: str) -> dict:
    v = raw.get(key, {})
    if not isinstance(v, dict):
        raise ConfigError(f"[{key}] must be a table")
    return v


def _engine(raw: dict) -> EngineConfig:
    eng = dict(_section(raw, "engine"))
    ladder = eng.pop("ladder", None)
    names = {f.name for f in fields(EngineConfig)} - {"ladder"}
    for k in eng:
        if k not in names:
            raise ConfigError(f"[engine]: unknown setting {k!r}; known: {sorted(names | {'ladder'})}")
    default = EngineConfig()
    for k, v in eng.items():
        want = type(getattr(default, k))
        if getattr(default, k) is None:  # optional float settings such as action_risk_cap
            want = float
        if want is float and isinstance(v, int) and not isinstance(v, bool):
            eng[k] = float(v)
        elif not isinstance(v, want):
            raise ConfigError(f"[engine].{k} must be {want.__name__}, got {v!r}")
    if ladder is not None:
        if not isinstance(ladder, dict):
            raise ConfigError("[engine.ladder] must be a table")
        bad = set(ladder) - set(LADDER_CAPS)
        if bad:
            raise ConfigError(f"[engine.ladder]: unknown capability {sorted(bad)}; known: {list(LADDER_CAPS)}")
        for cap, at in ladder.items():
            if not isinstance(at, (int, float)) or isinstance(at, bool) or not 0 < at <= 1:
                raise ConfigError(f"[engine.ladder].{cap} must be a number in (0, 1], got {at!r}")
        eng["ladder"] = tuple(sorted((float(at), cap) for cap, at in ladder.items()))
    cfg = EngineConfig(**eng)
    if not 0 < cfg.quarantine_at <= 1:
        raise ConfigError(f"[engine].quarantine_at must be in (0, 1], got {cfg.quarantine_at}")
    return cfg


def parse(raw: dict) -> Config:
    unknown = set(raw) - TOP_KEYS
    if unknown:
        raise ConfigError(f"unknown section(s) {sorted(unknown)}; known: {sorted(TOP_KEYS)}")
    tools: dict[str, dict] = {}
    for name, spec in _section(raw, "tools").items():
        if not isinstance(spec, dict) or "op" not in spec:
            raise ConfigError(f"[tools.{name}] needs an 'op'")
        extra = set(spec) - TOOL_KEYS
        if extra:
            raise ConfigError(f"[tools.{name}]: unknown key(s) {sorted(extra)}; known: {sorted(TOOL_KEYS)}")
        _enum(Op, spec["op"], f"[tools.{name}].op")
        tools[name] = dict(spec)
    grants = dict(_section(raw, "grants"))
    extra = set(grants) - GRANT_KEYS
    if extra:
        raise ConfigError(f"[grants]: unknown key(s) {sorted(extra)}; known: {sorted(GRANT_KEYS)}")
    if "max_classification" in grants:
        _enum(Classification, grants["max_classification"], "[grants].max_classification")
    return Config(
        engine=_engine(raw),
        classes={k: _enum(Classification, v, f"[classes].{k}") for k, v in _section(raw, "classes").items()},
        trust={k: _enum(Trust, v, f"[trust].{k}") for k, v in _section(raw, "trust").items()},
        tables={k: _enum(Classification, v, f"[tables].{k}") for k, v in _section(raw, "tables").items()},
        tools=tools, grants=grants)


def load_config(path: str | Path) -> Config:
    """Read a .toml (or .json) file. Raises ConfigError with the problem and where it is."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {p}: {exc}") from exc
    try:
        raw = json.loads(text) if p.suffix == ".json" else tomllib.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{p}: not valid {p.suffix.lstrip('.') or 'TOML'}: {exc}") from exc
    return parse(raw)
