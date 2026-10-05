"""Recursive YAML rule directory loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .rules import Rule, RuleError, RuleSet, build_rule


def load_ruleset(directory: str | Path, *, strict: bool = False) -> RuleSet:
    """Load every ``*.yaml``/``*.yml`` rule below ``directory``.

    Duplicate IDs, malformed YAML and invalid rules are collected as errors
    instead of raising, so a single bad file can never stop the daemon.

    Args:
        directory: Root rules directory (searched recursively).
        strict: When true, any error raises :class:`RuleError`.
    """
    root = Path(directory)
    errors: list[str] = []
    files: list[str] = []
    rules: list[Rule] = []
    by_id: dict[str, Rule] = {}

    if not root.is_dir():
        message = f"rules directory not found: {root}"
        if strict:
            raise RuleError(message)
        return RuleSet(rules=(), errors=(message,), files=())

    for path in sorted(root.rglob("*")):
        if path.suffix.lower() not in {".yaml", ".yml"} or not path.is_file():
            continue
        rel = str(path.relative_to(root))
        files.append(rel)
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{rel}: cannot read/parse YAML: {exc}")
            continue
        if payload is None:
            continue
        entries = payload if isinstance(payload, list) else [payload]
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                errors.append(f"{rel}[{index}]: rule must be a mapping")
                continue
            try:
                rule = build_rule(entry, source_file=rel)
            except RuleError as exc:
                errors.append(f"{rel}[{index}]: {exc}")
                continue
            if rule.id in by_id:
                errors.append(
                    f"{rel}: duplicate rule id {rule.id!r} (already defined in "
                    f"{by_id[rule.id].source_file})"
                )
                continue
            by_id[rule.id] = rule
            rules.append(rule)

    ruleset = RuleSet(rules=tuple(rules), errors=tuple(errors), files=tuple(files))
    if strict and ruleset.errors:
        raise RuleError("; ".join(ruleset.errors))
    return ruleset


def load_rule_document(path: str | Path) -> list[Any]:
    """Load a single rule file (used by tests and tooling)."""
    return list(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or [])


def ruleset_from_payload(payload: Any) -> RuleSet:
    """Build a ruleset directly from an in-memory YAML document."""
    rules: list[Rule] = []
    errors: list[str] = []
    entries = payload if isinstance(payload, list) else [payload]
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        try:
            rule = build_rule(entry, source_file="<memory>")
        except RuleError as exc:
            errors.append(str(exc))
            continue
        if rule.id in seen:
            errors.append(f"duplicate rule id {rule.id!r}")
            continue
        seen.add(rule.id)
        rules.append(rule)
    return RuleSet(rules=tuple(rules), errors=tuple(errors), files=("<memory>",))


def sorted_rules(ruleset: RuleSet) -> list[Rule]:
    """Deterministic rule ordering for evaluation and reporting."""
    return sorted(ruleset.rules, key=lambda r: r.id)