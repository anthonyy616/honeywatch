"""YAML rule models, loading and validation."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..models import Severity

# Guard rails against pathological rule definitions.
MAX_REGEX_SOURCE = 512
MAX_REGEX_REPETITION = 1000
_MODIFIER_RE = re.compile(r"^(?P<field>[a-z_]+)(?:\|(?P<modifier>[a-z]+))?$")

MODIFIERS = frozenset(
    {"exact", "contains", "startswith", "endswith", "re", "gt", "lt", "gte", "lte", "not"}
)

NUMERIC_MODIFIERS = frozenset({"gt", "lt", "gte", "lte"})
STRING_MODIFIERS = frozenset({"contains", "startswith", "endswith", "re", "not"})

DURATION_RE = re.compile(r"^(?P<value>\d+(?:\.\d+)?)(?P<unit>ms|s|m|h|d)$")
_UNIT_SECONDS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}

# Reject nested-quantifier shapes that are the classic ReDoS signature.
_REDOS_SIGNATURE = re.compile(r"\([^()]*[+*]\)[+*]|\([^()]*[+*]\)\{")


def parse_duration(value: str | int | float) -> float:
    """Parse ``30s`` / ``5m`` / ``1h`` into seconds.

    Raises:
        ValueError: The duration is malformed.
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value <= 0:
            raise ValueError("duration must be positive")
        return float(value)
    text = str(value).strip().lower()
    match = DURATION_RE.match(text)
    if not match:
        raise ValueError(f"invalid duration: {value!r} (use e.g. 30s, 5m, 1h)")
    amount = float(match.group("value"))
    seconds = amount * _UNIT_SECONDS[match.group("unit")]
    if seconds <= 0:
        raise ValueError("duration must be positive")
    return seconds


class MatchModifier(StrEnum):
    EXACT = "exact"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    RE = "re"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    NOT = "not"


@dataclass(frozen=True, slots=True)
class Condition:
    """One parsed match condition against a single event field."""

    field: str
    modifier: MatchModifier
    values: tuple[Any, ...]
    regexes: tuple[re.Pattern[str], ...] = ()

    def matches(self, actual: Any) -> bool:
        """Evaluate this condition. Never raises on hostile/None values."""
        if self.modifier is MatchModifier.NOT:
            return all(not _value_matches(self, v, actual) for v in self.values)
        if self.modifier in NUMERIC_MODIFIERS:
            return _numeric_match(self, actual)
        if actual is None:
            return False
        text = actual if isinstance(actual, str) else str(actual)
        return any(_value_matches(self, v, text) for v in self.values)


def _value_matches(cond: Condition, expected: Any, actual: Any) -> bool:
    match cond.modifier:
        case MatchModifier.RE:
            if actual is None:
                return False
            text = actual if isinstance(actual, str) else str(actual)
            return any(rx.search(text) for rx in cond.regexes)
        case MatchModifier.CONTAINS:
            if actual is None:
                return False
            text = actual if isinstance(actual, str) else str(actual)
            return _ci(str(expected)) in _ci(text)
        case MatchModifier.STARTSWITH:
            if actual is None:
                return False
            text = actual if isinstance(actual, str) else str(actual)
            return _ci(text).startswith(_ci(str(expected)))
        case MatchModifier.ENDSWITH:
            if actual is None:
                return False
            text = actual if isinstance(actual, str) else str(actual)
            return _ci(text).endswith(_ci(str(expected)))
        case _:
            if actual is None:
                return False
            return _ci(str(actual)) == _ci(str(expected))


def _ci(value: str) -> str:
    return value.casefold()


def _numeric_match(cond: Condition, actual: Any) -> bool:
    number = _to_number(actual)
    if number is None:
        return False
    for expected in cond.values:
        target = _to_number(expected)
        if target is None:
            continue
        match cond.modifier:
            case MatchModifier.GT:
                if number > target:
                    return True
            case MatchModifier.LT:
                if number < target:
                    return True
            case MatchModifier.GTE:
                if number >= target:
                    return True
            case MatchModifier.LTE:
                if number <= target:
                    return True
    return False


def _to_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


class DistinctSpec(BaseModel):
    """Distinct-value threshold specification."""

    model_config = ConfigDict(extra="forbid")

    field: str
    count: int = Field(ge=1, le=100000)

    @field_validator("field")
    @classmethod
    def _check_field(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z_]+", value):
            raise ValueError("distinct.field must be a snake_case event field")
        return value


class ThresholdSpec(BaseModel):
    """Threshold configuration for a rule."""

    model_config = ConfigDict(extra="forbid")

    group_by: str = "src_ip"
    count: int | None = Field(default=None, ge=1, le=1_000_000)
    distinct: DistinctSpec | None = None
    window: str = "60s"

    @field_validator("group_by")
    @classmethod
    def _check_group(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z_]+", value):
            raise ValueError("threshold.group_by must be a snake_case event field")
        return value

    @property
    def window_seconds(self) -> float:
        return parse_duration(self.window)

    @property
    def threshold(self) -> int:
        if self.distinct is not None:
            return self.distinct.count
        if self.count is None:
            raise ValueError("threshold requires either 'count' or 'distinct'")
        return self.count


class RuleModel(BaseModel):
    """One validated detection rule."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=200)
    description: str = ""
    attack: str | None = None
    attack_name: str | None = None
    severity: Severity = Severity.MEDIUM
    enabled: bool = True
    match: dict[str, Any] = Field(default_factory=dict)
    match_any: list[dict[str, Any]] = Field(default_factory=list)
    threshold: ThresholdSpec | None = None
    tags: list[str] = Field(default_factory=list)
    alert: bool = False

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9\-_]*", value):
            raise ValueError("rule id must match [a-z0-9][a-z0-9-_]*")
        return value


class RuleError(Exception):
    """A single rule failed validation. Reported, skipped, never fatal."""


@dataclass(slots=True)
class Rule:
    """A validated rule with pre-compiled conditions.

    ``conditions`` are ANDed. ``alternatives`` is an optional list of ORed
    condition groups, used when the same indicator can appear in more than one
    event field (for example a web probe in either the path or the query).
    """

    id: str
    title: str
    description: str
    attack: str | None
    attack_name: str | None
    severity: Severity
    enabled: bool
    tags: list[str]
    alert: bool
    conditions: tuple[Condition, ...]
    threshold: ThresholdSpec | None
    source_file: str = ""
    alternatives: tuple[tuple[Condition, ...], ...] = ()

    def matches(self, event: Any) -> bool:
        """Stateless AND evaluation across ``match``, plus ORed alternatives."""
        if not all(cond.matches(getattr(event, cond.field, None)) for cond in self.conditions):
            return False
        if self.alternatives:
            return any(
                all(cond.matches(getattr(event, cond.field, None)) for cond in group)
                for group in self.alternatives
            )
        return True


def compile_conditions(match: dict[str, Any]) -> tuple[Condition, ...]:
    """Compile a ``match`` mapping into conditions.

    Raises:
        RuleError: A key is malformed or a regex is invalid/unsafe.
    """
    conditions: list[Condition] = []
    for key, raw in match.items():
        parsed = _MODIFIER_RE.match(key)
        if not parsed:
            raise RuleError(f"invalid match key {key!r} (expected 'field' or 'field|modifier')")
        field_name = parsed.group("field")
        modifier = parsed.group("modifier") or "exact"
        if modifier not in MODIFIERS:
            raise RuleError(f"unknown modifier {modifier!r} in {key!r}")
        values = raw if isinstance(raw, list) else [raw]
        if not values:
            raise RuleError(f"match key {key!r} has an empty value list")
        regexes: tuple[re.Pattern[str], ...] = ()
        if modifier == "re":
            regexes = tuple(_compile_regex(v) for v in values)
        conditions.append(
            Condition(
                field=field_name,
                modifier=MatchModifier(modifier),
                values=tuple(values),
                regexes=regexes,
            )
        )
    if not conditions:
        raise RuleError("rule has an empty 'match' block")
    return tuple(conditions)


def _compile_regex(value: Any) -> re.Pattern[str]:
    source = str(value)
    if len(source) > MAX_REGEX_SOURCE:
        raise RuleError(f"regex source exceeds {MAX_REGEX_SOURCE} characters")
    if _REDOS_SIGNATURE.search(source):
        raise RuleError(f"regex rejected as potentially catastrophic: {source[:60]!r}")
    try:
        return re.compile(source, re.IGNORECASE)
    except re.error as exc:
        raise RuleError(f"invalid regex {source[:60]!r}: {exc}") from exc


def build_rule(payload: dict[str, Any], source_file: str = "") -> Rule:
    """Validate one raw rule mapping into a :class:`Rule`."""
    try:
        model = RuleModel.model_validate(payload)
    except ValidationError as exc:
        messages = "; ".join(
            f"{'.'.join(str(p) for p in e.get('loc', ()))}: {e.get('msg')}" for e in exc.errors()
        )
        raise RuleError("invalid rule: " + messages) from exc
    try:
        conditions = compile_conditions(model.match)
    except RuleError as exc:
        raise RuleError(f"{model.id}: {exc}") from exc
    alternatives: list[tuple[Condition, ...]] = []
    for index, group in enumerate(model.match_any):
        try:
            alternatives.append(compile_conditions(group))
        except RuleError as exc:
            raise RuleError(f"{model.id}: match_any[{index}]: {exc}") from exc
    if model.threshold is not None:
        try:
            model.threshold.threshold  # noqa: B018 - property validates presence
        except ValueError as exc:
            raise RuleError(f"{model.id}: {exc}") from exc
    return Rule(
        id=model.id,
        title=model.title,
        description=model.description,
        attack=model.attack,
        attack_name=model.attack_name,
        severity=model.severity,
        enabled=model.enabled,
        tags=list(model.tags),
        alert=model.alert,
        conditions=conditions,
        threshold=model.threshold,
        source_file=source_file,
        alternatives=tuple(alternatives),
    )


@dataclass(slots=True)
class RuleSet:
    """An immutable collection of validated rules."""

    rules: tuple[Rule, ...] = field(default_factory=tuple)
    errors: tuple[str, ...] = field(default_factory=tuple)
    files: tuple[str, ...] = field(default_factory=tuple)

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):  # type: ignore[override]
        return iter(self.rules)

    @property
    def ids(self) -> tuple[str, ...]:
        return tuple(r.id for r in self.rules)

    def get(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)