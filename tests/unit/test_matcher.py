"""Matcher modifier, condition and threshold engine tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from honeywatch.engine.rules import (
    Condition,
    MatchModifier,
    RuleError,
    build_rule,
    compile_conditions,
    parse_duration,
)
from honeywatch.engine.threshold import ThresholdEngine

from tests.conftest import make_event


def cond(field: str, modifier: str, *values) -> Condition:
    conditions = compile_conditions({f"{field}|{modifier}": list(values)})
    return conditions[0]


# ---- modifiers -----------------------------------------------------------


def test_exact_is_case_insensitive() -> None:
    assert cond("username", "exact", "ROOT").matches("root")
    assert not cond("username", "exact", "root").matches("admin")


def test_contains() -> None:
    assert cond("command", "contains", "wget").matches("cd /tmp && wget http://x/y")
    assert not cond("command", "contains", "wget").matches("uname -a")


def test_startswith_and_endswith() -> None:
    assert cond("command", "startswith", "uname").matches("uname -a")
    assert not cond("command", "startswith", "uname").matches("ls; uname -a")
    assert cond("command", "endswith", "-a").matches("uname -a")
    assert not cond("command", "endswith", "-a").matches("uname")


def test_regex_is_case_insensitive_and_searches() -> None:
    assert cond("command", "re", r"\bwget\b").matches("cd /tmp && WGET http://x")
    assert not cond("command", "re", r"\bwget\b").matches("uname -a")


def test_numeric_modifiers() -> None:
    assert cond("src_port", "gt", 1000).matches(5000)
    assert not cond("src_port", "gt", 1000).matches(500)
    assert cond("src_port", "gte", 5000).matches(5000)
    assert cond("src_port", "lt", 1000).matches(500)
    assert cond("src_port", "lte", 500).matches(500)


def test_numeric_comparison_rejects_non_numeric() -> None:
    assert not cond("src_port", "gt", 100).matches("not-a-number")
    assert not cond("src_port", "gt", 100).matches(None)
    assert not cond("src_port", "gt", 100).matches(True)


def test_not_modifier() -> None:
    assert cond("username", "not", "root").matches("admin")
    assert not cond("username", "not", "root").matches("root")


def test_list_values_are_or() -> None:
    condition = cond("username", "exact", "root", "admin", "guest")
    assert condition.matches("admin")
    assert not condition.matches("oracle")


def test_null_never_matches_positive_comparisons() -> None:
    for modifier in ("exact", "contains", "startswith", "endswith", "re"):
        assert not cond("command", modifier, "x").matches(None)


def test_multiple_fields_are_and() -> None:
    rule = build_rule(
        {
            "id": "t-1",
            "title": "t",
            "severity": "low",
            "match": {"service": "ssh", "event_type": "command"},
        }
    )
    assert rule.matches(make_event(event_type="command"))
    assert not rule.matches(make_event(event_type="login_attempt"))


def test_missing_attribute_is_treated_as_null() -> None:
    rule = build_rule(
        {"id": "t-2", "title": "t", "severity": "low", "match": {"not_a_field": "x"}}
    )
    assert not rule.matches(make_event())


# ---- validation ----------------------------------------------------------


def test_invalid_regex_is_rejected() -> None:
    with pytest.raises(RuleError):
        compile_conditions({"command|re": "([unclosed"})


def test_catastrophic_regex_is_rejected() -> None:
    with pytest.raises(RuleError):
        compile_conditions({"command|re": r"(a+)+b"})


def test_oversized_regex_is_rejected() -> None:
    with pytest.raises(RuleError):
        compile_conditions({"command|re": "a" * 600})


def test_unknown_modifier_is_rejected() -> None:
    with pytest.raises(RuleError):
        compile_conditions({"command|frobnicate": "x"})


def test_malformed_key_is_rejected() -> None:
    with pytest.raises(RuleError):
        compile_conditions({"Command": "x"})


def test_empty_match_is_rejected() -> None:
    with pytest.raises(RuleError):
        build_rule({"id": "t-3", "title": "t", "severity": "low", "match": {}})


def test_invalid_rule_id_is_rejected() -> None:
    with pytest.raises(RuleError):
        build_rule({"id": "Bad ID!", "title": "t", "severity": "low", "match": {"a": "b"}})


def test_threshold_needs_count_or_distinct() -> None:
    with pytest.raises(RuleError):
        build_rule(
            {
                "id": "t-4",
                "title": "t",
                "severity": "low",
                "match": {"service": "ssh"},
                "threshold": {"group_by": "src_ip", "window": "60s"},
            }
        )


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("30s", 30), ("5m", 300), ("1h", 3600), ("2d", 172800), ("500ms", 0.5)],
)
def test_duration_parsing(text: str, seconds: float) -> None:
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["abc", "10x", "", "-5s"])
def test_bad_durations_are_rejected(text: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(text)


# ---- thresholds ----------------------------------------------------------


def threshold_rule(threshold: dict) -> object:
    return build_rule(
        {
            "id": "thr-1",
            "title": "threshold rule",
            "severity": "high",
            "match": {"service": "ssh", "event_type": "login_attempt"},
            "threshold": threshold,
        }
    )


def test_count_threshold_below_at_and_above() -> None:
    rule = threshold_rule({"group_by": "src_ip", "count": 3, "window": "60s"})
    engine = ThresholdEngine()
    base = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    assert not engine.evaluate(rule, make_event(), base)
    assert not engine.evaluate(rule, make_event(), base + timedelta(seconds=1))
    assert engine.evaluate(rule, make_event(), base + timedelta(seconds=2))


def test_window_boundary_is_exclusive() -> None:
    rule = threshold_rule({"group_by": "src_ip", "count": 2, "window": "10s"})
    engine = ThresholdEngine()
    base = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    assert not engine.evaluate(rule, make_event(), base)
    # Exactly on the boundary the first observation is pruned.
    assert not engine.evaluate(rule, make_event(), base + timedelta(seconds=10))


def test_sources_are_independent() -> None:
    rule = threshold_rule({"group_by": "src_ip", "count": 2, "window": "60s"})
    engine = ThresholdEngine()
    base = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    assert not engine.evaluate(rule, make_event(src_ip="198.51.100.1"), base)
    assert not engine.evaluate(rule, make_event(src_ip="198.51.100.2"), base)
    assert engine.evaluate(rule, make_event(src_ip="198.51.100.1"), base + timedelta(seconds=1))


def test_distinct_threshold() -> None:
    rule = threshold_rule(
        {"group_by": "src_ip", "distinct": {"field": "username", "count": 3}, "window": "300s"}
    )
    engine = ThresholdEngine()
    base = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    assert not engine.evaluate(rule, make_event(username="a"), base)
    assert not engine.evaluate(rule, make_event(username="a"), base + timedelta(seconds=1))
    assert not engine.evaluate(rule, make_event(username="b"), base + timedelta(seconds=2))
    assert engine.evaluate(rule, make_event(username="c"), base + timedelta(seconds=3))


def test_distinct_prunes_old_values() -> None:
    rule = threshold_rule(
        {"group_by": "src_ip", "distinct": {"field": "username", "count": 2}, "window": "10s"}
    )
    engine = ThresholdEngine()
    base = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    assert not engine.evaluate(rule, make_event(username="a"), base)
    # 'a' ages out, so 'b' alone is not enough.
    assert not engine.evaluate(rule, make_event(username="b"), base + timedelta(seconds=11))
    assert engine.evaluate(rule, make_event(username="c"), base + timedelta(seconds=12))


def test_cooldown_equals_window() -> None:
    rule = threshold_rule({"group_by": "src_ip", "count": 1, "window": "10s"})
    engine = ThresholdEngine()
    base = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    assert engine.evaluate(rule, make_event(), base)
    # Within cooldown: reached again but suppressed.
    assert not engine.evaluate(rule, make_event(), base + timedelta(seconds=5))
    # Exactly on the cooldown boundary the rule is still suppressed.
    assert not engine.evaluate(rule, make_event(), base + timedelta(seconds=10))
    assert engine.evaluate(rule, make_event(), base + timedelta(seconds=11))


def test_out_of_order_replay_is_safe() -> None:
    rule = threshold_rule({"group_by": "src_ip", "count": 2, "window": "60s"})
    engine = ThresholdEngine()
    late = datetime(2026, 3, 12, 9, 5, tzinfo=UTC)
    early = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    assert not engine.evaluate(rule, make_event(), late)
    assert engine.evaluate(rule, make_event(), early)


def test_retain_compatible_drops_unknown_rules() -> None:
    rule = threshold_rule({"group_by": "src_ip", "count": 1, "window": "60s"})
    engine = ThresholdEngine()
    base = datetime(2026, 3, 12, 9, 0, tzinfo=UTC)
    engine.evaluate(rule, make_event(), base)
    assert engine.snapshot()
    engine.retain_compatible(())
    assert not engine.snapshot()


def test_condition_is_immutable() -> None:
    condition = cond("username", "exact", "root")
    assert condition.modifier is MatchModifier.EXACT
    with pytest.raises(AttributeError):
        condition.field = "x"  # type: ignore[misc]