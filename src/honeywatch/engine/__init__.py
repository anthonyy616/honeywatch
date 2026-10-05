"""Detection engine: rule loading, matching, thresholds and evaluation."""

from __future__ import annotations

from .detector import DetectionEngine, install_sighup_reload
from .loader import load_ruleset, ruleset_from_payload, sorted_rules
from .rules import (
    MODIFIERS,
    Condition,
    MatchModifier,
    Rule,
    RuleError,
    RuleModel,
    RuleSet,
    ThresholdSpec,
    build_rule,
    compile_conditions,
    parse_duration,
)
from .threshold import ThresholdEngine

__all__ = [
    "MODIFIERS",
    "Condition",
    "DetectionEngine",
    "MatchModifier",
    "Rule",
    "RuleError",
    "RuleModel",
    "RuleSet",
    "ThresholdEngine",
    "ThresholdSpec",
    "build_rule",
    "compile_conditions",
    "install_sighup_reload",
    "load_ruleset",
    "parse_duration",
    "ruleset_from_payload",
    "sorted_rules",
]