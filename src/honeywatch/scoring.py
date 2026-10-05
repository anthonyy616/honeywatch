"""Score computation, verdicts and attacker classification.

Scores are always recomputed from **stored rule hits**, never from a running
counter, so a restart or replay reproduces the same numbers.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timedelta

from .models import (
    VERDICT_THRESHOLDS,
    Classification,
    Severity,
    Verdict,
)

DEFAULT_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 1.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 8.0,
    Severity.HIGH: 20.0,
    Severity.CRITICAL: 40.0,
}

DEFAULT_HALF_LIFE_HOURS = 6.0


def weight_for(severity: Severity | str, weights: dict[str, float] | None = None) -> float:
    """Return the configured weight for a severity."""
    key = str(Severity(severity))
    table = {str(k): float(v) for k, v in (weights or DEFAULT_WEIGHTS).items()}
    return table.get(key, DEFAULT_WEIGHTS[Severity(severity)])


def decay_factor(age: timedelta, half_life_hours: float = DEFAULT_HALF_LIFE_HOURS) -> float:
    """Exponential decay factor for a hit of the given age."""
    hours = age.total_seconds() / 3600.0
    if hours <= 0:
        return 1.0
    return 0.5 ** (hours / half_life_hours)


def hit_contribution(
    severity: Severity | str,
    hit_ts: datetime,
    now: datetime,
    *,
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS,
    weights: dict[str, float] | None = None,
) -> float:
    """Decayed contribution of one stored rule hit."""
    if now < hit_ts:
        age = timedelta(0)
    else:
        age = now - hit_ts
    return weight_for(severity, weights) * decay_factor(age, half_life_hours)


def score_hits(
    hits: Iterable[tuple[Severity | str, datetime]],
    now: datetime,
    *,
    half_life_hours: float = DEFAULT_HALF_LIFE_HOURS,
    weights: dict[str, float] | None = None,
) -> float:
    """Sum decayed contributions of ``(severity, ts)`` pairs."""
    total = 0.0
    for severity, ts in hits:
        total += hit_contribution(
            severity, ts, now, half_life_hours=half_life_hours, weights=weights
        )
    return total


def verdict_for(score: float) -> Verdict:
    """Map a score to its verdict using documented boundaries."""
    for threshold, verdict in VERDICT_THRESHOLDS:
        if score >= threshold:
            return verdict
    return Verdict.NOISE


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

# Ordered priority (highest first). Each entry lists the tags that qualify.
CLASSIFICATION_RULES: tuple[tuple[Classification, frozenset[str]], ...] = (
    (Classification.INTRUDER, frozenset({"login-success", "post-compromise"})),
    (Classification.MALWARE_DROPPER, frozenset({"malware-dropper", "tool-transfer"})),
    (Classification.BRUTE_FORCER, frozenset({"brute-force"})),
    (Classification.CREDENTIAL_SPRAYER, frozenset({"credential-spray"})),
    (Classification.WEB_EXPLOITER, frozenset({"web-exploit"})),
    (Classification.SCANNER, frozenset({"scanner"})),
    (Classification.RECON, frozenset({"recon"})),
)


def classify_tags(tags: Iterable[str]) -> Classification:
    """Return the highest-priority classification satisfied by ``tags``."""
    present = {str(t).strip().casefold() for t in tags if t}
    for classification, required in CLASSIFICATION_RULES:
        if present & required:
            return classification
    return Classification.UNCLASSIFIED


def classification_from_hits(
    hit_rule_ids: Sequence[str],
    rules_by_id: dict[str, Sequence[str]],
) -> Classification:
    """Classify using rule IDs mapped to their tag sets."""
    tags: list[str] = []
    for rule_id in hit_rule_ids:
        tags.extend(rules_by_id.get(rule_id, ()))
    return classify_tags(tags)