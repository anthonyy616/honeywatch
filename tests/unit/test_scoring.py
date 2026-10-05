"""Scoring, verdict boundary and classification tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from honeywatch.models import Classification, Severity, Verdict
from honeywatch.scoring import (
    DEFAULT_WEIGHTS,
    classify_tags,
    decay_factor,
    hit_contribution,
    score_hits,
    verdict_for,
    weight_for,
)

NOW = datetime(2026, 3, 12, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("severity", "weight"),
    [("info", 1), ("low", 3), ("medium", 8), ("high", 20), ("critical", 40)],
)
def test_severity_weights_are_exact(severity: str, weight: float) -> None:
    assert weight_for(severity) == weight
    assert DEFAULT_WEIGHTS[Severity(severity)] == weight


def test_six_hour_half_life_is_exact() -> None:
    assert decay_factor(timedelta(hours=6)) == pytest.approx(0.5)
    assert decay_factor(timedelta(hours=12)) == pytest.approx(0.25)
    assert decay_factor(timedelta(0)) == pytest.approx(1.0)
    assert decay_factor(timedelta(hours=3)) == pytest.approx(0.7071067811865476, rel=1e-9)


def test_six_hour_old_hit_contributes_half() -> None:
    old = NOW - timedelta(hours=6)
    assert hit_contribution("high", old, NOW) == pytest.approx(10.0)


def test_future_timestamps_do_not_inflate() -> None:
    future = NOW + timedelta(hours=5)
    assert hit_contribution("high", future, NOW) == pytest.approx(20.0)


def test_score_sums_multiple_hits() -> None:
    hits = [
        ("critical", NOW),
        ("high", NOW - timedelta(hours=6)),
        ("info", NOW - timedelta(hours=12)),
    ]
    assert score_hits(hits, NOW) == pytest.approx(40 + 10 + 0.25)


def test_custom_weights_are_honoured() -> None:
    hits = [("high", NOW)]
    assert score_hits(hits, NOW, weights={"high": 7}) == pytest.approx(7.0)


@pytest.mark.parametrize(
    ("score", "verdict"),
    [
        (0, Verdict.NOISE),
        (9.999, Verdict.NOISE),
        (10, Verdict.SUSPICIOUS),
        (39.999, Verdict.SUSPICIOUS),
        (40, Verdict.HOSTILE),
        (99.999, Verdict.HOSTILE),
        (100, Verdict.PERSISTENT),
        (10_000, Verdict.PERSISTENT),
    ],
)
def test_verdict_boundaries(score: float, verdict: Verdict) -> None:
    assert verdict_for(score) is verdict


def test_classification_priority_order() -> None:
    assert classify_tags(["scanner", "brute-force", "login-success"]) is Classification.INTRUDER
    assert classify_tags(["scanner", "brute-force", "tool-transfer"]) is Classification.MALWARE_DROPPER
    assert classify_tags(["scanner", "brute-force"]) is Classification.BRUTE_FORCER
    assert classify_tags(["scanner", "credential-spray"]) is Classification.CREDENTIAL_SPRAYER
    assert classify_tags(["scanner", "web-exploit"]) is Classification.WEB_EXPLOITER
    assert classify_tags(["scanner"]) is Classification.SCANNER
    assert classify_tags(["recon"]) is Classification.RECON
    assert classify_tags([]) is Classification.UNCLASSIFIED
    assert classify_tags(["unknown-tag"]) is Classification.UNCLASSIFIED


def test_classification_is_case_insensitive() -> None:
    assert classify_tags(["BRUTE-FORCE"]) is Classification.BRUTE_FORCER


def test_score_is_reconstructable_after_restart(tmp_path) -> None:
    """Score must be recomputed from stored hits, not a running counter."""
    from honeywatch.scoring_service import Scorer
    from honeywatch.storage.queries import ReadStore
    from honeywatch.storage.sqlite import Storage
    from honeywatch.models import Event, RuleHit

    db = tmp_path / "rebuild.db"
    with Storage(db) as store:
        event = Event(
            ts=NOW,
            service="ssh",
            event_type="command",
            src_ip="203.0.113.5",
            session_id="s1",
            command="uname -a",
        )
        store.insert_event(event, [RuleHit(rule_id="r-1", severity="high", ts=NOW)])
        store.insert_event(
            Event(
                ts=NOW,
                service="ssh",
                event_type="command",
                src_ip="203.0.113.5",
                session_id="s1",
                command="wget http://x",
            ),
            [RuleHit(rule_id="r-2", severity="critical", ts=NOW)],
        )

    # A fresh read-only store reconstructs exactly the same score.
    scores = []
    for _ in range(2):
        with ReadStore(db) as read:
            scorer = Scorer(read)
            scores.append(scorer.score_ip("203.0.113.5", now=NOW))
    assert scores[0] == pytest.approx(60.0)
    assert scores[0] == scores[1]