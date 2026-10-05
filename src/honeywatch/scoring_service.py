"""Scoring service: reconstructs scores from stored rule hits.

Scores are never persisted as an irreversible value; every call recomputes
from the ``rule_hits`` table so restarts and replays agree.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .models import Classification, Severity, Verdict
from .scoring import (
    DEFAULT_HALF_LIFE_HOURS,
    classify_tags,
    hit_contribution,
    verdict_for,
)


class Scorer:
    """Read-side scoring/classification over a :class:`ReadStore`.

    Args:
        store: Read-only storage handle.
        scoring_config: The validated ``scoring`` config section (optional).
    """

    def __init__(self, store: Any, scoring_config: Any = None) -> None:
        self.store = store
        self.half_life_hours = float(
            getattr(scoring_config, "half_life_hours", DEFAULT_HALF_LIFE_HOURS)
        )
        raw_weights = getattr(scoring_config, "weights", None) or {}
        self.weights = {str(k): float(v) for k, v in raw_weights.items()} or None
        self._rule_tags: dict[str, list[str]] | None = None

    # ---- rule tag map --------------------------------------------------

    def load_rule_tags(self, rules: Any) -> None:
        """Populate the rule-ID -> tags map used by classification."""
        self._rule_tags = {rule.id: list(rule.tags) for rule in rules}

    @property
    def rule_tags(self) -> dict[str, list[str]]:
        if self._rule_tags is None:
            self._rule_tags = {}
        return self._rule_tags

    # ---- scoring -------------------------------------------------------

    def hits_for(self, src_ip: str) -> list[tuple[Severity, datetime]]:
        """Fetch ``(severity, ts)`` pairs for every stored hit from one IP."""
        rows = self.store._query(  # noqa: SLF001 - single read-only store
            "SELECT h.severity AS s, h.ts AS t FROM rule_hits h"
            " JOIN events e ON e.id = h.event_id WHERE e.src_ip = ? ORDER BY h.ts ASC",
            [src_ip],
        )
        out: list[tuple[Severity, datetime]] = []
        for row in rows:
            try:
                stamp = datetime.fromisoformat(str(row["t"]).replace("Z", "+00:00"))
            except ValueError:  # pragma: no cover - defensive
                continue
            out.append((Severity(row["s"]), stamp.astimezone(UTC)))
        return out

    def score_ip(self, src_ip: str, *, now: datetime | None = None) -> float:
        """Decayed score for one source address."""
        moment = now or datetime.now(UTC)
        total = 0.0
        for severity, ts in self.hits_for(src_ip):
            total += hit_contribution(
                severity,
                ts,
                moment,
                half_life_hours=self.half_life_hours,
                weights=self.weights,
            )
        return total

    def verdict(self, score: float) -> str:
        """Verdict label for a score."""
        return str(verdict_for(score))

    def rule_ids_for(self, src_ip: str) -> list[str]:
        rows = self.store._query(  # noqa: SLF001
            "SELECT DISTINCT h.rule_id AS r FROM rule_hits h"
            " JOIN events e ON e.id = h.event_id WHERE e.src_ip = ?",
            [src_ip],
        )
        return [row["r"] for row in rows]

    def classify(self, src_ip: str, *, now: datetime | None = None) -> str:
        """Highest-priority classification label for one source address."""
        del now  # classification is currently time independent
        tags: list[str] = []
        for rule_id in self.rule_ids_for(src_ip):
            tags.extend(self.rule_tags.get(rule_id, ()))
        if not tags:
            tags.extend(self._event_fallback_tags(src_ip))
        return str(classify_tags(tags))

    def _event_fallback_tags(self, src_ip: str) -> list[str]:
        """Derive classification tags from raw event shape when no rules fired."""
        rows = self.store._query(  # noqa: SLF001
            "SELECT event_type AS t, COUNT(*) AS c FROM events WHERE src_ip = ? GROUP BY event_type",
            [src_ip],
        )
        counts = {row["t"]: row["c"] for row in rows}
        tags: list[str] = []
        if counts.get("login_success") and counts.get("command"):
            tags.append("login-success")
        if counts.get("command"):
            tags.append("recon")
        if counts.get("http_login_attempt") or counts.get("http_request"):
            tags.append("scanner")
        return tags

    def summarize(self, src_ip: str, *, now: datetime | None = None) -> dict[str, Any]:
        """Convenience bundle used by the TUI and reports."""
        moment = now or datetime.now(UTC)
        score = self.score_ip(src_ip, now=moment)
        return {
            "src_ip": src_ip,
            "score": score,
            "verdict": self.verdict(score),
            "classification": self.classify(src_ip, now=moment),
        }


__all__ = ["Scorer", "Classification", "Verdict"]