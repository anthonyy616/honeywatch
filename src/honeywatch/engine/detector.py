"""The detection engine: one event in, deterministic rule hits out."""

from __future__ import annotations

import logging
import signal
import threading
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path

from ..models import Event, RuleHit, Severity
from .loader import load_ruleset, sorted_rules
from .rules import Rule, RuleSet
from .threshold import ThresholdEngine

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Evaluates a ruleset against events.

    Stateless rules fire on a match. Threshold rules fire through the
    :class:`~honeywatch.engine.threshold.ThresholdEngine`. The active ruleset
    is swapped atomically on reload; threshold state for still-present rule
    IDs is preserved.
    """

    def __init__(self, rules: Iterable[Rule]) -> None:
        self._lock = threading.RLock()
        self._ruleset: RuleSet = RuleSet(rules=tuple(sorted(rules, key=lambda r: r.id)))
        self.thresholds = ThresholdEngine()

    # ---- ruleset management -------------------------------------------

    @property
    def ruleset(self) -> RuleSet:
        with self._lock:
            return self._ruleset

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self.ruleset.rules

    def replace_rules(self, ruleset: RuleSet) -> None:
        """Swap in a validated ruleset atomically."""
        with self._lock:
            self.thresholds.retain_compatible(ruleset.rules)
            self._ruleset = RuleSet(
                rules=tuple(sorted(ruleset.rules, key=lambda r: r.id)),
                errors=ruleset.errors,
                files=ruleset.files,
            )

    def reload_from(self, directory: str | Path) -> RuleSet:
        """Reload rules from disk. Never leaves an empty ruleset behind."""
        candidate = load_ruleset(directory)
        if not candidate.rules:
            logger.error(
                "rule reload from %s produced no usable rules (%d errors); keeping current ruleset",
                directory,
                len(candidate.errors),
            )
            for err in candidate.errors:
                logger.error("rule error: %s", err)
            return self.ruleset
        for err in candidate.errors:
            logger.warning("rule skipped: %s", err)
        self.replace_rules(candidate)
        logger.info("reloaded %d rules from %s", len(candidate), directory)
        return self.ruleset

    # ---- evaluation ----------------------------------------------------

    def evaluate(self, event: Event, *, record_threshold: bool = True) -> list[RuleHit]:
        """Return every rule hit for ``event`` in deterministic rule-ID order."""
        hits: list[RuleHit] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            if not rule.matches(event):
                continue
            if rule.threshold is not None:
                if not record_threshold:
                    continue
                if not self.thresholds.evaluate(rule, event, event.ts):
                    continue
            else:
                self.thresholds.fire(rule, event, event.ts)
            hits.append(
                RuleHit(
                    rule_id=rule.id,
                    title=rule.title,
                    attack=rule.attack,
                    attack_name=rule.attack_name,
                    severity=rule.severity,
                    ts=event.ts,
                )
            )
            event.tags.extend(rule.tags)
        return hits

    def should_alert(self, hits: Iterable[RuleHit]) -> list[RuleHit]:
        """Filter hits down to those whose rule requests an alert."""
        wanted = {rule.id for rule in self.rules if rule.alert}
        return [hit for hit in hits if hit.rule_id in wanted]

    def reset(self) -> None:
        self.thresholds.clear()


def install_sighup_reload(engine: DetectionEngine, directory: str | Path) -> callable:  # type: ignore[valid-type]
    """Install a SIGHUP handler that atomically reloads rules.

    Returns:
        A callable that removes the handler again.
    """
    def _handler(signum: int, frame: object) -> None:
        logger.info("received SIGHUP (%s); reloading rules", signum)
        try:
            engine.reload_from(directory)
        except Exception:  # pragma: no cover - defensive
            logger.exception("rule reload failed; keeping current ruleset")

    try:
        signal.signal(signal.SIGHUP, _handler)
    except (ValueError, AttributeError, OSError):  # pragma: no cover - non-main thread
        logger.warning("cannot install SIGHUP handler in this thread")
        return lambda: None

    def _remove() -> None:
        try:
            signal.signal(signal.SIGHUP, signal.SIG_DFL)
        except (ValueError, AttributeError, OSError):  # pragma: no cover
            pass

    return _remove