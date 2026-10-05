"""Sliding-window threshold state.

State is keyed by ``(rule_id, group_value)``. Observations older than the
window are pruned on every relevant event. After a threshold fires, the key
enters cooldown for exactly the window duration.

Event timestamps (not wall-clock time) are authoritative, which keeps replay
deterministic.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .rules import Rule

# Entries untouched for this long are dropped to bound memory.
STATE_TTL_FACTOR = 10.0
STATE_TTL_FLOOR_S = 3600.0


@dataclass(slots=True)
class _KeyState:
    observations: deque[datetime] = field(default_factory=deque)
    distinct: dict[str, datetime] = field(default_factory=dict)
    last_fire: datetime | None = None
    touched: datetime | None = None


class ThresholdEngine:
    """Tracks count and distinct thresholds for threshold-based rules."""

    def __init__(self) -> None:
        self._state: dict[tuple[str, str], _KeyState] = {}

    # ---- public API ----------------------------------------------------

    def evaluate(self, rule: Rule, event: object, ts: datetime) -> bool:
        """Return True when the rule's threshold fires for this event."""
        if rule.threshold is None:
            return True
        window = timedelta(seconds=rule.threshold.window_seconds)
        group_value = _group_value(rule, event)
        key = (rule.id, group_value)
        state = self._state.setdefault(key, _KeyState())

        # Prune observations outside the window (including out-of-order replay).
        # The window is half-open: an observation exactly ``window`` old is out.
        cutoff = ts - window
        while state.observations and state.observations[0] <= cutoff:
            state.observations.popleft()
        stale_values = [value for value, seen in state.distinct.items() if seen <= cutoff]
        for value in stale_values:
            del state.distinct[value]

        state.observations.append(ts)
        state.touched = ts
        if rule.threshold.distinct is not None:
            state.distinct[_value_for(rule, event)] = ts

        limit = rule.threshold.threshold
        if rule.threshold.distinct is not None:
            reached = len(state.distinct) >= limit
        else:
            reached = len(state.observations) >= limit

        if not reached:
            self._prune_older(ts)
            return False

        # Cooldown equals the window for this key.
        if state.last_fire is not None and ts - state.last_fire <= window:
            self._prune_older(ts)
            return False
        state.last_fire = ts
        self._prune_older(ts)
        return True

    def fire(self, rule: Rule, event: object, ts: datetime) -> None:
        """Mark a key as fired without threshold evaluation (direct alert rule)."""
        group_value = _group_value(rule, event)
        key = (rule.id, group_value)
        state = self._state.setdefault(key, _KeyState())
        state.last_fire = ts
        state.touched = ts

    def in_cooldown(self, rule: Rule, group_value: str, ts: datetime) -> bool:
        state = self._state.get((rule.id, group_value))
        if state is None or state.last_fire is None:
            return False
        if rule.threshold is None:
            return False
        return ts - state.last_fire <= timedelta(seconds=rule.threshold.window_seconds)

    def clear(self) -> None:
        self._state.clear()

    def snapshot(self) -> dict[tuple[str, str], int]:
        """Test helper: current observation counts per key."""
        return {key: len(state.observations) for key, state in self._state.items()}

    # ---- internals -----------------------------------------------------

    def _prune_older(self, now: datetime) -> None:
        if not self._state:
            return
        horizon = now - timedelta(seconds=STATE_TTL_FLOOR_S)
        for key in [k for k, s in self._state.items() if s.touched is not None and s.touched < horizon]:
            del self._state[key]

    def retain_compatible(self, ruleset_rules: tuple[Rule, ...]) -> None:
        """Keep threshold state only for rule IDs that still exist."""
        valid = {rule.id for rule in ruleset_rules}
        for key in [k for k in self._state if k[0] not in valid]:
            del self._state[key]


def _group_value(rule: Rule, event: object) -> str:
    field_name = rule.threshold.group_by if rule.threshold else "src_ip"
    raw = getattr(event, field_name, None)
    return "" if raw is None else str(raw)


def _value_for(rule: Rule, event: object) -> str:
    assert rule.threshold is not None and rule.threshold.distinct is not None
    raw = getattr(event, rule.threshold.distinct.field, None)
    return "" if raw is None else str(raw)