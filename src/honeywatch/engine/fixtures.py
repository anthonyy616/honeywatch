"""Rule fixture runner.

Shared by ``honeywatch rules test`` and the test suite so CI and the CLI can
never disagree about rule coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import sys

from ..models import Event
from .detector import DetectionEngine
from .loader import load_ruleset


@dataclass(slots=True)
class FixtureResult:
    """Aggregated fixture outcome."""

    total: int = 0
    passed: int = 0
    lines: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.total > 0 and self.passed == self.total

    @property
    def failures(self) -> list[str]:
        return [line for line in self.lines if line.startswith("FAIL")]

    def add(self, line: str, *, passed: bool) -> None:
        """Record one fixture outcome line."""
        self.total += 1
        if passed:
            self.passed += 1
        self.lines.append(f"{'PASS' if passed else 'FAIL'} {line}")


def _event_from(payload: dict[str, Any]) -> Event:
    data = dict(payload)
    raw_ts = data.get("ts")
    if isinstance(raw_ts, str):
        data["ts"] = datetime.fromisoformat(raw_ts.replace("Z", "+00:00")).astimezone(UTC)
    return Event.model_validate(data)


def run_fixture_cases(cases: Any, ruleset: Any) -> list[tuple[str, bool, str]]:
    """Evaluate every fixture against a fresh engine.

    Each case gets its own engine so threshold state never leaks between
    fixtures, which is what makes the results deterministic.

    Returns:
        ``(description, passed, detail)`` triples.
    """
    engine = DetectionEngine(ruleset.rules)
    outcomes: list[tuple[str, bool, str]] = []
    for case in cases:
        fresh = DetectionEngine(ruleset.rules)
        fired: set[str] = set()
        for payload in case.events:
            hits = fresh.evaluate(_event_from(payload))
            fired.update(hit.rule_id for hit in hits)
        expected = case.expect_hit
        passed = (case.rule_id in fired) is expected
        detail = ",".join(sorted(fired)) or "none"
        outcomes.append(
            (
                f"{case.rule_id} [{case.kind}] {case.description}",
                passed,
                f"fired={detail}",
            )
        )
    del engine
    return outcomes


def load_default_cases() -> tuple[Any, ...] | None:
    """Load the repository fixtures by path.

    The fixtures live under ``tests/fixtures/`` (see the repository layout),
    so they are loaded by file path rather than imported as an installed
    module. Returns ``None`` when they cannot be found (e.g. an installed
    wheel without the test tree).
    """
    import importlib.util

    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / "tests" / "fixtures" / "rule_fixtures.py",
        Path.cwd() / "tests" / "fixtures" / "rule_fixtures.py",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        spec = importlib.util.spec_from_file_location("honeywatch_rule_fixtures", path)
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        # Register before exec so dataclasses can resolve their own module.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return tuple(module.FIXTURES)
    return None


def run_fixtures(rules_directory: str | Path, cases: Any = None) -> FixtureResult:
    """Run every fixture for the shipped ruleset."""
    if cases is None:
        cases = load_default_cases()
    if cases is None:
        result = FixtureResult()
        result.add(
            "fixtures [coverage] repository fixtures not found (tests/fixtures/rule_fixtures.py)",
            passed=False,
        )
        return result

    ruleset = load_ruleset(rules_directory)
    result = FixtureResult()
    for description, passed, detail in run_fixture_cases(cases, ruleset):
        result.add(f"{description}  ({detail})", passed=passed)

    covered = {case.rule_id for case in cases if case.expect_hit}
    missing = sorted(set(ruleset.ids) - covered)
    for rule_id in missing:
        result.add(f"{rule_id} [coverage] shipped rule has no positive fixture", passed=False)
    return result
