"""Shared pytest fixtures."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from honeywatch.config import parse_config  # noqa: E402
from honeywatch.engine.detector import DetectionEngine  # noqa: E402
from honeywatch.engine.loader import load_ruleset  # noqa: E402
from honeywatch.models import Event  # noqa: E402
from honeywatch.storage.sqlite import Storage  # noqa: E402

RULES_DIR = REPO_ROOT / "rules"


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def rules_dir() -> Path:
    return RULES_DIR


@pytest.fixture(scope="session")
def ruleset():
    loaded = load_ruleset(RULES_DIR)
    assert not loaded.errors, f"shipped rules must be valid: {loaded.errors}"
    return loaded


@pytest.fixture
def detector(ruleset) -> DetectionEngine:
    return DetectionEngine(ruleset.rules)


@pytest.fixture
def config(tmp_path: Path):
    return parse_config({"data_dir": str(tmp_path / "data")}, base_dir=tmp_path)


@pytest.fixture
def storage(tmp_path: Path) -> Storage:
    store = Storage(tmp_path / "test.db")
    yield store
    store.close()


def make_event(**overrides) -> Event:
    """Build a valid event with sensible defaults."""
    from datetime import UTC, datetime

    payload: dict = {
        "ts": datetime(2026, 3, 12, 9, 0, tzinfo=UTC),
        "service": "ssh",
        "event_type": "login_attempt",
        "src_ip": "203.0.113.10",
        "session_id": "test-0001",
    }
    payload.update(overrides)
    return Event.model_validate(payload)