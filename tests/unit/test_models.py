"""Event model validation and capture-limit tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from honeywatch.models import (
    MAX_COMMAND,
    MAX_PASSWORD,
    MAX_PATH,
    Event,
    EventType,
    Service,
    Severity,
    iso,
    max_severity,
    severity_at_least,
)


def make_event(**overrides) -> Event:
    payload: dict = {
        "ts": datetime(2026, 3, 12, 9, 0, tzinfo=UTC),
        "service": Service.SSH,
        "event_type": EventType.LOGIN_ATTEMPT,
        "src_ip": "203.0.113.10",
        "session_id": "abc123",
    }
    payload.update(overrides)
    return Event(**payload)


def test_naive_timestamps_become_utc() -> None:
    event = make_event(ts=datetime(2026, 3, 12, 9, 0))
    assert event.ts.tzinfo is not None


def test_iso_format_uses_z() -> None:
    assert iso(datetime(2026, 3, 12, 9, 0, tzinfo=UTC)).endswith("Z")


def test_password_is_truncated_at_capture() -> None:
    event = make_event(password="p" * 5000)
    assert len(event.password or "") == MAX_PASSWORD


def test_command_is_truncated_at_capture() -> None:
    event = make_event(command="c" * 5000)
    assert len(event.command or "") == MAX_COMMAND


def test_path_is_truncated_at_capture() -> None:
    event = make_event(path="/" + "a" * 5000)
    assert len(event.path or "") == MAX_PATH


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_event(unexpected="x")


def test_summary_variants() -> None:
    assert "login" in make_event().summary()
    assert make_event(event_type=EventType.COMMAND, command="uname -a").summary().startswith("cmd")
    assert make_event(
        service=Service.HTTP, event_type=EventType.HTTP_REQUEST, http_method="GET", path="/.env"
    ).summary() == "GET /.env"
    assert make_event(
        service=Service.HTTP,
        event_type=EventType.HTTP_LOGIN_ATTEMPT,
        path="/wp-login.php",
        username="a",
        password="b",
    ).summary().startswith("POST /wp-login.php")


def test_to_json_dict_is_flat_and_stable() -> None:
    data = make_event().to_json_dict()
    assert "geo_country" in data and data["geo_country"] is None
    assert data["ts"].endswith("Z")
    assert data["severity"] == "info"


def test_severity_ordering() -> None:
    assert severity_at_least(Severity.CRITICAL, Severity.HIGH)
    assert not severity_at_least(Severity.LOW, Severity.HIGH)
    assert max_severity([Severity.LOW, Severity.CRITICAL, Severity.INFO]) is Severity.CRITICAL
    assert max_severity([]) is Severity.INFO


def test_roundtrip_serialization() -> None:
    event = make_event(username="root", password="123456")
    again = Event.model_validate(event.to_json_dict())
    assert again.username == "root"
    assert again.ts == event.ts