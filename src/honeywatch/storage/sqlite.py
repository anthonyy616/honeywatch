"""SQLite operational storage (WAL) with an explicit schema version."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from ..models import AlertRecord, Event, RuleHit, Severity, iso

SCHEMA_VERSION = 1


class StorageError(RuntimeError):
    """Raised for unrecoverable storage failures. The daemon must fail loudly."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    service       TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    src_ip        TEXT    NOT NULL,
    src_port      INTEGER,
    session_id    TEXT    NOT NULL DEFAULT '',
    username      TEXT,
    password      TEXT,
    command       TEXT,
    http_method   TEXT,
    path          TEXT,
    query         TEXT,
    user_agent    TEXT,
    body_snippet  TEXT,
    client_banner TEXT,
    geo_country   TEXT,
    geo_city      TEXT,
    asn           INTEGER,
    as_org        TEXT,
    tags          TEXT    NOT NULL DEFAULT '',
    severity      TEXT    NOT NULL DEFAULT 'info'
);

CREATE TABLE IF NOT EXISTS rule_hits (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL REFERENCES events(id) ON DELETE CASCADE,
    rule_id     TEXT    NOT NULL,
    title       TEXT    NOT NULL DEFAULT '',
    attack      TEXT,
    attack_name TEXT,
    severity    TEXT    NOT NULL DEFAULT 'info',
    ts          TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT    NOT NULL,
    rule_id TEXT,
    src_ip  TEXT    NOT NULL,
    severity TEXT   NOT NULL,
    title   TEXT    NOT NULL DEFAULT '',
    status  TEXT    NOT NULL DEFAULT 'sent',
    detail  TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip    ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_session   ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_service   ON events(service);
CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_hits_event      ON rule_hits(event_id);
CREATE INDEX IF NOT EXISTS idx_hits_rule       ON rule_hits(rule_id);
CREATE INDEX IF NOT EXISTS idx_hits_ts         ON rule_hits(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ts       ON alerts(ts);
"""

_EVENT_COLUMNS: tuple[str, ...] = (
    "ts",
    "service",
    "event_type",
    "src_ip",
    "src_port",
    "session_id",
    "username",
    "password",
    "command",
    "http_method",
    "path",
    "query",
    "user_agent",
    "body_snippet",
    "client_banner",
    "geo_country",
    "geo_city",
    "asn",
    "as_org",
    "tags",
    "severity",
)


class Storage:
    """Write-side SQLite storage.

    All SQL is parameterized. Hostile strings are bound as values only.
    """

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=busy_timeout_ms / 1000)
        self._conn.row_factory = sqlite3.Row
        self._closed = False
        self._init_schema()

    # ---- lifecycle -----------------------------------------------------

    def _init_schema(self) -> None:
        cur = self._conn
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute(f"PRAGMA busy_timeout={5000}")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.executescript(_SCHEMA)
        cur.execute(
            "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )

    def close(self) -> None:
        """Close the connection; safe to call more than once."""
        if not self._closed:
            try:
                self._conn.commit()
            finally:
                self._conn.close()
                self._closed = True

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def closed(self) -> bool:
        return self._closed

    def schema_version(self) -> int:
        row = self._conn.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()
        return int(row["value"]) if row else 0

    # ---- writes --------------------------------------------------------

    def insert_event(self, event: Event, hits: Sequence[RuleHit] = ()) -> int:
        """Insert one enriched event plus its rule hits transactionally.

        Returns:
            The assigned row id.
        """
        values = (
            iso(event.ts),
            str(event.service),
            str(event.event_type),
            event.src_ip,
            event.src_port,
            event.session_id or "",
            event.username,
            event.password,
            event.command,
            event.http_method,
            event.path,
            event.query,
            event.user_agent,
            event.body_snippet,
            event.client_banner,
            event.geo_country,
            event.geo_city,
            event.asn,
            event.as_org,
            ",".join(event.tags),
            str(event.severity),
        )
        placeholders = ",".join("?" * len(_EVENT_COLUMNS))
        columns = ",".join(_EVENT_COLUMNS)
        try:
            cur = self._conn.execute(
                f"INSERT INTO events ({columns}) VALUES ({placeholders})",  # noqa: S608 - fixed columns
                values,
            )
        except sqlite3.Error as exc:
            raise StorageError(f"failed to insert event: {exc}") from exc
        event_id = int(cur.lastrowid or 0)
        for hit in hits:
            self._conn.execute(
                "INSERT INTO rule_hits (event_id, rule_id, title, attack, attack_name, severity, ts)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (event_id, *hit.to_row()),
            )
        if event.id is None:
            event.id = event_id
        return event_id

    def insert_alert(self, alert: AlertRecord) -> int:
        """Insert one alert audit row and return its id."""
        cur = self._conn.execute(
            "INSERT INTO alerts (ts, rule_id, src_ip, severity, title, status, detail)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                iso(alert.ts),
                alert.rule_id,
                alert.src_ip,
                str(alert.severity),
                alert.title,
                alert.status,
                alert.detail,
            ),
        )
        return int(cur.lastrowid or 0)

    # ---- maintenance ---------------------------------------------------

    def stats(self) -> dict[str, Any]:
        """Return aggregate counts for `honeywatch db stats`."""
        conn = self._conn
        total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
        unique_ips = conn.execute("SELECT COUNT(DISTINCT src_ip) AS c FROM events").fetchone()["c"]
        sessions = conn.execute("SELECT COUNT(DISTINCT session_id) AS c FROM events").fetchone()["c"]
        hits = conn.execute("SELECT COUNT(*) AS c FROM rule_hits").fetchone()["c"]
        alerts = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        oldest = conn.execute("SELECT MIN(ts) AS t FROM events").fetchone()["t"]
        newest = conn.execute("SELECT MAX(ts) AS t FROM events").fetchone()["t"]
        size = self.path.stat().st_size if self.path.exists() else 0
        by_service = {
            row["service"]: row["c"]
            for row in conn.execute("SELECT service, COUNT(*) AS c FROM events GROUP BY service")
        }
        by_severity = {
            row["severity"]: row["c"]
            for row in conn.execute("SELECT severity, COUNT(*) AS c FROM events GROUP BY severity")
        }
        return {
            "events": total,
            "unique_ips": unique_ips,
            "sessions": sessions,
            "rule_hits": hits,
            "alerts": alerts,
            "oldest": oldest,
            "newest": newest,
            "bytes": size,
            "schema_version": self.schema_version(),
            "by_service": by_service,
            "by_severity": by_severity,
        }

    def prune(self, older_than_iso: str) -> int:
        """Delete events (and cascaded hits/alerts-free rows) before a timestamp.

        The raw JSONL archive is deliberately untouched.
        """
        cur = self._conn.execute("DELETE FROM events WHERE ts < ?", (older_than_iso,))
        deleted = cur.rowcount or 0
        self._conn.execute(
            "DELETE FROM rule_hits WHERE event_id NOT IN (SELECT id FROM events)"
        )
        return deleted

    def vacuum(self) -> None:
        self._conn.execute("VACUUM")

    # ---- minimal helpers used by tests ---------------------------------

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, tuple(params))