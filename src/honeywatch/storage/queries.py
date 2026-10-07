"""Read-only query layer for the TUI and report generator.

Opened with ``file:...?mode=ro`` so a bug can never write through the UI or
report process. Every attacker-controlled value is bound as a parameter.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from ..models import Event, iso

MAX_FEED_ROWS = 300
MAX_TABLE_ROWS = 20
MAX_SPARKLINE_BUCKETS = 60


def _row_summary(data: dict[str, Any]) -> str:
    """Rebuild the display summary for a stored event row.

    ``summary`` is a derived presentation value (see docs/EVENT_SCHEMA.md),
    not a stored column, so it is recomputed from the row using the same
    rules the pipeline uses for live events.
    """
    try:
        payload = dict(data)
        payload["tags"] = [tag for tag in (payload.get("tags") or "").split(",") if tag]
        return Event.model_validate(payload).summary()
    except (ValueError, TypeError):  # pragma: no cover - defensive
        return str(data.get("event_type") or "")


@dataclass(slots=True)
class FeedRow:
    id: int
    ts: str
    service: str
    event_type: str
    src_ip: str
    geo_country: str | None
    username: str | None
    password: str | None
    command: str | None
    path: str | None
    http_method: str | None
    severity: str
    summary: str


@dataclass(slots=True)
class AttackerRow:
    src_ip: str
    geo_country: str | None
    as_org: str | None
    event_count: int
    score: float
    verdict: str
    classification: str
    first_seen: str | None = None
    last_seen: str | None = None


@dataclass(slots=True)
class MetricRow:
    label: str
    value: float


@dataclass(slots=True)
class AttackerDetail:
    src_ip: str
    geo_country: str | None = None
    geo_city: str | None = None
    asn: int | None = None
    as_org: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None
    score: float = 0.0
    verdict: str = "Noise"
    classification: str = "Unclassified"
    timeline: list[FeedRow] = field(default_factory=list)
    credentials: list[tuple[str, int]] = field(default_factory=list)
    commands: list[tuple[str, str, str]] = field(default_factory=list)
    rules: list[tuple[str, str, str | None, str]] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


class ReadStore:
    """Read-only SQLite access for presentation layers."""

    def __init__(self, path: str | Path, *, uri: bool = True) -> None:
        db_path = Path(path)
        if uri:
            self._conn = sqlite3.connect(
                f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
            )
        else:  # pragma: no cover - used only when the file may not exist yet
            self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA query_only=ON")

    def close(self) -> None:
        try:
            self._conn.close()
        except sqlite3.Error:  # pragma: no cover - defensive
            pass

    def __enter__(self) -> ReadStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- primitives ----------------------------------------------------

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        try:
            return list(self._conn.execute(sql, tuple(params)))
        except sqlite3.Error:
            return []

    @staticmethod
    def _since_expr(window_s: int | None) -> tuple[str, list[Any]]:
        if window_s is None:
            return "", []
        cutoff = iso(datetime.now(UTC) - timedelta(seconds=window_s))
        return "AND ts >= ?", [cutoff]

    @staticmethod
    def _feed_from_row(row: sqlite3.Row) -> FeedRow:
        data = dict(row)
        return FeedRow(
            id=data["id"],
            ts=data["ts"],
            service=data["service"],
            event_type=data["event_type"],
            src_ip=data["src_ip"],
            geo_country=data["geo_country"],
            username=data["username"],
            password=data["password"],
            command=data["command"],
            path=data["path"],
            http_method=data["http_method"],
            severity=data["severity"],
            summary=_row_summary(data),
        )

    # ---- dashboard -----------------------------------------------------

    def top_metrics(self, window_s: int | None = None) -> dict[str, Any]:
        where, params = self._since_expr(window_s)
        total = self._query(f"SELECT COUNT(*) AS c FROM events WHERE 1=1 {where}", params)
        ips = self._query(f"SELECT COUNT(DISTINCT src_ip) AS c FROM events WHERE 1=1 {where}", params)
        alerts = self._query("SELECT COUNT(*) AS c FROM alerts")
        newest = self._query("SELECT MAX(ts) AS t FROM events")
        last_hour = self._query(
            "SELECT COUNT(*) AS c FROM events WHERE ts >= ?",
            [iso(datetime.now(UTC) - timedelta(hours=1))],
        )
        last_seen = newest[0]["t"] if newest else None
        age: float | None = None
        if last_seen:
            try:
                age = (datetime.now(UTC) - datetime.fromisoformat(last_seen.replace("Z", "+00:00"))).total_seconds()
            except ValueError:  # pragma: no cover - defensive
                age = None
        return {
            "events": total[0]["c"] if total else 0,
            "unique_ips": ips[0]["c"] if ips else 0,
            "alerts": alerts[0]["c"] if alerts else 0,
            "events_last_hour": last_hour[0]["c"] if last_hour else 0,
            "last_event_age_s": age,
            "last_event_ts": last_seen,
        }

    def feed(
        self,
        *,
        after_id: int = 0,
        limit: int = 50,
        window_s: int | None = None,
        text: str | None = None,
    ) -> list[FeedRow]:
        """Newest-first feed rows, optionally strictly newer than ``after_id``."""
        clauses = ["1=1"]
        params: list[Any] = []
        if after_id:
            clauses.append("id > ?")
            params.append(after_id)
        if window_s is not None:
            clauses.append("ts >= ?")
            params.append(iso(datetime.now(UTC) - timedelta(seconds=window_s)))
        if text:
            clauses.append("(src_ip LIKE ? OR username LIKE ? OR command LIKE ? OR path LIKE ?)")
            needle = f"%{text}%"
            params.extend([needle] * 4)
        rows = self._query(
            "SELECT * FROM events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY id DESC LIMIT ?",
            [*params, max(1, min(limit, MAX_FEED_ROWS))],
        )
        return [self._feed_from_row(r) for r in rows]

    def top_attackers(
        self,
        *,
        window_s: int | None = None,
        limit: int = MAX_TABLE_ROWS,
        scorer: Any = None,
    ) -> list[AttackerRow]:
        where, params = self._since_expr(window_s)
        rows = self._query(
            "SELECT src_ip, geo_country, as_org, COUNT(*) AS c, MIN(ts) AS f, MAX(ts) AS l"
            f" FROM events WHERE 1=1 {where} GROUP BY src_ip ORDER BY c DESC LIMIT ?",
            [*params, max(1, min(limit, MAX_TABLE_ROWS))],
        )
        out: list[AttackerRow] = []
        for row in rows:
            score, verdict, classification = 0.0, "Noise", "Unclassified"
            if scorer is not None:
                score = scorer.score_ip(row["src_ip"], now=datetime.now(UTC))
                verdict = scorer.verdict(score)
                classification = scorer.classify(row["src_ip"], now=datetime.now(UTC))
            out.append(
                AttackerRow(
                    src_ip=row["src_ip"],
                    geo_country=row["geo_country"],
                    as_org=row["as_org"],
                    event_count=row["c"],
                    score=score,
                    verdict=verdict,
                    classification=classification,
                    first_seen=row["f"],
                    last_seen=row["l"],
                )
            )
        return out

    def top_credentials(self, limit: int = MAX_TABLE_ROWS, window_s: int | None = None) -> tuple[list[tuple[str, int]], list[tuple[str, int]]]:
        where, params = self._since_expr(window_s)
        users = self._query(
            "SELECT username AS k, COUNT(*) AS c FROM events"
            f" WHERE username IS NOT NULL AND username != '' {where}"
            " GROUP BY username ORDER BY c DESC LIMIT ?",
            [*params, max(1, limit)],
        )
        passwords = self._query(
            "SELECT password AS k, COUNT(*) AS c FROM events"
            f" WHERE password IS NOT NULL AND password != '' {where}"
            " GROUP BY password ORDER BY c DESC LIMIT ?",
            [*params, max(1, limit)],
        )
        return (
            [(r["k"], r["c"]) for r in users],
            [(r["k"], r["c"]) for r in passwords],
        )

    def sparkline(self, minutes: int = 30, window_s: int | None = None) -> list[int]:
        """Events-per-minute buckets, oldest first, for the TUI sparkline."""
        span = max(1, minutes)
        now = datetime.now(UTC)
        start = now - timedelta(minutes=span)
        rows = self._query(
            "SELECT ts FROM events WHERE ts >= ? ORDER BY ts ASC",
            [iso(start)],
        )
        buckets = [0] * span
        for row in rows:
            try:
                stamp = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
            except ValueError:  # pragma: no cover - defensive
                continue
            offset = int((stamp - start).total_seconds() // 60)
            if 0 <= offset < span:
                buckets[offset] += 1
        return buckets

    def rule_category_bars(self, window_s: int | None = None) -> list[tuple[str, int]]:
        where, params = self._since_expr(window_s)
        rows = self._query(
            "SELECT rule_id AS k, COUNT(*) AS c FROM rule_hits WHERE 1=1"
            f" {where} GROUP BY rule_id ORDER BY c DESC LIMIT 10",
            params,
        )
        return [(r["k"], r["c"]) for r in rows]

    def country_breakdown(self, window_s: int | None = None, limit: int = 8) -> list[tuple[str, int]]:
        where, params = self._since_expr(window_s)
        rows = self._query(
            "SELECT COALESCE(geo_country, '??') AS k, COUNT(*) AS c FROM events"
            f" WHERE 1=1 {where} GROUP BY k ORDER BY c DESC LIMIT ?",
            [*params, max(1, limit)],
        )
        return [(r["k"], r["c"]) for r in rows]

    # ---- detail screens ------------------------------------------------

    def attacker_detail(self, src_ip: str, scorer: Any = None, limit: int = 60) -> AttackerDetail:
        rows = self._query(
            "SELECT geo_country, geo_city, asn, as_org, MIN(ts) AS f, MAX(ts) AS l"
            " FROM events WHERE src_ip = ? GROUP BY src_ip",
            [src_ip],
        )
        detail = AttackerDetail(src_ip=src_ip)
        if rows:
            r = rows[0]
            detail.geo_country = r["geo_country"]
            detail.geo_city = r["geo_city"]
            detail.asn = r["asn"]
            detail.as_org = r["as_org"]
            detail.first_seen = r["f"]
            detail.last_seen = r["l"]
        if scorer is not None:
            now = datetime.now(UTC)
            detail.score = scorer.score_ip(src_ip, now=now)
            detail.verdict = scorer.verdict(detail.score)
            detail.classification = scorer.classify(src_ip, now=now)

        timeline = self._query(
            "SELECT * FROM events WHERE src_ip = ? ORDER BY id DESC LIMIT ?",
            [src_ip, max(1, min(limit, MAX_FEED_ROWS))],
        )
        detail.timeline = [self._feed_from_row(r) for r in timeline]

        users = self._query(
            "SELECT username AS k, COUNT(*) AS c FROM events WHERE src_ip = ? AND username IS NOT NULL"
            " GROUP BY username ORDER BY c DESC LIMIT 10",
            [src_ip],
        )
        passwords = self._query(
            "SELECT password AS k, COUNT(*) AS c FROM events WHERE src_ip = ? AND password IS NOT NULL"
            " GROUP BY password ORDER BY c DESC LIMIT 10",
            [src_ip],
        )
        detail.credentials = [(r["k"], r["c"]) for r in users] + [
            (f"pw:{r['k']}", r["c"]) for r in passwords
        ]

        commands = self._query(
            "SELECT session_id, ts, command FROM events WHERE src_ip = ? AND command IS NOT NULL"
            " ORDER BY id DESC LIMIT 40",
            [src_ip],
        )
        detail.commands = [(r["ts"], r["session_id"], r["command"] or "") for r in commands]

        rules = self._query(
            "SELECT h.rule_id AS k, h.attack AS a, h.severity AS s, COUNT(*) AS c"
            " FROM rule_hits h JOIN events e ON e.id = h.event_id"
            " WHERE e.src_ip = ? GROUP BY h.rule_id, h.attack, h.severity ORDER BY c DESC LIMIT 20",
            [src_ip],
        )
        detail.rules = [(r["k"], r["c"], r["a"], r["s"]) for r in rules]

        urls = self._query(
            "SELECT command AS k FROM events WHERE src_ip = ? AND"
            " (command LIKE '%http://%' OR command LIKE '%https://%' OR command LIKE '%ftp://%')"
            " ORDER BY id DESC LIMIT 20",
            [src_ip],
        )
        from ..honeypots.shell import extract_urls

        seen: set[str] = set()
        for row in urls:
            for url in extract_urls(row["k"] or ""):
                if url not in seen:
                    seen.add(url)
                    detail.urls.append(url)
        return detail

    def rules_with_hits(self) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT rule_id AS id, COUNT(*) AS hits, MAX(ts) AS last_ts"
            " FROM rule_hits GROUP BY rule_id ORDER BY hits DESC"
        )
        return [dict(r) for r in rows]

    def alerts(self, limit: int = MAX_TABLE_ROWS) -> list[dict[str, Any]]:
        rows = self._query(
            "SELECT ts, rule_id, src_ip, severity, title, status, detail FROM alerts"
            " ORDER BY id DESC LIMIT ?",
            [max(1, min(limit, 200))],
        )
        return [dict(r) for r in rows]

    def alert_counts(self) -> dict[str, int]:
        return {
            r["status"]: r["c"]
            for r in self._query("SELECT status, COUNT(*) AS c FROM alerts GROUP BY status")
        }

    # ---- report queries ------------------------------------------------

    def report_totals(self, window_s: int | None) -> dict[str, Any]:
        where, params = self._since_expr(window_s)
        events = self._query(f"SELECT COUNT(*) AS c FROM events WHERE 1=1 {where}", params)[0]["c"]
        ips = self._query(
            f"SELECT COUNT(DISTINCT src_ip) AS c FROM events WHERE 1=1 {where}", params
        )[0]["c"]
        hits = self._query(
            "SELECT COUNT(*) AS c FROM rule_hits h JOIN events e ON e.id=h.event_id"
            + (f" WHERE e.ts >= ?" if window_s else ""),
            [iso(datetime.now(UTC) - timedelta(seconds=window_s))] if window_s else [],
        )[0]["c"]
        return {"events": events, "unique_ips": ips, "rule_hits": hits}

    def report_group(self, column: str, window_s: int | None, limit: int = 10) -> list[tuple[str, int]]:
        """Aggregate one known-safe column. ``column`` comes from code only."""
        allowed = {"username", "password", "command", "src_ip", "user_agent", "path"}
        if column not in allowed:
            raise ValueError(f"unsupported report column: {column!r}")
        where, params = self._since_expr(window_s)
        rows = self._query(
            f"SELECT {column} AS k, COUNT(*) AS c FROM events"  # noqa: S608 - allowlisted column
            f" WHERE {column} IS NOT NULL AND {column} != '' {where}"
            " GROUP BY k ORDER BY c DESC LIMIT ?",
            [*params, limit],
        )
        return [(r["k"], r["c"]) for r in rows]

    def report_rule_summary(self, window_s: int | None) -> list[tuple[str, str, str | None, str, int]]:
        where, params = self._since_expr(window_s)
        rows = self._query(
            "SELECT h.rule_id AS id, h.title AS title, h.attack AS attack, h.severity AS sev,"
            " COUNT(*) AS c FROM rule_hits h JOIN events e ON e.id = h.event_id"
            f" WHERE 1=1 {where} GROUP BY h.rule_id ORDER BY c DESC",
            params,
        )
        return [(r["id"], r["title"], r["attack"], r["sev"], r["c"]) for r in rows]

    def report_sessions(self, window_s: int | None, limit: int = 5) -> list[dict[str, Any]]:
        where, params = self._since_expr(window_s)
        rows = self._query(
            "SELECT src_ip, session_id, MIN(ts) AS first_ts, MAX(ts) AS last_ts,"
            " COUNT(*) AS events FROM events"
            f" WHERE session_id != '' {where} GROUP BY src_ip, session_id"
            " ORDER BY events DESC LIMIT ?",
            [*params, limit],
        )
        return [dict(r) for r in rows]

    def report_payload_urls(self, window_s: int | None, limit: int = 25) -> list[tuple[str, str, int]]:
        commands = self.report_group("command", window_s, limit=limit)
        out: list[tuple[str, str, int]] = []
        from ..honeypots.shell import extract_urls

        for command, count in commands:
            for url in extract_urls(command):
                out.append((url, command, count))
        return out