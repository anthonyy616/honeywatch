"""Markdown report generation.

Reports are built from read-only queries. Every attacker-controlled string is
sanitized and Markdown-escaped before it reaches the document.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from .sanitize import safe_markdown, safe_text
from .storage.queries import ReadStore

WINDOW_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


def parse_since(value: str | None) -> int | None:
    """Parse ``24h`` / ``7d`` / ``30m`` into seconds (``None`` = all time)."""
    if not value or value.lower() in {"all", "any", "0"}:
        return None
    text = value.strip().lower()
    if text.isdigit():
        return int(text)
    unit = text[-1]
    if unit not in WINDOW_UNITS or not text[:-1].isdigit():
        raise ValueError(f"invalid --since value {value!r} (use e.g. 30m, 24h, 7d)")
    factor = {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]
    return int(text[:-1]) * factor


def _table(rows: list[tuple[str, ...]], headers: tuple[str, ...]) -> list[str]:
    if not rows:
        return ["_none observed_", ""]
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    lines.append("")
    return lines


def _md(value: object, limit: int = 80) -> str:
    return safe_markdown(value, limit=limit) or "-"


def generate_report(
    store: ReadStore,
    *,
    since: str | None = "24h",
    scorer: object | None = None,
    title: str = "HoneyWatch Report",
) -> str:
    """Render a Markdown report for the selected window."""
    window = parse_since(since)
    window_label = since or "all time"
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: list[str] = [
        f"# {safe_text(title, limit=120)}",
        "",
        f"- Generated: {generated}",
        f"- Window: {safe_text(window_label, limit=40)}",
        "",
    ]

    totals = store.report_totals(window)
    lines += [
        "## Totals",
        "",
        f"- Events: {totals['events']}",
        f"- Unique source IPs: {totals['unique_ips']}",
        f"- Rule hits: {totals['rule_hits']}",
        "",
    ]

    lines += ["## Top attackers", ""]
    attacker_rows: list[tuple[str, ...]] = []
    for row in store.top_attackers(window_s=window, limit=10, scorer=scorer):
        attacker_rows.append(
            (
                _md(row.src_ip, 45),
                _md(row.geo_country or "??", 8),
                _md(row.as_org or "-", 28),
                str(row.event_count),
                f"{row.score:.1f}",
                _md(row.verdict, 12),
                _md(row.classification, 20),
            )
        )
    lines += _table(attacker_rows, ("IP", "CC", "ASN org", "Events", "Score", "Verdict", "Classification"))

    users, passwords = store.top_credentials(limit=10, window_s=window)
    lines += ["## Top credentials", ""]
    lines += _table(
        [(f"`{_md(u, 48)}`", str(c)) for u, c in users],
        ("Username", "Attempts"),
    )
    lines += _table(
        [(f"`{_md(p, 48)}`", str(c)) for p, c in passwords],
        ("Password", "Attempts"),
    )

    lines += ["## Most attempted commands", ""]
    command_rows = [
        (f"`{_md(c, 90)}`", str(n)) for c, n in store.report_group("command", window, limit=15)
    ]
    lines += _table(command_rows, ("Command", "Count"))

    lines += ["## Payload URLs observed (recorded, never fetched)", ""]
    url_rows = [
        (f"`{_md(url, 110)}`", f"`{_md(cmd, 60)}`", str(n))
        for url, cmd, n in store.report_payload_urls(window)
    ]
    lines += _table(url_rows, ("URL", "Command", "Count"))

    lines += ["## Rule detections", ""]
    rule_rows = [
        (_md(rid, 40), _md(title, 40), _md(attack or "-", 12), _md(sev, 10), str(count))
        for rid, title, attack, sev, count in store.report_rule_summary(window)
    ]
    lines += _table(rule_rows, ("Rule", "Title", "ATT&CK", "Severity", "Hits"))

    lines += ["## MITRE ATT&CK techniques observed", ""]
    techniques: dict[str, list[str]] = {}
    for rid, title, attack, _sev, count in store.report_rule_summary(window):
        if attack:
            techniques.setdefault(attack, []).append(f"{rid} ({count})")
    if techniques:
        lines += _table(
            [(_md(tech, 16), _md(", ".join(rules), 80)) for tech, rules in sorted(techniques.items())],
            ("Technique", "Rules"),
        )
    else:
        lines += ["_none observed_", ""]

    lines += ["## Notable sessions", ""]
    session_rows = [
        (
            _md(row["src_ip"], 45),
            _md(row["session_id"], 24),
            _md(row["first_ts"], 24),
            _md(row["last_ts"], 24),
            str(row["events"]),
        )
        for row in store.report_sessions(window)
    ]
    lines += _table(session_rows, ("Source IP", "Session", "First seen", "Last seen", "Events"))

    lines += [
        "## Interpretation",
        "",
        "HoneyWatch services are emulated. A recorded login success is a",
        "controlled honeypot decision, not evidence that a real host was",
        "compromised. Detections indicate observed probe or attempt behaviour.",
        "",
    ]
    return "\n".join(lines) + "\n"


def generate_ip_report(store: ReadStore, src_ip: str, scorer: object | None = None) -> str:
    """Render a single-attacker report (used by the TUI export key)."""
    detail = store.attacker_detail(src_ip, scorer=scorer)
    lines = [
        f"# Attacker report: {safe_text(src_ip, limit=60)}",
        "",
        f"- First seen: {safe_text(detail.first_seen or '-', limit=32)}",
        f"- Last seen: {safe_text(detail.last_seen or '-', limit=32)}",
        f"- Country: {safe_text(detail.geo_country or '??', limit=8)}",
        f"- ASN: {_md(detail.as_org or '-', 40)}",
        f"- Score: {detail.score:.2f}",
        f"- Verdict: {_md(detail.verdict, 16)}",
        f"- Classification: {_md(detail.classification, 24)}",
        "",
        "## Timeline (most recent first)",
        "",
    ]
    lines += _table(
        [
            (
                safe_text(row.ts, limit=24),
                safe_text(row.service, limit=6),
                safe_text(row.event_type, limit=22),
                f"`{_md(row.summary, 70)}`",
                _md(row.severity, 10),
            )
            for row in detail.timeline[:40]
        ],
        ("Time (UTC)", "Service", "Event", "Summary", "Severity"),
    )
    lines += ["## Credentials", ""]
    lines += _table([(f"`{_md(k, 60)}`", str(v)) for k, v in detail.credentials], ("Value", "Count"))
    lines += ["## Commands by session", ""]
    lines += _table(
        [(safe_text(ts, limit=24), safe_text(sid, limit=20), f"`{_md(cmd, 70)}`") for ts, sid, cmd in detail.commands],
        ("Time (UTC)", "Session", "Command"),
    )
    lines += ["## Rules fired", ""]
    lines += _table(
        [(_md(rid, 40), str(count), _md(attack or "-", 12), _md(sev, 10)) for rid, count, attack, sev in detail.rules],
        ("Rule", "Hits", "ATT&CK", "Severity"),
    )
    lines += ["## Payload URLs (recorded only)", ""]
    lines += _table(
        [(f"`{_md(url, 110)}`",) for url in detail.urls],
        ("URL",),
    )
    return "\n".join(lines) + "\n"


def default_since(hours: int = 24) -> str:  # pragma: no cover - helper
    return f"{timedelta(hours=hours)}"