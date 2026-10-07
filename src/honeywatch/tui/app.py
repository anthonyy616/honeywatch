"""Textual dashboard.

Read-only by construction: the store is opened with ``mode=ro`` and
``PRAGMA query_only=ON``. Every attacker-controlled value is sanitized before
it becomes a Textual renderable, so hostile strings cannot inject markup or
terminal control sequences.

The layout is designed to remain usable at 80x24.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from pathlib import Path
from typing import Any

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen, Screen
from textual.widgets import DataTable, Footer, Header, Input, Label, Static, TabbedContent, TabPane

from ..models import Severity
from ..sanitize import safe_markup, safe_text
from ..scoring_service import Scorer
from ..storage.queries import FeedRow, ReadStore

logger = logging.getLogger("honeywatch.tui")

RANGES: dict[str, int | None] = {"15 min": 900, "1 hour": 3600, "24 hours": 86400, "all": None}
RANGE_KEYS = {"1": "15 min", "2": "1 hour", "3": "24 hours", "4": "all"}
MAX_ROWS = 200
BLOCKS = "▁▂▃▄▅▆▇█"

HELP_TEXT = (
    "[b]Key bindings[/b]\n"
    "q  quit        p  pause/resume feed\n"
    "/  filter      Enter  open attacker\n"
    "Esc back       r  rules screen\n"
    "a  alerts      e  export selected IP\n"
    "1  15 min      2  1 hour   3  24 hours   4  all\n"
    "?  help\n\n"
    "[b]Safety[/b]\n"
    "This dashboard is read-only and never stops collection.\n"
    "Attacker strings are sanitized before display."
)


class HelpScreen(ModalScreen[None]):
    """Modal key-binding reference."""

    BINDINGS = [Binding("escape,q,question_mark", "dismiss_help", "Close", show=True)]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-dialog"):
            yield Static(HELP_TEXT, id="help-body")

    def action_dismiss_help(self) -> None:
        self.dismiss(None)


class FilterScreen(ModalScreen[str | None]):
    """Modal text filter prompt."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def compose(self) -> ComposeResult:
        with Vertical(id="filter-dialog"):
            yield Label("Filter (substring of IP, user, command or path)")
            yield Input(placeholder="type filter, Enter to apply", id="filter-input")

    @on(Input.Submitted, "#filter-input")
    def _apply(self, event: Input.Submitted) -> None:
        self.dismiss(event.value or None)

    def action_cancel(self) -> None:
        self.dismiss(None)


class AttackerScreen(Screen[None]):
    """Detail view for one source address."""

    BINDINGS = [
        Binding("escape,q,backspace", "back", "Back"),
        Binding("e", "export", "Export"),
    ]

    def __init__(self, src_ip: str, store: ReadStore, scorer: Scorer) -> None:
        super().__init__()
        self.src_ip = src_ip
        self.store = store
        self.scorer = scorer

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        detail = self.store.attacker_detail(self.src_ip, scorer=self.scorer)
        header = (
            f"[b]{safe_markup(self.src_ip, 45)}[/b]  "
            f"{safe_markup(detail.geo_country or '??', 8)} "
            f"{safe_markup(detail.geo_city or '', 24)} "
            f"{safe_markup(detail.as_org or '-', 30)}\n"
            f"score {detail.score:.1f}  verdict {safe_markup(detail.verdict, 14)}  "
            f"class {safe_markup(detail.classification, 22)}\n"
            f"first {safe_markup(detail.first_seen or '-', 26)}  last "
            f"{safe_markup(detail.last_seen or '-', 26)}"
        )
        yield Static(header, id="detail-header")
        with TabbedContent():
            with TabPane("Timeline"):
                yield VerticalScroll(Static(_detail_timeline(detail.timeline), id="detail-timeline"))
            with TabPane("Commands"):
                yield VerticalScroll(Static(_detail_commands(detail.commands), id="detail-commands"))
            with TabPane("Rules"):
                yield VerticalScroll(Static(_detail_rules(detail.rules), id="detail-rules"))
            with TabPane("URLs"):
                yield VerticalScroll(Static(_detail_urls(detail.urls), id="detail-urls"))
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()  # type: ignore[attr-defined]

    def action_export(self) -> None:
        self.app.export_ip(self.src_ip)  # type: ignore[attr-defined]


class RulesScreen(Screen[None]):
    """Loaded rules with hit counts."""

    BINDINGS = [Binding("escape,q,backspace", "back", "Back")]

    def __init__(self, store: ReadStore, rules: Any = None) -> None:
        super().__init__()
        self.store = store
        self.rules = rules

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        hits = {row["id"]: row["hits"] for row in self.store.rules_with_hits()}
        table = DataTable(id="rules-table", cursor_type="row")
        yield VerticalScroll(table)
        yield Footer()
        table.add_columns("Rule", "Severity", "ATT&CK", "Hits")
        for rule in sorted(getattr(self.rules, "rules", self.rules or []), key=lambda r: r.id):
            table.add_row(
                safe_markup(rule.id, 34),
                safe_markup(str(rule.severity), 10),
                safe_markup(rule.attack or "-", 12),
                str(hits.get(rule.id, 0)),
            )

    def action_back(self) -> None:
        self.app.pop_screen()  # type: ignore[attr-defined]


class AlertsScreen(Screen[None]):
    """Alert audit history."""

    BINDINGS = [Binding("escape,q,backspace", "back", "Back")]

    def __init__(self, store: ReadStore) -> None:
        super().__init__()
        self.store = store

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        table = DataTable(id="alerts-table", cursor_type="row")
        yield VerticalScroll(table)
        yield Footer()
        table.add_columns("Time (UTC)", "Status", "Severity", "Rule", "Source")
        for row in self.store.alerts(limit=100):
            table.add_row(
                safe_markup(row["ts"], 26),
                safe_markup(row["status"], 12),
                safe_markup(row["severity"], 10),
                safe_markup(row["rule_id"] or "-", 28),
                safe_markup(row["src_ip"], 45),
            )

    def action_back(self) -> None:
        self.app.pop_screen()  # type: ignore[attr-defined]


class HoneyWatchTUI(App[None]):
    """Read-only operational dashboard over SQLite."""

    CSS = """
    Screen { background: $surface; }
    #metrics { height: 3; dock: top; }
    #feed { height: 1fr; }
    #tables { height: 10; }
    #bottom { height: 6; dock: bottom; }
    #help-dialog, #filter-dialog {
        width: 70; height: auto; padding: 1 2;
        border: thick $accent; background: $surface;
    }
    #help-dialog { height: 24; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("p", "toggle_pause", "Pause"),
        Binding("slash", "filter", "Filter"),
        Binding("enter", "open_selected", "Open"),
        Binding("r", "show_rules", "Rules"),
        Binding("a", "show_alerts", "Alerts"),
        Binding("e", "export_selected", "Export"),
        Binding("question_mark", "show_help", "Help"),
        Binding("1", "range_15m", "15m"),
        Binding("2", "range_1h", "1h"),
        Binding("3", "range_24h", "24h"),
        Binding("4", "range_all", "All"),
    ]

    def __init__(
        self,
        db_path: Path | str,
        *,
        refresh: float = 1.0,
        pipeline: Any = None,
        config: Any = None,
    ) -> None:
        super().__init__()
        self.db_path = Path(db_path)
        self.refresh_interval = max(0.2, float(refresh))
        self.store = ReadStore(self.db_path)
        self.scorer = Scorer(self.store)
        self.config = config
        self._load_rules()
        self.pipeline = pipeline
        self.paused = False
        self.filter_text: str | None = None
        self.range_label = "24 hours"
        self.last_id = 0
        self.retained: list[FeedRow] = []
        self._pending: list[FeedRow] = []

    # ---- setup ---------------------------------------------------------

    def _load_rules(self) -> None:
        """Load rules from the injected config, falling back to the default one."""
        from ..config import ConfigError, load_config
        from ..engine.loader import load_ruleset

        config = self.config
        if config is None:
            try:
                config = load_config(None)
            except ConfigError:
                self.ruleset = None
                return
        self.ruleset = load_ruleset(config.rules_dir)
        self.scorer.load_rule_tags(self.ruleset.rules)

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(id="metrics")
        with Horizontal(id="tables"):
            attackers = DataTable(id="attackers", cursor_type="row", zebra_stripes=True)
            yield attackers
            credentials = DataTable(id="credentials", cursor_type="row", zebra_stripes=True)
            yield credentials
        yield DataTable(id="feed", cursor_type="row", zebra_stripes=True)
        yield Static(id="bottom")
        yield Footer()

    def on_mount(self) -> None:
        """Populate table headers and start polling once widgets exist."""
        self._setup_tables()
        self.set_interval(self.refresh_interval, self.poll)
        self.poll()

    def _setup_tables(self) -> None:
        feed = self.query_one("#feed", DataTable)
        feed.add_columns("Time (UTC)", "Svc", "Source", "Summary", "Sev")
        attackers = self.query_one("#attackers", DataTable)
        attackers.add_columns("IP", "CC", "Org", "N", "Score", "Verdict", "Class")
        credentials = self.query_one("#credentials", DataTable)
        credentials.add_columns("Username", "N", "Password", "N")

    # ---- polling -------------------------------------------------------

    @property
    def window_seconds(self) -> int | None:
        return RANGES[self.range_label]

    def poll(self) -> None:
        """Refresh widgets. Display-only; the daemon is never touched."""
        if len(self.screen_stack) > 1:
            # A modal or detail screen is on top. The dashboard is not visible,
            # and ``query_one`` resolves against the *active* screen, so looking
            # up its widgets here would raise ``NoMatches`` and take the whole
            # app down with it on the next timer tick.
            return
        if self.paused:
            self.query_one("#metrics", Static).update(self._metrics_text("PAUSED"))
            return
        try:
            rows = self.store.feed(
                after_id=self.last_id if self.filter_text is None else 0,
                limit=40,
                window_s=self.window_seconds,
                text=self.filter_text,
            )
        except Exception:  # pragma: no cover - defensive, DB may be busy
            logger.debug("feed query failed", exc_info=True)
            return
        if rows:
            newest = max(row.id for row in rows)
            self.last_id = max(self.last_id, newest)
        self.retained = (rows + self.retained)[:MAX_ROWS]
        self.query_one("#metrics", Static).update(self._metrics_text())
        self._render_feed()
        self._render_tables()
        self.query_one("#bottom", Static).update(self._bottom_text())

    def _render_feed(self) -> None:
        table = self.query_one("#feed", DataTable)
        table.clear()
        for row in reversed(self.retained):
            table.add_row(
                safe_markup(row.ts[11:19], 8),
                safe_markup(row.service, 4),
                f"{safe_markup(row.src_ip, 38)} {safe_markup(row.geo_country or '', 3)}",
                safe_markup(row.summary, 52),
                _severity_markup(row.severity),
            )

    def _render_tables(self) -> None:
        attackers = self.query_one("#attackers", DataTable)
        attackers.clear()
        for row in self.store.top_attackers(
            window_s=self.window_seconds, limit=8, scorer=self.scorer
        ):
            attackers.add_row(
                safe_markup(row.src_ip, 16),
                safe_markup(row.geo_country or "??", 2),
                safe_markup(row.as_org or "-", 12),
                str(row.event_count),
                f"{row.score:.0f}",
                safe_markup(row.verdict, 10),
                safe_markup(row.classification, 14),
            )

        credentials = self.query_one("#credentials", DataTable)
        credentials.clear()
        users, passwords = self.store.top_credentials(limit=6, window_s=self.window_seconds)
        for index in range(max(len(users), len(passwords))):
            username, ucount = users[index] if index < len(users) else ("", 0)
            password, pcount = passwords[index] if index < len(passwords) else ("", 0)
            credentials.add_row(
                safe_markup(username, 12), str(ucount), safe_markup(password, 12), str(pcount)
            )

    # ---- renderers -----------------------------------------------------

    def _metrics_text(self, prefix: str = "") -> str:
        metrics = self.store.top_metrics(self.window_seconds)
        age = metrics.get("last_event_age_s")
        age_text = f"{int(age)}s ago" if age is not None else "no events"
        state = f"[b]{prefix}[/b] " if prefix else ""
        return (
            f"{state}events {metrics['events']}   ips {metrics['unique_ips']}   "
            f"alerts {metrics['alerts']}   last hour {metrics['events_last_hour']}   "
            f"last {age_text}   range {self.range_label}"
            + (f"   filter {self.filter_text}" if self.filter_text else "")
        )

    def _bottom_text(self) -> str:
        buckets = self.store.sparkline(minutes=30)
        spark = _sparkline(buckets)
        rules = self.store.rule_category_bars(window_s=self.window_seconds)[:5]
        rule_text = "  ".join(f"{safe_text(k, 22)}:{c}" for k, c in rules) or "no rule hits"
        countries = self.store.country_breakdown(window_s=self.window_seconds)[:6]
        country_text = "  ".join(f"{safe_text(c, 3)}:{n}" for c, n in countries) or "no geo data"
        return f"events/min  {spark}\nrules  {rule_text}\ngeo    {country_text}"

    # ---- actions -------------------------------------------------------

    def action_toggle_pause(self) -> None:
        self.paused = not self.paused

    def action_filter(self) -> None:
        self.push_screen(FilterScreen(), self._apply_filter)

    def _apply_filter(self, result: str | None) -> None:
        """Apply the filter chosen in the modal (``None`` clears it)."""
        self.filter_text = (result.strip() or None) if result else None
        # The buffered rows were selected under the previous filter; keeping
        # them would leave filtered-out events on screen indefinitely.
        self._reset_feed()
        self.poll()

    @on(DataTable.RowSelected, "#attackers")
    def _on_attacker_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter on the attacker table opens that attacker's detail view.

        ``DataTable`` binds Enter itself and consumes it, so the app-level
        ``enter`` binding below never sees the key while the table has focus.
        """
        event.stop()
        self._open_attacker_row(event.cursor_row)

    def action_open_selected(self) -> None:
        table = self.query_one("#attackers", DataTable)
        self._open_attacker_row(table.cursor_row)

    def _open_attacker_row(self, row_index: int) -> None:
        table = self.query_one("#attackers", DataTable)
        if table.row_count == 0:
            return
        try:
            row = table.get_row_at(row_index)
        except (IndexError, ValueError):  # pragma: no cover - empty table
            return
        self.push_screen(AttackerScreen(str(row[0]), self.store, self.scorer))

    def action_show_rules(self) -> None:
        self.push_screen(RulesScreen(self.store, self.ruleset))

    def action_show_alerts(self) -> None:
        self.push_screen(AlertsScreen(self.store))

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_export_selected(self) -> None:
        table = self.query_one("#attackers", DataTable)
        if table.row_count == 0:
            return
        try:
            row = table.get_row_at(table.cursor_row)
        except (IndexError, ValueError):  # pragma: no cover - empty table
            return
        self.export_ip(str(row[0]))

    def export_ip(self, src_ip: str) -> None:
        """Write a single-attacker Markdown report next to the database."""
        from ..report import generate_ip_report

        target = self.db_path.parent / f"report-{src_ip.replace(':', '_')}.md"
        try:
            target.write_text(
                generate_ip_report(self.store, src_ip, scorer=self.scorer), encoding="utf-8"
            )
        except OSError as exc:
            self.notify(f"export failed: {exc}", severity="error")
            return
        self.notify(f"exported {target.name}")

    def _reset_feed(self) -> None:
        """Drop buffered feed rows so the next poll rebuilds the view."""
        self.last_id = 0
        self.retained = []

    def _set_range(self, label: str) -> None:
        self.range_label = label
        self._reset_feed()

    def action_range_15m(self) -> None:
        self._set_range(RANGE_KEYS["1"])

    def action_range_1h(self) -> None:
        self._set_range(RANGE_KEYS["2"])

    def action_range_24h(self) -> None:
        self._set_range(RANGE_KEYS["3"])

    def action_range_all(self) -> None:
        self._set_range(RANGE_KEYS["4"])

    def action_quit(self) -> None:  # type: ignore[override]
        """Close the dashboard. Collection in the daemon is unaffected."""
        with_error = self.store
        try:
            with_error.close()
        except Exception:  # pragma: no cover - defensive
            pass
        self.exit()


# ---------------------------------------------------------------------------
# rendering helpers
# ---------------------------------------------------------------------------


def _severity_markup(severity: str) -> str:
    try:
        level = Severity(severity)
    except ValueError:  # pragma: no cover - defensive
        return safe_markup(severity, 10)
    label = safe_markup(str(level), 10)
    if level is Severity.CRITICAL:
        return f"[bold red]{label}[/]"
    if level is Severity.HIGH:
        return f"[red]{label}[/]"
    if level is Severity.MEDIUM:
        return f"[yellow]{label}[/]"
    if level is Severity.LOW:
        return f"[cyan]{label}[/]"
    return label


def _sparkline(values: list[int]) -> str:
    if not values or max(values) == 0:
        return " " * len(values) if values else "(no data)"
    peak = max(values)
    return "".join(
        BLOCKS[min(len(BLOCKS) - 1, int(value / peak * (len(BLOCKS) - 1)))] if value else " "
        for value in values
    )


def _detail_timeline(rows: list[FeedRow]) -> str:
    if not rows:
        return "no events"
    return "\n".join(
        f"{safe_text(row.ts, 24)} {safe_text(row.service, 5):<5} "
        f"{safe_markup(row.summary, 60)} [{_severity_markup(row.severity)}]"
        for row in rows
    )


def _detail_commands(rows: list[tuple[str, str, str]]) -> str:
    if not rows:
        return "no commands"
    return "\n".join(
        f"{safe_text(ts, 24)} {safe_text(session, 14)}  {safe_markup(command, 60)}"
        for ts, session, command in rows
    )


def _detail_rules(rows: list[tuple[str, int, str | None, str]]) -> str:
    if not rows:
        return "no rules fired"
    return "\n".join(
        f"{safe_markup(rule_id, 30)} x{count:<4} {safe_markup(attack or '-', 12)} "
        f"{_severity_markup(severity)}"
        for rule_id, count, attack, severity in rows
    )


def _detail_urls(urls: list[str]) -> str:
    if not urls:
        return "no payload URLs observed"
    return "\n".join(
        f"[b]recorded only (never fetched)[/b]\n{safe_markup(url, 100)}" for url in urls
    )


def age_text(seconds: float | None) -> str:  # pragma: no cover - helper
    if seconds is None:
        return "never"
    return str(timedelta(seconds=int(seconds)))