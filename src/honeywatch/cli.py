"""HoneyWatch command-line interface."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import signal
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import typer

from . import __version__
from .config import Config, ConfigError, load_config
from .models import Severity, iso
from .storage.jsonl import JsonlArchive, read_jsonl
from .storage.sqlite import Storage

logger = logging.getLogger("honeywatch")

app = typer.Typer(
    name="honeywatch",
    help="Non-executing SSH/HTTP honeypot with rule detection, scoring and a TUI.",
    no_args_is_help=True,
    add_completion=False,
)
rules_app = typer.Typer(help="Inspect and validate detection rules.", no_args_is_help=True)
db_app = typer.Typer(help="Inspect and maintain the event database.", no_args_is_help=True)
app.add_typer(rules_app, name="rules")
app.add_typer(db_app, name="db")

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_CONFIG = 2


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"honeywatch {__version__}")
        raise typer.Exit(EXIT_OK)


@app.callback()
def _main(
    config: Path = typer.Option(None, "--config", "-c", help="Path to a YAML configuration file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """Shared options for every command."""
    del version
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    try:
        _CONFIG.append(load_config(config))
    except ConfigError as exc:
        typer.secho(f"configuration error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG) from exc


# Click does not propagate a group callback return value into ``ctx.obj``,
# so the validated configuration is held here and read by each command.
_CONFIG: list[Config] = []


def current_config(ctx: typer.Context) -> Config:
    """Return the configuration validated by the group callback."""
    if _CONFIG:
        return _CONFIG[-1]
    raise typer.BadParameter("configuration was not loaded")


# ---------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------


@app.command()
def run(
    ctx: typer.Context,
    no_ssh: bool = typer.Option(False, "--no-ssh", help="Disable the SSH honeypot."),
    no_http: bool = typer.Option(False, "--no-http", help="Disable the HTTP honeypot."),
    duration: int = typer.Option(0, "--duration", "-d", help="Stop after N seconds (0 = run forever)."),
) -> None:
    """Run the collection daemon (SSH + HTTP + pipeline + storage)."""
    cfg = current_config(ctx)
    if no_ssh:
        cfg.ssh.enabled = False
    if no_http:
        cfg.http.enabled = False
    if not cfg.ssh.enabled and not cfg.http.enabled:
        typer.secho("both honeypots disabled; nothing to do", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG)
    try:
        _run_daemon(cfg, duration=duration)
    except OSError as exc:
        typer.secho(f"listener startup failed: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_FAILURE) from exc
    except KeyboardInterrupt:  # pragma: no cover - interactive
        typer.echo("interrupted; shutting down cleanly")


def _run_daemon(cfg: Config, *, duration: int = 0) -> None:
    from .alerts import build_alerter
    from .daemon import run_daemon

    asyncio.run(run_daemon(cfg, build_alerter, duration=duration))


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------


@rules_app.command("validate")
def rules_validate(ctx: typer.Context) -> None:
    """Validate every rule file. Exits non-zero when any rule is invalid."""
    cfg = current_config(ctx)
    from .engine.loader import load_ruleset

    ruleset = load_ruleset(cfg.rules_dir, strict=True)
    if ruleset.errors:  # pragma: no cover - strict raises first
        for err in ruleset.errors:
            typer.secho(f"error: {err}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_FAILURE)
    typer.secho(f"OK: {len(ruleset)} rules valid across {len(ruleset.files)} files", fg=typer.colors.GREEN)


@rules_app.command("list")
def rules_list(ctx: typer.Context) -> None:
    """List loaded rules with ATT&CK, severity and enabled state."""
    cfg = current_config(ctx)
    from .engine.loader import load_ruleset

    ruleset = load_ruleset(cfg.rules_dir)
    for err in ruleset.errors:
        typer.secho(f"warning: {err}", fg=typer.colors.YELLOW, err=True)
    for rule in sorted(ruleset.rules, key=lambda r: r.id):
        typer.echo(
            f"{rule.id:<26} {str(rule.severity):<9} {rule.attack or '-':<10} "
            f"{'on ' if rule.enabled else 'off'} {rule.title}"
        )
    typer.echo(f"\n{len(ruleset)} rules, {len(ruleset.files)} files")


@rules_app.command("test")
def rules_test(ctx: typer.Context) -> None:
    """Run the bundled rule fixtures and report pass/fail per rule."""
    cfg = current_config(ctx)
    from .engine.fixtures import run_fixtures

    result = run_fixtures(cfg.rules_dir)
    for line in result.lines:
        typer.echo(line)
    typer.echo(f"\n{result.passed}/{result.total} fixtures passed")
    raise typer.Exit(EXIT_OK if result.ok else EXIT_FAILURE)


# ---------------------------------------------------------------------------
# simulate / replay
# ---------------------------------------------------------------------------


@app.command()
def simulate(
    ctx: typer.Context,
    profile: list[str] = typer.Option(None, "--profile", "-p", help="Profile name (repeatable)."),
    rate: float = typer.Option(5.0, "--rate", help="Events per second."),
    duration: str = typer.Option("", "--duration", help="Run for e.g. 5m, 30s (default: one pass)."),
    seed: int = typer.Option(1337, "--seed", help="Random seed for reproducibility."),
    db: Path = typer.Option(None, "--db", help="Write to an explicit database path."),
) -> None:
    """Generate simulated traffic through the real pipeline."""
    cfg = current_config(ctx)
    from .simulate_cmd import run_simulation

    try:
        seconds = _parse_duration_seconds(duration) if duration else None
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG) from exc
    try:
        count = run_simulation(
            cfg,
            profiles=tuple(profile or ()),
            rate=rate,
            duration_s=seconds,
            seed=seed,
            db_path=db,
        )
    except ValueError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG) from exc
    typer.secho(f"simulated {count} events", fg=typer.colors.GREEN)


@app.command()
def replay(
    ctx: typer.Context,
    file: Path = typer.Argument(..., help="Raw JSONL archive to replay."),
    speed: float = typer.Option(10.0, "--speed", help="Replay speed multiplier."),
    db: Path = typer.Option(None, "--db", help="Write to an explicit database path."),
) -> None:
    """Replay a raw JSONL archive through the real pipeline."""
    cfg = current_config(ctx)
    if not file.is_file():
        typer.secho(f"file not found: {file}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG)
    from .simulate_cmd import run_replay

    count = run_replay(cfg, file, speed=speed, db_path=db)
    typer.secho(f"replayed {count} events from {file}", fg=typer.colors.GREEN)


# ---------------------------------------------------------------------------
# report / doctor / db
# ---------------------------------------------------------------------------


@app.command()
def report(
    ctx: typer.Context,
    since: str = typer.Option("24h", "--since", help="Window: 30m, 24h, 7d or 'all'."),
    out: Path = typer.Option(None, "--out", "-o", help="Write Markdown to this file."),
    db: Path = typer.Option(None, "--db", help="Read an explicit database path."),
    ip: str = typer.Option("", "--ip", help="Generate a single-attacker report."),
) -> None:
    """Generate a Markdown report from stored events."""
    cfg = current_config(ctx)
    from .report import generate_ip_report, generate_report
    from .scoring_service import Scorer

    db_path = db or cfg.db_path
    if not Path(db_path).is_file():
        typer.secho(f"database not found: {db_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG)
    from .storage.queries import ReadStore

    with ReadStore(db_path) as store:
        scorer = Scorer(store, cfg.scoring)
        try:
            text = (
                generate_ip_report(store, ip, scorer=scorer)
                if ip
                else generate_report(store, since=since, scorer=scorer)
            )
        except ValueError as exc:
            typer.secho(str(exc), fg=typer.colors.RED, err=True)
            raise typer.Exit(EXIT_CONFIG) from exc
    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        typer.secho(f"report written to {out}", fg=typer.colors.GREEN)
    else:
        typer.echo(text)


@app.command()
def doctor(ctx: typer.Context) -> None:
    """Check configuration, storage, rules, ports and optional integrations."""
    cfg = current_config(ctx)
    from .doctor import run_doctor

    result = run_doctor(cfg)
    for check in result.checks:
        colour = {"ok": typer.colors.GREEN, "warn": typer.colors.YELLOW, "fail": typer.colors.RED}[
            check.status
        ]
        typer.secho(f"[{check.status.upper():<4}] {check.name}: {check.detail}", fg=colour)
    if not result.ok:
        raise typer.Exit(EXIT_FAILURE)
    typer.secho("all required checks passed", fg=typer.colors.GREEN)


@db_app.command("stats")
def db_stats(ctx: typer.Context, db: Path = typer.Option(None, "--db")) -> None:
    """Show aggregate database statistics."""
    cfg = current_config(ctx)
    db_path = db or cfg.db_path
    if not Path(db_path).is_file():
        typer.secho(f"database not found: {db_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG)
    with Storage(db_path) as store:
        stats = store.stats()
    typer.echo(json.dumps(stats, indent=2, default=str))


@db_app.command("prune")
def db_prune(
    ctx: typer.Context,
    db: Path = typer.Option(None, "--db"),
    days: int = typer.Option(None, "--days", help="Retention days (default: from config)."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
) -> None:
    """Delete events older than the retention window. The raw archive is kept."""
    cfg = current_config(ctx)
    db_path = db or cfg.db_path
    if not Path(db_path).is_file():
        typer.secho(f"database not found: {db_path}", fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG)
    retention = days if days is not None else cfg.storage.retention_days
    cutoff = datetime.now(UTC) - timedelta(days=retention)
    if not yes:
        typer.confirm(f"Delete events older than {cutoff.date()} ({retention} days)?", abort=True)
    with Storage(db_path) as store:
        removed = store.prune(iso(cutoff))
        if days is not None and days == 0:
            store.vacuum()
    typer.secho(f"pruned {removed} events older than {cutoff.date()}", fg=typer.colors.GREEN)


# ---------------------------------------------------------------------------
# tui
# ---------------------------------------------------------------------------


@app.command()
def tui(
    ctx: typer.Context,
    db: Path = typer.Option(None, "--db", help="Read an explicit database path."),
    replay_file: Path = typer.Option(
        None, "--replay", help="Replay a JSONL archive into a temporary database and display it."
    ),
    speed: float = typer.Option(10.0, "--speed", help="Replay speed multiplier."),
    refresh: float = typer.Option(1.0, "--refresh", help="Poll interval in seconds."),
) -> None:
    """Open the read-only Textual dashboard."""
    cfg = current_config(ctx)
    from .tui.run import TUIOptions, run_tui

    options = TUIOptions(
        db_path=db or cfg.db_path,
        replay=replay_file,
        speed=speed,
        refresh=refresh,
        config=cfg,
    )
    try:
        run_tui(options)
    except FileNotFoundError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(EXIT_CONFIG) from exc


def _parse_duration_seconds(value: str) -> int:
    from .engine.rules import parse_duration

    try:
        return int(parse_duration(value))
    except ValueError as exc:
        raise ValueError(f"invalid duration {value!r} (use e.g. 30s, 5m, 1h)") from exc


def main() -> None:  # pragma: no cover - console entry point
    """Console-script entry point."""
    with contextlib.suppress(KeyboardInterrupt):
        app()


if __name__ == "__main__":  # pragma: no cover
    main()

# Keep imports referenced for linters that check module-level usage.
_UNUSED: tuple[Any, ...] = (sys, read_jsonl, JsonlArchive, Severity, signal)