"""CLI smoke tests.

Every command is invoked through Typer so that import errors, mis-wired
options and wrong exit codes are caught. The commands that need a live
terminal or long-running listeners are only checked up to their validation
step, which is what the user sees first.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from honeywatch.cli import app

pytestmark = pytest.mark.integration

runner = CliRunner()


@pytest.fixture
def config_file(tmp_path: Path, rules_dir: Path) -> Path:
    """A minimal config pointing at the repository rule catalogue."""
    path = tmp_path / "config.yaml"
    path.write_text(
        f"data_dir: {tmp_path / 'data'}\n"
        f"rules:\n  directory: {rules_dir}\n"
        "ssh:\n  enabled: true\n"
        "http:\n  enabled: true\n",
        encoding="utf-8",
    )
    return path


def test_help_lists_every_documented_command() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0, result.output
    for command in ("run", "rules", "simulate", "replay", "report", "doctor", "db", "tui"):
        assert command in result.output, f"{command} is missing from the CLI"


def test_rules_validate_and_list(config_file: Path) -> None:
    result = runner.invoke(app, ["-c", str(config_file), "rules", "validate"])
    assert result.exit_code == 0, result.output
    assert "17 rules valid" in result.output

    listed = runner.invoke(app, ["-c", str(config_file), "rules", "list"])
    assert listed.exit_code == 0, listed.output
    assert "ssh-default-creds-003" in listed.output


def test_rules_fixtures_pass(config_file: Path) -> None:
    result = runner.invoke(app, ["-c", str(config_file), "rules", "test"])
    assert result.exit_code == 0, result.output
    assert "fixtures passed" in result.output


def test_doctor_exits_zero(config_file: Path) -> None:
    result = runner.invoke(app, ["-c", str(config_file), "doctor"])
    assert result.exit_code == 0, result.output
    assert "all required checks passed" in result.output


def test_tui_imports_and_validates_the_database_path(config_file: Path, tmp_path: Path) -> None:
    """``honeywatch tui`` must reach its own validation, not fail on import.

    A missing ``run_tui`` import previously made every invocation die with an
    ``ImportError`` before any option was examined.
    """
    result = runner.invoke(app, ["-c", str(config_file), "tui", "--db", str(tmp_path / "nope.db")])
    assert result.exit_code == 2, result.output
    assert "database not found" in result.output
    assert "ImportError" not in result.output
    assert "Traceback" not in result.output


def test_tui_replay_reports_a_missing_archive(config_file: Path, tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["-c", str(config_file), "tui", "--replay", str(tmp_path / "nope.jsonl")]
    )
    assert result.exit_code == 2, result.output
    assert "replay file not found" in result.output
    assert "Traceback" not in result.output


def test_tui_uses_the_config_passed_with_dash_c(
    config_file: Path, tmp_path: Path, monkeypatch
) -> None:
    """``-c`` must be honoured wherever the command is run from.

    The dashboard used to re-discover a configuration from the working
    directory, so ``-c`` was ignored and the command failed outside the repo.
    """
    invoked: dict[str, object] = {}

    def capture(options) -> None:
        invoked["options"] = options

    # Stubbed so the dashboard itself never tries to take over the terminal.
    monkeypatch.setattr("honeywatch.tui.run.run_tui", capture)
    monkeypatch.chdir(tmp_path)  # no config/ directory here

    result = runner.invoke(app, ["-c", str(config_file), "tui", "--db", str(config_file)])
    assert result.exit_code == 0, result.output
    assert "options" in invoked, "run_tui was never called"
    assert invoked["options"].config is not None, "-c config was not passed to the dashboard"


def test_report_and_db_commands_need_an_existing_database(config_file: Path, tmp_path: Path) -> None:
    missing = str(tmp_path / "nope.db")
    for args in (["report", "--db", missing], ["db", "stats", "--db", missing]):
        result = runner.invoke(app, ["-c", str(config_file), *args])
        assert result.exit_code == 2, result.output
        assert "database not found" in result.output


def test_unknown_config_file_is_reported(config_file: Path, tmp_path: Path) -> None:
    result = runner.invoke(app, ["-c", str(tmp_path / "missing.yaml"), "doctor"])
    assert result.exit_code == 2, result.output
    assert "configuration error" in result.output
