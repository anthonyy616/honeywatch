"""Configuration loading and validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from honeywatch.config import ConfigError, load_config, parse_config


def test_defaults_are_safe(tmp_path: Path) -> None:
    config = parse_config({}, base_dir=tmp_path)
    assert config.ssh.port == 2222
    assert config.http.port == 8080
    assert config.alerts.telegram.enabled is False
    assert config.storage.retention_days == 30
    assert config.scoring.half_life_hours == 6.0


def test_relative_paths_resolve_against_cwd(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    config = parse_config({"data_dir": "./data"}, base_dir=tmp_path)
    assert config.db_path == (tmp_path / "data" / "honeywatch.db").resolve()
    assert config.rules_dir == (tmp_path / "rules").resolve()


def test_absolute_paths_are_preserved(tmp_path: Path) -> None:
    config = parse_config({"data_dir": "/var/lib/honeywatch"}, base_dir=tmp_path)
    assert config.data_dir == Path("/var/lib/honeywatch").resolve()


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as exc:
        parse_config({"ssh": {"prot": 2222}}, base_dir=tmp_path)
    assert "ssh.prot" in str(exc.value)


def test_invalid_severity_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        parse_config(
            {"alerts": {"telegram": {"min_severity": "apocalyptic"}}}, base_dir=tmp_path
        )


def test_bad_banner_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        parse_config({"ssh": {"banner": "Telnet 1.0"}}, base_dir=tmp_path)


def test_load_config_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError) as exc:
        load_config(tmp_path / "nope.yaml")
    assert "not found" in str(exc.value)


def test_load_config_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text("ssh: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError) as exc:
        load_config(path)
    assert "invalid YAML" in str(exc.value)


def test_load_config_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "list.yaml"
    path.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_load_example_config(repo_root: Path) -> None:
    config = load_config(repo_root / "config" / "honeywatch.example.yaml")
    assert config.ssh.enabled is True
    assert config.http.port == 8080


def test_telegram_token_comes_from_environment(tmp_path: Path, monkeypatch) -> None:
    config = parse_config(
        {"alerts": {"telegram": {"enabled": True, "token_env": "MY_TG", "chat_id": "1"}}},
        base_dir=tmp_path,
    )
    assert config.telegram_token() is None
    monkeypatch.setenv("MY_TG", "s3cret")
    assert config.telegram_token() == "s3cret"


def test_ensure_data_dir_creates_tree(tmp_path: Path) -> None:
    config = parse_config({"data_dir": str(tmp_path / "d")}, base_dir=tmp_path)
    config.ensure_data_dir()
    assert config.raw_dir.is_dir()
    assert config.geo_dir.is_dir()


def test_weight_table_is_validated(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        parse_config({"scoring": {"weights": {"info": 1, "nuclear": 99}}}, base_dir=tmp_path)