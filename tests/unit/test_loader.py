"""Rule loader tests including malformed-rule isolation."""

from __future__ import annotations

from pathlib import Path

import pytest

from honeywatch.engine.fixtures import run_fixtures, run_fixture_cases
from honeywatch.engine.loader import load_ruleset
from honeywatch.engine.rules import RuleError


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_loads_recursively(tmp_path: Path) -> None:
    write(tmp_path / "a" / "one.yaml", "id: a-1\ntitle: One\nseverity: low\nmatch:\n  service: ssh\n")
    write(tmp_path / "b" / "two.yml", "id: a-2\ntitle: Two\nseverity: high\nmatch:\n  service: http\n")
    ruleset = load_ruleset(tmp_path)
    assert len(ruleset) == 2
    assert not ruleset.errors


def test_duplicate_ids_are_reported(tmp_path: Path) -> None:
    write(tmp_path / "one.yaml", "id: dup\ntitle: One\nseverity: low\nmatch:\n  service: ssh\n")
    write(tmp_path / "two.yaml", "id: dup\ntitle: Two\nseverity: low\nmatch:\n  service: http\n")
    ruleset = load_ruleset(tmp_path)
    assert len(ruleset) == 1
    assert any("duplicate" in err for err in ruleset.errors)


def test_malformed_yaml_is_isolated(tmp_path: Path) -> None:
    write(tmp_path / "good.yaml", "id: g-1\ntitle: Good\nseverity: low\nmatch:\n  service: ssh\n")
    write(tmp_path / "bad.yaml", "id: [unclosed\n")
    ruleset = load_ruleset(tmp_path)
    assert [r.id for r in ruleset.rules] == ["g-1"]
    assert any("bad.yaml" in err for err in ruleset.errors)


def test_invalid_rule_is_isolated(tmp_path: Path) -> None:
    write(tmp_path / "good.yaml", "id: g-1\ntitle: Good\nseverity: low\nmatch:\n  service: ssh\n")
    write(tmp_path / "bad.yaml", "id: bad-1\ntitle: Bad\nseverity: nope\nmatch:\n  service: ssh\n")
    ruleset = load_ruleset(tmp_path)
    assert [r.id for r in ruleset.rules] == ["g-1"]
    assert ruleset.errors


def test_strict_mode_raises(tmp_path: Path) -> None:
    write(tmp_path / "bad.yaml", "id: bad-1\ntitle: Bad\nseverity: nope\nmatch:\n  service: ssh\n")
    with pytest.raises(RuleError):
        load_ruleset(tmp_path, strict=True)


def test_missing_directory_is_non_fatal(tmp_path: Path) -> None:
    ruleset = load_ruleset(tmp_path / "absent")
    assert len(ruleset) == 0
    assert ruleset.errors


def test_non_mapping_entry_is_reported(tmp_path: Path) -> None:
    write(tmp_path / "list.yaml", "- just a string\n- id: x\n")
    ruleset = load_ruleset(tmp_path)
    assert any("must be a mapping" in err for err in ruleset.errors)


def test_shipped_rules_are_valid(ruleset) -> None:
    assert not ruleset.errors
    assert len(ruleset) == 17


def test_every_shipped_rule_has_positive_and_near_miss(ruleset) -> None:
    from honeywatch.engine.fixtures import load_default_cases

    cases = load_default_cases()
    assert cases is not None
    for rule_id in ruleset.ids:
        kinds = {case.kind for case in cases if case.rule_id == rule_id}
        assert "positive" in kinds, f"{rule_id} has no positive fixture"
        assert "near_miss" in kinds, f"{rule_id} has no near-miss fixture"


def test_all_fixtures_pass(rules_dir: Path, ruleset) -> None:
    outcomes = run_fixture_cases.__wrapped__ if hasattr(run_fixture_cases, "__wrapped__") else None
    del outcomes
    result = run_fixtures(rules_dir)
    assert result.ok, "\n".join(result.failures)


def test_expected_rule_ids_are_exact(rules_dir: Path, ruleset) -> None:
    from honeywatch.engine.fixtures import load_default_cases

    cases = load_default_cases()
    positives = {case.rule_id for case in cases if case.expect_hit}
    assert positives <= set(ruleset.ids)