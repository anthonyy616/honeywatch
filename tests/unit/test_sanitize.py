"""Sanitization tests for hostile strings."""

from __future__ import annotations

import pytest

from honeywatch.sanitize import (
    clip,
    collapse_whitespace,
    safe_cell,
    safe_markdown,
    safe_markup,
    safe_multiline,
    safe_text,
    strip_control,
)


@pytest.mark.parametrize(
    "hostile",
    [
        "\x1b[31mred\x1b[0m",
        "\x1b]0;window title\x07",
        "\x1b]8;;http://evil.example\x1b\\link",
        "\x1b[2J\x1b[H",
        "\x9b31m",
        "carriage\rreturn",
        "back\x08space",
        "null\x00byte",
        "vertical\x0btab",
    ],
)
def test_control_sequences_are_removed(hostile: str) -> None:
    cleaned = safe_text(hostile)
    assert "\x1b" not in cleaned
    assert "\x9b" not in cleaned
    assert "\x00" not in cleaned
    assert "\r" not in cleaned
    assert "\x08" not in cleaned


def test_rich_markup_is_escaped() -> None:
    cleaned = safe_markup("[bold red]pwned[/]")
    assert "\\[" in cleaned
    assert cleaned.startswith("\\[bold")


def test_markdown_is_escaped() -> None:
    cleaned = safe_markdown("**bold** [link](x) `code`")
    assert "**" not in cleaned.replace("\\*\\*", "")
    assert "\\[" in cleaned


def test_multiline_is_bounded() -> None:
    cleaned = safe_multiline("a\nb\nc\n" * 100)
    assert cleaned.count("\n") < 20
    assert len(cleaned) <= 2000


def test_length_is_capped() -> None:
    assert len(safe_text("x" * 5000, limit=64)) == 64
    assert clip("abcdef", 3) == "abc"
    assert clip("abc", 0) == ""


def test_whitespace_collapse() -> None:
    assert collapse_whitespace("a     b    c") == "a b c"


def test_none_is_empty() -> None:
    assert safe_text(None) == ""
    assert safe_markup(None) == ""
    assert safe_multiline(None) == ""


def test_unicode_is_preserved_safely() -> None:
    cleaned = safe_text("раypal 中文 🙂", limit=100)
    assert "🙂" in cleaned


def test_strip_control_keeps_newlines_when_asked() -> None:
    assert strip_control("a\nb", keep_newlines=True) == "a\nb"
    assert strip_control("a\nb") == "a b"


def test_cell_is_bounded() -> None:
    assert len(safe_cell("y" * 500, limit=20)) == 20