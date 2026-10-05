"""Reusable sanitization helpers for hostile, attacker-controlled strings.

Every captured field is untrusted.  This module is the single place that
strips terminal control sequences, escapes Rich markup and bounds string
length before any value is rendered, logged, reported or alerted on.
"""

from __future__ import annotations

import re
import unicodedata

# CSI / OSC / single-character escape sequences.
_ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_ANSI_OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
_ANSI_OTHER = re.compile(r"\x1b[@-Z\\-_]|\x9b[0-?]*[ -/]*[@-~]")

# Control characters except tab and newline, plus C1 range and DEL.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_control(value: str, *, keep_newlines: bool = False) -> str:
    """Remove terminal control sequences and control characters.

    Args:
        value: Hostile string.
        keep_newlines: When true, ``\\n`` survives (tabs are always removed).
    """
    if not value:
        return ""
    text = _ANSI_OSC.sub("", value)
    text = _ANSI_CSI.sub("", text)
    text = _ANSI_OTHER.sub("", text)
    if keep_newlines:
        text = _CONTROL.sub("", text)
    else:
        text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
        text = _CONTROL.sub("", text)
    return text


def collapse_whitespace(value: str) -> str:
    """Collapse runs of spaces produced by stripped control characters."""
    return re.sub(r" {2,}", " ", value).strip()


def clip(value: str, limit: int) -> str:
    """Truncate to ``limit`` characters without splitting the string type."""
    if limit <= 0:
        return ""
    return value if len(value) <= limit else value[:limit]


def safe_text(value: object, limit: int = 200, *, keep_newlines: bool = False) -> str:
    """Sanitize a value for single-line plain-text display.

    Control sequences and control characters are removed, remaining
    whitespace is collapsed and the result is truncated to ``limit``.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\x00", "")
    text = strip_control(text, keep_newlines=keep_newlines)
    if not keep_newlines:
        text = collapse_whitespace(text)
    return clip(text, limit)


def safe_multiline(value: object, limit: int = 2000, max_lines: int = 20) -> str:
    """Sanitize a value that may legitimately span several lines."""
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\x00", "")
    text = strip_control(text, keep_newlines=True)
    lines = [line.rstrip() for line in text.split("\n")]
    lines = [line for line in lines if line]
    if len(lines) > max_lines:
        lines = lines[:max_lines]
    return clip("\n".join(lines), limit)


def safe_markup(value: object, limit: int = 200) -> str:
    """Escape Rich/Textual markup so hostile text cannot inject styles."""
    text = safe_text(value, limit=limit * 2 if limit else 0)
    # Escape the Rich markup metacharacters, then re-truncate.
    text = text.replace("[", "\\[")
    return clip(text, limit)


def safe_markdown(value: object, limit: int = 200) -> str:
    """Escape Markdown metacharacters for safe inclusion in a report."""
    text = safe_text(value, limit=limit * 2 if limit else 0)
    out = []
    for ch in text:
        if ch in "\\`*_{}[]()#+-.!|<>~":
            out.append("\\" + ch)
        else:
            out.append(ch)
    return clip("".join(out), limit)


def safe_cell(value: object, limit: int = 60) -> str:
    """Sanitize a value for a bounded single-line table cell."""
    return safe_text(value, limit=limit)


def normalize_unicode(value: str) -> str:
    """Normalize hostile unicode so layout cannot be broken by odd forms."""
    return unicodedata.normalize("NFKC", value)