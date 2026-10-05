"""Append-only raw JSONL archive.

The archive stores **raw, pre-enrichment** events so a future replay can
apply newer rules and GeoIP data to old observations. Writes are line
atomic: a full line plus newline is written in a single ``write`` call and
flushed, so a crash can never leave a partially written record.
"""

from __future__ import annotations

import gzip
import json
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import IO, Any

from ..models import Event, iso


def _daily_name(day: datetime, suffix: str) -> str:
    return f"events-{day.astimezone(UTC).strftime('%Y-%m-%d')}.jsonl{suffix}"


class JsonlArchive:
    """Daily-rotating raw event archive.

    The writer API is deliberately tiny so compression can be added later
    without changing callers.
    """

    def __init__(self, directory: str | Path, *, enabled: bool = True) -> None:
        self.directory = Path(directory)
        self.enabled = enabled
        self._handle: IO[str] | None = None
        self._current_day: str | None = None
        self._lock = threading.Lock()
        self.write_errors = 0

    # ---- lifecycle -----------------------------------------------------

    def _open(self, day: datetime) -> IO[str]:
        if self._handle is None or self._current_day != day.strftime("%Y-%m-%d"):
            self.close()
            self.directory.mkdir(parents=True, exist_ok=True)
            target = self.directory / _daily_name(day, "")
            self._handle = target.open("a", encoding="utf-8", newline="\n")
            self._current_day = day.strftime("%Y-%m-%d")
        return self._handle

    def write(self, event: Event) -> None:
        """Append one raw event. Never raises for I/O problems in the
        daemon path; increments ``write_errors`` instead."""
        if not self.enabled:
            return
        line = json.dumps(event.to_json_dict(), ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            try:
                handle = self._open(event.ts)
                handle.write(line + "\n")
                handle.flush()
            except OSError:
                self.write_errors += 1

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                try:
                    self._handle.flush()
                    self._handle.close()
                finally:
                    self._handle = None
                    self._current_day = None

    def __enter__(self) -> JsonlArchive:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---- maintenance ---------------------------------------------------

    def files(self) -> list[Path]:
        if not self.directory.is_dir():
            return []
        return sorted(self.directory.glob("events-*.jsonl*"))

    def compress_older_than(self, days: int, *, now: datetime | None = None) -> list[Path]:
        """Gzip day files older than ``days``. Never touches today's file."""
        if days <= 0:
            return []
        reference = now or datetime.now(UTC)
        cutoff = reference - timedelta(days=days)
        produced: list[Path] = []
        for path in self.files():
            if path.name.endswith(".gz"):
                continue
            try:
                stamp = datetime.strptime(path.stem.removeprefix("events-"), "%Y-%m-%d").replace(
                    tzinfo=UTC
                )
            except ValueError:
                continue
            if stamp >= cutoff:
                continue
            target = path.with_suffix(".jsonl.gz")
            try:
                with path.open("rb") as src, gzip.open(target, "wb") as dst:
                    while chunk := src.read(65536):
                        dst.write(chunk)
                path.unlink()
                produced.append(target)
            except OSError:
                continue
        return produced

    def count(self) -> int:
        return sum(1 for _ in self.iter_events())


def read_jsonl(path: str | Path) -> Iterator[Event]:
    """Yield validated events from a raw JSONL file.

    Malformed lines are skipped rather than aborting the whole replay.
    """
    file_path = Path(path)
    opener = gzip.open if file_path.suffix == ".gz" else open
    with opener(file_path, "rt", encoding="utf-8") as handle:  # type: ignore[operator]
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload: dict[str, Any] = json.loads(line)
                yield Event.model_validate(payload)
            except (json.JSONDecodeError, ValueError):
                continue