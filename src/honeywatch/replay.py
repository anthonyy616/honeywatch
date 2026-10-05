"""Replay producer: feeds archived JSONL events back through the pipeline."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Event
from .storage.jsonl import read_jsonl

logger = logging.getLogger(__name__)

# Above this speed factor, relative sleeping is skipped entirely.
NO_SLEEP_SPEED = 200.0


@dataclass(slots=True)
class ReplayResult:
    """Summary of one replay run."""

    events: int = 0
    skipped: int = 0
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    @property
    def duration_s(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return (self.last_ts - self.first_ts).total_seconds()


class Replay:
    """Replays a raw JSONL archive through the real pipeline.

    Relative timing is divided by ``speed`` so a 10x run finishes ten times
    faster while preserving ordering.
    """

    def __init__(
        self,
        path: str | Path,
        pipeline: Any,
        *,
        speed: float = 10.0,
        loop: bool = False,
    ) -> None:
        self.path = Path(path)
        self.pipeline = pipeline
        self.speed = max(0.01, float(speed))
        self.loop = loop

    async def run(self, *, max_events: int | None = None) -> ReplayResult:
        """Replay the file once, preserving relative timing."""
        result = await self._run_once(max_events=max_events)
        if self.loop:
            while True:
                result = await self._run_once(max_events=max_events)
        return result

    async def _run_once(self, *, max_events: int | None) -> ReplayResult:
        result = ReplayResult()
        previous: datetime | None = None
        sleeper = asyncio.sleep if self.speed <= NO_SLEEP_SPEED else _no_sleep
        for event in read_jsonl(self.path):
            if result.first_ts is None:
                result.first_ts = event.ts
            if previous is not None and self.speed <= NO_SLEEP_SPEED:
                gap = (event.ts - previous).total_seconds() / self.speed
                if gap > 0:
                    await sleeper(min(gap, 5.0))
            previous = event.ts
            result.last_ts = event.ts
            result.events += 1
            await self.pipeline.submit_async(event)
            if max_events is not None and result.events >= max_events:
                break
        logger.info("replayed %d events from %s", result.events, self.path)
        return result


async def _no_sleep(_seconds: float) -> None:
    """Yield control without delaying (fast replay mode)."""
    await asyncio.sleep(0)


def replay_file(path: str | Path) -> int:  # pragma: no cover - CLI helper
    """Count events in an archive without running the pipeline."""
    return sum(1 for _ in read_jsonl(path))


__all__ = ["Replay", "ReplayResult", "read_jsonl", "replay_file"]

# Re-export for type checkers.
_Event = Event