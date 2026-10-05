"""The single event pipeline.

    producer -> bounded queue -> raw JSONL -> enrichment -> detection
             -> scoring context -> SQLite -> optional alerts

Every producer (live SSH, live HTTP, replay, simulator) submits to this one
queue; none of them contain detection logic.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from .models import Event, RuleHit, Severity, max_severity, severity_at_least, utcnow
from .storage.jsonl import JsonlArchive
from .storage.sqlite import Storage, StorageError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .config import Config
    from .engine.detector import DetectionEngine
    from .enrich import Enricher

logger = logging.getLogger(__name__)


class EventPipeline:
    """Owns the bounded queue and its single ordered consumer."""

    def __init__(
        self,
        *,
        storage: Storage,
        archive: JsonlArchive,
        detector: DetectionEngine,
        enricher: Enricher | None = None,
        alerter: Any = None,
        queue_size: int = 10000,
        half_life_hours: float = 6.0,
        weights: dict[str, float] | None = None,
        min_alert_severity: Severity = Severity.HIGH,
    ) -> None:
        self.storage = storage
        self.archive = archive
        self.detector = detector
        self.enricher = enricher
        self.alerter = alerter
        self.half_life_hours = half_life_hours
        self.weights = weights
        self.min_alert_severity = min_alert_severity
        self.queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self.processed = 0
        self.dropped = 0
        self._task: asyncio.Task[None] | None = None
        self._closing = asyncio.Event()

    # ---- lifecycle -----------------------------------------------------

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._consume(), name="honeywatch-pipeline")

    async def stop(self, *, drain_timeout: float = 10.0) -> None:
        """Stop accepting, drain the queue, flush writers and close storage."""
        self._closing.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=drain_timeout)
            except (TimeoutError, asyncio.CancelledError):  # pragma: no cover - timing
                logger.warning("pipeline drain timed out; cancelling consumer")
                self._task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await self._task
            self._task = None
        if self.alerter is not None:
            with contextlib.suppress(Exception):
                await self.alerter.stop()
        self.archive.close()
        with contextlib.suppress(StorageError):
            self.storage.close()

    # ---- producer side -------------------------------------------------

    def submit(self, event: Event) -> None:
        """Non-blocking enqueue. Applies bounded backpressure when full."""
        if self._closing.is_set():
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped += 1
            logger.warning("event queue full; dropped event %s", event.event_type)

    async def submit_async(self, event: Event, timeout: float | None = 5.0) -> bool:
        """Await enqueue with a bounded wait (used by slow producers)."""
        if self._closing.is_set():
            return False
        try:
            await asyncio.wait_for(self.queue.put(event), timeout=timeout)
            return True
        except (TimeoutError, asyncio.QueueFull):
            self.dropped += 1
            logger.warning("event queue full; dropped event %s", event.event_type)
            return False

    def submit_from_thread(self, loop: asyncio.AbstractEventLoop, event: Event) -> bool:
        """Enqueue from another thread (e.g. a blocking producer)."""
        try:
            asyncio.run_coroutine_threadsafe(self.submit_async(event), loop)
            return True
        except RuntimeError:  # pragma: no cover - loop shutting down
            self.dropped += 1
            return False

    # ---- consumer side -------------------------------------------------

    async def _consume(self) -> None:
        while True:
            if self._closing.is_set() and self.queue.empty():
                return
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=0.25)
            except TimeoutError:
                continue
            try:
                self.process(event)
                self.processed += 1
            except StorageError:
                logger.critical("storage failure; aborting pipeline")
                raise
            except Exception:  # pragma: no cover - defensive
                logger.exception("unexpected pipeline error; event dropped")
            finally:
                self.queue.task_done()

    def process(self, event: Event) -> list[RuleHit]:
        """Run one event through the full path. Returns its rule hits."""
        if event.ts.tzinfo is None:
            event.ts = event.ts.replace(tzinfo=UTC)

        # 1. Raw archive first, so JSONL always holds the pre-enrichment event.
        self.archive.write(event)

        # 2. Enrichment.
        if self.enricher is not None:
            self.enricher(event)

        # 3. Detection.
        hits = self.detector.evaluate(event)
        event.rule_ids = [hit.rule_id for hit in hits]
        if hits:
            event.severity = max_severity([event.severity, *[h.severity for h in hits]])
        event.tags = sorted(set(event.tags))

        # 4. Persist.
        self.storage.insert_event(event, hits)

        # 5. Optional alerting (never blocking, never fatal).
        if self.alerter is not None and hits:
            eligible = [
                hit
                for hit in self.detector.should_alert(hits)
                if severity_at_least(hit.severity, self.min_alert_severity)
            ]
            if eligible:
                self._dispatch_alerts(event, eligible)
        return hits

    def _dispatch_alerts(self, event: Event, hits: list[RuleHit]) -> None:
        try:
            submit = getattr(self.alerter, "submit", None)
            if submit is None:
                return
            result = submit(event, hits)
            if isinstance(result, Awaitable):  # pragma: no cover - coroutine alerter
                asyncio.ensure_future(result)
        except Exception:  # pragma: no cover - alerting must never break collection
            logger.exception("alert dispatch failed; collection continues")

    # ---- diagnostics ---------------------------------------------------

    def stats(self) -> dict[str, Any]:
        return {
            "queued": self.queue.qsize(),
            "processed": self.processed,
            "dropped": self.dropped,
            "archive_errors": self.archive.write_errors,
        }





def build_pipeline(
    config: Config,
    *,
    storage: Storage,
    archive: JsonlArchive,
    detector: DetectionEngine,
    enricher: Enricher | None = None,
    alerter: Any = None,
) -> EventPipeline:
    """Construct a pipeline from validated configuration."""
    weights = {str(k): float(v) for k, v in config.scoring.weights.items()}
    return EventPipeline(
        storage=storage,
        archive=archive,
        detector=detector,
        enricher=enricher,
        alerter=alerter,
        queue_size=config.storage.queue_size,
        half_life_hours=config.scoring.half_life_hours,
        weights=weights,
        min_alert_severity=config.alerts.telegram.min_severity,
    )


def wait_for_queue(pipeline: EventPipeline, timeout: float = 30.0) -> bool:
    """Block until the queue drains (bounded). Used before shutdown/reports."""

    async def _wait() -> None:
        await asyncio.wait_for(pipeline.queue.join(), timeout=timeout)

    try:
        asyncio.run(_wait())
        return True
    except (TimeoutError, RuntimeError):  # pragma: no cover - timing dependent
        return False


def latest_ts() -> datetime:  # pragma: no cover - trivial helper
    return utcnow()