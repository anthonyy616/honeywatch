"""The collection daemon.

Owns listeners, the pipeline, the rule engine and optional alerting. The TUI is
never started here: collection must survive UI failure.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import signal
from collections.abc import Callable
from typing import Any

from .config import Config
from .engine.detector import DetectionEngine, install_sighup_reload
from .engine.loader import load_ruleset
from .enrich import Enricher, GeoEnricher
from .pipeline import EventPipeline
from .storage.jsonl import JsonlArchive
from .storage.sqlite import Storage

logger = logging.getLogger("honeywatch.daemon")


class Daemon:
    """Owns the listeners and the single pipeline consumer."""

    def __init__(self, config: Config, alerter: Any = None) -> None:
        self.config = config
        config.ensure_data_dir()

        self.ruleset = load_ruleset(config.rules_dir)
        for err in self.ruleset.errors:
            logger.warning("rule skipped: %s", err)
        if not self.ruleset.rules:
            raise RuntimeError(
                f"no valid rules found in {config.rules_dir}; refusing to start. "
                "Fix the rule files or point rules.directory at the catalogue."
            )
        self.detector = DetectionEngine(self.ruleset.rules)

        self.storage = Storage(config.db_path)
        self.archive = JsonlArchive(config.raw_dir, enabled=config.storage.raw_archive)
        self.geo = GeoEnricher(config.enrichment.geoip_city_db, config.enrichment.geoip_asn_db)
        self.pipeline = EventPipeline(
            storage=self.storage,
            archive=self.archive,
            detector=self.detector,
            enricher=Enricher(self.geo),
            alerter=alerter,
            queue_size=config.storage.queue_size,
            half_life_hours=config.scoring.half_life_hours,
            weights={str(k): float(v) for k, v in config.scoring.weights.items()},
            min_alert_severity=config.alerts.telegram.min_severity,
        )
        self.ssh: Any = None
        self.http: Any = None
        self._remove_sighup: Callable[[], None] | None = None

    # ---- lifecycle -----------------------------------------------------

    async def start(self) -> None:
        """Start the pipeline, then bind the listeners."""
        self.pipeline.start()
        if self.alerter_is_available:
            with contextlib.suppress(Exception):
                self.pipeline.alerter.start()

        if self.config.ssh.enabled:
            from .honeypots.ssh_server import SSHService

            self.ssh = SSHService(self.config.ssh, self.pipeline.submit, banner=self.config.ssh.banner)
            await self.ssh.start(self.config.host_key_path)
        if self.config.http.enabled:
            from .honeypots.http_server import HTTPService

            self.http = HTTPService(self.config.http, self.pipeline.submit)
            await self.http.start()

        if self.config.rules.reload_on_sighup:
            self._remove_sighup = install_sighup_reload(self.detector, self.config.rules_dir)

    @property
    def alerter_is_available(self) -> bool:
        return self.pipeline.alerter is not None

    async def stop(self) -> None:
        """Ordered shutdown: listeners, sessions, pipeline, writers, resources."""
        logger.info("shutdown starting")
        if self._remove_sighup is not None:
            self._remove_sighup()
            self._remove_sighup = None
        if self.ssh is not None:
            with contextlib.suppress(Exception):
                await self.ssh.stop()
            self.ssh = None
        if self.http is not None:
            with contextlib.suppress(Exception):
                await self.http.stop()
            self.http = None
        await self.pipeline.stop()
        self.geo.close()
        logger.info("shutdown complete")


async def run_daemon(
    config: Config,
    alerter_factory: Callable[[Config], Any] | None = None,
    *,
    duration: int = 0,
) -> None:
    """Run the daemon until SIGINT/SIGTERM or the optional duration elapses."""
    daemon = Daemon(config)
    if alerter_factory is not None:
        # The alerter needs the daemon's storage handle for alert audit rows.
        daemon.pipeline.alerter = alerter_factory(config, daemon.storage)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError, ValueError):
            loop.add_signal_handler(sig, stop_event.set)

    try:
        await daemon.start()
    except Exception:
        with contextlib.suppress(Exception):
            await daemon.stop()
        raise

    logger.info("honeywatch daemon ready (ssh=%s http=%s)", config.ssh.enabled, config.http.enabled)

    if duration > 0:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=duration)
    else:
        await stop_event.wait()

    await daemon.stop()


def run_daemon_sync(
    config: Config,
    alerter_factory: Callable[[Config], Any] | None = None,
    *,
    duration: int = 0,
) -> None:  # pragma: no cover - convenience wrapper
    """Synchronous wrapper used by the CLI."""
    asyncio.run(run_daemon(config, alerter_factory, duration=duration))