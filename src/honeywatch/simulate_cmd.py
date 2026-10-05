"""One-shot async harness used by ``simulate`` and ``replay``.

Both commands build the *same* pipeline the daemon uses, feed it from the
corresponding producer, then flush and close. There is no special-cased
downstream path.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from .config import Config
from .engine.detector import DetectionEngine
from .engine.loader import load_ruleset
from .enrich import Enricher, GeoEnricher
from .pipeline import EventPipeline
from .storage.jsonl import JsonlArchive
from .storage.sqlite import Storage

logger = logging.getLogger("honeywatch.simulate")


def build_offline_pipeline(
    config: Config,
    *,
    db_path: Path | None = None,
    write_archive: bool = True,
) -> tuple[EventPipeline, list[Any]]:
    """Construct a pipeline with the catalogue ruleset and an optional DB path.

    Returns:
        The pipeline and the resources that must be closed by the caller.
    """
    ruleset = load_ruleset(config.rules_dir)
    if not ruleset.rules:
        raise RuntimeError(
            f"no valid rules found in {config.rules_dir}; cannot build the pipeline"
        )
    target = Path(db_path) if db_path else config.db_path
    target.parent.mkdir(parents=True, exist_ok=True)
    storage = Storage(target)
    archive = JsonlArchive(config.raw_dir, enabled=write_archive and config.storage.raw_archive)
    geo = GeoEnricher(config.enrichment.geoip_city_db, config.enrichment.geoip_asn_db)
    pipeline = EventPipeline(
        storage=storage,
        archive=archive,
        detector=DetectionEngine(ruleset.rules),
        enricher=Enricher(geo),
        queue_size=config.storage.queue_size,
        half_life_hours=config.scoring.half_life_hours,
        weights={str(k): float(v) for k, v in config.scoring.weights.items()},
    )
    return pipeline, [storage, archive, geo]


async def _drain(pipeline: EventPipeline) -> None:
    """Wait until the consumer has processed every queued event."""
    import asyncio

    await asyncio.wait_for(pipeline.queue.join(), timeout=120)


def run_simulation(
    config: Config,
    *,
    profiles: tuple[str, ...] = (),
    rate: float = 5.0,
    duration_s: int | None = None,
    seed: int = 1337,
    db_path: Path | None = None,
) -> int:
    """Run the simulator once through the real pipeline."""
    import asyncio

    from .simulator import Simulator

    pipeline, resources = build_offline_pipeline(config, db_path=db_path)

    async def _run() -> int:
        pipeline.start()
        sim = Simulator(pipeline=pipeline, profiles=profiles, rate=rate, seed=seed)
        count = await sim.run(duration_s=duration_s)
        await _drain(pipeline)
        return count

    try:
        return asyncio.run(_run())
    finally:
        for resource in resources:
            close = getattr(resource, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:  # pragma: no cover - defensive
                    pass


def run_replay(
    config: Config,
    file: Path,
    *,
    speed: float = 10.0,
    db_path: Path | None = None,
) -> int:
    """Replay a JSONL archive once through the real pipeline."""
    import asyncio

    from .replay import Replay

    pipeline, resources = build_offline_pipeline(config, db_path=db_path)

    async def _run() -> int:
        pipeline.start()
        result = await Replay(file, pipeline, speed=speed).run()
        await _drain(pipeline)
        return result.events

    try:
        return asyncio.run(_run())
    finally:
        for resource in resources:
            close = getattr(resource, "close", None)
            if close is not None:
                try:
                    close()
                except Exception:  # pragma: no cover - defensive
                    pass