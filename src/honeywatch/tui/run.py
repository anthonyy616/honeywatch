"""TUI launcher and the temporary replay context used by ``tui --replay``."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("honeywatch.tui")


@dataclass(slots=True)
class TUIOptions:
    """Resolved options for a dashboard session.

    ``config`` is the configuration the CLI already validated. Passing it in
    keeps the dashboard on the same rules directory as the rest of the run
    instead of re-discovering a configuration from the working directory.
    """

    db_path: Path
    replay: Path | None = None
    speed: float = 10.0
    refresh: float = 1.0
    config: Any = None


@dataclass
class ReplayContext:
    """Temporary database/data directory used by the deterministic demo."""

    workdir: Path
    db_path: Path
    config: Any
    replay_file: Path
    speed: float = 10.0
    pipeline: Any = None
    _task: asyncio.Task[Any] | None = field(default=None, init=False, repr=False)

    def start_replay(self) -> None:
        """Start the replay producer on the running loop.

        Must be called from inside the event loop that runs the dashboard, so
        the producer is scheduled on that same loop and actually executes.
        """
        from ..replay import Replay

        if self.pipeline is None:  # pragma: no cover - guarded by builder
            raise RuntimeError("pipeline not initialised")
        self._task = asyncio.get_running_loop().create_task(
            Replay(self.replay_file, self.pipeline, speed=self.speed).run(),
            name="honeywatch-tui-replay",
        )

    def start_replay_cancel(self) -> None:
        """Cancel a still-running replay producer (best effort)."""
        if self._task is not None and not self._task.done():
            self._task.cancel()

    def cleanup(self) -> None:
        """Stop the producer and remove temporary state on normal exit."""
        self.start_replay_cancel()
        self._task = None
        shutil.rmtree(self.workdir, ignore_errors=True)


@contextlib.contextmanager
def replay_context(replay_file: Path, config: Any, *, speed: float = 10.0) -> Iterator[ReplayContext]:
    """Build a temporary data context for the replay demo.

    The temporary database and JSONL archive are deleted when the context
    exits, so a clean clone leaves nothing behind.
    """
    from ..config import parse_config

    workdir = Path(tempfile.mkdtemp(prefix="honeywatch-replay-"))
    raw = dict(config.model_dump(mode="json"))
    raw["data_dir"] = str(workdir)
    raw["storage"] = {**raw.get("storage", {}), "raw_archive": True}
    raw["alerts"] = {"telegram": {"enabled": False}}
    temp_config = parse_config(raw, base_dir=workdir)
    ctx = ReplayContext(
        workdir=workdir,
        db_path=temp_config.db_path,
        config=temp_config,
        replay_file=replay_file,
        speed=speed,
    )
    try:
        yield ctx
    finally:
        ctx.cleanup()


def build_pipeline_for_replay(ctx: ReplayContext) -> Any:
    """Create and start the pipeline the replay producer feeds.

    Must be called from inside the running event loop: ``pipeline.start()``
    schedules its consumer with ``asyncio.create_task``.
    """
    from ..simulate_cmd import build_offline_pipeline

    pipeline, _resources = build_offline_pipeline(ctx.config, db_path=ctx.db_path)
    ctx.pipeline = pipeline
    pipeline.start()
    return pipeline


def run_tui(options: TUIOptions) -> None:
    """Run the dashboard, blocking until the user quits.

    Raises:
        FileNotFoundError: The requested database or replay file is missing.
    """
    from ..config import ConfigError, load_config
    from .app import HoneyWatchTUI

    if options.replay is not None and not options.replay.is_file():
        raise FileNotFoundError(f"replay file not found: {options.replay}")

    config = options.config
    if config is None:
        try:
            config = load_config(None)
        except ConfigError as exc:  # pragma: no cover - doctor covers this path
            raise SystemExit(f"configuration error: {exc}") from exc

    if options.replay is not None:
        with replay_context(options.replay, config, speed=options.speed) as ctx:
            asyncio.run(_run_replay_dashboard(ctx, refresh=options.refresh))
        return

    if not options.db_path.is_file():
        raise FileNotFoundError(
            f"database not found: {options.db_path}. Start `honeywatch run` or use "
            "`honeywatch tui --replay <file>`."
        )
    asyncio.run(
        HoneyWatchTUI(
            options.db_path, refresh=options.refresh, config=config
        ).run_async()
    )


async def _run_replay_dashboard(ctx: ReplayContext, *, refresh: float) -> None:
    """Run the dashboard with the replay producer feeding it.

    Both the pipeline and the producer are started inside the running loop:
    ``asyncio.create_task`` needs a running loop, and a task scheduled on any
    other loop would never run, leaving the demo on an empty dashboard.
    """
    from .app import HoneyWatchTUI

    build_pipeline_for_replay(ctx)
    app = HoneyWatchTUI(
        ctx.db_path, refresh=refresh, pipeline=ctx.pipeline, config=ctx.config
    )
    ctx.start_replay()
    try:
        await app.run_async()
    finally:
        ctx.start_replay_cancel()
        with contextlib.suppress(Exception):
            await ctx.pipeline.stop()