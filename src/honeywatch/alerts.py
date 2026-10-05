"""Outbound Telegram alerting.

Strictly fire-and-forget: a bounded worker queue, short timeout, bounded
retries and a per-hour rate limiter with digest. A total Telegram failure
must never block or fail event collection.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import AlertRecord, Event, RuleHit, Severity, severity_at_least
from .sanitize import safe_markdown, safe_text

logger = logging.getLogger(__name__)

MAX_MESSAGE = 3500
DIGEST_HOLD_S = 300


def build_message(event: Event, hits: list[RuleHit]) -> str:
    """Render an alert body with all attacker-controlled text sanitized."""
    top = max(hits, key=lambda h: list(Severity).index(h.severity))
    lines = [
        "HoneyWatch detection",
        "",
        f"Severity: {top.severity}",
    ]
    if top.rule_id:
        lines.append(f"Rule: {safe_text(top.rule_id, limit=80)} - {safe_text(top.title, limit=120)}")
    if top.attack:
        lines.append(f"ATT&CK: {safe_text(top.attack, limit=20)} {safe_text(top.attack_name or '', limit=80)}")
    lines += [
        "",
        f"Source: {safe_text(event.src_ip, limit=60)}",
        f"Service: {event.service}",
        f"Time (UTC): {event.ts.astimezone(UTC).strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    if event.username or event.password:
        lines.append(
            "Credentials: "
            f"{safe_text(event.username or '', limit=64)} / {safe_text(event.password or '', limit=64)}"
        )
    if event.command:
        lines.append(f"Command: {safe_text(event.command, limit=300)}")
    if event.path:
        lines.append(f"Path: {safe_text(event.path, limit=200)}")
    return "\n".join(lines)[:MAX_MESSAGE]


def digest_message(events: list[tuple[Event, RuleHit]]) -> str:
    """Render a single rolled-up summary for suppressed alerts."""
    lines = ["HoneyWatch digest", "", f"Suppressed alerts: {len(events)}", ""]
    grouped: dict[str, int] = {}
    for _event, hit in events:
        grouped[hit.rule_id] = grouped.get(hit.rule_id, 0) + 1
    for rule_id, count in sorted(grouped.items(), key=lambda kv: -kv[1]):
        lines.append(f"- {safe_text(rule_id, limit=80)} x{count}")
    sources = sorted({e.src_ip for e, _ in events})
    lines.append("")
    lines.append("Sources: " + ", ".join(safe_text(ip, limit=60) for ip in sources[:10]))
    return "\n".join(lines)[:MAX_MESSAGE]


@dataclass
class AlertResult:
    """Outcome of one alert submission."""

    status: str
    detail: str = ""


@dataclass
class _Window:
    sent: deque[datetime] = field(default_factory=deque)
    suppressed: int = 0
    digest: list[tuple[Event, RuleHit]] = field(default_factory=list)
    digest_since: datetime | None = None


class TelegramAlerter:
    """Bounded, non-blocking Telegram notifier with audit rows.

    Args:
        token: Bot token. Read from the environment by the CLI; never logged.
        chat_id: Destination chat.
        min_severity: Alerts below this severity are ignored.
        max_per_hour: Hard ceiling on outbound messages per rolling hour.
        storage: Optional storage for alert audit rows.
    """

    def __init__(
        self,
        *,
        token: str | None,
        chat_id: str,
        min_severity: Severity = Severity.HIGH,
        max_per_hour: int = 20,
        storage: Any = None,
        timeout_s: float = 10.0,
        retries: int = 2,
        base_url: str = "https://api.telegram.org",
        queue_size: int = 1000,
    ) -> None:
        self.token = token or ""
        self.chat_id = chat_id
        self.min_severity = min_severity
        self.max_per_hour = max_per_hour
        self.storage = storage
        self.timeout_s = timeout_s
        self.retries = retries
        self.base_url = base_url.rstrip("/")
        self.queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=queue_size)
        self._window = _Window()
        self._task: asyncio.Task[None] | None = None
        self._closing = asyncio.Event()

    # ---- configuration -------------------------------------------------

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def describe(self) -> dict[str, Any]:
        """Non-secret configuration summary for ``honeywatch doctor``."""
        return {
            "configured": self.configured,
            "chat_id_set": bool(self.chat_id),
            "token_set": bool(self.token),
            "min_severity": str(self.min_severity),
            "max_per_hour": self.max_per_hour,
        }

    # ---- lifecycle -----------------------------------------------------

    def start(self) -> None:
        if not self.configured or self._task is not None:
            return
        self._task = asyncio.create_task(self._worker(), name="honeywatch-alerts")

    async def stop(self, *, timeout: float = 5.0) -> None:
        self._closing.set()
        if self._task is not None:
            try:
                await asyncio.wait_for(self._task, timeout=timeout)
            except (TimeoutError, asyncio.CancelledError):  # pragma: no cover - timing
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
            self._task = None

    # ---- submission ----------------------------------------------------

    def submit(self, event: Event, hits: list[RuleHit]) -> None:
        """Queue an alert. Never raises and never blocks the pipeline."""
        try:
            self.queue.put_nowait({"event": event, "hits": list(hits)})
        except asyncio.QueueFull:
            logger.warning("alert queue full; alert dropped (collection continues)")

    async def submit_async(self, event: Event, hits: list[RuleHit]) -> None:
        self.submit(event, hits)

    # ---- worker --------------------------------------------------------

    async def _worker(self) -> None:
        while True:
            if self._closing.is_set() and self.queue.empty():
                await self._flush_digest()
                return
            try:
                item = await asyncio.wait_for(self.queue.get(), timeout=0.5)
            except TimeoutError:
                continue
            if item is None:
                await self._flush_digest()
                return
            try:
                await self._handle(item["event"], item["hits"])
            except Exception:  # pragma: no cover - alerting is best-effort
                logger.exception("alert handling failed; collection continues")
            finally:
                self.queue.task_done()

    async def _handle(self, event: Event, hits: list[RuleHit]) -> None:
        eligible = [h for h in hits if severity_at_least(h.severity, self.min_severity)]
        if not eligible:
            return
        now = datetime.now(UTC)
        self._prune(now)

        if len(self._window.sent) >= self.max_per_hour:
            self._suppress(event, eligible[0], now)
            return
        text = build_message(event, eligible)
        ok = await self._send(text)
        if ok:
            self._window.sent.append(now)
            self._audit(event, eligible[0], "sent", None, now)
        else:
            self._audit(event, eligible[0], "failed", "delivery failed", now)

    def _suppress(self, event: Event, hit: RuleHit, now: datetime) -> None:
        self._window.suppressed += 1
        self._window.digest.append((event, hit))
        if self._window.digest_since is None:
            self._window.digest_since = now
        self._audit(event, hit, "suppressed", "rate limited", now)

    def _prune(self, now: datetime) -> None:
        cutoff = now - timedelta(hours=1)
        while self._window.sent and self._window.sent[0] < cutoff:
            self._window.sent.popleft()

    async def _flush_digest(self) -> None:
        if not self._window.digest:
            return
        if self._window.digest_since is not None:
            age = (datetime.now(UTC) - self._window.digest_since).total_seconds()
            if age < DIGEST_HOLD_S:
                return
        pending = self._window.digest
        self._window.digest = []
        self._window.digest_since = None
        await self._send(digest_message(pending))

    async def _send(self, text: str) -> bool:
        """POST a message. Retries are bounded; failures are recorded, not raised."""
        if not self.configured:
            return False
        url = f"{self.base_url}/bot{self.token}/sendMessage"
        payload = {
            "chat_id": self.chat_id,
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True,
        }
        import httpx

        for attempt in range(self.retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout_s) as client:
                    response = await client.post(url, json=payload)
                if response.status_code < 300:
                    return True
                logger.warning("telegram returned HTTP %s", response.status_code)
            except Exception as exc:
                logger.warning("telegram attempt %d failed: %s", attempt + 1, type(exc).__name__)
            if attempt < self.retries:
                await asyncio.sleep(min(2**attempt, 8))
        return False

    def _audit(
        self,
        event: Event,
        hit: RuleHit,
        status: str,
        detail: str | None,
        ts: datetime,
    ) -> None:
        if self.storage is None:
            return
        try:
            self.storage.insert_alert(
                AlertRecord(
                    ts=ts,
                    rule_id=hit.rule_id,
                    src_ip=event.src_ip,
                    severity=hit.severity,
                    title=safe_text(hit.title, limit=200),
                    status=status,
                    detail=detail,
                )
            )
        except Exception:  # pragma: no cover - audit must never break collection
            logger.exception("failed to write alert audit row")

    # ---- introspection -------------------------------------------------

    @property
    def sent_count(self) -> int:
        return len(self._window.sent)

    @property
    def suppressed_count(self) -> int:
        return self._window.suppressed


def build_alerter(config: Any, storage: Any = None) -> TelegramAlerter | None:
    """Create an alerter from config, or ``None`` when Telegram is disabled."""
    tg = config.alerts.telegram
    if not tg.enabled:
        return None
    token = config.telegram_token()
    if not token:
        logger.warning(
            "Telegram is enabled but %s is unset; alerts are disabled and collection continues",
            tg.token_env,
        )
        return None
    return TelegramAlerter(
        token=token,
        chat_id=tg.chat_id,
        min_severity=tg.min_severity,
        max_per_hour=tg.max_per_hour,
        storage=storage,
        timeout_s=tg.timeout_s,
        retries=tg.retries,
        base_url=tg.base_url,
    )


def masked_token(token: str | None) -> str:  # pragma: no cover - display helper
    """Never print a token; show only its length when debugging."""
    return f"<unset>" if not token else f"<set, {len(token)} chars>"


def env_token(name: str) -> str | None:  # pragma: no cover - trivial
    return os.environ.get(name) or None


__all__ = ["AlertResult", "TelegramAlerter", "build_alerter", "build_message", "digest_message", "safe_markdown"]