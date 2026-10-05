"""Fake SSH honeypot built on asyncssh.

Captures connect / login attempt / login success / disconnect events and
command activity. The session is emulated by :mod:`honeywatch.honeypots.shell`;
no host command is ever executed.

Design: :class:`SSHService` owns the listener, limits and event emission.
:class:`_SSHHandler` is created per connection by ``server_factory`` and holds
only that connection's state.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from ..config import SSHConfig
from ..models import MAX_SSH_LINE, Event, EventType, Service, utcnow
from ..sanitize import safe_text
from .shell import FakeShell, ShellSession, chain_indicators, split_chain

logger = logging.getLogger(__name__)

EmitFn = Callable[[Event], None]


def ensure_host_key(path: str | Path) -> Path:
    """Generate once and reuse a stable host key with restrictive permissions."""
    key_path = Path(path)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if not key_path.exists():
        key = asyncssh.generate_private_key("ssh-rsa", key_size=2048)
        key.write_private_key(str(key_path))
        with contextlib.suppress(OSError):
            key_path.chmod(0o600)
    return key_path


@dataclass
class ConnectionLimiter:
    """Global and per-source-IP concurrent connection limits."""

    max_total: int = 100
    max_per_ip: int = 5
    _total: int = field(default=0, init=False)
    _per_ip: dict[str, int] = field(default_factory=dict, init=False)

    def acquire(self, ip: str) -> bool:
        if self._total >= self.max_total:
            return False
        if self._per_ip.get(ip, 0) >= self.max_per_ip:
            return False
        self._total += 1
        self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
        return True

    def release(self, ip: str) -> None:
        self._total = max(0, self._total - 1)
        remaining = self._per_ip.get(ip, 1) - 1
        if remaining <= 0:
            self._per_ip.pop(ip, None)
        else:
            self._per_ip[ip] = remaining

    @property
    def total(self) -> int:
        return self._total


class SSHService:
    """Network-facing fake SSH service.

    Args:
        config: Validated SSH configuration section.
        emit: Callable receiving raw :class:`Event` objects.
    """

    def __init__(self, config: SSHConfig, emit: EmitFn, *, banner: str | None = None) -> None:
        self.config = config
        self.emit = emit
        self.banner = banner or config.banner
        self.limiter = ConnectionLimiter(config.max_connections, config.max_per_ip)
        self._server: asyncssh.SSHAcceptor | None = None

    # ---- event construction -------------------------------------------

    def _event(
        self,
        *,
        ip: str,
        event_type: EventType,
        session_id: str,
        port: int | None = None,
        **fields: object,
    ) -> Event:
        return Event(
            ts=utcnow(),
            service=Service.SSH,
            event_type=event_type,
            src_ip=ip,
            src_port=port,
            session_id=session_id,
            **fields,  # type: ignore[arg-type]
        )

    # ---- session logic -------------------------------------------------

    def _on_connect(self, ip: str, port: int, session_id: str, banner: str) -> None:
        self.emit(
            self._event(
                ip=ip,
                port=port,
                event_type=EventType.CONNECT,
                session_id=session_id,
                client_banner=safe_text(banner, limit=MAX_SSH_LINE) or None,
            )
        )

    def _on_disconnect(self, ip: str, session_id: str) -> None:
        self.emit(self._event(ip=ip, event_type=EventType.DISCONNECT, session_id=session_id))

    async def _on_password(self, handler: _SSHHandler, username: str, password: str) -> bool:
        """Record the attempt and decide acceptance per the weak-credential policy."""
        safe_user = safe_text(username, limit=256)
        safe_pass = safe_text(password, limit=256)
        handler.attempts += 1
        accepted = safe_pass in self.config.weak_passwords or (
            handler.attempts >= self.config.accept_after_failures
        )
        self.emit(
            self._event(
                ip=handler.ip,
                port=handler.port,
                event_type=EventType.LOGIN_ATTEMPT,
                session_id=handler.session_id,
                username=safe_user or None,
                password=safe_pass or None,
            )
        )
        if accepted:
            self.emit(
                self._event(
                    ip=handler.ip,
                    port=handler.port,
                    event_type=EventType.LOGIN_SUCCESS,
                    session_id=handler.session_id,
                    username=safe_user or None,
                    password=safe_pass or None,
                )
            )
            return True
        # Randomised rejection delay: guessing is slow and hard to fingerprint.
        await asyncio.sleep(0.3 + secrets.randbelow(90) / 100.0)
        return False

    def _on_command(self, handler: _SSHHandler, command: str, *, blocked: bool = False) -> None:
        tags = list(chain_indicators(command).get("tags") or [])
        if blocked:
            tags.append("limit-enforced")
        self.emit(
            self._event(
                ip=handler.ip,
                port=handler.port,
                event_type=EventType.COMMAND,
                session_id=handler.session_id,
                command=command[:1024],
                tags=tags,
            )
        )

    async def _serve_shell(self, handler: _SSHHandler, process: asyncssh.SSHServerProcess) -> bool:
        """Serve the emulated shell, enforcing idle/session/command limits."""
        session = ShellSession(hostname=self.config.hostname, username="root")
        shell = FakeShell(session)
        process.stdout.write(
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic)\r\n"
        )
        try:
            await asyncio.wait_for(
                self._pump(handler, process, shell, session),
                timeout=self.config.session_timeout_s,
            )
        except (TimeoutError, asyncio.CancelledError):
            with contextlib.suppress(Exception):
                process.stderr.write("\r\n[timed out]\r\n")
        finally:
            with contextlib.suppress(Exception):
                process.exit(0)
        return True

    async def _pump(
        self,
        handler: _SSHHandler,
        process: asyncssh.SSHServerProcess,
        shell: FakeShell,
        session: ShellSession,
    ) -> None:
        """Read bounded lines, emit command events, write fabricated output."""
        while True:
            try:
                line = await asyncio.wait_for(
                    process.stdin.readline(), timeout=self.config.idle_timeout_s
                )
            except TimeoutError:
                process.stderr.write("\r\n[timed out waiting for input]\r\n")
                return
            if not line:
                return
            text = safe_text(line, limit=MAX_SSH_LINE)
            if not text:
                process.stdout.write(session.prompt())
                continue

            components = split_chain(text) or [text]
            for component in components:
                if session.commands_used >= self.config.max_commands:
                    self._on_command(handler, text, blocked=True)
                    process.stderr.write("-bash: maximum number of commands reached\r\n")
                    return
                self._on_command(handler, component)

            output = shell.execute(text)
            if output:
                process.stdout.write(output.replace("\n", "\r\n") + "\r\n")
            first = text.split()[0].rsplit("/", 1)[-1].casefold() if text.split() else ""
            if first in {"exit", "logout"}:
                process.stdout.write("logout\r\n")
                return
            process.stdout.write(session.prompt())

    # ---- lifecycle -----------------------------------------------------

    async def start(self, host_key_path: str | Path) -> None:
        """Bind the listener.

        Raises:
            OSError: The address is unavailable (reported clearly by the CLI).
        """
        key = str(ensure_host_key(host_key_path))
        self._server = await asyncssh.create_server(
            _SSHHandler,
            self.config.bind,
            self.config.port,
            server_factory=lambda: _SSHHandler(self),
            server_host_keys=[key],
            server_version=self.banner,
            encoding="utf-8",
            errors="replace",
            login_timeout=self.config.idle_timeout_s,
        )
        logger.info("ssh honeypot listening on %s:%s", self.config.bind, self.config.port)

    async def stop(self) -> None:
        """Close the listener and release the port."""
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=5)
            self._server = None


class _SSHHandler(asyncssh.SSHServer):
    """Per-connection asyncssh handler. Holds only this connection's state."""

    def __init__(self, service: SSHService) -> None:
        self.service = service
        self.session_id = secrets.token_hex(4)
        self.ip = "0.0.0.0"
        self.port: int | None = None
        self.attempts = 0
        self._tracked = False

    # ---- connection lifecycle -----------------------------------------

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername")
        if peer:
            self.ip = str(peer[0])
            self.port = int(peer[1])
        if not self.service.limiter.acquire(self.ip):
            with contextlib.suppress(Exception):
                conn.abort()
            logger.info("ssh connection refused by limits from %s", self.ip)
            return
        self._tracked = True
        self.service._on_connect(
            self.ip,
            self.port or 0,
            self.session_id,
            str(conn.get_extra_info("client_version", "") or ""),
        )

    def connection_lost(self, exc: Exception | None) -> None:
        if self._tracked:
            self.service.limiter.release(self.ip)
            self.service._on_disconnect(self.ip, self.session_id)
            self._tracked = False

    # ---- authentication -----------------------------------------------

    def begin_auth(self, username: str) -> bool:
        del username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return False

    def public_key_auth_supported(self) -> bool:
        return False

    async def validate_password(self, username: str, password: str) -> bool:
        return await self.service._on_password(self, username, password)

    # ---- session -------------------------------------------------------

    def session_requested(self) -> object:
        return asyncssh.UNKNOWN

    async def shell_requested(self, process: asyncssh.SSHServerProcess) -> bool:
        return await self.service._serve_shell(self, process)