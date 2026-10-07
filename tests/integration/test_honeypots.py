"""Live honeypot tests: real listeners on loopback, driven by real clients.

The unit tests call the session helpers directly, so a mistake in how a
listener is wired to asyncssh or aiohttp never shows up there. These tests bind
ephemeral ports on 127.0.0.1 and drive them with real clients, which is the
only way to prove an attacking client is actually captured.
"""

from __future__ import annotations

from pathlib import Path

import aiohttp
import asyncssh
import pytest

from honeywatch.config import HTTPConfig, SSHConfig, parse_config
from honeywatch.daemon import Daemon
from honeywatch.honeypots.http_server import HTTPService
from honeywatch.honeypots.ssh_server import SSHService
from honeywatch.models import Event, EventType, Service

pytestmark = pytest.mark.integration


def ssh_config(**overrides) -> SSHConfig:
    payload = {
        "bind": "127.0.0.1",
        "port": 0,
        "weak_passwords": ["letmein"],
        "idle_timeout_s": 5,
        "session_timeout_s": 15,
        "max_commands": 5,
    }
    payload.update(overrides)
    return SSHConfig.model_validate(payload)


def http_config(**overrides) -> HTTPConfig:
    payload = {"bind": "127.0.0.1", "port": 0}
    payload.update(overrides)
    return HTTPConfig.model_validate(payload)


def commands(events: list[Event]) -> list[str]:
    return [e.command for e in events if e.event_type is EventType.COMMAND and e.command]


async def test_ssh_listener_captures_login_and_command(tmp_path: Path) -> None:
    """A real SSH client is challenged, accepted and its command recorded."""
    marker = tmp_path / "pwned"
    events: list[Event] = []
    service = SSHService(ssh_config(), events.append)
    await service.start(tmp_path / "host_key")
    try:
        port = service.bound_port
        assert port, "listener must report its bound port"
        async with asyncssh.connect(
            "127.0.0.1",
            port=port,
            username="root",
            password="letmein",
            known_hosts=None,
            client_keys=None,
            preferred_auth="password",
        ) as conn:
            result = await conn.run(f"touch {marker}", check=False)
            assert result.stdout is not None
    finally:
        await service.stop()

    kinds = [e.event_type for e in events]
    for expected in (
        EventType.CONNECT,
        EventType.LOGIN_ATTEMPT,
        EventType.LOGIN_SUCCESS,
        EventType.COMMAND,
        EventType.DISCONNECT,
    ):
        assert expected in kinds, f"{expected} was not captured (got {kinds})"

    assert (f"touch {marker}") in commands(events)
    assert all(e.service is Service.SSH for e in events)

    # The client's identification string must reach the audit record.
    attempt = next(e for e in events if e.event_type is EventType.LOGIN_ATTEMPT)
    assert attempt.client_banner is not None
    assert "asyncssh" in attempt.client_banner.lower()

    # The security invariant: attacker input is never executed.
    assert not marker.exists(), "the honeypot executed an attacker command"


async def test_ssh_listener_records_rejected_login(tmp_path: Path) -> None:
    """A wrong password is recorded as an attempt without a success event."""
    events: list[Event] = []
    service = SSHService(ssh_config(accept_after_failures=100), events.append)
    await service.start(tmp_path / "host_key")
    try:
        port = service.bound_port
        assert port
        with pytest.raises(asyncssh.PermissionDenied):
            await asyncssh.connect(
                "127.0.0.1",
                port=port,
                username="root",
                password="guessing",
                known_hosts=None,
                client_keys=None,
                preferred_auth="password",
            )
    finally:
        await service.stop()

    attempts = [e for e in events if e.event_type is EventType.LOGIN_ATTEMPT]
    assert [e.username for e in attempts] == ["root"]
    assert attempts[0].password == "guessing"
    assert EventType.LOGIN_SUCCESS not in [e.event_type for e in events]


async def test_http_listener_captures_request_and_credentials() -> None:
    """A real HTTP client is served a decoy and its credentials recorded."""
    events: list[Event] = []
    service = HTTPService(http_config(), events.append)
    await service.start()
    try:
        port = service.bound_port
        assert port
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://127.0.0.1:{port}/.env") as response:
                assert response.status == 200
                body = await response.text()
            async with session.post(
                f"http://127.0.0.1:{port}/wp-login.php",
                data={"log": "admin", "pwd": "s3cret"},
            ) as response:
                assert response.status == 200
    finally:
        await service.stop()

    assert "DB_PASSWORD" in body, "the decoy .env must be served, not a real file"

    get_events = [e for e in events if e.path == "/.env"]
    assert get_events and get_events[0].event_type is EventType.HTTP_REQUEST

    logins = [e for e in events if e.event_type is EventType.HTTP_LOGIN_ATTEMPT]
    assert len(logins) == 1
    assert (logins[0].username, logins[0].password) == ("admin", "s3cret")
    assert all(e.service is Service.HTTP for e in events)


async def test_daemon_starts_both_listeners(tmp_path: Path, rules_dir: Path) -> None:
    """``honeywatch run`` wiring: both honeypots bind and shut down cleanly."""
    config = parse_config(
        {
            "data_dir": str(tmp_path / "data"),
            "rules": {"directory": str(rules_dir)},
            "ssh": {"bind": "127.0.0.1", "port": 0},
            "http": {"bind": "127.0.0.1", "port": 0},
        },
        base_dir=tmp_path,
    )
    daemon = Daemon(config)
    await daemon.start()
    try:
        assert daemon.ssh is not None and daemon.ssh.bound_port
        assert daemon.http is not None and daemon.http.bound_port
        assert daemon.pipeline.storage is not None
    finally:
        await daemon.stop()
