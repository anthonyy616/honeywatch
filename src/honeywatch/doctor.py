"""``honeywatch doctor`` diagnostics.

Never prints secrets: tokens are reported only as present/absent.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .engine.loader import load_ruleset
from .storage.sqlite import Storage


@dataclass(slots=True)
class Check:
    """One diagnostic result."""

    name: str
    status: str  # ok | warn | fail
    detail: str


@dataclass(slots=True)
class DoctorReport:
    checks: list[Check]

    @property
    def ok(self) -> bool:
        """True when no check failed (warnings are allowed)."""
        return all(c.status != "fail" for c in self.checks)


def _port_free(host: str, port: int) -> bool:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def run_doctor(config: Config) -> DoctorReport:
    """Run every documented diagnostic."""
    checks: list[Check] = []
    checks.append(Check("config", "ok", f"loaded (log_level={config.log_level})"))

    # data dir
    try:
        data_dir = config.ensure_data_dir()
        checks.append(Check("data-dir", "ok", f"writable: {data_dir}"))
    except Exception as exc:
        checks.append(Check("data-dir", "fail", str(exc)))

    # database
    try:
        with Storage(config.db_path) as store:
            version = store.schema_version()
        checks.append(Check("database", "ok", f"schema v{version} at {config.db_path}"))
    except Exception as exc:
        checks.append(Check("database", "fail", f"cannot open {config.db_path}: {exc}"))

    # ports
    if config.ssh.enabled:
        status = "ok" if _port_free(config.ssh.bind, config.ssh.port) else "fail"
        detail = (
            f"{config.ssh.bind}:{config.ssh.port} available"
            if status == "ok"
            else f"{config.ssh.bind}:{config.ssh.port} already in use"
        )
        checks.append(Check("ssh-port", status, detail))
    else:
        checks.append(Check("ssh-port", "warn", "SSH honeypot disabled"))

    if config.http.enabled:
        status = "ok" if _port_free(config.http.bind, config.http.port) else "fail"
        detail = (
            f"{config.http.bind}:{config.http.port} available"
            if status == "ok"
            else f"{config.http.bind}:{config.http.port} already in use"
        )
        checks.append(Check("http-port", status, detail))
    else:
        checks.append(Check("http-port", "warn", "HTTP honeypot disabled"))

    # rules
    ruleset = load_ruleset(config.rules_dir)
    if not ruleset.rules:
        checks.append(Check("rules", "fail", f"no valid rules in {config.rules_dir}"))
    elif ruleset.errors:
        checks.append(
            Check("rules", "warn", f"{len(ruleset.rules)} valid, {len(ruleset.errors)} skipped")
        )
    else:
        checks.append(Check("rules", "ok", f"{len(ruleset.rules)} rules from {len(ruleset.files)} files"))

    # geoip
    geo_paths = [config.enrichment.geoip_city_db, config.enrichment.geoip_asn_db]
    configured = [Path(p) for p in geo_paths if p]
    present = [p for p in configured if p.is_file()]
    if configured and len(present) == len(configured):
        checks.append(Check("geoip", "ok", f"{len(present)} database(s) present"))
    else:
        checks.append(
            Check("geoip", "warn", "GeoLite2 databases missing; enrichment will be partial")
        )

    # telegram (only when enabled)
    tg = config.alerts.telegram
    if not tg.enabled:
        checks.append(Check("telegram", "ok", "disabled (no token required)"))
    else:
        token = os.environ.get(tg.token_env, "").strip()
        if not token:
            checks.append(
                Check("telegram", "fail", f"enabled but {tg.token_env} is not set")
            )
        elif not tg.chat_id:
            checks.append(Check("telegram", "fail", "enabled but chat_id is empty"))
        else:
            checks.append(
                Check("telegram", "ok", f"configured (chat {tg.chat_id}, token set via {tg.token_env})")
            )

    # privileges
    if hasattr(os, "geteuid") and os.geteuid() == 0:  # pragma: no cover - platform dependent
        checks.append(Check("privileges", "warn", "running as root; run unprivileged in production"))
    else:
        checks.append(Check("privileges", "ok", "running unprivileged"))

    return DoctorReport(checks=checks)