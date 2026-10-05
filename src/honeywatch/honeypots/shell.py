"""The fake shell emulator.

This module NEVER invokes a command interpreter, subprocess, socket or DNS
resolver. It parses attacker text for observation only and returns fabricated
output. Absolute prohibitions are enforced by ``tests/integration/
test_security_regression.py``.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..sanitize import safe_text

# Chain separators are observation syntax only.
_SEPARATORS = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
_URL_RE = re.compile(r"\b((?:https?|ftps?|tftp)://[^\s'\"<>\\]{1,300})", re.IGNORECASE)
_BARE_URL_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|top|xyz|cc|tk)\S{0,200}", re.IGNORECASE)

FILESYSTEM: dict[str, dict[str, str]] = {
    "/": {
        "bin": "drwxr-xr-x  2 root root  4096 Jan  9 03:14 sbin",
        "etc": "drwxr-xr-x 20 root root  4096 Feb 11 21:02 etc",
        "home": "drwxr-xr-x  3 root root  4096 Jan 22 18:31 home",
        "lib": "drwxr-xr-x  4 root root  4096 Feb  3 05:11 lib",
        "proc": "dr-xr-xr-x  9 root root     0 Mar 12 09:41 proc",
        "root": "drwx------  8 root root  4096 Mar 12 09:38 root",
        "sbin": "lrwxrwxrwx  1 root root     0 Jan  9 03:14 sbin -> /usr/sbin",
        "tmp": "drwxrwxrwt  9 root root  4096 Mar 12 09:40 tmp",
        "usr": "drwxr-xr-x 12 root root  4096 Mar  4 22:15 usr",
        "var": "drwxr-xr-x 12 root root  4096 Feb 20 06:33 var",
    },
    "/etc": {
        "passwd": "root:x:0:0:root:/root:/bin/bash",
        "shadow": "root:*:19000:0:99999:7:::",
        "hosts": "127.0.0.1\tlocalhost",
        "hostname": "",
        "resolv.conf": "nameserver 8.8.8.8",
        "nginx": "nginx.conf",
        "apache2": "apache2.conf",
    },
    "/root": {
        ".bash_history": "",
        ".bashrc": "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin",
        ".ssh": "drwx------ 2 root root 4096 Mar  1 08:12 .ssh",
        "authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAA... redacted",
    },
    "/var/log": {
        "auth.log": "Jan  1 00:00:01 srv-prod-02 sshd[1]: Server listening",
        "syslog": "Jan  1 00:00:01 srv-prod-2 systemd[1]: Started Session",
    },
    "/tmp": {},
    "/home": {},
}

PROCESSES = [
    (" 1 root      0  7128  5292 ?        Ss   Jan09 ?   0:01 /sbin/init splash",
     "root", "0:01.02", "/sbin/init", "/sbin/init splash"),
    (" 842 root      0 12844  9116 ?        Ss   Jan09 ?   0:04 sshd: /usr/sbin/sshd -D",
     "root", "0:04.11", "/usr/sbin/sshd", "/usr/sbin/sshd -D"),
    ("1104 mysql   999 48120 39200 ?        Sl   Feb11 ?  11:22 /usr/sbin/mariadbd",
     "mysql", "11:22.04", "/usr/sbin/mariadbd", ""),
    ("1288 www-data 33 22104 15880 ?        S    Mar12 ?   0:31 /usr/sbin/apache2 -k start",
     "www-data", "0:31.55", "/usr/sbin/apache2", "/usr/sbin/apache2 -k start"),
    ("1330 postgres 999 32088 20444 ?        Ss   Feb03 ?   2:10 postgres: main",
     "postgres", "2:10.02", "postgres", "postgres: main"),
    ("2051 root      0  6120  4188 pts/0    R+   09:41   0:00 -bash",
     "root", "0:00.02", "-bash", "-bash"),
]

MINER_MARKERS = (
    "stratum+tcp",
    "stratum+ssl",
    "xmrig",
    "minerd",
    "cpuminer",
    "ethminer",
    "nicehash",
    "nanopool",
    "supportxmr",
    "monero",
    "--donate-level",
)

BUSYBOX_MARKERS = (
    "busybox",
    "toybox",
    "mirai",
    "gafgyt",
    "hajime",
    "tsunami",
    "dvrHelper",
    "zollard",
    "/bin/busybox ",
    "wget http://",
)

PERSISTENCE_MARKERS = (
    "authorized_keys",
    "authorized_keys2",
    "crontab",
    "rc.local",
    "/etc/rc",
    ".bashrc",
    ".bash_profile",
    ".profile",
    "/etc/init.d",
    "systemctl enable",
    "chkconfig",
)

RECON_COMMANDS = (
    "uname",
    "hostname",
    "ifconfig",
    "ip addr",
    "ip a ",
    "cat /etc/passwd",
    "cat /proc",
    "ls /",
    "find /",
    "netstat",
    "ss -",
    "who",
    "w ",
    "last",
    "df",
    "free",
    "uptime",
    "ps aux",
    "env",
    "printenv",
    "id",
    "whoami",
)

TRANSFER_COMMANDS = ("wget", "curl", "tftp", "ftpget", "busybox wget", "busybox curl")

DOWNLOAD_RE = re.compile(
    r"\b(?:wget|curl|tftp|ftpget)\b[^;|&]{0,400}?(?:https?|ftp|tftp)://[^\s;|&]{1,300}",
    re.IGNORECASE,
)


def split_chain(command: str) -> list[str]:
    """Split a command chain for observation.

    Recognises ``;``, ``&&``, ``||`` and pipes. This is string splitting only:
    no expansion, substitution or execution ever happens.
    """
    if not command:
        return []
    parts = [part.strip() for part in _SEPARATORS.split(command)]
    return [part for part in parts if part]


def extract_urls(text: str) -> list[str]:
    """Extract transfer indicators (URLs / hostnames) without contacting them."""
    if not text:
        return []
    found: list[str] = []
    for match in _URL_RE.finditer(text):
        url = match.group(1).rstrip(").,;:'\"")
        if url not in found:
            found.append(url)
    if not found:
        for match in _BARE_URL_RE.finditer(text):
            host = match.group(0).rstrip(").,;:'\"")
            if host not in found:
                found.append(host)
    return found


def extract_filenames(command: str) -> list[str]:
    """Extract the filenames a transfer command appears to touch.

    Recognises the URL basename and explicit output flags (``-O file``,
    ``-o file``). Pure string parsing: nothing is opened or written.
    """
    text = safe_text(command, limit=1024)
    names: list[str] = []

    def _add(candidate: str) -> None:
        name = candidate.strip("'\";").rstrip(").,")
        if not name or len(name) > 128 or name.startswith("-"):
            return
        name = name.rsplit("/", 1)[-1]
        if name and name not in names:
            names.append(name)

    for url in extract_urls(text):
        base = url.rstrip("/").rsplit("/", 1)[-1]
        if base and "://" not in base:
            _add(base)

    tokens = text.split()
    expect_output = False
    for token in tokens:
        if expect_output:
            _add(token)
            expect_output = False
            continue
        if token.startswith("-O") or token.startswith("--output-document="):
            if "=" in token:
                _add(token.split("=", 1)[1])
            else:
                expect_output = True
    return names[:8]


def chain_indicators(command: str) -> dict[str, object]:
    """Extract IOC-ish indicators from a (possibly chained) command line."""
    lowered = command.casefold()
    tags: list[str] = []
    if DOWNLOAD_RE.search(command) or any(t in lowered for t in TRANSFER_COMMANDS):
        tags.append("tool-transfer")
    if any(m in lowered for m in MINER_MARKERS):
        tags.append("resource-hijacking")
    if any(b in lowered for b in BUSYBOX_MARKERS):
        tags.append("busybox-probe")
    if any(p in lowered for p in PERSISTENCE_MARKERS):
        tags.append("persistence-attempt")
    if any(r in lowered for r in RECON_COMMANDS):
        tags.append("recon")
    return {
        "tags": tags,
        "urls": extract_urls(command),
        "filenames": extract_filenames(command),
    }


@dataclass
class ShellSession:
    """Per-connection fake shell state. Pure data, no OS access."""

    hostname: str = "srv-prod-02"
    username: str = "root"
    cwd: str = "/root"
    created: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_activity: datetime = field(default_factory=lambda: datetime.now(UTC))
    history: list[str] = field(default_factory=list)
    commands_used: int = 0
    rng: random.Random = field(default_factory=random.Random)

    def touch(self) -> None:
        self.last_activity = datetime.now(UTC)

    def prompt(self) -> str:
        user = self.username or "root"
        return f"{user}@{self.hostname}:{self.cwd}$ "


class FakeShell:
    """Fabricated command responses for the honeypot shell."""

    def __init__(self, session: ShellSession) -> None:
        self.session = session

    # ---- public API ----------------------------------------------------

    def execute(self, line: str) -> str:
        """Handle one input line. Never executes anything on the host."""
        self.session.touch()
        text = safe_text(line, limit=4096)
        if not text:
            return ""
        components = split_chain(text)
        if not components:
            return ""
        self.session.history.append(text)
        self.session.commands_used += len(components)
        outputs: list[str] = []
        for index, component in enumerate(components):
            output = self._run_component(component)
            if index < len(components) - 1 and output:
                outputs.append(output.rstrip("\n"))
            elif output:
                outputs.append(output)
        return "\n".join(outputs)

    # ---- internals -----------------------------------------------------

    def _run_component(self, component: str) -> str:
        tokens = component.split()
        if not tokens:
            return ""
        name = tokens[0].rsplit("/", 1)[-1].casefold()
        args = tokens[1:]
        handler = getattr(self, f"_cmd_{name.replace('-', '_')}", None)
        if handler is not None:
            return str(handler(args, component))
        if name in {"exit", "logout"}:
            return ""
        return self._unknown(component)

    def _unknown(self, component: str) -> str:
        name = component.split()[0].rsplit("/", 1)[-1]
        options = {
            "find": "-printf: unknown option",
            "sudo": "sudo: no tty present and no askpass program specified",
            "apt": "E: Could not open lock file /var/lib/dpkg/lock-frontend - open (13: Permission denied)",
            "systemctl": "System has not been booted with systemd as init system (PID 1).",
        }
        hint = options.get(name.casefold(), "command not found")
        return f"bash: {name}: {hint}"

    # ---- identity / system --------------------------------------------

    def _cmd_whoami(self, args: list[str], raw: str) -> str:
        return self.session.username or "root"

    def _cmd_id(self, args: list[str], raw: str) -> str:
        user = self.session.username or "root"
        return f"uid=0({user}) gid=0({user}) groups=0({user}),27(sudo),6(disk)"

    def _cmd_pwd(self, args: list[str], raw: str) -> str:
        return self.session.cwd

    def _cmd_uname(self, args: list[str], raw: str) -> str:
        joined = " ".join(args).casefold()
        if "-a" in args or "--all" in joined:
            return (
                "Linux srv-prod-02 5.15.0-91-generic #101-Ubuntu SMP "
                "x86_64 x86_64 x86_64 GNU/Linux"
            )
        if "-r" in args or "--kernel-release" in joined:
            return "5.15.0-91-generic"
        if "-m" in args or "--machine" in joined:
            return "x86_64"
        return "Linux"

    def _cmd_hostname(self, args: list[str], raw: str) -> str:
        return self.session.hostname

    def _cmd_hostnamectl(self, args: list[str], raw: str) -> str:
        return (
            "Static hostname: srv-prod-02\n"
            "       Icon name: computer-vm\n"
            "      Machine ID: 5f2c1b9ad4e34c0e9b7a1d2c3e4f5061\n"
            "Operating System: Ubuntu 22.04.3 LTS LTS\n"
            "          Kernel: Linux 5.15.0-91-generic"
        )

    # ---- filesystem ---------------------------------------------------

    def _cmd_ls(self, args: list[str], raw: str) -> str:
        target = next((a for a in args if not a.startswith("-")), None)
        if target in {"-la", "--all"}:
            target = None
        path = self._resolve(target or self.session.cwd)
        entries = FILESYSTEM.get(path)
        if entries is None:
            return f"ls: cannot access '{target}': No such file or directory"
        if not entries:
            return ""
        long_format = any(a in {"-l", "-la", "-al", "-al", "-lh"} for a in args)
        if not long_format:
            return "  ".join(sorted(entries))
        lines = []
        for name in sorted(entries):
            if name.startswith("."):
                mode = "drwx------ 2 root root  4096 Mar  1 08:12"
            else:
                mode = "-rw-r--r-- 1 root root  1284 Feb 11 21:02"
            lines.append(f"{mode} {name}")
        return "\n".join(lines)

    def _cmd_cd(self, args: list[str], raw: str) -> str:
        if not args:
            self.session.cwd = "/root"
            return ""
        path = self._resolve(args[0])
        if path in FILESYSTEM:
            self.session.cwd = path
            return ""
        return f"bash: cd: {args[0]}: No such file or directory"

    def _cmd_cat(self, args: list[str], raw: str) -> str:
        if not args:
            return ""
        target = args[0]
        if "=" in target and not target.startswith("/"):
            return ""
        path = self._resolve(target)
        if path in FILESYSTEM and target not in {"/", "//"}:
            parent, _, name = path.rpartition("/")
            entries = FILESYSTEM.get(parent, {})
            if name in entries:
                return entries[name]
        return f"cat: {target}: No such file or directory"

    def _cmd_head(self, args: list[str], raw: str) -> str:
        return self._cmd_cat(args, raw)

    def _cmd_tail(self, args: list[str], raw: str) -> str:
        return self._cmd_cat(args, raw)

    def _cmd_wc(self, args: list[str], raw: str) -> str:
        return "      42       6      412 /tmp/x.sh"

    def _cmd_lsblk(self, args: list[str], raw: str) -> str:
        return (
            "NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINT\n"
            "sda      8:0    0   40G  0 disk\n"
            "|-sda1  8:1    0    1G  0 part /boot\n"
            "`-sda2  8:2    0   39G  0 part \n"
            "  `-ubuntu 253:0  0   37G  0 lvm  /"
        )

    # ---- processes / network / resources ------------------------------

    def _cmd_ps(self, args: list[str], raw: str) -> str:
        lines = ["  PID TTY          TIME CMD"]
        for line, *_ in PROCESSES:
            lines.append(line)
        return "\n".join(lines)

    def _cmd_top(self, args: list[str], raw: str) -> str:
        return (
            "top - 09:41:22 up 62 days,  3:14,  2 users,  load average: 0.14, 0.11, 0.09\n"
            "Tasks:  84 total,   1 running,  83 sleeping,   0 stopped,   0 zombie\n"
            "%Cpu(s):  1.2 us,  0.6 sy,  0.0 ni, 98.1 id,  0.1 wa"
        )

    def _cmd_ifconfig(self, args: list[str], raw: str) -> str:
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            "        inet 10.0.4.19  netmask 255.255.255.0  broadcast 10.0.4.255\n"
            "        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>"
        )

    def _cmd_ip(self, args: list[str], raw: str) -> str:
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
            "    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff\n"
            "    inet 10.0.4.19/24 brd 10.0.4.255 scope global eth0"
        )

    def _cmd_ifstat(self, args: list[str], raw: str) -> str:
        return "    eth0                RX                   TX\n"
        return "               bytes  packets    bytes  packets\n"
        return "    0  10241.221  118       0      4219  94\n"

    def _cmd_free(self, args: list[str], raw: str) -> str:
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:        4035304     1832144     1104424      101272     1098736     1904296\n"
            "Swap:       2097148           0     2097148"
        )

    def _cmd_df(self, args: list[str], raw: str) -> str:
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "/dev/mapper/ubuntu-ubuntu-lv  38G   11G   25G  31% /\n"
            "tmpfs            2.0G     0  2.0G   0% /dev/shm\n"
            "/dev/sda1        511M  127M  384M  26% /boot"
        )

    def _cmd_uptime(self, args: list[str], raw: str) -> str:
        return " 09:41:22 up 62 days,  3:14,  2 users,  load average: 0.14, 0.11, 0.09"

    def _cmd_who(self, args: list[str], raw: str) -> str:
        return "root     pts/0        2026-03-12 09:38 (10.0.4.2)"

    def _cmd_w(self, args: list[str], raw: str) -> str:
        return (
            " 09:41:22 up 62 days,  3:14,  2 users,  load average: 0.14, 0.11, 0.09\n"
            "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            "root     pts/0    10.0.4.2         09:38    0.00s  0.02s  0.00s -bash"
        )

    def _cmd_netstat(self, args: list[str], raw: str) -> str:
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp6       0      0 :::80                   :::*                    LISTEN"
        )

    # ---- misc ---------------------------------------------------------

    def _cmd_history(self, args: list[str], raw: str) -> str:
        return "\n".join(
            f"{index:5d}  {entry}" for index, entry in enumerate(self.session.history, start=1)
        )

    def _cmd_crontab(self, args: list[str], raw: str) -> str:
        if args and args[0] in {"-l", "-e", "-r"}:
            return "no crontab for root"
        return "crontab: installing new crontab"

    def _cmd_echo(self, args: list[str], raw: str) -> str:
        parts = [a for a in args if not a.startswith("-")]
        return " ".join(parts).replace("\\n", "\n")

    def _cmd_whoami_command(self, args: list[str], raw: str) -> str:  # pragma: no cover
        return self._cmd_whoami(args, raw)

    def _cmd_sleep(self, args: list[str], raw: str) -> str:
        return ""

    def _cmd_nop(self, args: list[str], raw: str) -> str:
        return ""

    # ---- fake transfers (never touch the network) ---------------------

    def _cmd_wget(self, args: list[str], raw: str) -> str:
        urls = extract_urls(raw)
        name = (extract_filenames(raw) or ["index.html"])[0]
        target = urls[0] if urls else "unknown"
        if "-q" in args or "--quiet" in args:
            return ""
        lines = [
            f"--2026-03-12 09:41:30--  {target}",
            f"Resolving {target.split('/')[2] if '://' in target else target} ... failed: Temporary failure in name resolution.",
            "wget: unable to resolve host address: temporary failure in name resolution",
        ]
        if not urls:
            lines = [
                f"wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry 'wget --help' for more information.",
            ]
        del name
        return "\n".join(lines)

    def _cmd_curl(self, args: list[str], raw: str) -> str:
        urls = extract_urls(raw)
        if not urls:
            return "curl: (3) URL using bad/illegal format or missing URL"
        if "-I" in args or "--head" in args:
            return "curl: (6) Could not resolve host: temporary failure in name resolution"
        return "curl: (6) Could not resolve host: temporary failure in name resolution"

    def _cmd_tftp(self, args: list[str], raw: str) -> str:
        return "Transfer timed out."

    def _cmd_ftpget(self, args: list[str], raw: str) -> str:
        return "ftpget: connection refused"

    def _cmd_busybox(self, args: list[str], raw: str) -> str:
        if not args:
            return "BusyBox v1.35.0 (Ubuntu 1:1.35.0-4ubuntu3) multi-call binary."
        sub = args[0]
        if sub == "--help":
            return (
                "BusyBox v1.35.0 multi-call binary.\n\n"
                "Usage: busybox [applet [arguments...]]\n"
                "Currently defined functions:\n"
                "  [, [[, addgroup, adduser, ash, awk, base64, cat, chmod, chown, cp, "
                "cron, cut, date, dd, df, echo, env, expr, false, grep, gunzip, gzip, "
                "head, hostname, id, ifconfig, kill, ln, ls, md5sum, mkdir, mknod, "
                "more, mount, mv, nc, netstat, pidof, ping, ps, pwd, rm, sed, sh, "
                "sha1sum, sleep, sort, stat, strings, sync, tar, tee, test, touch, "
                "tr, true, uname, uniq, uptime, wget, xargs, zcat"
            )
        return f"{sub}: applet not found"

    # ---- helpers ------------------------------------------------------

    def _resolve(self, path: str) -> str:
        """Normalise a path inside the fabricated filesystem (no real I/O)."""
        base = self.session.cwd if path.startswith(".") else "/"
        target = path if path.startswith("/") else f"{self.session.cwd}/{path}"
        parts: list[str] = []
        for chunk in target.split("/"):
            if chunk in {"", "."}:
                continue
            if chunk == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(chunk)
        del base
        return "/" + "/".join(parts) if parts else "/"