# HoneyWatch

HoneyWatch is a Python honeypot and rule-based detection project. It
exposes a fake SSH service and a fake HTTP service, records hostile
activity, enriches events, evaluates YAML detection rules, maps
detections to MITRE ATT&CK, scores source IPs, stores the results in
SQLite and JSONL, and presents the activity in a Textual terminal
dashboard. High-severity detections can optionally be sent to Telegram.

The system is deliberately non-executing: the fake SSH shell never runs
attacker commands, HTTP uploads are never stored, and download commands
never fetch remote content.

## Project outcome

A reviewer must be able to clone the repository and get a convincing
demonstration even when there is no live internet attack traffic. The
minimum polished demonstration is:

``` bash
honeywatch tui --replay sample.jsonl
```

The project must also support a live daemon on a hardened VPS.

## Core stack

-   Python 3.12
-   asyncio
-   asyncssh
-   aiohttp
-   SQLite in WAL mode
-   append-only JSONL archive
-   pydantic v2
-   PyYAML
-   geoip2 / MaxMind GeoLite2 City + ASN
-   Textual / Rich
-   httpx
-   Typer
-   pytest + pytest-asyncio
-   ruff
-   GitHub Actions

## Commands

``` text
honeywatch run [--config PATH]
honeywatch tui [--db PATH] [--replay FILE --speed N]
honeywatch simulate [--profile NAME] [--rate N] [--duration 5m]
honeywatch replay FILE [--speed N]
honeywatch rules validate
honeywatch rules list
honeywatch rules test
honeywatch report [--since 24h] [--out FILE.md]
honeywatch db stats
honeywatch db prune
honeywatch doctor
```

## Architecture

``` mermaid
flowchart LR
    SSH[Fake SSH] --> Q[asyncio.Queue]
    HTTP[Fake HTTP] --> Q
    Replay[Replay / Simulator] --> Q
    Q --> ENRICH[Enrichment]
    ENRICH --> DETECT[Rule engine]
    DETECT --> SCORE[Scoring / classification]
    SCORE --> DB[(SQLite WAL)]
    SCORE --> JSONL[Raw JSONL archive]
    DETECT --> ALERT[Telegram alerter]
    DB --> TUI[Textual TUI]
    DB --> REPORT[Markdown reports]
```

The collection daemon and TUI are separate processes. The daemon owns
collection and writes; the TUI is read-only and polls SQLite. Closing
the TUI must never stop collection.

## Safety boundary

HoneyWatch is an observation system, not an exploitation platform.

-   Never execute attacker-supplied commands.
-   Never evaluate attacker-supplied code.
-   Never fetch attacker-supplied URLs.
-   Never persist uploaded files.
-   Never expose a real shell.
-   Never place the honeypot on a network containing real sensitive
    systems or data.
-   Never commit secrets, GeoLite databases, raw logs, host keys or live
    attacker data.
-   Always sanitise attacker-controlled strings before terminal, report
    or Telegram output.

## Quick start target

``` bash
uv sync --dev
uv run honeywatch rules validate
uv run honeywatch tui --replay sample.jsonl --speed 10
```

Equivalent `pip` installation must also work.

## Detection model

Rules are YAML and intentionally simpler than Sigma. Rules can be
stateless or threshold-based. The initial catalogue contains 17 rules
spanning SSH brute force, credential spraying, post-login activity,
payload-transfer attempts, HTTP scanning/exploitation probes and
cross-service reconnaissance.

Severity weights:

  Severity     Weight
  ---------- --------
  info              1
  low               3
  medium            8
  high             20
  critical         40

Scores decay with a six-hour half-life:

``` text
score(ip, now) = Σ weight(hit) × 0.5 ^ ((now - hit.ts) / 6h)
```

Verdicts: `<10 Noise`, `10–39 Suspicious`, `40–99 Hostile`,
`>=100 Persistent`.

## Repository layout

``` text
honeywatch/
  README.md
  AGENTS.md
  IMPLEMENTATION.md
  ACCEPTANCE.md
  pyproject.toml
  config/honeywatch.example.yaml
  rules/{ssh,http,cross}/
  docs/
  src/honeywatch/
    cli.py config.py models.py pipeline.py
    honeypots/
    engine/
    enrich/
    storage/
    alerts/
    replay/
    report/
    tui/
  tests/{unit,integration,fixtures}/
  deploy/
  scripts/
```

## Limitations

The first version intentionally has no TLS on the HTTP honeypot, no
machine learning, no malware sandbox, no real shell, no active
countermeasures, no multi-user web dashboard and no external database.
GeoIP is approximate and rule tuning remains manual.

Read `AGENTS.md` and `IMPLEMENTATION.md` before modifying the codebase.
