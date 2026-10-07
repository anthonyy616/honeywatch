# HoneyWatch: real-world example

This is a reproducible walkthrough for using HoneyWatch from a clean checkout.
It shows the three most useful modes:

1. Install and validate the detection rules.
2. Generate synthetic attack traffic through the real pipeline.
3. Inspect the results in the terminal dashboard and as a Markdown report.

You can run all of this locally with no external attacker traffic.

## Prerequisites

- Python 3.12
- A Unix-like shell
- Optional: `uv` if you want faster environment management

The example assumes you are inside the repository root.

## 1. Install the project

With `uv`:

```bash
cd honeywatch
uv sync --dev
```

With pip:

```bash
cd honeywatch
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
```

Either way, the `honeywatch` command should now be available:

```bash
honeywatch --version
```

Expected result: a version string such as `honeywatch 1.0.0`.

## 2. Verify the environment

Before starting anything real, run the built-in diagnostic check:

```bash
honeywatch doctor
```

Typical output looks like:

```text
[OK   ] configuration: configuration loaded from config/honeywatch.example.yaml
[OK   ] database: schema v1 at ./data/honeywatch.db
[OK   ] rules: 17 rules valid across 17 files
[OK   ] geoip: no database(s) present
[WARN ] geoip: geoip databases not configured or missing
all required checks passed
```

If `doctor` fails, fix the configuration or directory structure before
continuing. The important thing here is that rules and storage are healthy.

## 3. Validate the detection rules

HoneyWatch ships with 17 YAML detection rules across SSH, HTTP and cross-service
reconnaissance.

```bash
honeywatch rules validate
```

Expected output:

```text
OK: 17 rules valid across 17 files
```

You can also inspect the rule catalogue:

```bash
honeywatch rules list
```

The output includes each rule ID, severity, optional ATT&CK mapping, and
enabled state.

A good demonstration follow-up is:

```bash
honeywatch rules test
```

That runs the bundled rule fixtures and shows which rules are actually firing
against sample events.

## 4. Start with a clean database

The example commands below are easier to read if you begin with a known state.
The simplest approach is to remove any existing database and let HoneyWatch
recreate it on first use:

```bash
rm -f data/honeywatch.db
```

HoneyWatch stores its SQLite database at `data/honeywatch.db` by default and
uses WAL mode.

## 5. Generate simulated attack traffic

If you do not have live attack traffic, use the simulator. The simulator sends
traffic through the same pipeline the honeypots use.

```bash
honeywatch simulate \
  --profile ssh-bruteforcer,credential-sprayer \
  --rate 3 \
  --duration 30s
```

A realistic result looks like:

```text
simulated 90 events
```

The exact count depends on the profiles, rate and duration you choose.

Useful profile combinations for a demo:

- `ssh-bruteforcer` — SSH logins against default and weak credentials
- `credential-sprayer` — many distinct usernames from one source
- `web-scanner` — HTTP probes, sensitive paths and suspicious user agents
- `ssh-bruteforcer,credential-sprayer` — combined SSH brute force and spraying
- `ssh-bruteforcer,web-scanner` — combined SSH and HTTP activity
- `ssh-bruteforcer,credential-sprayer,web-scanner` — richer cross-service noise

You can make the demo more deterministic by fixing the seed:

```bash
honeywatch simulate --profile ssh-bruteforcer,credential-sprayer --rate 3 --duration 30s --seed 42
```

## 6. Inspect the database

Once there is data, query the stored statistics:

```bash
honeywatch db stats
```

Example output:

```json
{
  "events": 90,
  "rule_hits": 14,
  "attackers": 3,
  "first_event": "2026-10-07T10:11:22+00:00",
  "last_event": "2026-10-07T10:11:52+00:00"
}
```

The exact numbers will vary based on the simulation you ran.

## 7. View the terminal dashboard

The dashboard is read-only. It polls SQLite, so it can be run in a separate
terminal from any live daemon.

```bash
honeywatch tui
```

If you want to demo without starting the daemon, replay a recorded archive
instead:

```bash
honeywatch tui --replay data/raw/events.jsonl --speed 10
```

Inside the dashboard, the documented key bindings are:

- `q` — quit
- `p` — pause or resume the feed
- `/` — filter the feed
- `r` — show rules
- `a` — show alerts
- Enter — open the selected attacker detail
- `e` — export the selected attacker as a Markdown report
- `?` — help
- `1`, `2`, `3`, `4` — change the display range

A good demo flow is:

1. Open the dashboard.
2. Show the feed, attacker and credential tables.
3. Press `r` to view loaded rules with hit counts.
4. Press `a` to view recent alerts.
5. Use the arrow keys to move the cursor over an attacker.
6. Press Enter to open that attacker's detail view.
7. Press `e` to export a per-attacker report.
8. Press `?` to show the help screen, then Escape to close it.
9. Quit with `q`.

## 8. Replay a recorded archive

Replay is useful when you want a repeatable demonstration without needing a
live honeypot.

First, create or obtain a raw JSONL archive. If you already have one, replay it
directly:

```bash
honeywatch replay data/raw/events.jsonl --speed 10
```

Expected output:

```text
replayed 50 events from data/raw/events.jsonl
```

You can also combine replay with the dashboard:

```bash
honeywatch tui --replay data/raw/events.jsonl --speed 10
```

The replay path writes events into a temporary database and displays them. It
does not require `honeywatch run` to be active.

## 9. Generate a report

Once there is stored traffic, generate a Markdown report:

```bash
honeywatch report --since 30m
```

To write it to a file:

```bash
honeywatch report --since 30m --out report-30m.md
```

To focus on one source IP:

```bash
honeywatch report --since all --ip 192.0.2.1 --out attacker-192.0.2.1.md
```

A report typically includes:

- summary counts
- top attacking source IPs
- notable detections
- a focused section for the selected attacker, if `--ip` was used

If you ran the dashboard export feature, you may also see files written next to
the database, named like `report-<ip>.md`.

## 10. Interpret the output

When you show this to someone, the most convincing signals are:

- verified rule hits in `honeywatch rules list` and `honeywatch db stats`
- attacker summaries in the dashboard
- per-attacker reports that connect raw events to detections and scoring
- the safety story: the honeypot recorded activity without executing anything

A strong narrative is:

1. Simulate or replay hostile traffic.
2. Validate that rules caught it.
3. Show the same activity in the dashboard.
4. Export one attacker for a human-readable report.

That makes the system feel like a detection-and-reporting tool, not just a dummy
service.

## 11. Cleanup

If you used a temporary database only for the demo:

```bash
rm -f data/honeywatch.db
```

If you created report files:

```bash
rm -f report-30m.md attacker-192.0.2.1.md
```

If you started a live honeypot for the demo, stop it cleanly with Ctrl-C. The
daemon shuts down the SSH and HTTP listeners and releases the ports.

## Optional: run the real honeypot

If you want to show live collection instead of simulation:

```bash
honeywatch run
```

This starts both the SSH and HTTP honeypots using the example configuration by
default. The example config binds SSH to port 2222 and HTTP to port 8080.

To limit what starts:

```bash
honeywatch run --no-http
honeywatch run --no-ssh
```

To run for a fixed time:

```bash
honeywatch run --duration 60
```

While `honeywatch run` is active, you can open another terminal and use
`honeywatch tui`, `honeywatch db stats`, or `honeywatch report` against the same
database.

## Things this example intentionally avoids

- Exposing the honeypots to a public interface without understanding the
  networking and security implications.
- Committing secrets, GeoLite databases, host keys or raw attacker data.
- Executing attacker-supplied commands or fetching attacker-supplied URLs.

If you deploy the honeypot on a VPS, treat the host as untrusted and only bind
the services you intend to expose.
