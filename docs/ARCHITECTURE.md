# Architecture

## Process model

HoneyWatch deliberately uses two processes.

### Daemon

`honeywatch run` owns: - SSH listener; - HTTP listener; - bounded event
queue; - enrichment; - detection; - scoring/classification context; -
SQLite writes; - JSONL archive; - optional Telegram alerts.

All components share one asyncio event loop. No worker thread is
required for normal I/O.

### TUI

`honeywatch tui` is a separate read-only process. It polls SQLite about
once per second. Its lifecycle is independent of the daemon.

This means a UI crash cannot stop collection and no dashboard network
port is exposed.

## Event lifecycle

``` mermaid
sequenceDiagram
    participant P as Producer
    participant Q as asyncio.Queue
    participant E as Enrichment
    participant R as Rules
    participant S as Storage
    participant A as Alerts
    participant T as TUI

    P->>Q: raw Event
    Q->>E: consume
    E->>R: enriched Event
    R->>S: Event + RuleHits
    R-->>A: eligible detections
    S-->>T: read-only polling
```

Raw JSONL must represent the event before enrichment so future replay
can apply updated enrichment and rules.

## Component boundaries

### `models.py`

Canonical schemas/enums only. It must not know about SQLite, Textual or
network servers.

### `config.py`

Loads and validates configuration. No runtime service startup.

### `pipeline.py`

Orchestrates processing. It receives events from producers and calls
injected enrichment/detection/storage/alert dependencies.

### `honeypots/`

Capture and emulate only. They create raw events but do not directly
write SQLite or evaluate rules.

### `engine/`

Rule loading, stateless matching, threshold state and scoring helpers.
Keep matcher independent from storage.

### `storage/`

SQLite schema/access and JSONL archive. Separate read-query APIs for
TUI/reporting from write APIs.

### `enrich/`

Local GeoIP only.

### `alerts/`

Outbound Telegram only. It receives sanitized/structured alert data and
cannot affect event acceptance.

### `replay/`

Producers for historical/synthetic data.

### `tui/`

Presentation only. No daemon control dependency except observing
database state.

## Concurrency

Use a bounded queue. A single pipeline consumer is the simplest
deterministic default. If performance later requires parallel
enrichment, preserve per-event consistency and SQLite serialization.

Network handlers should do minimum capture work and enqueue. They should
not perform slow Telegram requests or database analytics.

Shutdown: 1. stop accepting new connections; 2. close listeners; 3.
cancel/close sessions with bounded grace; 4. stop producers; 5. drain
queued events where practical; 6. flush JSONL/SQLite; 7. stop alert
worker; 8. close resources.

## Failure isolation

-   GeoIP missing -\> null enrichment + one warning.
-   Invalid rule -\> skip rule + error; daemon continues.
-   Telegram unavailable -\> alert row failed; pipeline continues.
-   TUI unavailable -\> no effect on daemon.
-   One malformed HTTP/SSH input -\> reject/record safely; listener
    continues.
-   SQLite fatal error -\> log prominently and fail daemon rather than
    pretend data is being recorded.

## Time model

Use timezone-aware UTC everywhere. Event timestamps are authoritative
for replay and threshold evaluation. UI may display concise UTC by
default; any local-time feature must be explicit.

## Data ownership

SQLite is operational/query storage. JSONL is the replayable raw
archive. Neither is a substitute for the other.

The TUI never writes operational data. Report generation should use read
queries.

## Performance expectations

This is a small honeypot, not a high-volume SIEM. Optimize for bounded
resource use and correctness: - indexed queries; - bounded UI rows; -
LRU GeoIP; - compiled regexes; - threshold pruning; - no N+1 queries on
every refresh where an aggregate query can do the work.
