# Event Schema

Every observation becomes one flat event. Fields that do not apply are
explicitly null.

``` json
{
  "id": 18234,
  "ts": "2026-10-20T14:03:11.482Z",
  "service": "ssh",
  "event_type": "login_attempt",
  "src_ip": "203.0.113.45",
  "src_port": 51822,
  "session_id": "b7f3c9e2",
  "username": "root",
  "password": "123456",
  "command": null,
  "http_method": null,
  "path": null,
  "query": null,
  "user_agent": null,
  "body_snippet": null,
  "client_banner": "SSH-2.0-libssh_0.9.6",
  "geo_country": "CN",
  "geo_city": "Shenzhen",
  "asn": 4134,
  "as_org": "CHINANET-BACKBONE",
  "tags": [],
  "rule_ids": [],
  "severity": "info"
}
```

## Event types

-   `connect`
-   `disconnect`
-   `login_attempt`
-   `login_success`
-   `command`
-   `http_request`
-   `http_login_attempt`

## Capture limits

  Field                 Maximum
  ---------------- ------------
  username            256 chars
  password            256 chars
  command            1024 chars
  path               2048 chars
  query              2048 chars
  body snippet       1024 bytes
  user agent          512 chars
  HTTP body read     8192 bytes
  SSH line           4096 bytes

Truncate at capture time, not only at display time.

## Raw vs processed event

The JSONL archive stores the raw event before GeoIP/detection
enrichment. SQLite stores the processed event plus normalized
`rule_hits`. Avoid treating `rule_ids` as the sole source of detection
truth; `rule_hits` is the relational audit record.

## Sanitisation

Captured data and displayed data are different concerns. Preserve
bounded evidence in storage, but before any display: 1. remove C0/C1
control characters except intentionally normalized whitespace; 2. remove
ANSI/OSC/CSI escape sequences; 3. escape Rich markup; 4. normalize
embedded newlines where a single-line cell/message is expected; 5.
truncate again to the destination's display limit.

Never trust username, password, command, path, query, user-agent, banner
or body fields.

## Session IDs

Session IDs should be opaque random identifiers, stable for all events
in one SSH connection. HTTP may use a request/session identifier if
useful, but do not invent cross-request identity beyond what is actually
observed.

## Severity on events

Base events default to `info`. After detection, event severity may
reflect the maximum severity among rule hits for convenient rendering.
The `rule_hits` table remains authoritative.

## Compatibility

Schema changes require an explicit schema version in `meta` and a
migration strategy. Do not silently mutate an existing DB into an
incompatible shape.
