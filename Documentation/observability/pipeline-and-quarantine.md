# Pipeline counters and quarantine (Phase 4, part 2)

> Status: **implemented**. This is the "how much did the pipeline actually do" view plus the bounded
> quarantine for input the parser refused.

## Stage counters

`GET /api/pipeline` (viewer) returns one number per stage, each computed from the table that owns it:

| Stage | Source | Means |
|---|---|---|
| `observed` | `SUM(ingest_batches.received)` | records senders offered |
| `accepted` | `SUM(ingest_batches.accepted)` | parsed into events |
| `rejected` | `SUM(ingest_batches.rejected)` | refused by the parser |
| `stored` | `COUNT(events)` | event rows **currently** in the hot tier |
| `aggregated` | `SUM(event_rollups.events)` | events folded into rollups, no longer individual rows |
| `detected` | `COUNT(alerts)` | alerts raised — *not* a count of events |
| `quarantined` | `COUNT(quarantine)` | rejected records retained for inspection |

`observed = accepted + rejected` always holds. **Nothing else is additive**, and the payload carries a
`note` saying so, because a dashboard that sums these stages produces a meaningless total: `stored`
excludes everything archived, `aggregated` counts events that no longer exist as rows, and `detected`
counts alerts rather than events.

## Quarantine

`GET /api/admin/quarantine` (admin) returns the bounds and the newest entries.

What is always recorded: timestamp, source, batch id, record position, and the parser's reason.
What is **not** recorded by default: the rejected content — a line the parser could not interpret may
hold a password or a token. An operator can opt in:

```
SIEM_QUARANTINE_RECORDS=1     # store a redacted excerpt, max 160 characters
SIEM_QUARANTINE_ROWS=5000     # hard row ceiling (newest kept)
SIEM_QUARANTINE_HOURS=72      # TTL
```

Three independent bounds apply on every write, so the quarantine cannot become a second log database:
a **per-batch cap** of 50 records, the **row ceiling**, and the **TTL**. Excerpts are redacted before
storage with the same `redact()` used for event messages, and truncated, so a rejected secret is not
preserved verbatim.

## Why rejection counts and content are separate settings

The parser already refused to record rejected content before this phase, on purpose. Keeping that
default and adding an opt-in excerpt preserves the privacy choice while still making a malformed feed
debuggable when someone asks for it. The reason alone usually identifies the problem ("line is not in
syslog format", "ts is required"); the excerpt is for the cases where it does not.

## Category D telemetry — an honest gap

The policy has a fifth category for operational telemetry (CPU, disk, queue depth, latency) that
should become time-series rows rather than security events. **It is not reachable today**: the ingest
contract has no metric event type, so nothing can express it. It is recorded as Phase 6 work rather
than pretended to be done.

## Verified

- `tests/test_pipeline.py` — **13 tests**, all in-memory so they run everywhere: per-stage counts and
  the `observed = accepted + rejected` identity, `detected` being alerts not events, `aggregated` from
  rollups, the hours clamp (1 h … 90 days), the quarantine per-batch cap, row ceiling, TTL, the
  default-without-content and opt-in-with-redacted-content behaviour, and the route roles
  (`/api/pipeline` and `/api/rollups` viewer; `/api/admin/quarantine` admin).
- Full suite: 350 tests, with only the pre-existing failure from the in-progress WAF rule and the
  known sandbox errors.

## Limitations

- The counters are computed on read from aggregate SQL; cheap, but they are not a time series. A
  trend of `observed`/`stored` over time needs the metrics table that comes with Phase 6.
- `archived` is not a counter: partition row counts would mean opening every archive file. The
  retention report (`GET /api/admin/retention`) answers what a pass *would* move.
- Quarantine excerpts are truncated at 160 characters; long JSON records are represented by their head
  only.
