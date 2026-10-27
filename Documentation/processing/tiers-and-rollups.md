# Value tiers and rollups (Phase 4, part 1)

> Status: **tiers + aggregation implemented**. Metrics table, quarantine and the pipeline stage
> counters are the remaining half of Phase 4.

## Why tiers

The retention policy should not treat every record the same. `auth_failure` is evidence; a `200` on a
static asset is noise that happens to be identical in shape. Tiers let the hot tier hold the former
longer and the latter briefly, without ever changing what gets *detected*.

| Tier | Examples | Stored how |
|---|---|---|
| **A** | `auth_failure`, `auth_success`, `account_lockout`, `user_created`, `privilege_use`, `privilege_escalation`, `process_start`, `file_access`, `network_connection`, `cloud_iam_change`, `vpn_login` | full record, hot for `SIEM_HOT_HOURS` |
| **B** | `web_scan`, `web_error`, `fw_deny`, `cloud_data_access` | full record, hot for `SIEM_HOT_HOURS` |
| **C** | `web_request`, `fw_allow`, `cloud_api_call`, `syslog`, `other` | full record, hot for `SIEM_ROUTINE_HOURS` (shorter), then rolled up |
| **D** | CPU, disk, queue depth, latency | never an event row (metrics — part 2) |
| **E** | malformed / unsupported input | rejected before storage, quarantined (part 2) |

## Two rules the classifier is careful about

1. **Classification never gates detection.** Detection runs on every event twice-over — before any
   reduction, and on every tier alike. The tier is consulted only when deciding how long a row stays
   in the fast tier. A tier is not a verdict on whether something is interesting.
2. **A severe event is never routine.** A normally-boring type that arrives with `high` or `critical`
   severity is promoted to B, so a sudden flood of severity cannot be aged out early merely because
   its type is usually dull.

Lists are configurable per deployment with `SIEM_TIER_A` / `SIEM_TIER_B` (comma-separated event
types). Anything in neither list is C. A source-level override is **not** implemented yet — a stated
limitation, not an oversight.

## Value-based retention

```
SIEM_HOT_HOURS=24        # A and B stay hot for a day
SIEM_ROUTINE_HOURS=2     # C stays hot for two hours, then expires into rollups
```

The routine window is **clamped to never exceed** the hot window, so a misconfiguration cannot keep
routine traffic in the fast tier longer than the evidence beside it. `0` means "same as
`SIEM_HOT_HOURS`", and retention as a whole stays off while `SIEM_HOT_HOURS` is 0.

## Rollups

When a Category C row leaves hot, it is folded into an hourly bucket first, so counts and trends
survive the detail:

```sql
event_rollups(bucket_start, event_type, source, host, outcome, severity,
              events, first_seen, last_seen)
```

- One row per (hour, type, source, host, outcome, severity); counts accumulate across passes, so a
  day that arrives in slices still produces a single bucket per key.
- The rollup and the delete are **one transaction in the hot database**, which is what keeps retries
  honest: a crash cannot leave a rollup recorded for rows that are still waiting to move, so a retry
  cannot double-count.
- A and B rows are archived, never rolled up — their detail is the point.

Example: five `web_request` events between 10:00 and 10:04 from `web01-web` become one row with
`events = 5`, `bucket_start = 2026-01-02T10:00:00.000Z`, `first_seen = 10:00`, `last_seen = 10:04`.

## Where the tier is visible

`events.tier` is stored on every ingested row and returned by `GET /api/events` alongside the other
fields, so an analyst (or a query) can see why a record will expire when it will.

## Verified

- `tests/test_classify.py` — **7 tests**, all runnable anywhere: A/B/C mapping, severity promotion,
  missing fields, environment configuration.
- `tests/test_archive.py` — **5 new tests** for value-based expiry, hourly bucketing, accumulation
  across sliced passes, and that A/B rows are never rolled up. They need a writable temp dir (skip in
  some sandboxes, run on the host).
- A one-off 25-check harness against a real filesystem passed, including "a retry does not
  double-count" and "routine expires earlier than evidence".

## Limitations

- **No rollup API yet.** The rows exist and are queryable in SQL; a dashboard endpoint and the
  six stage counters (`observed / parsed / stored / aggregated / detected / rejected`) belong to the
  second half of Phase 4.
- **Hourly buckets only.** Fine for trends; a burst analysis that needs per-minute resolution must
  come from the hot window or the archive.
- **Rollups are lossy by design** — that is the whole point — so they cannot answer "which exact
  requests happened". The archive holds the raw rows if it is searched by time range.
