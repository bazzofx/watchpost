# Architecture and event lifecycle

> Status: current as of commit `400d4b3`. This page describes the repository as it is, not as the
> older README still describes it. Where the plan changes something, that is called out in the
> [project plan](project-plan.md).

## Components

The server is a single process. Modules in `watchpost/`:

| Group | Modules | Responsibility |
|---|---|---|
| Entry | `server`, `main.py` | HTTP routing (`http.server`, 48 routes), request handling |
| Ingest & normalize | `normalize`, `syslog_listener` | parse formats, normalize to the common schema, syslog UDP/TCP listener |
| Storage | `db`, `engine`, `queries`, `maintenance` | schema/migrations, batched writes, detection orchestration, reads, reset |
| Detection | `rules`, `attack`, `correlate`, `incidents`, `improve`, `simulate`, `storyline` | pure-function rules, MITRE mapping, correlation → incidents, review workflow, synthetic scenarios |
| Presentation | `queries`, `report`, `pdfwriter`, `stream`, `agents`, `health` | dashboard data, reports, SSE stream, agent fleet, health |
| Security/ops | `auth`, `config`, `ratelimit`, `diagnostics`, `geo` | sessions/roles/tokens, env config, rate limits, error capture, geo lookup |

## Lifecycle of a log line

```
source → agent/shipper (external) → POST /api/ingest/upload (Bearer token)
      → normalize.parse_payload → events[]
      → engine.ingest → store_batch (one transaction) → run_detection (per batch)
      → alerts → correlate → incidents
      → dashboard (queries.py) and SSE stream
```

1. **Read** — done by the collector *outside* the server (see note below).
2. **Parse/normalize** — `normalize.py` turns each line/record into the common `events` shape; timestamps → UTC ISO-8601; control chars stripped; secrets redacted.
3. **Store** — `engine.store_batch` inserts the whole batch in one transaction (batched write).
4. **Detect** — `engine.run_detection` evaluates all enabled rules over per-rule time windows, then applies findings as alerts in a single write transaction.
5. **Correlate** — alerts become incidents (`correlate.py`).
6. **Serve** — bounded, paginated queries with indexes; an SSE stream pushes changes.

## The collector (agent / shipper)

The Linux collection agent and file shipper that used to live in `scripts/agent.py` and
`scripts/shipper.py` were **removed in commit `400d4b3` ("clean up")** and are being replaced or moved
elsewhere. Until the replacement lands, note:

- `deploy/agent/install-agent.sh` still references `scripts/agent.py` / `scripts/shipper.py` and will
  refuse to run from a full checkout (its own guard fires).
- `run_tests.sh` still calls `scripts/smoke.py`, which no longer exists, so `run_tests.sh` is currently
  broken (run `python -m unittest discover -s tests -t . -v` directly instead).

The server side — parsing, storage, detection, dashboard — is unaffected and is what this plan builds on.

## Storage today

Single SQLite file (`data/watchpost.db`, WAL, `synchronous=NORMAL`). Tables: `events`, `alerts`,
`alert_events`, `alert_notes`, `alert_activity`, `incidents`, `incident_alerts`, `rules`, `rule_history`,
`change_requests`, `evaluation_runs`, `detection_runs`, `ingest_batches`, `api_tokens`, `audit_log`,
`error_log`, `health_probe`, `sessions`, `settings`, `users`, `meta`.

`events` (the hot path) has indexes on `ts`, `(src_ip, ts)`, `(user, ts)`, `(event_type, ts)`,
`batch_id`. Schema additions are applied in place via `db.ADDED_COLUMNS` at startup.

## Search — FTS5 (Phase 1 landed)

The dashboard `q` filter used to be `message LIKE '%term%'` (a full table scan): correct but linear,
~55 ms over 200k rows in memory. Phase 1 added a FTS5 trigram index and routes `q` through it for
plain terms of ≥3 characters, falling back to the exact old `LIKE … ESCAPE` semantics for wildcards,
escape characters and short terms. See [search/fts5.md](search/fts5.md) for the compatibility contract.

## Measured baseline (local development workstation)

Measured on the development box — **Windows, Python 3.12.6, SQLite 3.45.3 (FTS5 + trigram
tokenizers present), in-memory synthetic events. Not the production host (AiSwarm).** Production
numbers must be re-measured before setting retention/partition defaults.

| Metric | Value |
|---|---|
| Row size, fields + `raw` | 292 B/row |
| Row size, fields only (no `raw`) | 182 B/row (−38%) |
| Row size + FTS5 trigram index on `message` | 387 B/row (the word tokenizer would be ~77 B/row but loses substring search) |
| `q` via `LIKE '%orders/12345%'` (200k rows) | 55.5 ms, 2 hits (the old full scan) |
| `q` via FTS5 trigram `LIKE` (200k rows) | ~1.05 ms, 2 hits |
| Prior backfill measurement (20k events / 40 batches) | 19.5 s → 8.6 s ≈ 2,300 events/s after detection left the write path |

## Known gaps (the plan)

1. ~~`q` full-table scan~~ — done in Phase 1 (FTS5 trigram + LIKE fallback).
2. No client-batch idempotency — a retry after an uncertain ack can duplicate events.
3. No retention/archive; unbounded hot growth; manual reset only.
4. No value-tier classification, aggregation, metrics, or quarantine.
5. Detection runs per ingest batch.
6. No parser/source version metadata or explicit data-quality fields.
7. No bounded durable spool/backpressure surface (only HTTP 429 + agent backoff).
8. `run_tests.sh` and several docs still reference the deleted `scripts/…`.
