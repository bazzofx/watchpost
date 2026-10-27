# Retention and archive (Phase 3)

> Status: **implemented**. Retention is **off by default** — nothing is moved or deleted until an
> operator sets `SIEM_HOT_HOURS`.

## What it does

Three tiers, one database each:

| Tier | Where | Holds |
|---|---|---|
| **Hot** | `data/watchpost.db` | recent events: interactive search, active detections, dashboards |
| **Archive** | `data/archive/watchpost-YYYY-MM-DD.db` | one file per UTC day, event ids preserved, `raw` kept |
| **Pinned** | stays in hot, whatever its age | evidence for any *unresolved* alert **or incident** |

The archive is a real SQLite file with the same `events` schema and indexes, so it can be opened,
inspected, backed up and copied with ordinary tools.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SIEM_HOT_HOURS` | `0` | events older than this move to the archive. **0 = retention off** (keep everything) |
| `SIEM_ARCHIVE_DIR` | `<db dir>/archive` | where the per-day partitions live |

`cutoff_for(0)` raises rather than treating 0 as "now", so a caller that passes the off value by
mistake cannot archive the entire store.

## The mover, step by step

Per eligible day, in this order:

1. **Select** up to `limit` (default 5000) rows older than the cutoff and not pinned.
2. **Write** them to the day's partition — `INSERT OR IGNORE` on the event id, so a retry cannot
   duplicate a row.
3. **Re-read the partition** and verify every id is present. Any gap aborts the day.
4. **Commit** the partition (its own transaction, its own file).
5. **Delete** the same ids from hot, in a separate transaction.
6. **Audit** the pass in `audit_log` (`retention_archive`: cutoff, counts, days, errors).

### Why that order

SQLite cannot commit atomically across two database files in WAL mode. Archive-then-delete makes the
crash states safe:

| Crash point | Result |
|---|---|
| during the partition write | partition rolls back; hot untouched; next run retries |
| after the partition commit, before the delete | rows exist in both; the next run's `INSERT OR IGNORE` is a no-op and the delete completes |
| during the delete | the delete transaction rolls back; retried next run |
| while pinned | the row is never selected at all |

A row is **never** deleted unless it was verifiably written to a partition first.

## Pinned evidence

An event is pinned when it is referenced by an alert or incident whose status is not `resolved`:

```sql
id IN (SELECT event_id FROM alert_events JOIN alerts … WHERE alerts.status != 'resolved')
OR id IN (SELECT event_id FROM alert_events JOIN incident_alerts JOIN incidents … WHERE incidents.status != 'resolved')
```

Both paths matter: an incident can stay open after one of its alerts is resolved, and an alert can
exist outside any incident. Closing an investigation releases its evidence to normal retention on the
next pass.

## Reading an archived event

`GET /api/events/{id}` falls back to the partitions when the event is not in hot, and tags the
response `"archived": true`. The lookup goes newest-partition-first and stops at the first hit, so its
cost is bounded by the number of partitions, not their size.

Alert links live in the hot database and are unchanged, which is why an archived event of a *resolved*
alert can still list the alerts that referenced it.

## Admin API

| Route | Role | Effect |
|---|---|---|
| `GET /api/admin/retention` | admin | dry run: per-day rows and a byte estimate, the pinned count, nothing changed |
| `POST /api/admin/retention/run` | admin | performs the move; body must be `{"confirm": "ARCHIVE"}`; refused while retention is off |

The dry run creates nothing on disk — it only reads and reports — so it is safe to call at any time.

## Verified

A 31-check harness against a real filesystem passed, covering: dry run changes nothing, move
archives then deletes the same ids, the partition schema and indexes mirror hot (`http_status`
included), a second pass is a no-op, an archived-but-not-deleted crash window is completed by the next
pass without duplicating rows, only pre-cutoff rows move, unpinned rows move while pinned stay, an open
incident keeps pinning after its alerts are resolved, `find_event`/`get_event` read from the archive,
and the zero-hours guard.

`tests/test_archive.py` carries the same coverage plus the route guards (confirmation word, retention
off). It needs a writable temporary directory for the partitions, so it skips where the environment
denies one (some sandboxes) and runs on the deployment host.

## Limitations (deliberate, for now)

- **No background timer.** Retention runs when triggered (`POST /api/admin/retention/run`). A cron
  entry or a scheduler belongs to Phase 6 rather than to the storage layer.
- **No full-text index inside partitions.** A trigram index would roughly double archive size; the
  archive is queried by id (`get_event`) and, later, by explicit bounded time ranges. Adding
  per-partition FTS is a Phase 4/6 decision, not an oversight.
- **The file does not shrink** after a delete. SQLite reuses freed pages, so the hot file stops
  growing but keeps its size; `VACUUM` is deliberately not run on every pass because it would lock a
  large database. The existing "Reset log data" path still vacuums.
- **One hot store = one archive.** Ids are unique across partitions only because the hot store never
  reuses them. `maintenance.reset_logs` currently clears `sqlite_sequence`; with retention enabled that
  would let ids restart, so treat a reset as "and its archives" (documented in the Phase 4 work).
- **Partitions are plain files.** Back them up like the hot database; they are the only copy of the
  events they hold.

## Sources

- [SQLite: WAL and multi-database transactions](https://sqlite.org/wal.html) (why cross-file atomicity
  is not available, and what ordering to use instead).
- [SQLite: `INSERT OR IGNORE`](https://sqlite.org/lang_insert.html) for idempotent re-application.
