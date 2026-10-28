# "Database is locked": why it happens and how to avoid it

## The model

Watchpost is one SQLite file in WAL mode: **readers never block**, but there is exactly **one writer**.
Every request opens its own connection with `PRAGMA busy_timeout = 20000` (`db.connect`), so a write
that cannot get the lock waits up to 20 seconds before it fails.

That means a request only ever sees `database is locked` because one of these is true:

1. **A writer held the lock longer than 20 s**, and this request queued behind it until its timeout.
2. **A read-then-write upgrade raced a commit** (a WAL snapshot conflict). This one returns *immediately*,
   without waiting — so it is the case to look for when the failures are far apart from the busy timeout.

## Reading the pattern in a log

```
23:35:38,186  database is locked
23:35:38,620  database is locked
23:35:38,970  database is locked
```

Failures a few hundred milliseconds apart are not three separate incidents. They are three requests
that all **started** ~20 seconds earlier and each hit the same `busy_timeout` — a queue draining. The
question to ask is therefore not "why is this request slow?" but **"what held the write lock for 20 s?"**

## The design flaw that was fixed

`correlate_alerts` loaded **every evidence row of every open alert** — and it loaded them *inside*
`BEGIN IMMEDIATE`:

```python
with transaction(conn):          # takes SQLite's single write lock
    alerts = _candidate_alerts(conn)   # ...then reads for O(total evidence)
```

Correlation runs on **every ingest**, so every batch held the single writer for the length of that read.
As an alert's evidence grew, the hold grew with it, and every other request queued behind it. This is
the same cost that Phase 6 profiling identified as 61% of a detection pass; the merge brought it into
the write path.

**Fixed:** the candidate load and the grouping now happen *before* the transaction, which then covers
only the inserts and updates. Two resilience changes came with it:

- a **read** that hits contention is retried up to three times (the handler has not answered yet);
- a **write** that hits contention is answered `503` with `Retry-After: 2` instead of a generic `500`,
  so a sender backs off rather than treating it as a bug. Writes are not retried blindly: a second
  attempt could apply a change twice (ingest is the exception — it carries its own batch id).

## How to see it next time

| Signal | Where |
|---|---|
| `correlation.seconds` on every ingest response | `POST /api/ingest` result, `detection.correlation` |
| A warning when correlation exceeds 2 s | the server log: *"correlation took N s; open alerts are carrying a large evidence set"* |
| Stage counts | `GET /api/pipeline` |
| The lock error itself | **`error_log` will often be empty during a lock storm**, because recording an error also needs the write lock. The log file is the reliable record. |

## The second flaw: evidence grew without bound

Every detection run links the events a rule matched to the alert as evidence. A rule that keeps
matching — a scanner, a brute force, a burst — linked **every** matching event, forever. Correlation
then reads all of an alert's evidence on every ingest, so each run was slower than the last, each
ingest queued longer behind it, and eventually nothing could get the write lock. The tell is a
detection run whose `events_scanned` climbs batch after batch and whose gap to the next run grows:
18 s, 23 s, 28 s, 35 s, 43 s, 54 s.

Measured, 15 batches of 500 alerting events against one long-lived alert:

| Evidence cap | Evidence rows | Correlation, first 3 batches | last 3 batches | Growth |
|---|---|---|---|---|
| uncapped (old) | 7,500 | 0.010 s | 0.075 s | **×7.5** |
| 500 (new default) | 500 | 0.005 s | 0.005 s | ×1.0 |
| 100 | 100 | 0.003 s | 0.002 s | ×0.7 |

`SIEM_ALERT_EVIDENCE_MAX` (default 500) now bounds it. The first N matches stay linked; the overflow is
recorded as an `evidence_capped` activity entry, so the alert says how many it did not link instead of
silently under-reporting.

## The third: ingest no longer queues behind detection

Detection has a process-wide lock, and ingest used to block on it. A 50-second run therefore parked
every incoming request until each one hit its `busy_timeout`. Ingest now tries the lock **without
blocking**: if a run is in progress the batch is stored, its `detection_status` becomes `deferred`,
and the next run widens its window back to the earliest deferred event so nothing is left undetected
(the batch becomes `recovered`). The ingest response says `detection.status: "deferred"`.

## Coalescing rapid, repetitive rows (opt-in)

The decision a burst deserves is usually one alert, not one row per request. After detection has run
over the whole batch, `SIEM_BURST_KEEP` limits how many stored rows survive per
`(source, src_ip, event_type)` in that batch:

```
SIEM_BURST_KEEP=50                      # 0 (default) = off
SIEM_BURST_TYPES=web_request,fw_allow   # which event types may be reduced
```

Properties worth knowing:

- **detection has already seen the whole batch** when this runs, so no rule misses the burst;
- **evidence is never removed** — only rows with no `alert_events` reference;
- only the listed event types are touched; auth failures and probes stay as they are;
- it is a trade, which is why it is off by default: anything that later reads *stored* events — a
  rule's history window, an analyst scrolling the list — will see fewer of them.

## What to do when it happens

1. **One instance per database file.** Two processes against one file always contend and no timeout
   fixes that. Confirm a single server owns `data/watchpost.db`.
2. **Bound growth with retention.** `SIEM_HOT_HOURS` (and `SIEM_ROUTINE_HOURS` for routine traffic)
   moves old events out of hot and into per-day archives. Evidence pinned to *unresolved* alerts stays
   hot by design, so also:
3. **Close stale investigations.** Pinned evidence never expires, so an alert left open for weeks keeps
   its evidence and keeps making correlation expensive.
4. **Send fewer, larger batches.** Every ingest runs detection and correlation; ten concurrent 50-event
   batches cost far more than one 500-event batch.
5. **Do not run `VACUUM` or a file copy during a load spike.**
6. Raising `busy_timeout` only moves the failure later; it does not remove the contention.

## Honest status

The fix above removes a real reason for long lock holds, but it was **not reproduced end-to-end here**:
two concurrent writers plus two readers for 20 seconds produced 0 lock errors on a local database, so
the original burst could not be replayed in this environment. If the errors continue after this change,
the first thing to check is a second process on the same file, then how long `correlation.seconds` is
on a failing batch.

The structural fix — bounding `_candidate_alerts` to the correlation window — is the next step, and it
also needs the detection-decoupling decision in [detection/decoupling.md](../detection/decoupling.md)
re-measured, because the merge replaced the per-rule window those numbers were taken with.
