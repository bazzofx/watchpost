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
