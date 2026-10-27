# Operational hardening and load tests (Phase 6)

> Status: **implemented**. This page records what the load test found, what was fixed, what was
> measured and deliberately not changed, and — explicitly — what was not executed.

## What was hardened

### The admin re-scan is now boundable

`POST /api/detection/run?hours=N` limits the scan to the last N hours (clamped 1 h … 90 days). Without
the parameter the whole store is still scanned — the existing behaviour, preserved on purpose — because
that is the "re-scan everything after a rule change" action. The measured cost of that action is 8.4 s
at 100k events and ~84 s at a million, which is why the bound exists and why ingest never runs an
unbounded window (it always scopes detection to the batch's own time range).

### Failure paths keep data

`tests/test_hardening.py` injects failures instead of filling a disk:

| Injected failure | Asserted outcome |
|---|---|
| partition write raises `OSError("no space left on device")` | nothing deleted, error recorded, hot rows intact |
| partition write raises `sqlite3.OperationalError("database or disk is full")` | same |
| partition comes back with one row missing | nothing deleted, "missing after the insert" error recorded |
| control case, no failure | the move completes |

That is the ordering guarantee from Phase 3, now proven on the failure path rather than only described.

## Bug found by the load test, and fixed

**Symptom.** `[detection] OperationalError: too many SQL variables`, on every batch, in a 50,000-event
ingest. Only 2 alerts existed afterwards, and detection had effectively stopped working.

**Cause.** `_apply_finding` built one `IN (?, …)` clause with a parameter per evidence event id. A
detection window covering tens of thousands of events exceeded SQLite's bound-parameter cap (999 on
older builds, 32,766 on modern ones), so the whole detection pass for that batch failed. The error was
reported in the response and the batch was stored — but nothing was detected.

**Fix.** The evidence check is chunked at 900 ids (`engine._count_present`). The archive mover's delete
and verification statements were chunked for the same reason: its default batch is 5,000 ids, which
would fail on a SQLite build with the 999 cap.

**Verified.** `tests/test_hardening.py` runs the chunked path with a chunk size of 2 and asserts the
count is still exact, plus the mover deleting in chunks. The load test no longer logs the error.

## Measured: the real scaling wall is correlation

A profile of one scoped detection run at 20,000 events (500-event batch):

| Component | Time | Share |
|---|---|---|
| `correlate_alerts` | 1.00 s | 61% |
| `_rule_scan` (21 rules) | 0.47 s | 28% |
| `_candidate_alerts` | 0.33 s | 20% |
| whole run | 1.66 s | |

The cause is precise: `_candidate_alerts` loads **every evidence event of every open alert** on every
run:

```sql
SELECT a.id, e.ts, e.src_ip, e.user, e.host FROM alerts a
JOIN alert_events ae ON ae.alert_id = a.id JOIN events e ON e.id = ae.event_id …
```

Two long-lived alerts had accumulated 20,000 evidence rows, producing 61,500 timestamp conversions in a
single run. Cost therefore grows with the total evidence a busy alert has ever collected, not with the
batch being detected.

**Effect**, measured end to end with [`tools/load_ingest.py`](../../tools/load_ingest.py) (file-backed
SQLite, 500-event batches, a stream where every record is a failed login):

| Total ingested | Throughput | p50 | p95 |
|---|---|---|---|
| 20,000 events | 580 events/s | 860 ms | 1,330 ms |
| 50,000 events | 337 events/s | 1,485 ms | 2,651 ms |

The same ingest of *mixed* traffic (mostly web requests) measured 1,013 lines/s in Phase 5, so this is
the pathological case: 100% of the stream tripping auth rules, so every batch extends the same two
alerts. Under a flood, the alert's evidence set — and the cost of each subsequent batch — grows.

**This is not fixed here, deliberately.** Bounding the evidence load to the correlation window would
change how incident stages are computed for long-lived alerts. `tests/test_correlate.py` passes in this
environment and would be the validation for that change; it is the recommended next step, not something
to slip in at the end of a hardening pass.

## Optimisation tried and reverted

The profile showed 68,865 `parse_iso` calls per run, so an LRU cache was added. It cut the calls to
29,691 — and changed end-to-end p50 by 1,520 ms → 1,485 ms, which is noise. It was **reverted**: a
cache that does not measurably help is unjustified state. The cost was correlation's work, not
timestamp parsing.

## Load-test tool

```bash
python tools/load_ingest.py --db data/loadtest.db --events 50000 --batch 500
python tools/load_ingest.py --events 20000 --batch 500          # in-memory
python tools/load_ingest.py --db data/x.db --events 50000 --dense
```

`--dense` wraps the generated clock so rule windows overlap heavily (277 events/s measured) — a
deliberate stress case, not the default.

The tool also earned its keep by being wrong once: an earlier version generated syslog lines the parser
could not read, and it happily reported **47,103 events/s** while storing nothing. It now prints the
rejected count and warns when no events were stored. A benchmark that cannot tell "fast" from "did
nothing" is worse than no benchmark.

## Not executed — stated plainly

- **A real disk-full.** The error *type* was injected and handled; no filesystem was actually filled.
- **Concurrent writers.** The load test is single-process, sequential. SQLite write contention under
  parallel ingest is untested here.
- **A soak test.** No multi-hour run; all measurements are short bursts.
- **Correlation bound**, as above.
- **Category D telemetry** (metrics rows for CPU/disk/latency) — the ingest contract still has no metric
  event type, so it remains a design gap rather than a bug.
