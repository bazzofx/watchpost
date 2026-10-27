# Final report — scalability programme

What was built, what was measured, and what remains open. Every number here came from a command run
in this environment; nothing is projected. Where a claim could not be executed here, it says so.

## Phases

| Phase | Deliverable | Committed | Evidence |
|---|---|---|---|
| 0 | Scaffold, architecture map, measurement method | ✅ | [architecture](architecture.md), [security logging](security-logging.md) |
| 1 | FTS5 trigram search with LIKE-parity fallback | ✅ | [search/fts5.md](search/fts5.md), 11 tests |
| 2 | Client-batch idempotency | ✅ `ef50493` | [ingestion/idempotency.md](ingestion/idempotency.md), 9 tests |
| 3 | Per-day archive, pinned evidence, recoverable mover | ✅ `1ce7bc1` | [retention/archive.md](retention/archive.md), 14 tests + 31-check harness |
| 4 | Value tiers, rollups, stage counters, quarantine | ✅ `1cddd1f`, `f0b5ab1` | [tiers/rollups](processing/tiers-and-rollups.md), [counters/quarantine](observability/pipeline-and-quarantine.md), 20 tests + 25-check harness |
| 5 | Detection decoupling — **measured, not needed** | ✅ `b99a2e6` | [detection/decoupling.md](detection/decoupling.md) + `tools/bench_detection.py` |
| 6 | Hardening, load test, bug fix | ✅ | [phase6/hardening.md](phase6/hardening.md) + `tools/load_ingest.py` |

## The numbers that matter

**Storage** (Phase 1, 200k rows, in-memory, this box):

| Shape | Bytes/row |
|---|---|
| fields + `raw` | 292 |
| fields only (−`raw`) | 182 (−38%) |
| + FTS5 trigram index | 387 |

Search: `LIKE '%orders/12345%'` 55.5 ms vs trigram FTS ≈ 1.05 ms at 200k rows.

**Ingest** (Phase 5, 100k-event store, 500-line batches, median of 5):

| Stage | Time |
|---|---|
| parse | 97.5 ms |
| store | 41.2 ms |
| detect (quiet / alerting batch) | 168.6 / 217.3 ms |
| **request end-to-end** | **493.6 ms (1,013 lines/s)** |
| detection share | 34% |

Scoped detection is **flat with store size** (142 ms at 20k events, 140 ms at 100k). The one
O(history) operation is the admin full re-scan: 8.4 s at 100k events — now boundable with
`?hours=`.

**Durability** (Phase 3, harness against a real filesystem, 31/31 checks): dry run changes nothing;
move preserves ids; schema and indexes mirrored from hot; a second pass is a no-op; a partition
written but not deleted is completed by the next pass without duplicating rows; pinned evidence moves
only once its alert *and* incident are resolved.

## What was found

1. **A silent detection failure at scale (Phase 6, fixed).** `_apply_finding` built one SQL `IN (?, …)`
   with a parameter per evidence id; a window covering tens of thousands of events exceeded SQLite's
   bound-parameter cap, so detection failed for the whole batch with "too many SQL variables" while the
   events were still stored. Chunked at 900 ids, with tests that exercise the chunked path exactly. The
   archive mover's delete/verify were chunked for the same reason.
2. **Correlation is O(total evidence) (Phase 6, identified, not fixed).** `_candidate_alerts` loads
   every evidence row of every open alert per detection run: 61% of a detection pass at 20k evidence
   rows. Under a flood that trips one alert repeatedly, per-batch cost grows with the alert's history:
   p50 860 ms at 20k events → 1,485 ms at 50k. Recommended fix: bound the evidence load to the
   correlation window, validated against `tests/test_correlate.py`.
3. **A benchmark that lied (Phase 6, fixed).** The first load-test run reported 47,103 events/s because
   the generated syslog lines could not be parsed — nothing was stored. The tool now reports rejected
   records and warns when nothing was stored.
4. **An optimisation that did nothing (Phase 6, reverted).** An `lru_cache` on `parse_iso` cut 39,000
   calls and changed end-to-end latency by noise. Reverted rather than kept as unjustified state.

## What is not verified here, and why

This session runs on Windows inside a sandbox that denies a writable temporary directory, so any test
needing one cannot run: 98 errors out of 350 in the full suite are environmental (`ServerTestCase`
classes, the maintenance API tests, the archive mover tests). They are not failures of the code.

To keep the archive and rollup work honest despite that, the mover and the tier/rollup pipeline were
verified by a harness that used an explicit directory instead of `tempfile` (31/31 and 25/25 checks).
Those committed tests skip here and will run on the deployment host.

One failure is real and not mine: `test_single_tactic_incident_is_not_escalated` fails because the
uncommitted `web_rapid_discovery` rule maps to `T1083`/`T1595` and adds stages to an incident an older
test asserts is single-tactic.

Not executed at all: a genuine disk-full (the error *type* was injected), concurrent writers, a
multi-hour soak, and Category D telemetry (no metric event type exists in the ingest contract).

## What I would do next, in order

1. **Bound correlation** — the measured wall. Load evidence for the correlation window only; validate
   with `tests/test_correlate.py`; re-run `tools/load_ingest.py` to confirm the improvement.
2. **Run the suite on Linux** and replace the environmental errors with real results; the skips and
   errors above should collapse to green.
3. **Category D** — decide whether operational metrics become rows (a `metrics` table plus a metric
   event type) or stay out of scope.
4. **Schedule retention** — a timer or cron entry for `POST /api/admin/retention/run`, so the archive
   actually runs without a human.
