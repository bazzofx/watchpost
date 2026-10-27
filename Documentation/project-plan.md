# Project plan — scalable ingestion, storage and search

The goal, in one sentence: **make Watchpost an evidence-preserving analytics pipeline — not a
database copy of every log file** — while keeping the existing agent/server split, the
stdlib-only / single-SQLite constraints, and adding no infrastructure until measurements require it.

Principles that govern every phase: read incrementally, parse once, evaluate security significance
*before* any lossy reduction, aggregate repetitive activity, correlate efficiently, preserve evidence
for active investigations, archive safely, and expose the health of the whole pipeline.

## Status

| Phase | Title | Status |
|---|---|---|
| 0 | Baseline & documentation | ✅ done (this page, [architecture](architecture.md), [security logging](security-logging.md)) |
| 1 | FTS5 search | ✅ done — [search/fts5.md](search/fts5.md) |
| 2 | Ingestion idempotency | ✅ done — [ingestion/idempotency.md](ingestion/idempotency.md) |
| 3 | Retention & archive | ⬜ |
| 4 | Classification & aggregation | ⬜ |
| 5 | Detection decoupling | ⬜ (only if measured) |
| 6 | Operational hardening & load tests | ⬜ |

## Phase 0 — Baseline and assessment ✅

No behaviour changes. Deliverables: this documentation set, the architecture map, and the measured
baseline in [architecture.md](architecture.md). **The production baseline (events/day, peak rate,
search p50/p95, DB size, free disk, CPU/RAM) is still outstanding** — those numbers decide the
retention and partition defaults in Phases 3–4, so they must be measured on AiSwarm before those
phases set defaults.

## Phase 1 — FTS5 search

Replace the `q` full-table scan with SQLite FTS5, with explicit semantics.

- Confirm the deployed SQLite build has FTS5 (local build does).
- Decide and document `q` semantics: FTS5 is *tokenised*, not substring — `q=ords` will not match
  `orders`. Plan: FTS5 for token/word search; exact-match indexes for IPs/hosts/ids; a LIKE fallback
  for substrings that FTS cannot serve (short terms, punctuation-heavy IOCs).
- Keep the FTS index in sync with inserts (triggers), and make the table survive restarts/migrations.
- Gate: query correctness for punctuation-heavy IOCs, paths, hashes, partial terms — plus p95
  < 20 ms at 1M hot rows (provisional, re-measured on target hardware).

Deliverable page: `search/`.

## Phase 2 — Ingestion idempotency ✅

Add a stable client batch ID so a retried upload cannot duplicate events or repeat detection.

- `POST /api/ingest/upload` accepts an idempotency key (query param or header).
- `ingest_batches` records the key; a repeat returns the stored acknowledgement without re-inserting
  or re-running detection. The batch record and its event inserts commit together.
- Define how the collector persists the key across retries (same payload ⇒ same key).
- Gate: retry and crash-after-commit-but-before-ack produce zero duplicate events and zero duplicate
  detection side effects.

This is a **prerequisite** for safe retries, spool, and the archive mover — do it before Phase 3.

Deliverable page: `ingestion/`.

## Phase 3 — Retention and archive

Three logical tiers with a value-aware expiry.

- **Hot** (`data/watchpost.db`): recent events for interactive search and active detections.
- **Archive** (`data/archive/watchpost-YYYYMMDD.db`): one file per day, IDs preserved, `raw`
  compressed, its own FTS index; attached read-only and only for the requested time range.
- **Pinned**: evidence linked to unresolved alerts/incidents is never expired.

Safe mover (idempotent, archive-first — SQLite cannot commit across two WAL databases atomically):

1. select a bounded set of eligible rows →
2. `INSERT OR IGNORE INTO archive …` (same ids) →
3. commit archive →
4. verify counts/references →
5. delete from hot in a separate transaction →
6. write the result to `audit_log`.

Gate: a forced crash between archive-commit and hot-delete causes no loss and no duplicates, and
`COUNT(*)` hot+archive equals what was ingested. Do **not** reset `sqlite_sequence` while an archive
exists. Provide a dry-run that reports rows/bytes to move and to delete, grouped by category and age.

Deliverable page: `retention/`.

## Phase 4 — Classification, aggregation, metrics, quarantine

Classify every normalized event into a value tier **after** detection has run, then route it:

| Tier | Routing |
|---|---|
| A high-value / B suspicious | full row, pinned to active detections, long retention |
| C repetitive low-risk | detect → aggregate into rollups + representative sample; routine raw expires |
| D operational | → `metrics` time-series, not `events` |
| E malformed | reject with reason; bounded `quarantine` with TTL |

Gate: noisy traffic yields bounded detections while a single high-risk event still alerts; detection
outcomes are equivalent with aggregation on vs off (replayed over the same retained evidence).
Quarantine and aggregation state must be bounded.

Deliverable pages: `processing/`, `observability/`.

## Phase 5 — Detection decoupling

Only if Phase 0/1 measurements show per-batch detection is the bottleneck. Introduce a watermark-based
scheduled correlation over `(last_id, max_id]` with explicit handling for late/out-of-order events,
rule changes, and restarts. Keep detection idempotent.

Deliverable page: `detection/`.

## Phase 6 — Operational hardening

Expose the ingestion-stage metrics (observed / parsed / stored / aggregated / detected / rejected /
dropped), test disk-full, queue saturation and recovery, review access controls, run the load tests,
and write the final report. No new infrastructure (Elasticsearch/OpenSearch/Kafka/Kubernetes) unless
measured numbers demand it.

## Acceptance criteria

The work is complete only when:

1. Existing sources and the dashboard keep working; agent checkpoints are reused and regression-tested.
2. Retried batches create no duplicate events and no duplicate detection side effects.
3. Search semantics are documented and tested across token, exact, and substring cases.
4. Archive movement recovers from crashes with no loss and no duplicate logical records.
5. Event IDs are stable and never reused after reset or archival.
6. Evidence linked to any open investigation survives retention cleanup.
7. Aggregation bounds memory and reduces repetitive storage/alert volume.
8. A single high-risk event stays detectable amid large routine volume.
9. Detection outcomes are equivalent across aggregation modes for the same retained evidence.
10. Queue saturation, failures, dropped events and gaps are visible.
11. Quarantine and spool storage are bounded.
12. Retention has a dry-run and records real deletions in `audit_log`.
13. Dashboard queries are bounded and stay responsive during ingestion.
14. Load tests report real throughput, latency, resource use and DB growth.
15. Migrations and configuration are documented and recovery is tested.

**No untested performance claim or unverified implementation is reported as successful.**
