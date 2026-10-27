# Detection decoupling — measured, and not needed (Phase 5)

> Status: **measured; decoupling deliberately not implemented.** This page records the numbers and
> the decision, so the next person can re-run the measurement instead of trusting the conclusion.

## The question

Should detection run inside the ingest request, or as a separate pass that ingest never waits for?

Decoupling is a real scalability technique, but it costs something concrete: a queue, a delivery
cursor, staleness between "stored" and "detected", and the loss of the current property that an
ingest response says what detection did with the events it just stored. That trade is only worth
making if measurement shows ingest is actually blocked by detection.

## Method

- Tool: [`tools/bench_detection.py`](../../tools/bench_detection.py) — in-memory, never touches
  `data/watchpost.db`, no temp directory needed.
- `python tools/bench_detection.py --events 100000 --batch 500`
- Local Windows box, Python 3.12.6, SQLite 3.45.3, median of 5 repetitions.
- Two detection measurements on purpose: ingest calls `run_detection(start, end)` **scoped to the
  batch's own window**, while the admin "run detection" button scans the whole store. Measuring only
  one of them is how the wrong conclusion gets reached.

## Results (100,000 events hot, 500-line batches)

| Stage | Time | Throughput |
|---|---|---|
| parse 500 auth lines | 97.5 ms | 5,126 lines/s |
| store 500 events | 41.2 ms | 12,139 events/s |
| detect, quiet batch (no rule fires) | 168.6 ms | 2,966 events/s |
| detect, alerting batch (rules fire, 5,000 evidence links) | 217.3 ms | 2,301 events/s |
| **request end-to-end** (parse + store + detect + correlate) | **493.6 ms** | **1,013 lines/s** |
| detection share of a request | **34%** | |
| manual **full** run (no window) | 8,443 ms | scales with store size |

Store-size independence, measured separately: scoped detection took 142 ms at 20,000 events and
140 ms at 100,000 events. It follows the batch, not the history — because ingest passes the batch's
time range and the rules read only their own windows through `idx_events_ts`.

## Decision: do not decouple

1. **Ingest is not blocked by detection.** Detection is ~34% of a request and flat as the store grows.
   The other two thirds (parse 20%, store 8%, correlation and fan-out the rest) would remain.
2. **Parse is the hard floor.** You cannot detect what has not been parsed, so moving detection off the
   request path would not raise the ceiling: at 5,126 parse-optimised lines/s vs 1,013 end-to-end,
   parsing and the rest of the request are what bound throughput.
3. **The observable cost is small and bounded.** A 500-event batch adds ~170 ms; a 20,000-event batch
   (the configured maximum) would add ~7 s to a *bulk backfill*, which is acceptable and visible.
4. **Decoupling would trade a documented property for an unmeasured gain.** Today the response's
   `detection` block reports what happened to those events. A queue would make that "pending".

## What would change this decision

Revisit decoupling if any of these is measured on the deployment host:

- sustained ingest above roughly **1,000 lines/s** per process (i.e. the request is the bottleneck, not
  the sender), or
- a **single request exceeds ~2 s** at the configured batch size, or
- detection's share of a request grows with history (it currently does not — that would mean a rule is
  scanning outside its window, and that is a bug to fix before adding a queue).

## The one real O(history) cost

The **manual full run** scans the whole store: 8.4 s at 100,000 events, so roughly 84 s at a million.
It is admin-initiated (`POST /api/detection/run`), never on the ingest path, and it is the honest place
to bound or background later (Phase 6) — not a reason to decouple ingest.

## Not done, on purpose

- No queue, no worker, no cursor, no schema change. This phase produced a measurement and a decision.
- No change to the ingest contract: detection still runs inside the request, scoped to the batch.

Reproduce with:

```bash
python tools/bench_detection.py --events 100000 --batch 500
python tools/bench_detection.py --events 20000  --batch 500   # same detection time: flat
```
