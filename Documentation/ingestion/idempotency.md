# Ingestion idempotency (Phase 2)

> Status: **implemented**. This page is the contract for retrying an upload safely.

## The problem

A sender cannot always tell whether an upload succeeded. If the connection drops after the server
committed the batch but before the acknowledgement arrived, the sender retries — and before this
change, the retry stored the events **again**: duplicate rows, duplicate detections, duplicate alerts,
and a detection count that no longer matched reality.

## How it works

Every ingest call may carry a **stable batch id**, which doubles as the idempotency key:

```
POST /api/ingest/upload?source=web01-web&format=auto&batch_id=web01-web-2026-10-03T10-00-00
POST /api/ingest?batch_id=web01-web-2026-10-03T10-00-00
Idempotency-Key: web01-web-2026-10-03T10-00-00
```

- Validated with the same character set as a source name: **1–64 chars of letters, digits, `_ . : -`**
  (anything else is `400`).
- The id is stored as `ingest_batches.id`.
- **A replay is a no-op**: if that batch id is already stored, the server returns the original
  acknowledgement with `"duplicate": true` and does *not* parse, store, or run detection. No second
  copy of the events, no second detection pass, no duplicate alerts.
- **No id keeps the old behaviour**: every call stores a new batch, exactly as before, so existing
  senders are unaffected.

### What the acknowledgement looks like

```json
{"batch_id": "web01-web-2026-10-03T10-00-00", "received": 12, "accepted": 12, "rejected": 0,
 "rejections": [], "duplicate": true, "detection": {"status": "ok", "replayed": true}}
```

The status code is derived from the same stored counts, so a replay answers with the same HTTP
status as the original (`201`, `207`, or `422`).

## Crash windows

`store_batch` writes the events and the `ingest_batches` row in **one transaction**, so the durable
states are only "nothing" or "the whole batch":

| Crash point | Result |
|---|---|
| before commit | nothing stored — the retry stores it once |
| after commit, before the ack reaches the sender | the retry finds the batch and returns the original acknowledgement |
| during a retry, racing another retry | the loser's insert conflicts, is caught, and is answered as a replay |

## Deliberate semantics

- **The id identifies the batch, not its contents.** Replaying the same id with a *different* payload
  returns the original acknowledgement. That asymmetry is the point: a different payload under an old
  id is a sender bug, and guessing which one is "right" would be worse than refusing to store twice.
- **Content is never the key.** Two identical log lines can be two legitimate events, so idempotency
  keys on what the sender declares, not on a hash of the bytes.
- **Detection is not repeated.** This is the subtle one: storing the events twice would be bad, but
  re-running detection over the same evidence would also inflate occurrence counts and alert timing.

## What the sender must do

1. Choose a stable id per batch (a hash of source + file identity + first byte offset + first
   timestamp is a good one).
2. Persist it *before* sending, and reuse the **same** id on every retry of that batch.
3. Treat `duplicate: true` as success.

## Tests

`tests/test_idempotency.py` — replay returns the original acknowledgement, no second detection
pass, no-key behaviour preserved, a new key stores again, committed-but-unacknowledged retry is a
no-op, a failed insert leaves neither events nor a batch row, and the id validation rules.

## Sources

- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
  (do not silently lose or duplicate security events).
- HTTP idempotency-key convention (`Idempotency-Key`).
