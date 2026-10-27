# Search (FTS5 full-text index)

> Status: **implemented** (Phase 1). Semantics below are the compatibility contract for the `q`
> parameter.

## What it solves

The dashboard's `q` filter was `message LIKE '%term%'` — a full table scan. That is correct but
linear in table size: measured **55.5 ms** over 200k rows in memory, i.e. ~5.5 s projected at 20M
rows (before disk I/O). The fix adds a SQLite FTS5 index so the common query is a lookup instead of
a scan.

## How it works

`db.init_schema` creates an FTS5 table when the build supports it:

```sql
CREATE VIRTUAL TABLE events_fts USING fts5(message, tokenize='trigram', content='events');
```

- **`tokenize='trigram'`** indexes every 3-character window of `message`, which is what lets it
  answer *substring* `LIKE '%term%'` queries through an index (the word tokenizer cannot — it only
  matches whole tokens).
- **`content='events'`** makes it an external-content table: it stores the index, not a second copy
  of the text, so `message` is not stored twice.
- Two triggers keep it in step with `events` (insert and delete). The delete trigger uses FTS5's
  special `'delete'` command, because an external-content table has no rows of its own.
- On a database that predates the index, a one-time `'rebuild'` indexes the rows already present.

Search routes through the index only when it is safe; otherwise it keeps the original `LIKE … ESCAPE`
scan:

```
term is at least 3 chars AND contains none of  \  %  _   →  FTS index
otherwise (short term, or a wildcard/escape character)  →  LIKE, exactly as before
```

Why the gate: the trigram tokenizer returns **nothing** for substrings shorter than three characters,
and it does not honour `LIKE`'s `ESCAPE` clause — so `q=50%` (a literal `%`) and `q=ab` (two
characters) would silently break if they were served by the index.

## Semantics (the compatibility contract)

- **Case-insensitive** for ASCII, matching the old `LIKE` behaviour.
- Substring match for `/`, `-`, spaces, digits, and punctuation, as before.
- **Unchanged for** `%`, `_`, `\` and terms shorter than 3 characters — those still use `LIKE`.
- The `q` value is still truncated to 200 characters, and the query is still parameterised (no SQL
  injection — there is a regression test).

## Measured

Local development box (Windows, Python 3.12.6, SQLite 3.45.3, in-memory; not the production host):

| Path | Latency (200k rows) | Index cost |
|---|---|---|
| `LIKE '%orders/12345%'` (old) | 55.5 ms | — |
| FTS5 trigram `LIKE` (new) | ~1.05 ms | **387 B/row** |

The trigram index is ~5× larger than a word-tokenizer index (~77 B/row), which is the price of
substring semantics. Because the index lives on the hot tier only (the archive tier is a separate
decision), this cost is bounded; see [retention](../retention/README.md) when Phase 3 lands.

## Configuration

- `SIEM_SEARCH_FTS=0` disables the index entirely (a storage-constrained deployment); `q` then uses
  the plain `LIKE` scan and everything else is unchanged.
- The index is created automatically at startup when available; no migration step is needed.

## Example

```
GET /api/events?q=orders/12345      → fast (trigram index)
GET /api/events?q=50%25             → 50% literal, LIKE path
GET /api/events?q=ab                → 2-char term, LIKE path
```

## Sources

- [SQLite FTS5 trigram tokenizer](https://sqlite.org/fts5.html#the_trigram_tokenizer)
- [SQLite FTS5 external content tables](https://sqlite.org/fts5.html#external_content_tables)

## Tests

`tests/test_search.py` covers: index creation, insert/delete sync, backfill on upgrade, literal
`%` and `_`, short-term fallback, SQL-injection inertness, missing-index fallback, and the routing
gate. The API-level `q` behaviour is unchanged by construction (the route logic is unit-tested).
