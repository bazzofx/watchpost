"""Load test: drive real ingest requests and report throughput and latency.

    python tools/load_ingest.py --db data/loadtest.db --events 50000 --batch 500
    python tools/load_ingest.py --events 20000 --batch 500            # in-memory, no disk

Each batch is a genuine request path: auth-log text -> parse -> store -> scoped detection ->
correlation. The numbers are per-batch latency plus the distribution, because a mean hides the tail
that actually hurts an operator.

Use a throwaway --db path: the script creates the file and leaves it in place so you can inspect the
result with the app or sqlite3. It never touches the configured data/watchpost.db.
"""

import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from watchpost import engine
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload


def authlog(count, offset, dense=False):
    """A realistic auth log slice: failing logins on a handful of accounts and addresses.

    Timestamps advance monotonically, one second per event, so each batch moves event time forward
    the way real traffic does. `dense` wraps the clock instead, which packs every batch into the same
    few hours: that models a very busy host where rule windows overlap heavily, and it is markedly
    slower (see Documentation/phase6/hardening.md) — it is a deliberate stress case, not the default.
    """
    lines = []
    for i in range(count):
        total = offset + i
        if dense:
            second, minute = total % 60, (total // 60) % 60
            hour, day = 3 + (total // 3600) % 6, 3
        else:
            second, minute = total % 60, (total // 60) % 60
            hour, day = (total // 3600) % 24, 3 + total // 86_400
        lines.append("Oct %2d %02d:%02d:%02d web01 sshd[%d]: Failed password for %s from"
                     " 203.0.113.%d port 22 ssh2"
                     % (day, hour, minute, second, 1000 + i % 900,
                        "admin" if i % 7 else "svc-backup", i % 250))
    return "\n".join(lines)


def percentile(values, fraction):
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(len(ordered) * fraction))
    return ordered[index]


def main():
    parser = argparse.ArgumentParser(description="Ingest load test.")
    parser.add_argument("--db", default=":memory:", help="SQLite path, or :memory: (default)")
    parser.add_argument("--events", type=int, default=50_000, help="total events to ingest")
    parser.add_argument("--batch", type=int, default=500, help="events per request")
    parser.add_argument("--dense", action="store_true",
                        help="wrap the clock so rule windows overlap heavily (stress case)")
    args = parser.parse_args()

    conn = connect(args.db)
    init_schema(conn)
    engine.seed_rules(conn)

    latencies = []
    sent = 0
    rejected_total = 0
    started = time.perf_counter()
    while sent < args.events:
        size = min(args.batch, args.events - sent)
        text = authlog(size, sent, dense=args.dense)
        request_start = time.perf_counter()
        events, rejections = parse_payload(text, "authlog", "loadtest", year=2026)
        engine.ingest(conn, events, rejections, "loadtest", "authlog", "loadtest")
        rejected_total += len(rejections)
        latencies.append((time.perf_counter() - request_start) * 1000)
        sent += size

    elapsed = time.perf_counter() - started
    batches = len(latencies)
    print(f"Python {sys.version.split()[0]}  db={args.db}  batch={args.batch}"
          f"{'  (dense windows)' if args.dense else ''}")
    print(f"ingested  : {sent:,} events in {batches} requests")
    print(f"wall time : {elapsed:.2f} s")
    print(f"throughput: {sent / elapsed:,.0f} events/s   ({batches / elapsed:,.1f} requests/s)")
    print(f"latency   : p50 {statistics.median(latencies):.1f} ms   "
          f"p95 {percentile(latencies, 0.95):.1f} ms   max {max(latencies):.1f} ms")
    print(f"stored    : {conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]:,} events,"
          f" {conn.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]:,} alerts,"
          f" {conn.execute('SELECT COUNT(*) FROM event_rollups').fetchone()[0]:,} rollup rows")
    if args.db != ":memory:" and os.path.exists(args.db):
        size_mb = os.path.getsize(args.db) / (1024 * 1024)
        print(f"db size   : {size_mb:.1f} MB  ({args.db})")
    if rejected_total:
        print(f"REJECTED  : {rejected_total:,} of {sent:,} records were refused by the parser"
              f" — the throughput above is not real ingest work")
    if conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0:
        print("WARNING   : nothing was stored; check the generated payload before trusting the rate")
    conn.close()


if __name__ == "__main__":
    main()
