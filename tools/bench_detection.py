"""Measure where an ingest request spends its time: parse, store, detection.

The Phase 5 decision (decouple detection from ingest, or not) is based on these numbers, so they are
reproducible rather than remembered:

    python tools/bench_detection.py
    python tools/bench_detection.py --events 200000 --batch 500

Everything is in-memory, so it never touches data/watchpost.db and never needs a temp directory.
Ingest scopes detection to the batch's own time window; a manual "run detection" scans the whole
store. The two are timed separately on purpose — confusing them produces the wrong conclusion.
"""

import argparse
import os
import statistics
import sys
import time
from datetime import datetime, timedelta, timezone

# Run directly (python tools/bench_detection.py): put the repository root on the path.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from watchpost import engine
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload

BASE = datetime(2026, 10, 1, tzinfo=timezone.utc)


def stamp(offset):
    return (BASE + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def routine_events(count, base):
    return [{"ts": stamp(base + i), "source": "web01-web", "event_type": "web_request",
             "severity": "low", "src_ip": "198.51.100.%d" % (i % 250),
             "message": "GET /static/app.css 200"} for i in range(count)]


def alerting_events(count, base):
    return [{"ts": stamp(base + i), "source": "web01-auth", "event_type": "auth_failure",
             "severity": "medium", "user": "admin", "src_ip": "203.0.113.9",
             "message": "Failed password for admin"} for i in range(count)]


def authlog_text(count):
    return "\n".join(
        "Oct  3 10:%02d:%02d web01 sshd[1]: Failed password for admin from 203.0.113.%d port 22 ssh2"
        % (i % 60, i % 60, i % 250) for i in range(count))


def median_ms(fn, reps):
    times = []
    for _ in range(reps):
        start = time.perf_counter()
        fn()
        times.append((time.perf_counter() - start) * 1000)
    return statistics.median(times)


def main():
    parser = argparse.ArgumentParser(description="Measure parse, store and detection cost.")
    parser.add_argument("--events", type=int, default=100_000, help="backfilled hot store size")
    parser.add_argument("--batch", type=int, default=500, help="events per measured batch")
    parser.add_argument("--reps", type=int, default=5, help="repetitions; the median is reported")
    args = parser.parse_args()

    conn = connect(":memory:")
    init_schema(conn)
    engine.seed_rules(conn)

    started = time.perf_counter()
    filled = 0
    while filled < args.events:
        size = min(1000, args.events - filled)
        engine.store_batch(conn, routine_events(size, 1_000_000 + filled), [], "bench", "json", "bench")
        filled += size
    print(f"Python {sys.version.split()[0]} - hot store {args.events:,} events"
          f" (backfill {time.perf_counter() - started:.1f}s) - batch {args.batch} - median of {args.reps}")

    lines = authlog_text(args.batch)
    parse_ms = median_ms(lambda: parse_payload(lines, "authlog", "bench", year=2026), args.reps)

    store, quiet, alerting, request = [], [], [], []
    base = 2_000_000
    for _ in range(args.reps):
        base += 5000
        batch = routine_events(args.batch, base)
        store.append(median_ms(lambda: engine.store_batch(conn, batch, [], "bench", "json", "bench"), 1))
        start = time.perf_counter()
        engine.run_detection(conn, trigger="bench", start=batch[0]["ts"], end=batch[-1]["ts"])
        quiet.append((time.perf_counter() - start) * 1000)

        base += 5000
        hot = alerting_events(args.batch, base)
        engine.store_batch(conn, hot, [], "bench", "json", "bench")
        start = time.perf_counter()
        engine.run_detection(conn, trigger="bench", start=hot[0]["ts"], end=hot[-1]["ts"])
        alerting.append((time.perf_counter() - start) * 1000)

        request.append(median_ms(lambda: engine.ingest(
            conn, *parse_payload(lines, "authlog", "bench", year=2026), "bench", "authlog", "bench"), 1))

    def rate(ms):
        return f"{args.batch / (ms / 1000):,.0f}/s"

    print(f"\nparse        {args.batch} lines  : {parse_ms:8.1f} ms  {rate(parse_ms)}")
    print(f"store        {args.batch} events : {statistics.median(store):8.1f} ms  {rate(statistics.median(store))}")
    print(f"detect quiet batch          : {statistics.median(quiet):8.1f} ms  {rate(statistics.median(quiet))}")
    print(f"detect alerting batch       : {statistics.median(alerting):8.1f} ms  {rate(statistics.median(alerting))}")
    request_ms = statistics.median(request)
    print(f"REQUEST parse+store+detect  : {request_ms:8.1f} ms  {rate(request_ms)}")
    print(f"detection share of request  : {(statistics.median(quiet) / request_ms) * 100:.0f}% (quiet batch)")

    start = time.perf_counter()
    engine.run_detection(conn, trigger="bench-full")
    print(f"\nmanual FULL run, no window  : {(time.perf_counter() - start) * 1000:,.0f} ms"
          f"  (scales with store size; an admin action, not the ingest path)")
    conn.close()


if __name__ == "__main__":
    main()
