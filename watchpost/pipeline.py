"""Pipeline stage counters and the rollup read side.

Each stage counts something different, and the numbers are **not** interchangeable:

    observed   = accepted + rejected   (what senders offered)
    accepted   -> parsed into events
    stored     = event rows still in the hot tier (archived rows have moved out)
    aggregated = events folded into rollups (no longer individual rows)
    detected   = alerts raised
    quarantined = rejected records retained for inspection

So `stored` is not "everything ever ingested", `detected` is not a count of events, and adding the
stages together produces a meaningless total. The payload says so explicitly, because a dashboard that
sums these is worse than one that shows none of them.
"""

from datetime import datetime, timedelta, timezone

from . import quarantine
from .db import iso

NOTE = ("Distinct pipeline stages, not interchangeable totals: observed = accepted + rejected; "
        "stored excludes rows that were archived; aggregated counts events that are no longer "
        "individual rows; detected counts alerts, not events.")


def stages(conn):
    """The stage counts, each computed from the table that owns it."""
    observed, accepted, rejected, batches = conn.execute(
        "SELECT COALESCE(SUM(received), 0), COALESCE(SUM(accepted), 0), COALESCE(SUM(rejected), 0),"
        " COUNT(*) FROM ingest_batches").fetchone()
    return {
        "batches": batches,
        "observed": observed,
        "accepted": accepted,
        "rejected": rejected,
        "stored": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "aggregated": conn.execute("SELECT COALESCE(SUM(events), 0) FROM event_rollups").fetchone()[0],
        "detected": conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
        "quarantined": quarantine.stats(conn)["count"],
        "note": NOTE,
    }


def rollups(conn, hours=24, limit=500):
    """Rollup buckets inside the last `hours`, newest first, with their event total."""
    try:
        hours = max(1, min(int(hours), 24 * 90))
    except (TypeError, ValueError):
        hours = 24
    limit = max(1, min(int(limit or 500), 5000))
    cutoff = iso(datetime.now(timezone.utc) - timedelta(hours=hours))
    rows = [dict(r) for r in conn.execute(
        "SELECT bucket_start, event_type, source, host, outcome, severity, events, first_seen,"
        " last_seen FROM event_rollups WHERE bucket_start >= ?"
        " ORDER BY bucket_start DESC, events DESC LIMIT ?", (cutoff, limit)).fetchall()]
    return {"hours": hours, "total_events": sum(r["events"] for r in rows),
            "buckets": len(rows), "rollups": rows}
