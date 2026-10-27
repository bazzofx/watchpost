"""Bounded quarantine for rejected records.

Rejected input is always counted, with its reason, position and source. The *content* is stored only
when an operator opts in (`SIEM_QUARANTINE_RECORDS=1`), because a rejected line can contain a password
or a token and the parser could not interpret it well enough to be sure.

The quarantine is deliberately self-limiting — a per-batch cap, a row ceiling and a TTL, enforced on
every write — so it can never grow into a second log database.
"""

import os
from datetime import datetime, timedelta, timezone

from .db import iso, now_iso

DEFAULT_MAX_ROWS = 5000
DEFAULT_TTL_HOURS = 72
PER_BATCH_CAP = 50


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def limits():
    """(max_rows, ttl_hours, keep_records) from the environment, with safe fallbacks."""
    return (_env_int("SIEM_QUARANTINE_ROWS", DEFAULT_MAX_ROWS),
            _env_int("SIEM_QUARANTINE_HOURS", DEFAULT_TTL_HOURS),
            os.environ.get("SIEM_QUARANTINE_RECORDS", "0") == "1")


def add_many(conn, source, batch_id, rejections, cap=PER_BATCH_CAP):
    """Record up to `cap` rejections from one batch, then enforce the limits. Returns how many."""
    added = 0
    now = now_iso()
    for rejection in rejections[:cap]:
        conn.execute(
            "INSERT INTO quarantine(received_at, source, batch_id, record_index, reason, record)"
            " VALUES (?,?,?,?,?,?)",
            (now, source, batch_id, rejection.get("index"),
             str(rejection.get("reason") or "")[:500], rejection.get("record")))
        added += 1
    if added:
        prune(conn)
    return added


def prune(conn, max_rows=None, ttl_hours=None):
    """Drop records past the TTL and everything beyond the row ceiling. Returns rows removed."""
    max_rows = limits()[0] if max_rows is None else max_rows
    ttl_hours = limits()[1] if ttl_hours is None else ttl_hours
    removed = 0
    if ttl_hours > 0:
        cutoff = iso(datetime.now(timezone.utc) - timedelta(hours=ttl_hours))
        removed += conn.execute("DELETE FROM quarantine WHERE received_at < ?", (cutoff,)).rowcount
    if max_rows > 0:
        removed += conn.execute(
            "DELETE FROM quarantine WHERE id NOT IN ("
            " SELECT id FROM quarantine ORDER BY id DESC LIMIT ?)", (max_rows,)).rowcount
    return max(removed, 0)


def stats(conn):
    """Counts and the configured bounds, without exposing any record content."""
    row = conn.execute(
        "SELECT COUNT(*), MIN(received_at), MAX(received_at) FROM quarantine").fetchone()
    max_rows, ttl_hours, keeps = limits()
    return {"count": row[0], "oldest": row[1], "newest": row[2],
            "max_rows": max_rows, "ttl_hours": ttl_hours, "keeps_records": keeps}


def recent(conn, limit=50):
    """The newest rejections for the admin view. `record` is null unless records are kept."""
    return [dict(r) for r in conn.execute(
        "SELECT id, received_at, source, batch_id, record_index, reason, record FROM quarantine"
        " ORDER BY id DESC LIMIT ?", (limit,))]
