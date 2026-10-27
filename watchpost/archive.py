"""Retention: move events older than a cutoff into per-day archive partitions.

Two databases, two steps, in this order: write the partition and commit it, then delete from hot.
SQLite cannot commit atomically across two database files in WAL mode, so the *order* is what makes
the move recoverable: a crash between the steps leaves rows in both places, and the next run is a
no-op because the partition insert is `INSERT OR IGNORE` on the event id.

Nothing here runs unless retention is enabled. `SIEM_HOT_HOURS` defaults to 0 ("keep everything"),
so a fresh install never moves or deletes a row by accident; an operator opts in with a dry run
first.

Pinned evidence — events referenced by an alert or incident that is not resolved — is never moved,
whatever its age. That is what keeps an open investigation's evidence in the fast tier.
"""

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .db import audit, iso, transaction

DEFAULT_BATCH = 5000
PARTITION_SUFFIX = ".db"


# --- partitions -------------------------------------------------------------------------

def partition_day(ts):
    """The UTC day a timestamp belongs to, as the partition name: every ts is stored as UTC ISO."""
    return ts[:10]


def partition_path(archives_dir, day):
    return Path(archives_dir) / f"watchpost-{day}{PARTITION_SUFFIX}"


def ensure_schema(hot_conn, archive_conn):
    """Create the events table and its indexes in a partition, mirroring the hot store.

    The definition is derived from the hot database instead of being duplicated here, so a column
    added later (dest_port, bytes, http_status, …) cannot silently be missing from the archive.
    AUTOINCREMENT is deliberately dropped: archived ids are supplied by the source rows, and a
    partition must never mint ids of its own.
    """
    columns = []
    for row in hot_conn.execute("PRAGMA table_info(events)").fetchall():
        name, kind, notnull, default, _pk = row[1], row[2] or "TEXT", row[3], row[4], row[5]
        if name == "id":
            columns.append("id INTEGER PRIMARY KEY")
            continue
        piece = f"{name} {kind}"
        if notnull:
            piece += " NOT NULL"
        if default is not None:
            piece += f" DEFAULT {default}"
        columns.append(piece)
    archive_conn.execute("CREATE TABLE IF NOT EXISTS events (%s)" % ", ".join(columns))
    # Indexes are rebuilt from the hot index list rather than copied from sqlite_master: SQLite
    # stores the stored definition without `IF NOT EXISTS`, so re-running a copied statement on an
    # existing partition fails. These are all plain column indexes.
    for index in hot_conn.execute("PRAGMA index_list('events')").fetchall():
        name, unique = index[1], index[2]
        if name.startswith("sqlite_autoindex"):
            continue
        cols = [row[2] for row in hot_conn.execute(f"PRAGMA index_info('{name}')").fetchall()]
        archive_conn.execute("CREATE %sINDEX IF NOT EXISTS %s ON events(%s)"
                             % ("UNIQUE " if unique else "", name, ", ".join(cols)))


def list_partitions(archives_dir):
    """Archive partition files, newest first, so a lookup can stop at the first hit."""
    directory = Path(archives_dir)
    if not directory.is_dir():
        return []
    return sorted(directory.glob(f"*{PARTITION_SUFFIX}"), reverse=True)


def _open(path):
    # Autocommit, so the explicit BEGIN/COMMIT around a partition write is the only transaction.
    archive = sqlite3.connect(str(path), timeout=30, isolation_level=None)
    archive.row_factory = sqlite3.Row
    return archive


def find_event(archives_dir, event_id):
    """Look an event up in the partitions, newest first. None when it is not archived."""
    for path in list_partitions(archives_dir):
        try:
            archive = _open(path)
        except sqlite3.Error:
            continue
        try:
            row = archive.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        except sqlite3.Error:
            row = None
        finally:
            archive.close()
        if row is not None:
            return dict(row)
    return None


# --- retention policy -------------------------------------------------------------------

def pinned_predicate():
    """SQL predicate: this event is evidence for an alert or incident that is still open.

    Two paths are needed because an incident can stay open after one of its alerts is resolved, and
    because an alert can exist outside any incident.
    """
    return (
        "id IN (SELECT ae.event_id FROM alert_events ae"
        " JOIN alerts a ON a.id = ae.alert_id WHERE a.status != 'resolved')"
        " OR id IN (SELECT ae.event_id FROM alert_events ae"
        " JOIN incident_alerts ia ON ia.alert_id = ae.alert_id"
        " JOIN incidents i ON i.id = ia.incident_id WHERE i.status != 'resolved')"
    )


def cutoff_for(hot_hours, now=None):
    """The boundary: events with ts strictly before this are eligible.

    A non-positive `hot_hours` is refused rather than treated as "now": 0 means retention is off, and
    a caller that passes it by mistake must not be able to archive the whole store.
    """
    if hot_hours <= 0:
        raise ValueError("hot_hours must be positive; 0 means retention is off")
    now = now or datetime.now(timezone.utc)
    return iso(now - timedelta(hours=hot_hours))


def plan(conn, cutoff):
    """Per-day eligible rows and a rough byte estimate. Read-only."""
    pinned = pinned_predicate()
    rows = conn.execute(
        f"SELECT substr(ts, 1, 10) AS day, COUNT(*) AS rows,"
        f" SUM(LENGTH(COALESCE(message, '')) + LENGTH(COALESCE(raw, ''))) AS text_bytes"
        f" FROM events WHERE ts < ? AND NOT ({pinned}) GROUP BY day ORDER BY day",
        (cutoff,)).fetchall()
    pinned_rows = conn.execute(
        f"SELECT COUNT(*) FROM events WHERE ts < ? AND ({pinned})", (cutoff,)).fetchone()[0]
    return rows, pinned_rows


def dry_run(conn, cutoff, archives_dir):
    """What a retention pass would move, by day. Changes nothing and pins nothing."""
    rows, pinned_rows = plan(conn, cutoff)
    days = [{
        "day": row["day"],
        "rows": row["rows"],
        # Coarse: the two text columns plus ~120 bytes of fixed-width columns. An estimate, not a
        # measurement of the page file.
        "bytes_estimate": int((row["text_bytes"] or 0) + 120 * row["rows"]),
        "partition": str(partition_path(archives_dir, row["day"])),
    } for row in rows]
    return {"cutoff": cutoff, "dry_run": True, "days": days, "pinned": pinned_rows,
            "eligible": sum(d["rows"] for d in days), "archives_dir": str(archives_dir)}


def move(conn, cutoff, archives_dir, limit=DEFAULT_BATCH, actor=None):
    """Archive then delete eligible events. Never deletes a row that is not in a partition.

    Per day: write the partition (idempotent on the event id), re-read it to prove the rows arrived,
    and only then delete them from hot in a separate transaction. A failure at any earlier point
    leaves the hot rows in place and records the reason, so the next run retries the same work.
    `limit` bounds how many rows one pass handles.
    """
    rows, pinned_rows = plan(conn, cutoff)
    report = {"cutoff": cutoff, "dry_run": False, "archives_dir": str(archives_dir),
              "archived": 0, "deleted": 0, "pinned": pinned_rows, "days": [], "errors": []}
    remaining = limit
    pinned = pinned_predicate()
    for row in rows:
        if remaining <= 0:
            break
        day = row["day"]
        batch = [dict(r) for r in conn.execute(
            f"SELECT * FROM events WHERE ts < ? AND ts LIKE ? AND NOT ({pinned})"
            f" ORDER BY id LIMIT ?", (cutoff, day + "%", remaining)).fetchall()]
        if not batch:
            continue
        path = partition_path(archives_dir, day)
        try:
            present = set(_write_partition(conn, path, batch))
        except (sqlite3.Error, OSError) as exc:
            report["errors"].append({"day": day, "partition": str(path),
                                     "error": f"{type(exc).__name__}: {exc}"})
            continue                      # nothing was deleted: the rows are still in hot
        ids = [r["id"] for r in batch]
        if present != set(ids):
            report["errors"].append({"day": day, "partition": str(path),
                                     "error": f"{len(ids) - len(present)} row(s) missing after the "
                                              f"insert; nothing deleted"})
            continue
        with transaction(conn):
            conn.execute("DELETE FROM events WHERE id IN (%s)" % ",".join("?" * len(ids)), ids)
        report["archived"] += len(ids)
        report["deleted"] += len(ids)
        report["days"].append({"day": day, "rows": len(ids), "partition": str(path)})
        remaining -= len(ids)
    if actor:
        audit(conn, actor, "retention_archive", None,
              {"cutoff": cutoff, "archived": report["archived"], "deleted": report["deleted"],
               "pinned": pinned_rows, "days": [d["day"] for d in report["days"]],
               "errors": report["errors"]})
    return report


def _write_partition(hot_conn, path, rows):
    """Insert rows into the day's partition and return the ids found there afterwards."""
    path.parent.mkdir(parents=True, exist_ok=True)
    archive = _open(path)
    try:
        ensure_schema(hot_conn, archive)
        columns = [row[1] for row in hot_conn.execute("PRAGMA table_info(events)").fetchall()]
        sql = "INSERT OR IGNORE INTO events (%s) VALUES (%s)" % (
            ", ".join(columns), ", ".join("?" * len(columns)))
        archive.execute("BEGIN IMMEDIATE")
        try:
            archive.executemany(sql, [[r.get(c) for c in columns] for r in rows])
            archive.execute("COMMIT")
        except BaseException:
            archive.execute("ROLLBACK")
            raise
        ids = [r["id"] for r in rows]
        found = {r[0] for r in archive.execute(
            "SELECT id FROM events WHERE id IN (%s)" % ",".join("?" * len(ids)), ids).fetchall()}
        return found
    finally:
        archive.close()
