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
# SQLite caps bound parameters (999 on older builds); every statement built from an unbounded id
# list is split at this size. The mover's limit is larger than the cap on purpose.
IN_CHUNK = 900


def _chunks(items, size=IN_CHUNK):
    """Split a list so no generated SQL statement exceeds the bound-parameter limit."""
    for start in range(0, len(items), size):
        yield items[start:start + size]


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


def cutoffs(hot_hours, routine_hours=0, now=None):
    """(hot_cutoff, routine_cutoff-or-None) from the two retention windows.

    Category C expires on `routine_hours`, everything else on `hot_hours`. The routine window is
    clamped so it can never be *longer* than the hot window: a misconfiguration must not keep routine
    traffic in the fast tier longer than the evidence sitting next to it.
    """
    now = now or datetime.now(timezone.utc)
    hot = cutoff_for(hot_hours, now)
    if not routine_hours or routine_hours <= 0:
        return hot, None
    return hot, max(cutoff_for(routine_hours, now), hot)


def _eligible(hot_cutoff, routine_cutoff):
    """SQL for "this row is old enough for its tier", with its arguments."""
    routine = routine_cutoff or hot_cutoff
    return ("((tier = 'C' AND ts < ?) OR ((tier IS NULL OR tier != 'C') AND ts < ?))",
            (routine, hot_cutoff))


def plan(conn, hot_cutoff, routine_cutoff=None):
    """Per-day, per-tier eligible rows. Read-only."""
    pinned = pinned_predicate()
    where, args = _eligible(hot_cutoff, routine_cutoff)
    rows = conn.execute(
        f"SELECT substr(ts, 1, 10) AS day, COALESCE(tier, '?') AS tier, COUNT(*) AS rows,"
        f" SUM(LENGTH(COALESCE(message, '')) + LENGTH(COALESCE(raw, ''))) AS text_bytes"
        f" FROM events WHERE {where} AND NOT ({pinned})"
        f" GROUP BY day, tier ORDER BY day, tier", args).fetchall()
    pinned_rows = conn.execute(
        f"SELECT COUNT(*) FROM events WHERE {where} AND ({pinned})", args).fetchone()[0]
    return rows, pinned_rows


def dry_run(conn, hot_cutoff, archives_dir, routine_cutoff=None):
    """What a retention pass would move, by day and tier. Changes nothing, creates no file."""
    rows, pinned_rows = plan(conn, hot_cutoff, routine_cutoff)
    days = {}
    for row in rows:
        entry = days.setdefault(row["day"], {
            "day": row["day"], "rows": 0, "bytes_estimate": 0, "by_tier": {},
            "partition": str(partition_path(archives_dir, row["day"]))})
        entry["rows"] += row["rows"]
        # Coarse: the two text columns plus ~120 bytes of fixed-width columns. An estimate, not a
        # measurement of the page file.
        entry["bytes_estimate"] += int((row["text_bytes"] or 0) + 120 * row["rows"])
        entry["by_tier"][row["tier"]] = entry["by_tier"].get(row["tier"], 0) + row["rows"]
    ordered = [days[day] for day in sorted(days)]
    return {"cutoff": hot_cutoff, "routine_cutoff": routine_cutoff or hot_cutoff, "dry_run": True,
            "days": ordered, "pinned": pinned_rows, "eligible": sum(d["rows"] for d in ordered),
            "archives_dir": str(archives_dir)}


def move(conn, hot_cutoff, archives_dir, routine_cutoff=None, limit=DEFAULT_BATCH, actor=None):
    """Archive then delete eligible events. Never deletes a row that is not in a partition.

    Per day: write the partition (idempotent on the event id), re-read it to prove the rows arrived,
    then — in one hot-database transaction — record the Category C rollups and delete the ids. Putting
    the rollup and the delete in the same transaction is what keeps the retry honest: a crash cannot
    leave a rollup counted for rows that are still queued to move.
    """
    rows, pinned_rows = plan(conn, hot_cutoff, routine_cutoff)
    report = {"cutoff": hot_cutoff, "routine_cutoff": routine_cutoff or hot_cutoff, "dry_run": False,
              "archives_dir": str(archives_dir), "archived": 0, "deleted": 0, "rolled_up": 0,
              "pinned": pinned_rows, "days": [], "errors": []}
    where, args = _eligible(hot_cutoff, routine_cutoff)
    pinned = pinned_predicate()
    remaining = limit
    for day in sorted({row["day"] for row in rows}):
        if remaining <= 0:
            break
        batch = [dict(r) for r in conn.execute(
            f"SELECT * FROM events WHERE {where} AND ts LIKE ? AND NOT ({pinned})"
            f" ORDER BY id LIMIT ?", (*args, day + "%", remaining)).fetchall()]
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
            report["rolled_up"] += _rollup_batch(conn, batch)
            # Chunked: `limit` can exceed SQLite's bound-parameter cap on older builds.
            for part in _chunks(ids):
                conn.execute("DELETE FROM events WHERE id IN (%s)" % ",".join("?" * len(part)), part)
        report["archived"] += len(ids)
        report["deleted"] += len(ids)
        report["days"].append({"day": day, "rows": len(ids), "partition": str(path)})
        remaining -= len(ids)
    if actor:
        audit(conn, actor, "retention_archive", None,
              {"cutoff": hot_cutoff, "routine_cutoff": routine_cutoff or hot_cutoff,
               "archived": report["archived"], "deleted": report["deleted"],
               "rolled_up": report["rolled_up"], "pinned": pinned_rows,
               "days": [d["day"] for d in report["days"]], "errors": report["errors"]})
    return report


def run_retention(conn, hot_hours, archives_dir, routine_hours=0, limit=DEFAULT_BATCH, actor=None):
    """One retention pass: roll routine traffic up, archive what expired, delete what was archived."""
    hot_cutoff, routine_cutoff = cutoffs(hot_hours, routine_hours)
    return move(conn, hot_cutoff, archives_dir, routine_cutoff=routine_cutoff, limit=limit,
                actor=actor)


def _rollup_batch(conn, rows):
    """Fold the Category C rows of one batch into hourly rollups. Returns how many events.

    Called inside the same transaction as the delete, so a rollup is never recorded for a row that
    survives to be counted again. Counts accumulate across passes (a day can arrive in slices).
    """
    buckets = {}
    for row in rows:
        if row.get("tier") != "C":
            continue
        key = (row["ts"][:13] + ":00:00.000Z", row["event_type"], row["source"],
               row.get("host") or "", row.get("outcome") or "", row["severity"])
        entry = buckets.get(key)
        if entry is None:
            buckets[key] = [1, row["ts"], row["ts"]]
        else:
            entry[0] += 1
            entry[1] = min(entry[1], row["ts"])
            entry[2] = max(entry[2], row["ts"])
    for (bucket, event_type, source, host, outcome, severity), (count, first, last) in buckets.items():
        conn.execute(
            "INSERT INTO event_rollups(bucket_start, event_type, source, host, outcome, severity,"
            " events, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(bucket_start, event_type, source, host, outcome, severity) DO UPDATE SET"
            " events = events + excluded.events,"
            " first_seen = MIN(first_seen, excluded.first_seen),"
            " last_seen = MAX(last_seen, excluded.last_seen)",
            (bucket, event_type, source, host, outcome, severity, count, first, last))
    return sum(entry[0] for entry in buckets.values())


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
        found = set()
        for part in _chunks(ids):
            found.update(row[0] for row in archive.execute(
                "SELECT id FROM events WHERE id IN (%s)" % ",".join("?" * len(part)),
                part).fetchall())
        return found
    finally:
        archive.close()
