"""Destructive maintenance: clear the log store while keeping all configuration.

One operation lives here — resetting the log data. It is deliberately narrow about what it removes,
it is serialized against detection, and it is always audited, so a wipe stays visible in the Audit
log even though the data it removed does not.

What it keeps, on purpose: accounts and sessions (a reset must not log anyone out), API tokens (an
agent must not start failing with 401), rules and their history with tuned thresholds, security
settings, change requests, evaluation runs, and the audit log itself.
"""

import sqlite3

from .db import audit, transaction
from .engine import detection_lock

# Every table populated by ingesting events. Order is irrelevant: the schema declares no foreign
# keys, so no delete can violate one.
LOG_TABLES = (
    "alert_activity", "alert_notes", "alert_events", "incident_alerts",
    "alerts", "incidents", "detection_runs", "ingest_batches", "events", "error_log",
)

# Everything the reset leaves untouched. A test asserts these two tuples together cover every table
# in the schema, so a new table cannot be added without deciding which side it belongs on.
KEPT_TABLES = (
    "users", "sessions", "api_tokens", "rules", "rule_history", "settings",
    "change_requests", "evaluation_runs", "audit_log", "meta", "health_probe",
)


def counts(conn):
    """Row counts per log table, so a caller can show what a reset would remove before doing it."""
    return {name: conn.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0] for name in LOG_TABLES}


def preview(conn):
    """What a reset would remove and what it would keep, without changing anything."""
    per_table = counts(conn)
    return {"counts": per_table, "total": sum(per_table.values()), "kept_tables": list(KEPT_TABLES)}


def reset_logs(conn, actor):
    """Delete every ingested event and everything derived from it. Returns what was removed.

    Holds the engine's detection lock: a detection run reads events before writing the alerts it
    derives from them, and deleting those events mid-run would leave alerts with no evidence. The
    deletes and the audit entry share one transaction, so a reset either happens completely or not
    at all. `VACUUM` runs afterwards to return the file to the filesystem; if it fails (for example
    the disk has no room for the rewrite) the reset still stands and the result says so.
    """
    with detection_lock:
        removed = counts(conn)
        with transaction(conn):
            for name in LOG_TABLES:
                conn.execute(f"DELETE FROM {name}")
            # Restart AUTOINCREMENT counters so a fresh store begins at id 1 again.
            try:
                conn.execute("DELETE FROM sqlite_sequence WHERE name IN (%s)"
                             % ",".join("?" * len(LOG_TABLES)), LOG_TABLES)
            except sqlite3.OperationalError:
                pass  # the table only exists once an AUTOINCREMENT table has held a row
            audit(conn, actor, "logs_reset", None, {"removed": removed})
        result = {"removed": removed, "removed_total": sum(removed.values()),
                  "kept_tables": list(KEPT_TABLES), "vacuumed": True}
        try:
            conn.execute("VACUUM")
        except sqlite3.Error as exc:
            result["vacuumed"] = False
            result["vacuum_note"] = (f"{type(exc).__name__}: {exc}. The data was removed; the file "
                                     f"was not compacted, so its size on disk is unchanged.")
        return result
