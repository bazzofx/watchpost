"""Read-side view of the collection agents that report to this instance.

An "agent" is an ingest token plus the batches it has sent. There is no separate registration
step and no agent table: `ingest_batches.submitted_by` records `token:<name>` for any batch sent
with `Authorization: Bearer wp_...`, so the fleet is derived from data already stored. Nothing
extra has to be deployed for an agent to appear here.

What that means for honesty of the status column: every signal available is *activity* based. An
agent only contacts the server when it has new log lines to send, so a host that is simply quiet
(a lab box at the weekend, a server with no traffic) looks the same as an agent that has stopped.
`status` therefore describes how recently logs arrived, not whether the agent process is alive,
and the API returns the thresholds so the UI can say so plainly.
"""

from datetime import timedelta

from .db import now_iso, parse_iso, utcnow

REPORTING_SECONDS = 600     # a batch within this window: logs are arriving
QUIET_SECONDS = 3600        # within this one: quiet; older: silent
TOKEN_SUBMITTER_PREFIX = "token:"


def _common_prefix(values):
    """Longest common prefix of `values`, trimmed back to a clean source-name prefix.

    Source names are `<prefix>-<source>`, so the shared part is the host prefix. Returns "" when
    there is nothing useful to strip (fewer than two sources, or no shared separator).
    """
    if len(values) < 2:
        return ""
    shortest = min(values, key=len)
    length = 0
    for index, char in enumerate(shortest):
        if all(value[index] == char for value in values):
            length = index + 1
        else:
            break
    prefix = values[0][:length]
    return prefix[:prefix.rfind("-")] if "-" in prefix else ""


def _agent_prefix(found, host):
    """The `<host>-` part of an agent's source names, so the source kind can be shown on its own.

    Two or more sources give it away directly: their shared prefix is the host part. With a single
    source there is nothing to compare against, so the agent's naming convention is used instead —
    and only when that source literally starts with `"<hostname>-"` for the hostname its own events
    reported. Nothing is guessed from a partial match.
    """
    if not found:
        return ""
    prefix = _common_prefix([entry["source"] for entry in found])
    if not prefix and host and all(entry["source"].startswith(f"{host}-") for entry in found):
        return host
    return prefix


def _status(revoked_at, last_batch_at, reporting_seconds, quiet_seconds, now):
    if revoked_at:
        return "revoked"
    if not last_batch_at:
        return "never_reported"
    age = (now - parse_iso(last_batch_at)).total_seconds()
    if age <= reporting_seconds:
        return "reporting"
    if age <= quiet_seconds:
        return "quiet"
    return "silent"


def _batch_rows(conn):
    """Batches sent with an ingest token, grouped by agent, source, and format."""
    return conn.execute(
        "SELECT submitted_by, source, format, COUNT(*) AS batches, SUM(accepted) AS accepted,"
        " SUM(rejected) AS rejected, MIN(created_at) AS first_batch, MAX(created_at) AS last_batch,"
        f" SUM(detection_status = 'failed') AS detection_failures"
        f" FROM ingest_batches WHERE submitted_by LIKE '{TOKEN_SUBMITTER_PREFIX}%'"
        " GROUP BY submitted_by, source, format"
    ).fetchall()


def _event_rows(conn):
    """Events per agent and source, joined through the batch that delivered them."""
    return conn.execute(
        "SELECT b.submitted_by AS agent, e.source AS source, COUNT(*) AS events, MAX(e.ts) AS last_log"
        " FROM events e JOIN ingest_batches b ON b.id = e.batch_id"
        f" WHERE b.submitted_by LIKE '{TOKEN_SUBMITTER_PREFIX}%'"
        " GROUP BY b.submitted_by, e.source"
    ).fetchall()


def _host_rows(conn):
    """Events per agent and reported host, so the most common hostname can be picked."""
    return conn.execute(
        "SELECT b.submitted_by AS agent, e.host AS host, COUNT(*) AS n"
        " FROM events e JOIN ingest_batches b ON b.id = e.batch_id"
        f" WHERE b.submitted_by LIKE '{TOKEN_SUBMITTER_PREFIX}%' AND e.host IS NOT NULL"
        " GROUP BY b.submitted_by, e.host ORDER BY n DESC"
    ).fetchall()


def overview(conn, reporting_seconds=REPORTING_SECONDS, quiet_seconds=QUIET_SECONDS):
    """Every ingest token with the sources it reports and how recently logs arrived."""
    now = utcnow()

    # Hostname the logs themselves claim, per agent; the busiest value wins.
    hostname = {}
    for row in _host_rows(conn):
        hostname.setdefault(row["agent"], row["host"])

    events = {(row["agent"], row["source"]): row["events"] for row in _event_rows(conn)}
    last_log = {(row["agent"], row["source"]): row["last_log"] for row in _event_rows(conn)}

    sources = {}   # agent -> {source: {...}}
    for row in _batch_rows(conn):
        agent = row["submitted_by"]
        entry = sources.setdefault(agent, {}).setdefault(row["source"], {
            "source": row["source"], "formats": [], "batches": 0, "accepted": 0, "rejected": 0,
            "events": 0, "last_log_at": None, "first_batch_at": row["first_batch"],
            "last_batch_at": row["last_batch"], "detection_failures": 0,
        })
        if row["format"] not in entry["formats"]:
            entry["formats"].append(row["format"])
        entry["batches"] += row["batches"]
        entry["accepted"] += row["accepted"] or 0
        entry["rejected"] += row["rejected"] or 0
        entry["detection_failures"] += row["detection_failures"] or 0
        entry["events"] += events.get((agent, row["source"]), 0)
        entry["last_log_at"] = last_log.get((agent, row["source"]))
        entry["first_batch_at"] = min(entry["first_batch_at"], row["first_batch"])
        entry["last_batch_at"] = max(entry["last_batch_at"], row["last_batch"])

    agents = []
    for token in conn.execute(
        "SELECT id, name, prefix, created_by, created_at, last_used_at, revoked_at FROM api_tokens"
        " ORDER BY created_at, id"
    ):
        agent_key = f"{TOKEN_SUBMITTER_PREFIX}{token['name']}"
        found = sorted(sources.get(agent_key, {}).values(), key=lambda s: s["source"])
        prefix = _agent_prefix(found, hostname.get(agent_key))
        for entry in found:
            entry["formats"] = sorted(entry["formats"])
            # The short name the agent's catalogue used ("auth"), when the host prefix is clear.
            entry["kind"] = entry["source"][len(prefix) + 1:] \
                if prefix and entry["source"].startswith(prefix + "-") else entry["source"]

        last_batch_at = max((s["last_batch_at"] for s in found), default=None)
        first_batch_at = min((s["first_batch_at"] for s in found), default=None)
        state = _status(token["revoked_at"], last_batch_at, reporting_seconds, quiet_seconds, now)
        agents.append({
            "token_id": token["id"],
            "name": token["name"],
            "token_prefix": token["prefix"],
            "hostname": hostname.get(agent_key) or prefix or None,
            "status": state,
            # When the agent was provisioned: its ingest token was created for it.
            "installed_at": token["created_at"],
            "installed_by": token["created_by"],
            "revoked_at": token["revoked_at"],
            "last_token_use_at": token["last_used_at"],
            "first_batch_at": first_batch_at,
            "last_batch_at": last_batch_at,
            "sources": found,
            "source_count": len(found),
            "batches": sum(s["batches"] for s in found),
            "events": sum(s["events"] for s in found),
            "rejected": sum(s["rejected"] for s in found),
            "detection_failures": sum(s["detection_failures"] for s in found),
        })

    order = {"silent": 0, "revoked": 1, "never_reported": 2, "quiet": 3, "reporting": 4}
    agents.sort(key=lambda a: (order[a["status"]], a["name"]))
    counted = {}
    for agent in agents:
        counted[agent["status"]] = counted.get(agent["status"], 0) + 1
    return {
        "generated_at": now_iso(),
        "reporting_seconds": reporting_seconds,
        "quiet_seconds": quiet_seconds,
        "summary": {
            "total": len(agents),
            **{state: counted.get(state, 0)
               for state in ("reporting", "quiet", "silent", "never_reported", "revoked")},
            "events": sum(a["events"] for a in agents),
            "batches": sum(a["batches"] for a in agents),
        },
        "agents": agents,
    }


def stale_thresholds():
    """The window boundaries as a human sentence, for the UI to explain the status column."""
    return (f"reporting = a batch in the last {REPORTING_SECONDS // 60} min, "
            f"quiet = within {QUIET_SECONDS // 60} min, silent = longer")
