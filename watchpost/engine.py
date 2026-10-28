"""Ingestion and detection orchestration against the database."""

import json
import os
import sqlite3
import threading
import time
import uuid
from datetime import timedelta

from . import assets as assets_mod
from . import classify
from . import quarantine
from . import correlate as correlate_mod
from . import grouping
from . import rules as rules_mod
from . import sources as sources_mod
from . import stream
from .db import audit, iso, now_iso, parse_iso, row_to_dict, transaction
from .diagnostics import describe_exception, log, record_error

EVENT_COLUMNS = ["ts", "source", "host", "event_type", "outcome", "severity",
                 "user", "src_ip", "dest_ip", "dest_port", "bytes", "http_status", "tier", "message",
                 "raw"]
# Fields detection rules can read. source and ingested_at let a backtest replay log_source_silent's gaps.
# http_status is included because the web/WAF rules read it.
RULE_EVENT_FIELDS = ("id, ts, event_type, user, src_ip, host, dest_ip, dest_port, bytes, http_status,"
                     " message, synthetic, source, ingested_at")

# SQLite caps bound parameters (999 on older builds, 32766 on modern ones). Any query built from an
# unbounded list of ids must be chunked or it fails at scale — see _count_present.
IN_CHUNK = 900

# How many evidence rows one alert may accumulate. A rule that keeps matching (a scanner, a brute
# force, a burst) otherwise links every matching event forever; correlation then reads all of them on
# every ingest, which is what made each detection run slower than the last until ingest failed on the
# write lock. Bounded evidence keeps the cost flat; the overflow is counted, not silently lost.
EVIDENCE_MAX = int(os.environ.get("SIEM_ALERT_EVIDENCE_MAX", "500"))

# Burst coalescing (off by default). A scanner walking paths, or a burst of identical allowed flows,
# arrives as hundreds of rows that differ only by path; they cost storage and future scan time without
# changing a decision — the alert *is* the summary. With SIEM_BURST_KEEP set, at most that many stored
# rows survive per (source, src_ip, event_type) within one batch. Events already linked as evidence
# are never removed, and only the event types listed in SIEM_BURST_TYPES are touched.
BURST_KEEP = int(os.environ.get("SIEM_BURST_KEEP", "0"))
BURST_TYPES = tuple(part.strip() for part in
                    os.environ.get("SIEM_BURST_TYPES", "web_request,fw_allow,other,cloud_api_call")
                    .split(",") if part.strip())
# Fields detection rules can read.
#
# `http_status` was added for the OWASP web rules, which need the response code as a field rather
# than a regex over the message. `outcome` was missing until the same change, and its absence was
# silent: a rule asking for a field this projection omits gets None, so `web_path_discovery` — which
# tests what percentage of requests failed — never fired on live data, while its labeled scenario
# passed because the evaluation harness feeds raw scenario dicts, which do carry `outcome`. Anything
# a rule reads has to be listed here; tests/test_engine.py walks the real path to keep that true.
RULE_EVENT_FIELDS = "id, ts, event_type, outcome, user, src_ip, host, dest_ip, dest_port, bytes," \
                    " http_status, message, synthetic"

# Detection runs are serialized so concurrent ingests cannot create duplicate alerts. Also held by
# maintenance.reset_logs, so events cannot be deleted underneath a run that is reading them.
detection_lock = threading.Lock()


def seed_rules(conn, actor="system"):
    now = now_iso()
    for rule in rules_mod.DEFAULT_RULES:
        techniques = json.dumps(rule["techniques"])
        exists = conn.execute("SELECT 1 FROM rules WHERE id = ?", (rule["id"],)).fetchone()
        if exists:
            # ATT&CK mappings are static metadata, not tunable: keep stored rules in step with the code.
            conn.execute("UPDATE rules SET techniques = ? WHERE id = ? AND techniques IS NOT ?",
                         (techniques, rule["id"], techniques))
            continue
        params = json.dumps(rule["params"])
        conn.execute(
            "INSERT INTO rules(id, name, description, severity, enabled, params, version, updated_at, updated_by,"
            " techniques) VALUES (?,?,?,?,1,?,1,?,?,?)",
            (rule["id"], rule["name"], rule["description"], rule["severity"], params, now, actor, techniques),
        )
        conn.execute(
            "INSERT INTO rule_history(rule_id, version, enabled, params, changed_at, changed_by, note)"
            " VALUES (?,?,?,?,?,?,?)",
            (rule["id"], 1, 1, params, now, actor, "initial rule definition"),
        )


def load_rules(conn, enabled_only=True):
    sql = "SELECT * FROM rules" + (" WHERE enabled = 1" if enabled_only else "") + " ORDER BY id"
    rules = [row_to_dict(r, ["params", "techniques", "grouping"]) for r in conn.execute(sql)]
    for rule in rules:
        rule["techniques"] = rule.get("techniques") or []
    return rules


# --- Ingestion ------------------------------------------------------------------

def stored_batch(conn, batch_id):
    """The acknowledgement for a batch that is already stored, or None if it is not.

    This is the read half of client-batch idempotency: a retried upload reuses its batch id, and a
    replay returns this acknowledgement unchanged instead of storing the events again or repeating
    the detection side effects.
    """
    if not batch_id:
        return None
    row = conn.execute(
        "SELECT id, received, accepted, rejected, errors, detection_status"
        " FROM ingest_batches WHERE id = ?", (batch_id,)).fetchone()
    if row is None:
        return None
    try:
        rejections = json.loads(row["errors"] or "[]")
    except ValueError:
        rejections = []
    return {
        "batch_id": row["id"],
        "received": row["received"],
        "accepted": row["accepted"],
        "rejected": row["rejected"],
        "rejections": rejections if isinstance(rejections, list) else [],
        "duplicate": True,
        "detection": {"status": row["detection_status"], "replayed": True},
    }


def store_batch(conn, events, rejections, source, fmt, submitted_by, synthetic=False, batch_id=None):
    """Persist a batch atomically and return its id. Detection is run separately.

    The events and the batch row share one transaction, so a crash leaves either the whole batch or
    none of it — never events without their batch record. `batch_id` is the caller's idempotency key
    when supplied, and a fresh random one otherwise.
    """
    batch_id = batch_id or uuid.uuid4().hex
    now = now_iso()
    # Value tier, computed once here so every writer gets it: it decides how long a row stays in
    # the hot tier, never whether it is detected (detection runs on everything after storage).
    for event in events:
        if event.get("tier") is None:
            event["tier"] = classify.tier_for(event)
    with transaction(conn):
        conn.executemany(
            f"INSERT INTO events(ingested_at, synthetic, batch_id, {', '.join(EVENT_COLUMNS)})"
            f" VALUES (?, ?, ?, {', '.join('?' for _ in EVENT_COLUMNS)})",
            [(now, int(synthetic), batch_id, *[e.get(c) for c in EVENT_COLUMNS]) for e in events],
        )
        conn.execute(
            "INSERT INTO ingest_batches(id, created_at, source, format, received, accepted, rejected,"
            " errors, synthetic, submitted_by, detection_status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (batch_id, now, source, fmt, len(events) + len(rejections), len(events), len(rejections),
             json.dumps(rejections[:100]), int(synthetic), submitted_by, "pending"),
        )
    return batch_id


def coalesce_batch(conn, batch_id, keep=None, event_types=None):
    """Keep at most `keep` stored rows per (source, src_ip, event_type) for one batch.

    Detection has already run over the whole batch by the time this is called, so the decision has
    been made; what is dropped are the redundant rows behind that decision. Evidence already linked to
    an alert is never touched. Returns how many rows were removed.

    Off unless SIEM_BURST_KEEP is set, because it is a trade: anything that later reads *stored*
    events (a rule's history window, an analyst scrolling the list) sees fewer of them.
    """
    keep = BURST_KEEP if keep is None else keep
    if keep <= 0:
        return 0
    types = event_types or BURST_TYPES
    if not types:
        return 0
    placeholders = ",".join("?" for _ in types)
    try:
        cur = conn.execute(
            "DELETE FROM events WHERE id IN ("
            " SELECT id FROM ("
            "  SELECT id, ROW_NUMBER() OVER (PARTITION BY source, src_ip, event_type ORDER BY id) AS rn"
            f"  FROM events WHERE batch_id = ? AND event_type IN ({placeholders})"
            " ) WHERE rn > ?"
            ") AND id NOT IN (SELECT event_id FROM alert_events)",
            (batch_id, *types, keep))
    except sqlite3.OperationalError:
        return 0      # a SQLite without window functions: leave the rows alone
    return max(cur.rowcount, 0)


def ingest(conn, events, rejections, source, fmt, submitted_by, synthetic=False, batch_id=None):
    """Store a batch, then detect over it. With a batch_id, a replay changes nothing.

    Without a batch id — the historical behaviour — every call stores a new batch. With one, a batch
    that is already stored returns its original acknowledgement and nothing else happens: no second
    copy of the events, no second detection run, no duplicate alerts.
    """
    if batch_id is not None:
        replayed = stored_batch(conn, batch_id)
        if replayed is not None:
            return replayed
    try:
        batch_id = store_batch(conn, events, rejections, source, fmt, submitted_by, synthetic,
                               batch_id=batch_id)
    except sqlite3.IntegrityError:
        # Two requests raced on the same id and the other one committed first: answer as a replay.
        replayed = stored_batch(conn, batch_id)
        if replayed is not None:
            return replayed
        raise
    if rejections:
        # Counted always; content only when the operator opted into quarantine excerpts.
        quarantine.add_many(conn, source, batch_id, rejections)
    result = {
        "batch_id": batch_id,
        "received": len(events) + len(rejections),
        "accepted": len(events),
        "rejected": len(rejections),
        "rejections": rejections[:100],
    }
    _publish_events(conn, batch_id, len(events), synthetic)
    if not events:
        conn.execute("UPDATE ingest_batches SET detection_status = 'skipped' WHERE id = ?", (batch_id,))
        result["detection"] = {"status": "skipped", "reason": "no accepted events"}
        return result
    # Scan the time range touched by this batch, widened by the longest rule window.
    start = min(e["ts"] for e in events)
    end = max(e["ts"] for e in events)
    # If an earlier batch had to defer detection, start from its earliest event so nothing is left
    # undetected when this run does get the lock.
    deferred_from = conn.execute(
        "SELECT MIN(e.ts) FROM events e JOIN ingest_batches b ON e.batch_id = b.id"
        " WHERE b.detection_status = 'deferred'").fetchone()[0]
    if deferred_from and deferred_from < start:
        start = deferred_from
    run = run_detection(conn, trigger=f"ingest:{batch_id[:8]}", start=start, end=end, blocking=False)
    conn.execute("UPDATE ingest_batches SET detection_status = ? WHERE id = ?", (run["status"], batch_id))
    if run["status"] == "ok" and deferred_from:
        # This run started at the earliest deferred event, so those batches are covered now.
        conn.execute("UPDATE ingest_batches SET detection_status = 'recovered'"
                     " WHERE detection_status = 'deferred' AND created_at <= ?", (now_iso(),))
    if run["status"] == "ok":
        # Detection has already seen the whole batch; now drop the redundant rows behind its decision.
        removed = coalesce_batch(conn, batch_id)
        if removed:
            result["coalesced"] = removed
    result["detection"] = run
    return result


# --- Detection --------------------------------------------------------------------

def _existing_alert(conn, rule_id, group_key, first_seen, window):
    cutoff = iso(parse_iso(first_seen) - timedelta(seconds=window))
    return conn.execute(
        "SELECT * FROM alerts WHERE rule_id = ? AND group_key = ? AND status != 'resolved'"
        " AND last_seen >= ? ORDER BY id DESC LIMIT 1",
        (rule_id, group_key, cutoff),
    ).fetchone()


def _count_present(conn, rule_id, group_key, ids, chunk=IN_CHUNK):
    """How many of these event ids are already evidence for this rule and group.

    Chunked on purpose. A detection window can cover tens of thousands of events, and a single
    `IN (?, …)` with one parameter per id exceeds SQLite's bound-variable limit — measured in the
    Phase 6 load test as "too many SQL variables", which made detection fail for whole batches.
    Event ids are unique, so summing per-chunk distinct counts is exact.
    """
    if not ids:
        return 0
    total = 0
    for start in range(0, len(ids), chunk):
        part = ids[start:start + chunk]
        total += conn.execute(
            f"SELECT COUNT(DISTINCT ae.event_id) FROM alert_events ae"
            f" JOIN alerts a ON a.id = ae.alert_id"
            f" WHERE a.rule_id = ? AND a.group_key = ?"
            f" AND ae.event_id IN ({','.join('?' for _ in part)})",
            (rule_id, group_key, *part)).fetchone()[0]
    return total


def _evidence_has(conn, rule_id, group_key, event_id):
    """Is this event already evidence for this rule and group? One indexed lookup."""
    return conn.execute(
        "SELECT 1 FROM alert_events ae JOIN alerts a ON a.id = ae.alert_id"
        " WHERE a.rule_id = ? AND a.group_key = ? AND ae.event_id = ? LIMIT 1",
        (rule_id, group_key, event_id)).fetchone() is not None


def _weigh(conn, rule, alert_id, assets_idx):
    """Severity after asset weighting, from every evidence event now on the alert."""
    events = [dict(r) for r in conn.execute(
        "SELECT e.host, e.src_ip, e.dest_ip FROM events e JOIN alert_events ae ON ae.event_id = e.id"
        " WHERE ae.alert_id = ?", (alert_id,))]
    weighed = assets_mod.weigh(rule["severity"], assets_mod.match(assets_idx, events))
    weighed["assets"] = json.dumps(weighed["assets"])
    return weighed


def _apply_finding(conn, rule, finding, synthetic, assets_idx):
    """Create or extend an alert. Returns 'created', 'updated', or 'unchanged'."""
    ids = finding["event_ids"]
    if not ids:
        return "unchanged"
    # "Is the whole finding already linked?" only matters for a rescan or a re-delivery. On a live
    # batch the newest id is new, so one indexed lookup settles it; the full count is the rare path.
    # Before this, every batch counted the whole finding, which grew with the alert's evidence and
    # made detection O(evidence) per batch (measured: ~1,030 ms per 500 events at 20k events).
    if _evidence_has(conn, rule["id"], finding["group_key"], max(ids)):
        already = _count_present(conn, rule["id"], finding["group_key"], ids)
        if already == len(ids):
            return "unchanged"  # e.g. a rescan, or evidence already on a resolved alert

    now = now_iso()
    window = rule["params"].get("window_seconds", 3600)
    existing = _existing_alert(conn, rule["id"], finding["group_key"], finding["first_seen"], window)
    if existing:
        linked = conn.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id = ?",
                              (existing["id"],)).fetchone()[0]
        # Bounded evidence. A rule that keeps matching (a scanner, a brute force) used to link every
        # matching event forever: the alert grew without limit, correlation then had to read all of it
        # on every run, and each run got slower until ingest started failing on the write lock. The
        # first EVIDENCE_MAX are kept, the rest are counted in an activity entry.
        kept = ids[:max(0, EVIDENCE_MAX - linked)]
        if kept:
            conn.executemany("INSERT OR IGNORE INTO alert_events(alert_id, event_id) VALUES (?,?)",
                             [(existing["id"], i) for i in kept])
        count = conn.execute("SELECT COUNT(*) FROM alert_events WHERE alert_id = ?",
                             (existing["id"],)).fetchone()[0]
        dropped = len(ids) - len(kept)
        if dropped:
            conn.execute(
                "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                (existing["id"], "detection", "evidence_capped",
                 f"{dropped} further matching event(s) not linked; an alert keeps at most "
                 f"{EVIDENCE_MAX} evidence rows (SIEM_ALERT_EVIDENCE_MAX)", now),
            )
        weighed = _weigh(conn, rule, existing["id"], assets_idx)
        conn.execute(
            "UPDATE alerts SET last_seen = MAX(last_seen, ?), first_seen = MIN(first_seen, ?),"
            " event_count = ?, explanation = ?, title = ?, updated_at = ?, severity = ?, base_severity = ?,"
            " assets = ?, severity_note = ? WHERE id = ?",
            (finding["last_seen"], finding["first_seen"], count, finding["explanation"],
             finding["title"], now, weighed["severity"], weighed["base_severity"], weighed["assets"],
             weighed["severity_note"], existing["id"]),
        )
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (existing["id"], "detection", "evidence_added", f"now {count} related events", now),
        )
        if weighed["severity"] != existing["severity"]:
            conn.execute(
                "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
                (existing["id"], "assets", "severity_changed",
                 f"{existing['severity']} -> {weighed['severity']} ({weighed['severity_note']})", now),
            )
        return "updated"

    cur = conn.execute(
        "INSERT INTO alerts(rule_id, rule_version, group_key, severity, title, explanation, status,"
        " first_seen, last_seen, event_count, synthetic, created_at, updated_at)"
        " VALUES (?,?,?,?,?,?,'open',?,?,?,?,?,?)",
        (rule["id"], rule["version"], finding["group_key"], rule["severity"], finding["title"],
         finding["explanation"], finding["first_seen"], finding["last_seen"], len(ids),
         int(synthetic), now, now),
    )
    alert_id = cur.lastrowid
    kept = ids[:EVIDENCE_MAX]
    conn.executemany("INSERT OR IGNORE INTO alert_events(alert_id, event_id) VALUES (?,?)",
                     [(alert_id, i) for i in kept])
    if len(ids) > len(kept):
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (alert_id, "detection", "evidence_capped",
             f"{len(ids) - len(kept)} matching event(s) not linked; an alert keeps at most "
             f"{EVIDENCE_MAX} evidence rows (SIEM_ALERT_EVIDENCE_MAX)", now),
        )
    conn.execute(
        "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
        (alert_id, "detection", "created", f"rule {rule['id']} v{rule['version']}", now),
    )
    weighed = _weigh(conn, rule, alert_id, assets_idx)
    conn.execute("UPDATE alerts SET severity = ?, base_severity = ?, assets = ?, severity_note = ? WHERE id = ?",
                 (weighed["severity"], weighed["base_severity"], weighed["assets"], weighed["severity_note"],
                  alert_id))
    if weighed["severity"] != rule["severity"]:
        conn.execute(
            "INSERT INTO alert_activity(alert_id, actor, action, detail, created_at) VALUES (?,?,?,?,?)",
            (alert_id, "assets", "severity_changed",
             f"{rule['severity']} -> {weighed['severity']} ({weighed['severity_note']})", now),
        )
    return "created"


def active_suppressions(conn):
    """Approved tuning exceptions that are neither expired nor revoked, as a set of (rule_id, group_key)."""
    return {(r["rule_id"], r["group_key"]) for r in conn.execute(
        "SELECT rule_id, group_key FROM suppressions WHERE expires_at > ? AND revoked_at IS NULL", (now_iso(),))}


def active_rule_suppressions(conn):
    """Rule ids whose reviewed suppression window contains the current time."""
    now = now_iso()
    return {r["rule_id"] for r in conn.execute(
        "SELECT rule_id FROM rule_suppression_windows"
        " WHERE starts_at <= ? AND expires_at > ? AND ended_at IS NULL", (now, now))}


def scan_events(conn, rules, max_id, start=None, end=None):
    """The stored events a detection run of `rules` over [start, end] reads (default: all events).

    Returns (events, history_events, scan_start). The range is widened by the longest rule window;
    rules that compare with earlier activity also get the span before it as history context.
    Shared by run_detection and the rule backtest, so a backtest reads what detection reads.
    """
    sql, args = f"SELECT {RULE_EVENT_FIELDS} FROM events WHERE id <= ?", [max_id]
    if not (start and end):
        return [dict(r) for r in conn.execute(sql, args)], [], None
    pad = timedelta(seconds=rules_mod.lookback_seconds(rules))
    scan_start = iso(parse_iso(start) - pad)
    events = [dict(r) for r in conn.execute(sql + " AND ts >= ? AND ts <= ?",
                                            args + [scan_start, iso(parse_iso(end) + pad)])]
    # Rules that compare with earlier activity also get the span before the scan window, but only
    # the event types they read: a week of every event per batch was most of the ingest time.
    history_events = []
    history = timedelta(seconds=rules_mod.history_seconds(rules))
    types = sorted({t for r in rules if r["params"].get("history_seconds")
                    for t in rules_mod.HISTORY_EVENT_TYPES[r["id"]]})
    if history and types:
        history_events = [dict(r) for r in conn.execute(
            sql + f" AND ts >= ? AND ts < ? AND event_type IN ({','.join('?' for _ in types)})",
            args + [iso(parse_iso(scan_start) - history), scan_start, *types])]
    return events, history_events, scan_start


def rule_findings(rule, events, history_events, scan_start, suppressed, suppress_rule=False):
    """One rule's findings over scanned events, as detection alerts on them.

    Returns (findings, skipped): findings built only from history context are dropped, and those a
    reviewed tuning exception covers are skipped and counted.
    """
    # For the exfil rule an exception is passed in as a baseline principal, not skipped here.
    params = rules_mod.exception_params(rule["id"], rule["params"], suppressed)
    skips = rule["id"] not in rules_mod.EXCEPTION_ENABLES_BASELINE
    rule_events = events
    if history_events and params.get("history_seconds"):
        since = iso(parse_iso(scan_start) - timedelta(seconds=params["history_seconds"]))
        wanted = rules_mod.HISTORY_EVENT_TYPES[rule["id"]]
        rule_events = [e for e in history_events
                       if e["event_type"] in wanted and e["ts"] >= since] + events
    findings, skipped = [], 0
    raw_findings = rules_mod.rule_function(rule["id"])(rule_events, params)
    for finding in grouping.apply(raw_findings, rule_events, rule.get("grouping") or []):
        if scan_start and finding["last_seen"] < scan_start:
            continue  # built only from history context; outside this scan
        if skips and (rule["id"], finding["group_key"]) in suppressed:
            skipped += 1
            continue
        findings.append(finding)
    if suppress_rule:
        return [], skipped + len(findings)
    return findings, skipped


def run_detection(conn, trigger="manual", start=None, end=None, blocking=True):
    """Run all enabled rules over a time range (default: all events).

    Rules are evaluated *before* any write transaction is opened. They are pure Python over
    potentially large event lists, and holding SQLite's single writer lock for that whole time is
    what makes unrelated requests fail with "database is locked"; the lock is now held only for the
    inserts that follow.

    `blocking=False` is the ingest path: if a run is already in progress the batch is **not** queued
    behind it (a slow run used to make every ingest wait and then fail on the write lock). The events
    are stored, the run is reported as `deferred`, and the next run widens its window to cover them.

    Failures are recorded in detection_runs and error_log and returned honestly;
    the ingested events stay stored so the run can be retried.
    """
    if not blocking and detection_lock.locked():
        return {"status": "deferred", "events_scanned": 0, "alerts_created": 0, "alerts_updated": 0,
                "alerts_suppressed": 0,
                "reason": "a detection run is already in progress; this range is covered by the "
                          "next run"}
    with detection_lock:
        started = now_iso()
        run_id = conn.execute(
            "INSERT INTO detection_runs(started_at, trigger, status) VALUES (?,?,'running')",
            (started, trigger),
        ).lastrowid
        summary = {"run_id": run_id, "status": "running", "events_scanned": 0,
                   "alerts_created": 0, "alerts_updated": 0, "alerts_suppressed": 0}
        try:
            active = load_rules(conn)
            for rule in active:
                if rules_mod.rule_function(rule["id"]) is None:
                    raise rules_mod.RuleConfigError(f"no implementation for rule {rule['id']}")
                rule["params"] = rules_mod.validate_params(rule["id"], rule["params"])

            max_id = conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]
            events, history_events, scan_start = scan_events(conn, active, max_id, start, end)
            # No explicit range means the whole store, which is the only case where a batch whose
            # detection failed can be considered covered and marked recovered below.
            full_scan = not (start and end)
            synthetic_ids = {e["id"] for e in events + history_events if e["synthetic"]}
            summary["events_scanned"] = len(events) + len(history_events)
            assets_idx = assets_mod.load_index(conn)
            suppressed = active_suppressions(conn)
            suppressed_rules = active_rule_suppressions(conn)
            with transaction(conn):
                for rule in active:
                    if rule["id"] == sources_mod.RULE_ID:
                        # Silence is an absence: the rule reads each source's recent arrivals and the wall
                        # clock, not the events of the scanned time range.
                        arrivals = sources_mod.arrival_events(conn, max_id)
                        synthetic_ids.update(e["id"] for e in arrivals if e["synthetic"])
                        rule = {**rule, "params": sources_mod.clock_params(conn, rule["params"])}
                        findings, skipped = rule_findings(rule, arrivals, [], None, suppressed,
                                                          rule["id"] in suppressed_rules)
                    else:
                        findings, skipped = rule_findings(rule, events, history_events, scan_start, suppressed,
                                                          rule["id"] in suppressed_rules)
                    summary["alerts_suppressed"] += skipped  # a reviewed exception or rule window covers them
                    for finding in findings:
                        synthetic = all(i in synthetic_ids for i in finding["event_ids"])
                        outcome = _apply_finding(conn, rule, finding, synthetic, assets_idx)
                        if outcome == "created":
                            summary["alerts_created"] += 1
                        elif outcome == "updated":
                            summary["alerts_updated"] += 1
            summary["status"] = "ok"
            conn.execute(
                "UPDATE detection_runs SET status='ok', finished_at=?, events_scanned=?, alerts_created=?,"
                " alerts_updated=?, alerts_suppressed=?, max_event_id=? WHERE id=?",
                (now_iso(), summary["events_scanned"], summary["alerts_created"],
                 summary["alerts_updated"], summary["alerts_suppressed"], max_id, run_id),
            )
            if full_scan:
                # A full scan covers every stored event, including batches whose detection failed.
                conn.execute(
                    "UPDATE ingest_batches SET detection_status = 'recovered'"
                    " WHERE detection_status = 'failed' AND created_at <= ?", (started,))
            # Correlation runs after the alerts are safely stored; if it fails, alerts stay as they are.
            started_correlation = time.perf_counter()
            try:
                summary["correlation"] = {"status": "ok", **correlate_alerts(conn)}
            except Exception as exc:
                summary["correlation"] = {"status": "failed", "error": describe_exception(exc)}
                record_error(conn, "correlation", exc,
                             guidance="Alerts are unaffected. Fix the cause, then use 'Run detection' to "
                                      "correlate again.")
            seconds = round(time.perf_counter() - started_correlation, 3)
            # Kept beside `correlation`, not inside it: that dict's shape is documented (status and
            # the incident counts) and the timing is diagnostic.
            summary["correlation_seconds"] = seconds
            if seconds > 2:
                # Correlation reads every evidence row of every open alert. When that grows, it is the
                # operation that makes an ingest slow and, before the read moved out of the write
                # transaction, the one that held SQLite's single writer long enough to lock everyone out.
                log.warning("correlation took %.1f s; open alerts are carrying a large evidence set "
                            "(enable retention with SIEM_HOT_HOURS to bound it)", seconds)
            conn.execute("UPDATE detection_runs SET correlation = ? WHERE id = ?",
                         (summary["correlation"]["status"], run_id))
        except Exception as exc:
            message = describe_exception(exc)
            summary.update(status="failed", error=message)
            record_error(conn, "detection", exc,
                         guidance="Check the rule configuration on the Rules page, fix it through a "
                                  "reviewed change request, then use 'Run detection' to process the backlog.")
            conn.execute("UPDATE detection_runs SET status='failed', finished_at=?, error=? WHERE id=?",
                         (now_iso(), message, run_id))
        _publish_detection(conn, started, summary)
        return summary


# --- Correlation into incidents -----------------------------------------------------

_CANDIDATE_FILTER = (
    " LEFT JOIN incident_alerts ia ON ia.alert_id = a.id LEFT JOIN incidents i ON i.id = ia.incident_id"
    " WHERE (ia.incident_id IS NULL AND a.status != 'resolved') OR (ia.incident_id IS NOT NULL AND i.status != 'resolved')"
)


def _candidate_alerts(conn):
    """Unassigned alerts that are not resolved, plus every alert of an incident that is not resolved."""
    alerts = {r["id"]: {**dict(r), "entities": {k: set() for k in correlate_mod.ENTITY_TYPES}, "sightings": set()}
              for r in conn.execute("SELECT a.*, ia.incident_id FROM alerts a" + _CANDIDATE_FILTER)}
    rows = conn.execute("SELECT a.id AS alert_id, e.ts, e.src_ip, e.user, e.host FROM alerts a"
                        " JOIN alert_events ae ON ae.alert_id = a.id JOIN events e ON e.id = ae.event_id"
                        + _CANDIDATE_FILTER)
    for row in rows:
        alert = alerts[row["alert_id"]]
        for kind in correlate_mod.ENTITY_TYPES:
            if row[kind]:
                value = row[kind].lower() if kind == "user" else row[kind]
                alert["entities"][kind].add(value)
                alert["sightings"].add((kind, value, row["ts"]))
    tactics = {r["id"]: [t["tactic"] for t in r["techniques"]] for r in load_rules(conn, enabled_only=False)}
    for alert in alerts.values():
        alert["entities"] = {k: sorted(v) for k, v in alert["entities"].items()}
        alert["sightings"] = sorted(alert["sightings"])
        alert["tactics"] = tactics.get(alert["rule_id"], [])
    return alerts


def _incident_values(summary):
    return (summary["title"], summary["severity"], summary["first_seen"], summary["last_seen"],
            json.dumps(summary["entities"], sort_keys=True), json.dumps(summary["stages"]),
            summary["alert_count"], summary["synthetic"])


def correlate_alerts(conn, window_seconds=correlate_mod.DEFAULT_WINDOW_SECONDS):
    """Group related alerts into incidents and persist them. Safe to rerun: nothing changes twice.

    The candidate load reads every evidence row of every open alert, and it runs **before** the write
    transaction on purpose. SQLite has a single writer: doing that read inside BEGIN IMMEDIATE held the
    write lock for the length of the read, so every other request queued behind correlation and failed
    with "database is locked" once its busy timeout expired. Reads now happen first; the transaction
    covers only the inserts and updates.
    """
    result = {"incidents_created": 0, "incidents_updated": 0}
    alerts = _candidate_alerts(conn)
    groups = correlate_mod.correlate(list(alerts.values()), window_seconds)
    now = now_iso()
    with transaction(conn):
        for group in groups:
            members = [alerts[i] for i in group["alert_ids"]]
            incident_id = group["incident_id"]
            if incident_id is None and not correlate_mod.should_open(members):
                continue
            values = _incident_values(correlate_mod.summarize(members))
            if incident_id is None:
                incident_id = conn.execute(
                    "INSERT INTO incidents(title, severity, first_seen, last_seen, entities, stages, alert_count,"
                    " synthetic, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,'open',?,?)",
                    (*values, now, now)).lastrowid
                result["incidents_created"] += 1
            else:
                current = conn.execute(
                    "SELECT title, severity, first_seen, last_seen, entities, stages, alert_count, synthetic"
                    " FROM incidents WHERE id = ?", (incident_id,)).fetchone()
                if tuple(current) != values:
                    conn.execute(
                        "UPDATE incidents SET title = ?, severity = ?, first_seen = ?, last_seen = ?, entities = ?,"
                        " stages = ?, alert_count = ?, synthetic = ?, updated_at = ? WHERE id = ?",
                        (*values, now, incident_id))
                    result["incidents_updated"] += 1
            new = group["alert_ids"] if group["incident_id"] is None else group["new_alert_ids"]
            conn.executemany("INSERT OR IGNORE INTO incident_alerts(alert_id, incident_id, added_at) VALUES (?,?,?)",
                             [(i, incident_id, now) for i in new])
    return result


# --- Live stream (SSE) ------------------------------------------------------------

STREAM_EVENT_LIMIT = 50
STREAM_EVENT_FIELDS = ("id, ts, source, host, event_type, outcome, severity, user, src_ip, dest_ip, message,"
                       " synthetic")
STREAM_ALERT_FIELDS = ("id, rule_id, severity, title, status, group_key, first_seen, last_seen, event_count,"
                       " synthetic, created_at, updated_at")


def _publish_events(conn, batch_id, count, synthetic):
    """Tell dashboards about a stored batch (newest events only). Never fails the ingest."""
    if not count or not stream.BROKER.active():
        return
    try:
        rows = conn.execute(f"SELECT {STREAM_EVENT_FIELDS} FROM events WHERE batch_id = ?"
                            " ORDER BY ts DESC, id DESC LIMIT ?", (batch_id, STREAM_EVENT_LIMIT))
        stream.BROKER.publish("event", {"batch_id": batch_id, "count": count, "synthetic": bool(synthetic),
                                        "events": [dict(r) for r in rows]})
    except Exception as exc:  # the stream is best-effort; storage already succeeded
        record_error(conn, "stream", exc, guidance="Live dashboard updates may lag; reload the dashboard.")


def _publish_detection(conn, started, summary):
    """Publish alerts (and incidents, once that table exists) touched by this run, plus detection health."""
    if not stream.BROKER.active():
        return
    try:
        failed = summary["status"] != "ok"
        stream.BROKER.publish("health", {"partial": True, "checks": {"detection": "failing" if failed else "ok"},
                                         "error": summary.get("error")})
        if failed:
            return
        for row in conn.execute(f"SELECT {STREAM_ALERT_FIELDS} FROM alerts WHERE updated_at >= ? ORDER BY id",
                                (started,)):
            alert = dict(row)
            alert["change"] = "created" if alert["created_at"] >= started else "updated"
            stream.BROKER.publish("alert", alert)
        has_incidents = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'incidents'").fetchone()
        if has_incidents:
            for row in conn.execute("SELECT * FROM incidents WHERE updated_at >= ? ORDER BY id", (started,)):
                stream.BROKER.publish("incident", dict(row))
    except Exception as exc:
        record_error(conn, "stream", exc, guidance="Live dashboard updates may lag; reload the dashboard.")


# --- Rule changes (applied only through approved change requests) ------------------

def apply_rule_change(conn, rule_id, payload, changed_by, approved_by, change_request_id, note):
    rule = conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if rule is None:
        raise rules_mod.RuleConfigError(f"unknown rule {rule_id!r}")
    params = json.loads(rule["params"])
    if "params" in payload:
        params = rules_mod.validate_params(rule_id, {**params, **payload["params"]})
    grouping_fields = json.loads(rule["grouping"] or "[]")
    if "grouping" in payload:
        grouping_fields = grouping.validate(payload["grouping"])
    enabled = int(payload.get("enabled", rule["enabled"]))
    version = rule["version"] + 1
    now = now_iso()
    conn.execute(
        "UPDATE rules SET params = ?, grouping = ?, enabled = ?, version = ?, updated_at = ?, updated_by = ?"
        " WHERE id = ?",
        (json.dumps(params), json.dumps(grouping_fields), enabled, version, now, approved_by, rule_id),
    )
    conn.execute(
        "INSERT INTO rule_history(rule_id, version, enabled, params, grouping, changed_at, changed_by, approved_by,"
        " change_request_id, note) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (rule_id, version, enabled, json.dumps(params), json.dumps(grouping_fields), now, changed_by, approved_by,
         change_request_id, note),
    )
    audit(conn, approved_by, "rule_changed", rule_id, {"version": version, "change_request": change_request_id})
    return version
