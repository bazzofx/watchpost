"""Retention and archiving: the dry run, the mover, pinning, and cross-tier reads.

âš  These tests need a writable temporary directory for the archive partitions. Where the environment
denies one (some sandboxes), each test skips rather than failing â€” the mover is exercised on a real
filesystem wherever the suite can write, including the deployment host.
"""

import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from watchpost import archive, engine, queries, server
from watchpost.db import connect, init_schema

OLD = "2026-01-02T10:00:00.000Z"        # safely before CUTOFF
CUTOFF = "2026-01-03T00:00:00.000Z"


def old_event(i, event_type="other", ip="203.0.113.7", user=None):
    return {"ts": OLD, "source": "src", "event_type": event_type, "severity": "info",
            "src_ip": ip, "user": user, "message": f"row {i}"}


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        try:
            self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
            probe = os.path.join(self.tmp.name, "probe")
            with open(probe, "w") as fh:
                fh.write("x")
            os.remove(probe)
        except (PermissionError, OSError) as exc:
            self.skipTest(f"no writable temporary directory here: {exc}")
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        self.archives = os.path.join(self.tmp.name, "archive")

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def hot_ids(self):
        return [r[0] for r in self.conn.execute("SELECT id FROM events ORDER BY id")]

    def partition_rows(self, day="2026-01-02"):
        part = sqlite3.connect(archive.partition_path(self.archives, day))
        try:
            return [r[0] for r in part.execute("SELECT id FROM events ORDER BY id")]
        finally:
            part.close()

    # --- dry run and the mover ---------------------------------------------------------

    def test_dry_run_reports_and_changes_nothing(self):
        engine.ingest(self.conn, [old_event(i) for i in range(5)], [], "s", "json", "t")
        before = self.hot_ids()
        report = archive.dry_run(self.conn, CUTOFF, self.archives)
        self.assertTrue(report["dry_run"])
        self.assertEqual(report["eligible"], 5)
        self.assertEqual([d["day"] for d in report["days"]], ["2026-01-02"])
        self.assertGreater(report["days"][0]["bytes_estimate"], 0)
        self.assertEqual(self.hot_ids(), before)          # nothing moved
        self.assertFalse(os.path.exists(self.archives))   # nothing created

    def test_move_archives_then_deletes_with_the_same_ids(self):
        engine.ingest(self.conn, [old_event(i) for i in range(4)], [], "s", "json", "t")
        before = self.hot_ids()
        report = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual((report["archived"], report["deleted"]), (4, 4))
        self.assertEqual(report["errors"], [])
        self.assertEqual(self.hot_ids(), [])
        self.assertEqual(self.partition_rows(), before)

    def test_the_partition_schema_is_mirrored_from_hot(self):
        engine.ingest(self.conn, [old_event(0)], [], "s", "json", "t")
        archive.move(self.conn, CUTOFF, self.archives)
        part = sqlite3.connect(archive.partition_path(self.archives, "2026-01-02"))
        try:
            columns = {r[1] for r in part.execute("PRAGMA table_info(events)")}
            indexes = {r[0] for r in part.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='events'")}
        finally:
            part.close()
        self.assertLessEqual({"ts", "source", "event_type", "http_status", "raw", "batch_id"}, columns)
        self.assertIn("idx_events_ts", indexes)

    def test_a_second_pass_is_a_no_op(self):
        engine.ingest(self.conn, [old_event(i) for i in range(2)], [], "s", "json", "t")
        archive.move(self.conn, CUTOFF, self.archives)
        again = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual((again["archived"], again["deleted"]), (0, 0))
        self.assertEqual(len(self.partition_rows()), 2)   # not duplicated

    def test_archived_but_not_deleted_is_completed_by_the_next_pass(self):
        """The crash window: the partition write committed, the hot delete never ran."""
        engine.ingest(self.conn, [old_event(i) for i in range(3)], [], "s", "json", "t")
        rows = [dict(r) for r in self.conn.execute("SELECT * FROM events ORDER BY id")]
        archive._write_partition(self.conn, archive.partition_path(self.archives, "2026-01-02"), rows)
        self.assertEqual(len(self.hot_ids()), 3)          # hot still holds them
        report = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual(report["deleted"], 3)
        self.assertEqual(self.hot_ids(), [])
        self.assertEqual(len(self.partition_rows()), 3)   # still exactly three

    def test_only_events_before_the_cutoff_move(self):
        engine.ingest(self.conn, [old_event(0)], [], "s", "json", "t")
        engine.ingest(self.conn, [{"ts": "2026-06-01T10:00:00.000Z", "source": "s",
                                   "event_type": "other", "severity": "info"}], [], "s", "json", "t")
        report = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual(report["deleted"], 1)
        self.assertEqual(len(self.hot_ids()), 1)          # the newer one stays

    # --- pinning ------------------------------------------------------------------------

    def test_pinned_evidence_is_never_moved_until_the_investigation_closes(self):
        # twelve failures in one window trip brute_force_ip, so these become alert evidence
        failures = [{"ts": OLD, "source": "auth", "event_type": "auth_failure",
                     "severity": "medium", "src_ip": "203.0.113.9", "user": "admin",
                     "message": f"fail {i}"} for i in range(12)]
        engine.ingest(self.conn, failures, [], "auth", "json", "t")
        engine.ingest(self.conn, [old_event(i) for i in range(3)], [], "s", "json", "t")
        self.assertGreaterEqual(self.conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status != 'resolved'").fetchone()[0], 1)

        report = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual(report["archived"], 3, "only the unpinned rows move")
        self.assertEqual(report["pinned"], 12)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 12)

        # An open *incident* pins evidence too, even once its alerts are resolved.
        self.conn.execute("UPDATE alerts SET status = 'resolved'")
        still_open = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual(still_open["archived"], 0, "an open incident still pins the evidence")

        self.conn.execute("UPDATE incidents SET status = 'resolved'")
        closed = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual(closed["archived"], 12)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)

    # --- cross-tier reads ---------------------------------------------------------------

    def test_an_archived_event_is_still_readable(self):
        engine.ingest(self.conn, [old_event(0)], [], "s", "json", "t")
        event_id = self.hot_ids()[0]
        archive.move(self.conn, CUTOFF, self.archives)
        self.assertIsNone(self.conn.execute("SELECT 1 FROM events WHERE id = ?", (event_id,)).fetchone())
        self.assertEqual(archive.find_event(self.archives, event_id)["id"], event_id)
        event = queries.get_event(self.conn, event_id, archive_dir=self.archives)
        self.assertTrue(event["archived"])
        self.assertEqual(event["message"], "row 0")

    def test_a_missing_event_is_still_a_404(self):
        with self.assertRaises(queries.QueryError) as ctx:
            queries.get_event(self.conn, 999999, archive_dir=self.archives)
        self.assertEqual(ctx.exception.status, 404)

    # --- policy guard -------------------------------------------------------------------

    def test_zero_hours_is_refused_rather_than_archiving_everything(self):
        with self.assertRaises(ValueError):
            archive.cutoff_for(0)

    # --- value tiers ---------------------------------------------------------------------

    def test_routine_traffic_expires_before_high_value_evidence(self):
        """Category C uses the routine window; A/B use the hot window."""
        engine.ingest(self.conn, [{"ts": "2026-01-03T10:00:00.000Z", "source": "web",
                                   "event_type": "web_request", "severity": "low",
                                   "message": "routine"}], [], "web", "json", "t")
        engine.ingest(self.conn, [{"ts": "2026-01-03T10:00:00.000Z", "source": "auth",
                                   "event_type": "auth_failure", "severity": "medium",
                                   "message": "evidence"}], [], "auth", "json", "t")
        hot = "2026-01-02T00:00:00.000Z"          # only evidence older than this expires
        routine = "2026-01-05T00:00:00.000Z"      # routine older than this expires
        report = archive.move(self.conn, hot, self.archives, routine_cutoff=routine)
        self.assertEqual(report["archived"], 1)
        self.assertEqual([r[0] for r in self.conn.execute("SELECT event_type FROM events")],
                         ["auth_failure"])

    def test_routine_rows_become_hourly_rollups_as_they_expire(self):
        events = [{"ts": "2026-01-02T10:%02d:00.000Z" % i, "source": "web", "host": "web01",
                   "event_type": "web_request", "severity": "low", "outcome": "success",
                   "message": "ok"} for i in range(5)]
        engine.ingest(self.conn, events, [], "web", "json", "t")
        report = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual(report["rolled_up"], 5)
        rows = [dict(r) for r in self.conn.execute("SELECT * FROM event_rollups")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["events"], 5)
        self.assertEqual(rows[0]["bucket_start"], "2026-01-02T10:00:00.000Z")
        self.assertEqual(rows[0]["event_type"], "web_request")
        self.assertEqual(rows[0]["first_seen"], "2026-01-02T10:00:00.000Z")
        self.assertEqual(rows[0]["last_seen"], "2026-01-02T10:04:00.000Z")

    def test_rollups_accumulate_across_sliced_passes(self):
        events = [{"ts": "2026-01-02T10:%02d:00.000Z" % i, "source": "web",
                   "event_type": "web_request", "severity": "low", "message": "ok"}
                  for i in range(3)]
        engine.ingest(self.conn, events, [], "web", "json", "t")
        for _ in range(3):
            archive.move(self.conn, CUTOFF, self.archives, limit=1)
        self.assertEqual(self.conn.execute("SELECT SUM(events) FROM event_rollups").fetchone()[0], 3)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM event_rollups").fetchone()[0], 1)

    def test_different_hours_are_different_buckets(self):
        engine.ingest(self.conn, [
            {"ts": "2026-01-02T10:10:00.000Z", "source": "web", "event_type": "web_request",
             "severity": "low", "message": "a"},
            {"ts": "2026-01-02T11:10:00.000Z", "source": "web", "event_type": "web_request",
             "severity": "low", "message": "b"}], [], "web", "json", "t")
        archive.move(self.conn, CUTOFF, self.archives)
        buckets = [r[0] for r in self.conn.execute(
            "SELECT bucket_start FROM event_rollups ORDER BY bucket_start")]
        self.assertEqual(buckets, ["2026-01-02T10:00:00.000Z", "2026-01-02T11:00:00.000Z"])

    def test_high_value_rows_are_not_rolled_up(self):
        engine.ingest(self.conn, [{"ts": OLD, "source": "auth", "event_type": "auth_failure",
                                   "severity": "medium", "message": "x"}], [], "auth", "json", "t")
        report = archive.move(self.conn, CUTOFF, self.archives)
        self.assertEqual(report["rolled_up"], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM event_rollups").fetchone()[0], 0)


    # --- alerts-only policy --------------------------------------------------------------

    def test_alerts_only_discard_archives_before_deleting(self):
        engine.ingest(self.conn, [
            {"ts": OLD, "source": "auth", "event_type": "auth_failure", "severity": "medium",
             "src_ip": "203.0.113.9", "user": "admin", "message": "fail"} for _ in range(12)],
            [], "auth", "json", "t")
        engine.ingest(self.conn, [old_event(i) for i in range(3)], [], "s", "json", "t")
        linked = {r[0] for r in self.conn.execute("SELECT event_id FROM alert_events")}
        unlinked = {r[0] for r in self.conn.execute(
            "SELECT id FROM events WHERE id NOT IN (SELECT event_id FROM alert_events)")}
        report = archive.discard_unlinked(self.conn, CUTOFF, self.archives, archive_first=True)
        self.assertEqual((report["archived"], report["discarded"]), (len(unlinked), len(unlinked)))
        self.assertEqual({r[0] for r in self.conn.execute("SELECT id FROM events")}, linked)
        part = sqlite3.connect(archive.partition_path(self.archives, "2026-01-02"))
        try:
            self.assertEqual({r[0] for r in part.execute("SELECT id FROM events")}, unlinked)
        finally:
            part.close()

    def test_alerts_only_discard_keeps_rows_when_the_partition_fails(self):
        engine.ingest(self.conn, [old_event(i) for i in range(3)], [], "s", "json", "t")
        before = {r[0] for r in self.conn.execute("SELECT id FROM events")}
        with mock.patch.object(archive, "_write_partition",
                               side_effect=sqlite3.OperationalError("database or disk is full")):
            report = archive.discard_unlinked(self.conn, CUTOFF, self.archives, archive_first=True)
        self.assertEqual(report["discarded"], 0)
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual({r[0] for r in self.conn.execute("SELECT id FROM events")}, before)


class JournalModeTests(unittest.TestCase):
    """The partition is a separate file; it must open and close cleanly on every call."""

    def test_partitions_are_listed_newest_first(self):
        try:
            with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                for day in ("2026-01-01", "2026-01-03", "2026-01-02"):
                    archive.partition_path(tmp, day).write_bytes(b"")
                names = [p.name for p in archive.list_partitions(tmp)]
        except (PermissionError, OSError) as exc:
            self.skipTest(f"no writable temporary directory here: {exc}")
        self.assertEqual(names, ["watchpost-2026-01-03.db", "watchpost-2026-01-02.db",
                                 "watchpost-2026-01-01.db"])


class RetentionRouteGuardTests(unittest.TestCase):
    """The admin routes are the only way to trigger deletion; their guards must hold without a server."""

    class Req:
        def __init__(self, body):
            self.body = body
            self.query = {}
            self.headers = {}
            self.user = {"username": "admin"}
            self.conn = None
            self.app = None

    @staticmethod
    def app(hot_hours):
        config = type("Config", (), {"hot_hours": hot_hours, "archive_dir": "/x"})()
        return type("App", (), {"config": config})()

    def test_running_retention_needs_the_confirmation_word(self):
        with self.assertRaises(server.ApiError) as ctx:
            server.retention_run(self.Req(b'{"confirm": "nope"}'))
        self.assertEqual(ctx.exception.status, 400)

    def test_running_retention_is_refused_while_it_is_off(self):
        req = self.Req(b'{"confirm": "ARCHIVE"}')
        req.app = self.app(0)
        with self.assertRaises(server.ApiError) as ctx:
            server.retention_run(req)
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("retention is off", str(ctx.exception))

    def test_preview_reports_that_retention_is_off(self):
        req = self.Req(b"")
        req.app = self.app(0)
        report = server.retention_preview(req)
        self.assertFalse(report["enabled"])
        self.assertIn("SIEM_HOT_HOURS", report["note"])


class AlertsOnlyDiscardTests(unittest.TestCase):
    """Policy: keep the events an alert references, discard everything else past the grace window.

    Exercised with `archive_first=False`, which is the mode that deletes outright â€” so these run in
    memory, everywhere, with no temporary directory.
    """

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        # Twelve failures become alert evidence (linked); three routine requests stay unlinked.
        engine.ingest(self.conn, [
            {"ts": "2026-01-02T09:00:%02d.000Z" % i, "source": "auth", "event_type": "auth_failure",
             "severity": "medium", "src_ip": "203.0.113.9", "user": "admin",
             "message": "Failed password"} for i in range(12)], [], "auth", "json", "t")
        engine.ingest(self.conn, [
            {"ts": "2026-01-02T09:30:%02d.000Z" % i, "source": "web", "event_type": "web_request",
             "severity": "low", "message": "GET /a.css 200"} for i in range(3)], [], "web", "json", "t")

    def tearDown(self):
        self.conn.close()

    def linked_ids(self):
        return {r[0] for r in self.conn.execute("SELECT event_id FROM alert_events")}

    def unlinked_ids(self):
        return {r[0] for r in self.conn.execute(
            "SELECT id FROM events WHERE id NOT IN (SELECT event_id FROM alert_events)")}

    def test_linked_events_survive_and_unlinked_ones_are_discarded(self):
        linked, unlinked = self.linked_ids(), self.unlinked_ids()
        self.assertTrue(linked, "the fixture must produce alert evidence")
        report = archive.discard_unlinked(self.conn, CUTOFF, "/unused", archive_first=False)
        self.assertEqual(report["mode"], "alerts")
        self.assertEqual(report["discarded"], len(unlinked))
        remaining = {r[0] for r in self.conn.execute("SELECT id FROM events")}
        self.assertEqual(remaining, linked, "only alert-linked events may remain")
        self.assertEqual({r[0] for r in self.conn.execute("SELECT event_id FROM alert_events")}, linked,
                         "evidence links must survive the event rows")

    def test_evidence_of_a_resolved_alert_is_still_kept(self):
        """The policy is 'linked to an alert', not 'linked to an open one'."""
        self.conn.execute("UPDATE alerts SET status = 'resolved'")
        linked = self.linked_ids()
        archive.discard_unlinked(self.conn, CUTOFF, "/unused", archive_first=False)
        self.assertEqual({r[0] for r in self.conn.execute("SELECT id FROM events")}, linked)

    def test_events_after_the_cutoff_are_kept(self):
        """Unlinked does not mean deleted immediately: the grace window protects recent events."""
        engine.ingest(self.conn, [{"ts": "2026-06-01T09:00:00.000Z", "source": "web",
                                   "event_type": "web_request", "severity": "low",
                                   "message": "recent"}], [], "web", "json", "t")
        archive.discard_unlinked(self.conn, CUTOFF, "/unused", archive_first=False)
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE ts > ?", (CUTOFF,)).fetchone()[0], 1)

    def test_the_pass_is_bounded_by_limit(self):
        unlinked = len(self.unlinked_ids())
        report = archive.discard_unlinked(self.conn, CUTOFF, "/unused", limit=2, archive_first=False)
        self.assertEqual(report["discarded"], min(2, unlinked))
        self.assertEqual(len(self.unlinked_ids()), unlinked - report["discarded"])

    def test_routine_rows_are_rolled_up_before_they_go(self):
        report = archive.discard_unlinked(self.conn, CUTOFF, "/unused", archive_first=False)
        self.assertGreater(report["rolled_up"], 0)
        row = self.conn.execute("SELECT SUM(events) FROM event_rollups").fetchone()[0]
        self.assertEqual(row, report["rolled_up"])

    def test_the_pass_is_audited(self):
        archive.discard_unlinked(self.conn, CUTOFF, "/unused", archive_first=False, actor="admin")
        detail = self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'retention_discard'").fetchone()
        self.assertIsNotNone(detail)
        self.assertIn("discarded", detail[0])

    def test_preview_counts_what_would_go_and_what_stays(self):
        unlinked = len(self.unlinked_ids())
        report = archive.preview_unlinked(self.conn, CUTOFF, "/unused")
        self.assertEqual(report["mode"], "alerts")
        self.assertEqual(report["discardable"], unlinked)
        self.assertEqual(report["kept_linked"], len(self.linked_ids()))
        self.assertTrue(report["dry_run"])
        # Read-only: nothing moved.
        self.assertEqual(len(self.unlinked_ids()), unlinked)


class AlertsOnlyRouteTests(unittest.TestCase):
    """The route must demand the word that matches the policy: DISCARD deletes, ARCHIVE archives."""

    class Req:
        def __init__(self, body, mode="alerts", discard_archive=True, keep_hours=1):
            self.body = body
            self.query = {}
            self.headers = {}
            self.user = {"username": "admin"}
            self.conn = None
            config = type("Config", (), {"hot_hours": 0, "routine_hours": 0, "archive_dir": "/x",
                                         "retention_mode": mode, "keep_unlinked_hours": keep_hours,
                                         "discard_archive": discard_archive})()
            self.app = type("App", (), {"config": config})()

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        engine.ingest(self.conn, [
            {"ts": "2026-01-02T09:00:%02d.000Z" % i, "source": "auth", "event_type": "auth_failure",
             "severity": "medium", "src_ip": "203.0.113.9", "user": "admin",
             "message": "Failed password"} for i in range(12)], [], "auth", "json", "t")
        engine.ingest(self.conn, [{"ts": "2026-01-02T09:30:00.000Z", "source": "web",
                                   "event_type": "web_request", "severity": "low",
                                   "message": "routine"}], [], "web", "json", "t")

    def tearDown(self):
        self.conn.close()

    def test_the_wrong_confirmation_word_is_refused(self):
        req = self.Req(b'{"confirm": "ARCHIVE"}')
        req.conn = self.conn
        with self.assertRaises(server.ApiError) as ctx:
            server.retention_run(req)
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("DISCARD", str(ctx.exception))

    def test_discard_runs_and_reports_the_policy(self):
        req = self.Req(b'{"confirm": "DISCARD"}')
        req.conn = self.conn
        report = server.retention_run(req)
        self.assertEqual(report["mode"], "alerts")
        self.assertTrue(report["enabled"])
        self.assertGreater(report["discarded"], 0)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events WHERE id NOT IN"
                                           " (SELECT event_id FROM alert_events)").fetchone()[0], 0)

    def test_preview_uses_the_alerts_policy(self):
        req = self.Req(b"")
        req.conn = self.conn
        report = server.retention_preview(req)
        self.assertEqual(report["mode"], "alerts")
        self.assertGreaterEqual(report["kept_linked"], 1)
        self.assertIn("discardable", report)

    def test_an_unknown_mode_falls_back_to_age(self):
        req = self.Req(b'{"confirm": "ARCHIVE"}', mode="nonsense")
        req.conn = self.conn
        with self.assertRaises(server.ApiError) as ctx:
            server.retention_run(req)          # age mode with hot_hours 0 -> refused
        self.assertIn("retention is off", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
