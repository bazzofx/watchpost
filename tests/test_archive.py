"""Retention and archiving: the dry run, the mover, pinning, and cross-tier reads.

⚠ These tests need a writable temporary directory for the archive partitions. Where the environment
denies one (some sandboxes), each test skips rather than failing — the mover is exercised on a real
filesystem wherever the suite can write, including the deployment host.
"""

import os
import sqlite3
import tempfile
import unittest

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
            self.tmp = tempfile.TemporaryDirectory()
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


class JournalModeTests(unittest.TestCase):
    """The partition is a separate file; it must open and close cleanly on every call."""

    def test_partitions_are_listed_newest_first(self):
        try:
            with tempfile.TemporaryDirectory() as tmp:
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


if __name__ == "__main__":
    unittest.main()
