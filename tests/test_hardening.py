"""Phase 6 hardening: failure paths that must not lose data, and the bounded re-scan.

The mover tests inject failures rather than filling a disk, so they run in memory everywhere. What
they prove is the ordering guarantee: a row is never deleted from hot unless it is verifiably present
in a partition — including when the partition write fails or is incomplete.
"""

import sqlite3
import threading
import unittest
from unittest import mock

from watchpost import archive, engine, server
from watchpost.db import connect, init_schema

OLD = "2026-01-02T10:00:00.000Z"
CUTOFF = "2026-01-03T00:00:00.000Z"


def old_event(i):
    return {"ts": OLD, "source": "src", "event_type": "other", "severity": "info",
            "message": f"row {i}"}


class Stub:
    """The minimum a route function touches."""

    def __init__(self, query=None):
        self.query = query or {}
        self.headers = {}
        self.body = b""
        self.user = {"username": "admin"}
        self.conn = None
        self.app = None


class MoverFailureTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        engine.ingest(self.conn, [old_event(i) for i in range(3)], [], "src", "json", "t")
        self.ids = [r[0] for r in self.conn.execute("SELECT id FROM events ORDER BY id")]

    def tearDown(self):
        self.conn.close()

    def test_a_failed_partition_write_keeps_every_row_in_hot(self):
        with mock.patch.object(archive, "_write_partition",
                               side_effect=OSError("no space left on device")):
            report = archive.move(self.conn, CUTOFF, "/unused")
        self.assertEqual((report["archived"], report["deleted"]), (0, 0))
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn("no space left", report["errors"][0]["error"])
        self.assertEqual([r[0] for r in self.conn.execute("SELECT id FROM events ORDER BY id")],
                         self.ids, "hot rows must survive a failed archive write")

    def test_a_disk_full_error_is_reported_and_nothing_is_deleted(self):
        with mock.patch.object(archive, "_write_partition",
                               side_effect=sqlite3.OperationalError("database or disk is full")):
            report = archive.move(self.conn, CUTOFF, "/unused")
        self.assertEqual(report["deleted"], 0)
        self.assertIn("disk is full", report["errors"][0]["error"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)

    def test_an_incomplete_partition_blocks_the_delete(self):
        """The verify-before-delete guarantee, exercised with a partition that lost a row."""
        with mock.patch.object(archive, "_write_partition", return_value={self.ids[0]}):
            report = archive.move(self.conn, CUTOFF, "/unused")
        self.assertEqual(report["deleted"], 0)
        self.assertEqual(len(report["errors"]), 1)
        self.assertIn("missing after the insert", report["errors"][0]["error"])
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)

    def test_a_complete_partition_still_deletes(self):
        """Control case: the same flow without an injected failure does the move."""
        with mock.patch.object(archive, "_write_partition", return_value=set(self.ids)):
            report = archive.move(self.conn, CUTOFF, "/unused")
        self.assertEqual(report["deleted"], 3)
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)


class DetectionRunWindowTests(unittest.TestCase):
    """The admin re-scan is the one O(history) operation; it must be boundable."""

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def call(self, query):
        req = Stub(query)
        req.conn = self.conn
        with mock.patch.object(server.engine, "run_detection",
                               return_value={"status": "ok"}) as run:
            result = server.detection_run(req)
        return result, run

    def test_without_hours_the_whole_store_is_scanned(self):
        result, run = self.call({})
        self.assertIsNone(run.call_args.kwargs["start"])
        self.assertIsNone(result["window_hours"])
        self.assertEqual(result["status"], "ok")

    def test_hours_bounds_the_scan(self):
        result, run = self.call({"hours": "6"})
        self.assertEqual(result["window_hours"], 6)
        self.assertIsNotNone(run.call_args.kwargs["start"])
        self.assertTrue(run.call_args.kwargs["start"].endswith("Z"))

    def test_hours_are_clamped(self):
        self.assertEqual(self.call({"hours": "0"})[0]["window_hours"], 1)
        self.assertEqual(self.call({"hours": "999999"})[0]["window_hours"], 24 * 90)

    def test_garbage_hours_is_rejected(self):
        with self.assertRaises(server.ApiError) as ctx:
            self.call({"hours": "yesterday"})
        self.assertEqual(ctx.exception.status, 400)

    def test_the_run_is_audited_with_its_window(self):
        self.call({"hours": "12"})
        row = self.conn.execute(
            "SELECT detail FROM audit_log WHERE action = 'detection_run' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertIn("12", row[0])


class BoundParameterTests(unittest.TestCase):
    """The bug the Phase 6 load test found: an unbounded IN (...) fails at scale.

    SQLite caps bound parameters, so a detection window covering tens of thousands of events made
    `_apply_finding` raise "too many SQL variables" and detection stop for whole batches. Both places
    that build a list from an unbounded id set are now chunked; these prove the chunking is exact.
    """

    def test_the_evidence_check_is_chunked_and_exact(self):
        conn = connect(":memory:")
        init_schema(conn)
        engine.seed_rules(conn)
        failures = [{"ts": f"2026-10-03T10:00:{i:02d}.000Z", "source": "auth",
                     "event_type": "auth_failure", "severity": "medium",
                     "src_ip": "203.0.113.9", "user": "admin", "message": f"f{i}"} for i in range(12)]
        engine.ingest(conn, failures, [], "auth", "json", "t")
        alert_id, rule_id, group_key = conn.execute(
            "SELECT id, rule_id, group_key FROM alerts LIMIT 1").fetchone()
        ids = [r[0] for r in conn.execute(
            "SELECT event_id FROM alert_events WHERE alert_id = ? ORDER BY event_id",
            (alert_id,))]
        self.assertGreater(len(ids), 4, "the fixture must produce several evidence rows")
        # A tiny chunk size exercises the same path the real limit does.
        self.assertEqual(engine._count_present(conn, rule_id, group_key, ids, chunk=2), len(ids))
        self.assertEqual(engine._count_present(conn, rule_id, group_key, ids + [999_999], chunk=2),
                         len(ids))
        self.assertEqual(engine._count_present(conn, rule_id, group_key, [], chunk=2), 0)
        conn.close()

    def test_chunks_split_without_losing_items(self):
        items = list(range(10))
        parts = list(archive._chunks(items, 3))
        self.assertEqual([len(p) for p in parts], [3, 3, 3, 1])
        self.assertEqual([i for p in parts for i in p], items)

    def test_the_mover_deletes_in_chunks(self):
        conn = connect(":memory:")
        init_schema(conn)
        engine.seed_rules(conn)
        engine.ingest(conn, [old_event(i) for i in range(5)], [], "src", "json", "t")
        ids = {r[0] for r in conn.execute("SELECT id FROM events")}
        two = lambda items: (items[i:i + 2] for i in range(0, len(items), 2))
        with mock.patch.object(archive, "_write_partition", return_value=ids), \
                mock.patch.object(archive, "_chunks", two):
            report = archive.move(conn, CUTOFF, "/unused")
        self.assertEqual(report["deleted"], 5)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)
        conn.close()


class LockErrorHandlingTests(unittest.TestCase):
    """Transient SQLite contention must not look like a bug: reads retry, writes ask for a retry."""

    def test_lock_and_busy_errors_are_recognised(self):
        for message in ("database is locked", "database is busy", "database table is locked"):
            with self.subTest(message=message):
                self.assertTrue(server._is_lock_error(sqlite3.OperationalError(message)))

    def test_other_errors_are_not_treated_as_contention(self):
        for exc in (sqlite3.OperationalError("no such table: nope"),
                    sqlite3.IntegrityError("database is locked"),   # not an OperationalError
                    ValueError("database is locked")):
            with self.subTest(exc=repr(exc)):
                self.assertFalse(server._is_lock_error(exc))

    def test_correlation_reports_how_long_it_took(self):
        conn = connect(":memory:")
        init_schema(conn)
        engine.seed_rules(conn)
        result = engine.ingest(conn, [{"ts": f"2026-10-03T10:00:{i:02d}.000Z", "source": "auth",
                                       "event_type": "auth_failure", "severity": "medium",
                                       "src_ip": "203.0.113.9", "user": "admin",
                                       "message": "fail"} for i in range(12)], [], "auth", "json", "t")
        self.assertIn("correlation_seconds", result["detection"])
        self.assertGreaterEqual(result["detection"]["correlation_seconds"], 0.0)
        conn.close()


class EvidenceCapTests(unittest.TestCase):
    """A rule that keeps matching must not make its alert — and correlation — grow forever."""

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def tearDown(self):
        self.conn.close()

    def failures(self, n=12, offset=0):
        return [{"ts": "2026-10-03T%02d:%02d:%02d.000Z" % ((offset // 3600) % 24, (offset // 60) % 60,
                                                           (offset + i) % 60),
                 "source": "auth", "event_type": "auth_failure", "severity": "medium",
                 "user": "admin", "src_ip": "203.0.113.9", "message": f"fail {i}"} for i in range(n)]

    def test_evidence_per_alert_is_capped_and_the_overflow_is_recorded(self):
        with mock.patch.object(engine, "EVIDENCE_MAX", 3):
            engine.ingest(self.conn, self.failures(12), [], "auth", "json", "t")
            engine.ingest(self.conn, self.failures(12, offset=60), [], "auth", "json", "t")
        worst = self.conn.execute(
            "SELECT MAX(linked) FROM (SELECT COUNT(*) AS linked FROM alert_events GROUP BY alert_id)"
        ).fetchone()[0]
        self.assertLessEqual(worst, 3, "evidence must stay bounded per alert")
        capped = self.conn.execute(
            "SELECT COUNT(*) FROM alert_activity WHERE action = 'evidence_capped'").fetchone()[0]
        self.assertGreater(capped, 0, "the overflow must be recorded, not silently dropped")

    def test_correlation_cost_no_longer_grows_with_matches(self):
        with mock.patch.object(engine, "EVIDENCE_MAX", 5):
            for offset in range(0, 600, 60):
                engine.ingest(self.conn, self.failures(12, offset=offset), [], "auth", "json", "t")
        total = self.conn.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0]
        alerts = self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        self.assertLessEqual(total, 5 * alerts, "evidence must stay proportional to alerts, not events")


class DeferredDetectionTests(unittest.TestCase):
    """Ingest must never queue behind a slow detection run — that is what produced the lock storm."""

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def tearDown(self):
        self.conn.close()

    def batch(self, offset):
        return [{"ts": "2026-10-03T10:%02d:%02d.000Z" % ((offset // 60) % 60, (offset + i) % 60),
                 "source": "auth", "event_type": "auth_failure", "severity": "medium",
                 "user": "admin", "src_ip": "203.0.113.9", "message": "fail"} for i in range(12)]

    def test_ingest_defers_instead_of_waiting_when_a_run_is_in_progress(self):
        busy = threading.Lock()
        busy.acquire()                      # a detection run is in progress
        with mock.patch.object(engine, "detection_lock", busy):
            result = engine.ingest(self.conn, self.batch(0), [], "auth", "json", "t")
        self.assertEqual(result["detection"]["status"], "deferred")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 12,
                         "the events must still be stored")
        status = self.conn.execute(
            "SELECT detection_status FROM ingest_batches ORDER BY id DESC LIMIT 1").fetchone()[0]
        self.assertEqual(status, "deferred")

    def test_the_next_run_covers_the_deferred_range(self):
        busy = threading.Lock()
        busy.acquire()
        with mock.patch.object(engine, "detection_lock", busy):
            engine.ingest(self.conn, self.batch(0), [], "auth", "json", "t")
        busy.release()
        result = engine.ingest(self.conn, self.batch(30), [], "auth", "json", "t")
        self.assertEqual(result["detection"]["status"], "ok")
        statuses = [r[0] for r in self.conn.execute(
            "SELECT detection_status FROM ingest_batches ORDER BY id")]
        self.assertIn("recovered", statuses, "the deferred batch must be marked covered")
        self.assertGreater(self.conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0], 0,
                           "detection must actually have run over the stored events")


class BurstCoalescingTests(unittest.TestCase):
    """Rapid, repetitive rows are stored once per bucket — after detection, never through evidence."""

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def tearDown(self):
        self.conn.close()

    def web(self, n, ip="198.51.100.7"):
        return [{"ts": "2026-10-03T10:00:%02d.000Z" % i, "source": "web01-web",
                 "event_type": "web_request", "severity": "low", "src_ip": ip,
                 "message": f"GET /path/{i} 404"} for i in range(n)]

    def test_off_by_default(self):
        engine.ingest(self.conn, self.web(10), [], "web", "json", "t")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 10)

    def test_repetitive_rows_are_reduced_to_the_keep_limit(self):
        with mock.patch.object(engine, "BURST_KEEP", 3):
            result = engine.ingest(self.conn, self.web(10), [], "web", "json", "t")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0], 3)
        self.assertEqual(result["coalesced"], 7)

    def test_evidence_is_never_removed(self):
        # Twelve failures trip a rule, so those events become evidence; they are tier A and linked.
        failures = [{"ts": "2026-10-03T10:01:%02d.000Z" % i, "source": "auth",
                     "event_type": "auth_failure", "severity": "medium", "user": "admin",
                     "src_ip": "203.0.113.9", "message": "fail"} for i in range(12)]
        engine.ingest(self.conn, failures, [], "auth", "json", "t")
        linked = self.conn.execute("SELECT COUNT(DISTINCT event_id) FROM alert_events").fetchone()[0]
        self.assertGreater(linked, 0)
        with mock.patch.object(engine, "BURST_KEEP", 1), \
                mock.patch.object(engine, "BURST_TYPES", ("auth_failure",)):
            engine.coalesce_batch(self.conn, self.conn.execute(
                "SELECT id FROM ingest_batches ORDER BY id DESC LIMIT 1").fetchone()[0])
        remaining = self.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertGreaterEqual(remaining, linked, "linked evidence must survive coalescing")

    def test_other_event_types_are_untouched(self):
        engine.ingest(self.conn, self.web(5), [], "web", "json", "t")
        engine.ingest(self.conn, [{"ts": "2026-10-03T10:02:00.000Z", "source": "web",
                                   "event_type": "web_scan", "severity": "medium",
                                   "src_ip": "198.51.100.7", "message": "probe"}],
                      [], "web", "json", "t")
        with mock.patch.object(engine, "BURST_KEEP", 1):
            engine.coalesce_batch(self.conn, self.conn.execute(
                "SELECT id FROM ingest_batches ORDER BY id DESC LIMIT 1").fetchone()[0])
        self.assertEqual(self.conn.execute(
            "SELECT COUNT(*) FROM events WHERE event_type = 'web_scan'").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
