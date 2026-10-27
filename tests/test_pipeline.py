"""Pipeline stage counters, the rollup read side, and the bounded quarantine.

All in-memory: nothing here needs a filesystem, so these tests run everywhere.
"""

import os
import unittest
from unittest import mock

from watchpost import engine, pipeline, quarantine, server
from watchpost.db import connect, init_schema
from watchpost.normalize import parse_payload


def event(i, event_type="auth_failure"):
    return {"ts": f"2026-10-03T10:00:{i:02d}.000Z", "source": "src", "event_type": event_type,
            "severity": "medium", "src_ip": "203.0.113.9", "user": "admin", "message": f"e{i}"}


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def add(self, count=1, record=None):
        rejections = [{"index": i, "reason": "bad line", "record": record} for i in range(count)]
        return quarantine.add_many(self.conn, "web01-web", "b1", rejections, cap=count)

    def test_rejections_are_recorded_with_reason_and_position(self):
        self.add(3)
        rows = quarantine.recent(self.conn)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0]["reason"], "bad line")
        self.assertEqual(rows[0]["source"], "web01-web")
        self.assertIn(rows[0]["record_index"], (0, 1, 2))
        self.assertIsNone(rows[0]["record"], "content is not kept by default")

    def test_the_per_batch_cap_is_honoured(self):
        rejections = [{"index": i, "reason": "bad line"} for i in range(100)]
        self.assertEqual(quarantine.add_many(self.conn, "web01-web", "b1", rejections),
                         quarantine.PER_BATCH_CAP)
        self.assertEqual(quarantine.stats(self.conn)["count"], quarantine.PER_BATCH_CAP)

    def test_the_row_ceiling_keeps_the_newest(self):
        with mock.patch.dict(os.environ, {"SIEM_QUARANTINE_ROWS": "3"}):
            self.add(5)
            stats = quarantine.stats(self.conn)
        self.assertEqual(stats["count"], 3)
        self.assertEqual(stats["max_rows"], 3)

    def test_the_ttl_drops_old_records(self):
        self.conn.execute(
            "INSERT INTO quarantine(received_at, source, reason) VALUES ('2020-01-01T00:00:00.000Z',"
            " 'old', 'predates the ttl')")
        removed = quarantine.prune(self.conn, max_rows=10000, ttl_hours=1)
        self.assertEqual(removed, 1)
        self.assertEqual(quarantine.stats(self.conn)["count"], 0)

    def test_limits_are_configurable(self):
        with mock.patch.dict(os.environ, {"SIEM_QUARANTINE_ROWS": "10",
                                          "SIEM_QUARANTINE_HOURS": "5",
                                          "SIEM_QUARANTINE_RECORDS": "1"}):
            self.assertEqual(quarantine.limits(), (10, 5, True))


class RejectedContentTests(unittest.TestCase):
    """The default must stay privacy-safe: reasons yes, content no."""

    def test_content_is_not_kept_by_default(self):
        events, rejections = parse_payload("not a log line\n", "authlog", "src")
        self.assertEqual(events, [])
        self.assertEqual(len(rejections), 1)
        self.assertNotIn("record", rejections[0])
        self.assertTrue(rejections[0]["reason"])

    def test_content_is_kept_when_asked_for_and_is_scrubbed(self):
        line = 'Failed password for admin from 10.0.0.1  password=hunter2  ' + "x" * 400
        events, rejections = parse_payload(line + "\n", "authlog", "src", keep_rejected=True)
        self.assertEqual(events, [])
        snippet = rejections[0]["record"]
        self.assertLessEqual(len(snippet), 160)
        self.assertNotIn("hunter2", snippet, "secrets must be redacted before quarantine")


class PipelineStageTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_each_stage_counts_its_own_thing(self):
        engine.ingest(self.conn, [event(i) for i in range(3)],
                      [{"index": 9, "reason": "bad line"}], "src", "json", "t")
        stages = pipeline.stages(self.conn)
        self.assertEqual((stages["observed"], stages["accepted"], stages["rejected"]), (4, 3, 1))
        self.assertEqual(stages["observed"], stages["accepted"] + stages["rejected"])
        self.assertEqual(stages["stored"], 3)
        self.assertEqual(stages["quarantined"], 1)
        self.assertEqual(stages["batches"], 1)
        self.assertIn("not interchangeable", stages["note"])

    def test_detected_counts_alerts_not_events(self):
        engine.ingest(self.conn, [event(i) for i in range(12)], [], "src", "json", "t")
        stages = pipeline.stages(self.conn)
        self.assertEqual(stages["stored"], 12)
        self.assertGreaterEqual(stages["detected"], 1)
        self.assertNotEqual(stages["detected"], stages["stored"])

    def test_aggregated_counts_rolled_up_events(self):
        self.conn.execute(
            "INSERT INTO event_rollups(bucket_start, event_type, source, host, outcome, severity,"
            " events, first_seen, last_seen) VALUES ('2026-10-03T10:00:00.000Z', 'web_request',"
            " 'web', '', '', 'low', 7, '2026-10-03T10:00:00.000Z', '2026-10-03T10:59:00.000Z')")
        self.assertEqual(pipeline.stages(self.conn)["aggregated"], 7)

    def seed_bucket(self, hours_ago, count):
        from datetime import datetime, timedelta, timezone
        from watchpost.db import iso
        bucket = iso(datetime.now(timezone.utc) - timedelta(hours=hours_ago))
        self.conn.execute(
            "INSERT INTO event_rollups(bucket_start, event_type, source, host, outcome, severity,"
            " events, first_seen, last_seen) VALUES (?, 'web_request', 'web', '', '', 'low', ?, ?, ?)",
            (bucket, count, bucket, bucket))

    def test_rollups_read_is_bounded_by_hours(self):
        self.seed_bucket(1, 5)
        self.seed_bucket(24 * 100, 9)          # 100 days old
        recent = pipeline.rollups(self.conn, hours=24)
        self.assertEqual(recent["buckets"], 1)
        self.assertEqual(recent["total_events"], 5)
        clamped = pipeline.rollups(self.conn, hours=24 * 365 * 3)
        self.assertEqual(clamped["hours"], 24 * 90, "the read is capped at 90 days on purpose")
        self.assertEqual(clamped["buckets"], 1, "the 100-day-old bucket is still out of range")

    def test_rollup_hours_are_clamped(self):
        self.assertEqual(pipeline.rollups(self.conn, hours=0)["hours"], 1)
        self.assertEqual(pipeline.rollups(self.conn, hours="nonsense")["hours"], 24)
        self.assertEqual(pipeline.rollups(self.conn, hours=24 * 365 * 3)["hours"], 24 * 90)


class RouteRoleTests(unittest.TestCase):
    def roles(self):
        return {pattern.pattern: role for _method, pattern, _fn, role, _csrf in server.ROUTES}

    def test_pipeline_views_are_readable_and_quarantine_is_admin_only(self):
        roles = self.roles()
        self.assertEqual(roles["^/api/pipeline$"], "viewer")
        self.assertEqual(roles["^/api/rollups$"], "viewer")
        self.assertEqual(roles["^/api/admin/quarantine$"], "admin")


if __name__ == "__main__":
    unittest.main()
