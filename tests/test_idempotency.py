"""Client-batch idempotency: a retried upload must not duplicate events or detection.

The guarantee lives in the engine, so these exercise it directly against an in-memory store. The
HTTP layer only forwards the key; its validation is covered by `BatchIdValidationTests`.
"""

import sqlite3
import unittest

from watchpost import engine, server
from watchpost.db import connect, init_schema


def failure(offset):
    """One auth failure; twelve of them from one IP in the same window trip `brute_force_ip`."""
    return {"ts": f"2026-10-03T10:00:{offset:02d}.000Z", "source": "web01-auth",
            "event_type": "auth_failure", "severity": "medium", "outcome": "failure",
            "user": "admin", "src_ip": "203.0.113.9", "message": f"Failed password ({offset})"}


class IdempotentIngestTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)

    def tearDown(self):
        self.conn.close()

    def rows(self, table):
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def test_a_replay_returns_the_original_acknowledgement(self):
        events = [failure(i) for i in range(3)]
        first = engine.ingest(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-a")
        self.assertNotIn("duplicate", first)
        second = engine.ingest(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-a")
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["batch_id"], "batch-a")
        self.assertEqual((second["accepted"], second["received"]),
                         (first["accepted"], first["received"]))
        self.assertEqual(self.rows("events"), 3)          # not 6
        self.assertEqual(self.rows("ingest_batches"), 1)

    def test_a_replay_does_not_repeat_detection(self):
        events = [failure(i) for i in range(12)]          # brute_force_ip needs 10 in 300 s
        engine.ingest(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-b")
        alerts, links = self.rows("alerts"), self.rows("alert_events")
        self.assertGreater(alerts, 0, "the fixture must actually trip a rule")
        engine.ingest(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-b")
        self.assertEqual((self.rows("alerts"), self.rows("alert_events")), (alerts, links))

    def test_without_a_key_every_submission_stores_a_batch(self):
        """The historical behaviour must be preserved for callers that send no key."""
        events = [failure(0)]
        engine.ingest(self.conn, events, [], "web01-auth", "json", "tester")
        engine.ingest(self.conn, events, [], "web01-auth", "json", "tester")
        self.assertEqual(self.rows("events"), 2)
        self.assertEqual(self.rows("ingest_batches"), 2)

    def test_a_new_key_stores_the_same_payload_again(self):
        """Content is not the key: identical lines can legitimately be separate events."""
        events = [failure(0)]
        engine.ingest(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-c")
        engine.ingest(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-d")
        self.assertEqual(self.rows("events"), 2)

    def test_committed_but_unacknowledged_is_safe_to_retry(self):
        """The crash window: the batch committed, then the process died before acknowledging."""
        events = [failure(0), failure(1)]
        engine.store_batch(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-e")
        self.assertEqual(self.rows("events"), 2)
        retry = engine.ingest(self.conn, events, [], "web01-auth", "json", "tester", batch_id="batch-e")
        self.assertTrue(retry["duplicate"])
        self.assertEqual(self.rows("events"), 2)          # the retry added nothing

    def test_a_failed_insert_leaves_neither_events_nor_a_batch(self):
        """Events and the batch row share one transaction, so a failure stores nothing at all."""
        broken = [{"ts": None, "source": "s", "event_type": "other", "severity": "info"}]
        with self.assertRaises(sqlite3.IntegrityError):
            engine.store_batch(self.conn, broken, [], "s", "json", "tester", batch_id="batch-f")
        self.assertEqual(self.rows("events"), 0)
        self.assertEqual(self.rows("ingest_batches"), 0)
        self.assertIsNone(engine.stored_batch(self.conn, "batch-f"))


class BatchIdValidationTests(unittest.TestCase):
    class Req:
        def __init__(self, query=None, headers=None):
            self.query = query or {}
            self.headers = headers or {}

    def test_a_valid_id_is_returned_from_either_place(self):
        self.assertEqual(server._batch_id(self.Req({"batch_id": "abc-123"})), "abc-123")
        self.assertEqual(server._batch_id(self.Req(headers={"Idempotency-Key": "hdr-1"})), "hdr-1")

    def test_absent_or_blank_is_none(self):
        self.assertIsNone(server._batch_id(self.Req()))
        self.assertIsNone(server._batch_id(self.Req({"batch_id": "   "})))

    def test_bad_values_are_rejected(self):
        for bad in ["x" * 65, "has space", "semi;colon", "new\nline"]:
            with self.subTest(bad=bad):
                with self.assertRaises(server.ApiError) as ctx:
                    server._batch_id(self.Req({"batch_id": bad}))
                self.assertEqual(ctx.exception.status, 400)


if __name__ == "__main__":
    unittest.main()
