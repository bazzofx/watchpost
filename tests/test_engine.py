"""Engine-level tests: how a detection run reads events, and what it holds while doing so.

These are the regression guards for the "database is locked" report. Two properties matter:

1. A rule reads only its own window. Previously one global window — the longest lookback plus the
   longest history, about 30 hours — was read and handed to every rule, so a 300-second rule cost
   the same as a 24-hour one and the cost of an ingest grew with the whole store.
2. Rules are evaluated *before* a write transaction is opened. They are pure Python over possibly
   large event lists, and holding SQLite's single writer lock for that whole time is what made
   unrelated requests fail.
"""

import json
import os
import random
import sqlite3
import tempfile
import unittest
from datetime import timedelta

from watchpost import engine, normalize, rules as rules_mod, simulate
from watchpost.db import connect, init_schema, iso, utcnow


class _Detector(unittest.TestCase):
    """A file-backed store, because lock behaviour needs two connections to the same database."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.db")
        self.conn = connect(self.db_path)
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        self.rules = {r["id"]: r for r in engine.load_rules(self.conn)}

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def add_event(self, minutes_ago, event_type="auth_failure", user="admin", src_ip="203.0.113.5"):
        cur = self.conn.execute(
            "INSERT INTO events(ts, ingested_at, source, event_type, severity, user, src_ip, synthetic)"
            " VALUES (?,?,?,?,'low',?,?,0)",
            (iso(utcnow() - timedelta(minutes=minutes_ago)), iso(utcnow()), "web01-auth", event_type,
             user, src_ip))
        return cur.lastrowid

    def max_id(self):
        return self.conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]

    def scan(self, rule_id, start, end):
        events, scan_start = engine._rule_scan(self.conn, self.rules[rule_id], self.max_id(), start, end)
        return {e["id"] for e in events}, scan_start

    def ingest(self, events, source="web01-auth"):
        text = json.dumps(events)
        parsed, rejections = normalize.parse_payload(text, "json", source)
        return engine.ingest(self.conn, parsed, rejections, source, "json", "tester")


class PerRuleWindowTests(_Detector):
    def setUp(self):
        super().setUp()
        self.now = iso(utcnow())
        self.recent = self.add_event(0)          # at the batch time
        self.hour_ago = self.add_event(60)
        self.day_ago = self.add_event(20 * 60)

    def test_a_short_window_rule_reads_only_its_own_window(self):
        """web_request_burst looks back 60 s: a 20-hour-old event is none of its business."""
        found, _ = self.scan("web_request_burst", self.now, self.now)
        self.assertEqual(found, {self.recent})

    def test_a_medium_window_rule_reaches_back_its_span(self):
        """brute_force_ip spans 300 s, so the event an hour old is still out of reach."""
        found, _ = self.scan("brute_force_ip", self.now, self.now)
        self.assertEqual(found, {self.recent})

    def test_a_wide_window_rule_reaches_further(self):
        """impossible_geo_login spans 6 h, so the event an hour ago is included."""
        found, _ = self.scan("impossible_geo_login", self.now, self.now)
        self.assertEqual(found, {self.recent, self.hour_ago})

    def test_a_history_rule_reaches_back_its_history_too(self):
        """cloud_iam_change_by_new_principal needs 24 h of history before its window."""
        found, _ = self.scan("cloud_iam_change_by_new_principal", self.now, self.now)
        self.assertEqual(found, {self.recent, self.hour_ago, self.day_ago})

    def test_a_full_scan_still_reads_everything(self):
        events, scan_start = engine._rule_scan(
            self.conn, self.rules["web_request_burst"], self.max_id(), None, None)
        self.assertEqual({e["id"] for e in events}, {self.recent, self.hour_ago, self.day_ago})
        self.assertIsNone(scan_start)

    def test_the_scan_start_marks_where_history_context_begins(self):
        _, scan_start = self.scan("brute_force_ip", self.now, self.now)
        self.assertIsNotNone(scan_start)
        self.assertLess(scan_start, self.now)


class DetectionUnderLoadTests(_Detector):
    def test_events_scanned_counts_distinct_events_not_work_per_rule(self):
        """Thirteen rules reading the same twelve events is twelve events, not a hundred and fifty-six."""
        stamp = iso(utcnow())
        result = self.ingest([{"ts": stamp, "event_type": "auth_failure", "user": "admin",
                               "src_ip": "203.0.113.5"} for _ in range(12)])
        self.assertEqual(result["detection"]["events_scanned"], 12)

    def test_rules_are_evaluated_without_holding_the_write_lock(self):
        """A second connection must be able to write while rules are running.

        Regression: the rules used to execute inside the write transaction, so a slow rule held
        SQLite's single writer lock for seconds and unrelated requests failed with
        "database is locked". The probe below writes with busy_timeout = 0, so if the lock were held
        it fails immediately instead of waiting.
        """
        observed = {}

        def probe(events, params):
            other = connect(self.db_path)
            try:
                other.execute("PRAGMA busy_timeout = 0")
                other.execute("INSERT OR REPLACE INTO health_probe(id, written_at) VALUES (1, ?)",
                              (iso(utcnow()),))
                observed["wrote"] = True
            except sqlite3.OperationalError as exc:
                observed["wrote"] = f"blocked: {exc}"
            finally:
                other.close()
            return []

        original = rules_mod.RULE_FUNCTIONS["web_scanner"]
        rules_mod.RULE_FUNCTIONS["web_scanner"] = probe
        try:
            self.ingest([{"ts": iso(utcnow()), "event_type": "auth_failure", "user": "admin",
                          "src_ip": "203.0.113.5"} for _ in range(3)])
        finally:
            rules_mod.RULE_FUNCTIONS["web_scanner"] = original
        self.assertIs(observed.get("wrote"), True, observed)

    def test_ingest_still_detects_after_the_restructure(self):
        """The per-rule windows must not lose findings: twelve failures still trip brute force."""
        stamp = iso(utcnow())
        result = self.ingest([{"ts": stamp, "event_type": "auth_failure", "user": "admin",
                               "src_ip": "203.0.113.5"} for _ in range(12)])
        self.assertEqual(result["detection"]["status"], "ok")
        self.assertGreater(result["detection"]["alerts_created"], 0)
        self.assertGreater(self.conn.execute("SELECT COUNT(*) FROM alert_events").fetchone()[0], 0)

    def test_a_full_scan_reads_each_event_once(self):
        stamp = iso(utcnow())
        self.ingest([{"ts": stamp, "event_type": "auth_failure", "user": "admin",
                      "src_ip": "203.0.113.5"} for _ in range(5)])
        summary = engine.run_detection(self.conn, trigger="test-full")
        self.assertEqual(summary["events_scanned"], 5)


class ScenarioPathTests(unittest.TestCase):
    """Every labeled scenario must alert through the engine, not only through improve.evaluate().

    Regression: RULE_EVENT_FIELDS did not list `outcome`, so a rule reading it got None. Nothing in
    the evaluation harness could see that — it feeds rules the raw scenario dicts, which carry
    `outcome` themselves, whereas the engine hands rules the projected columns. web_path_discovery
    therefore passed its labeled scenario and never fired on a real ingested event, and a new rule
    reading `outcome` would have been stillborn in exactly the same way. This walks the real path:
    normalize, ingest, detect, read the alerts back.

    An in-memory store is all this needs; nothing here is about files or locking.
    """

    def alerts_for(self, name, spec):
        """{(rule_id, group_key)} raised by ingesting one scenario through the engine."""
        conn = connect(":memory:")
        try:
            init_schema(conn)
            engine.seed_rules(conn)
            events = [normalize.normalize_record(record, f"demo:{name}")
                      for record in spec["build"](simulate.demo_day(), random.Random(7))]
            engine.ingest(conn, events, [], f"demo:{name}", "json", "tester", synthetic=True)
            return {(row["rule_id"], row["group_key"])
                    for row in conn.execute("SELECT rule_id, group_key FROM alerts")}
        finally:
            conn.close()

    def test_every_labeled_scenario_alerts_through_the_engine(self):
        for name, spec in simulate.SCENARIOS.items():
            if not spec["expected"]:
                continue
            with self.subTest(scenario=name):
                by_rule = {}
                for rule_id, group_key in self.alerts_for(name, spec):
                    by_rule.setdefault(rule_id, set()).add(group_key)
                for rule_id, want in spec["expected"].items():
                    self.assertIn(rule_id, by_rule,
                                  f"{name}: {rule_id} raised no alert through the engine "
                                  f"(raised: {sorted(by_rule)})")
                    if want is not None:
                        self.assertIn(want, by_rule[rule_id],
                                      f"{name}: {rule_id} alerted on {sorted(by_rule[rule_id])}, not {want}")


if __name__ == "__main__":
    unittest.main()
