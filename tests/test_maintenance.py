"""Tests for the admin log-data reset (watchpost/maintenance.py and its two routes).

The whole point of the feature is that it is *narrow*: it destroys ingested data and nothing else.
So the tests concentrate on what survives — rules, accounts, sessions, tokens, settings, the audit
log — as much as on what is deleted.
"""

import json
import unittest

from tests.helpers import ServerTestCase
from watchpost import auth, engine, improve, maintenance, normalize, rules
from watchpost.db import connect, init_schema, iso, utcnow


class ClassificationTests(unittest.TestCase):
    def test_every_table_is_classified_as_log_or_kept(self):
        """A new table must be placed deliberately, or a reset silently leaves data behind."""
        conn = connect(":memory:")
        init_schema(conn)
        present = {row["name"] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        conn.close()

        logs, kept = set(maintenance.LOG_TABLES), set(maintenance.KEPT_TABLES)
        self.assertEqual(logs & kept, set(), "a table cannot be both cleared and kept")
        self.assertEqual(present - (logs | kept), set(), "unclassified table(s)")
        self.assertEqual((logs | kept) - present, set(), "classified table(s) that do not exist")
        self.assertEqual(len(present), len(logs) + len(kept), "every schema table is covered once")


class ResetTests(unittest.TestCase):
    """Reset behaviour against a real (in-memory) schema, seeded by the real ingest path."""

    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)
        engine.seed_rules(self.conn)
        improve.seed_settings(self.conn)
        auth.create_user(self.conn, "admin", "admin-test-password-1", "admin")
        self.token = auth.create_api_token(self.conn, "web01-agent", "admin")
        self.ship_failures()
        self.fill_remaining_tables()

    def tearDown(self):
        self.conn.close()

    def ship_failures(self):
        """Twelve failed logins, so detection really creates an alert with evidence."""
        stamp = iso(utcnow())
        text = json.dumps([{"ts": stamp, "event_type": "auth_failure", "user": "admin", "host": "web01",
                            "src_ip": "203.0.113.5"} for _ in range(12)])
        events, rejections = normalize.parse_payload(text, "json", "web01-auth")
        engine.ingest(self.conn, events, rejections, "web01-auth", "json", "token:web01-agent")

    def fill_remaining_tables(self):
        """Populate the log tables the ingest path does not reach directly.

        Alerts, evidence, activity, incidents and incident_alerts are left to the real ingest path:
        twelve failures from one IP trip two rules whose evidence shares an IP and an account, so
        correlation builds an incident on its own. `test_every_log_table_is_populated_before_the_reset`
        fails if that ever stops being true, which is the point.
        """
        alert_id = self.conn.execute("SELECT id FROM alerts").fetchone()[0]
        now = iso(utcnow())
        self.conn.execute("INSERT INTO alert_notes(alert_id, author, body, created_at) VALUES (?,?,?,?)",
                          (alert_id, "analyst", "investigating", now))
        self.conn.execute("INSERT INTO error_log(created_at, component, message, guidance)"
                          " VALUES (?, 'ingestion', 'boom', 'retry')", (now,))

    def rows(self, table):
        return self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]

    def test_every_log_table_is_populated_before_the_reset(self):
        """Guards the test itself: an empty table would make a cleared table meaningless."""
        empty = [name for name in maintenance.LOG_TABLES if not self.rows(name)]
        self.assertEqual(empty, [], f"test setup left these empty: {empty}")

    def test_reset_empties_every_log_table(self):
        maintenance.reset_logs(self.conn, "admin")
        remaining = {name: self.rows(name) for name in maintenance.LOG_TABLES if self.rows(name)}
        self.assertEqual(remaining, {}, "log data survived the reset")

    def test_reset_keeps_configuration_and_credentials(self):
        # The audit log is kept but grows: the reset records itself. Everything else is untouched.
        kept = [name for name in maintenance.KEPT_TABLES if name != "audit_log"]
        before = {name: self.rows(name) for name in kept}
        before_audit = self.rows("audit_log")
        maintenance.reset_logs(self.conn, "admin")
        after = {name: self.rows(name) for name in kept}
        self.assertEqual(after, before, "the reset changed configuration or credentials")
        self.assertEqual(self.rows("audit_log"), before_audit + 1, "the reset must be recorded")
        self.assertEqual(after["rules"], len(rules.DEFAULT_RULES))
        self.assertEqual(after["api_tokens"], 1, "the agent's token must survive")
        self.assertEqual(after["users"], 1)
        self.assertGreater(after["settings"], 0)

    def test_reset_reports_what_it_removed(self):
        result = maintenance.reset_logs(self.conn, "admin")
        self.assertEqual(result["removed_total"], sum(result["removed"].values()))
        self.assertGreater(result["removed"]["events"], 0)
        self.assertGreater(result["removed"]["alerts"], 0)
        self.assertIn("rules", result["kept_tables"])
        self.assertTrue(result["vacuumed"])

    def test_reset_is_audited_because_the_data_it_removed_is_gone(self):
        maintenance.reset_logs(self.conn, "analyst")
        row = self.conn.execute("SELECT actor, action, detail FROM audit_log"
                                " ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual((row["actor"], row["action"]), ("analyst", "logs_reset"))
        self.assertGreater(json.loads(row["detail"])["removed"]["events"], 0)

    def test_a_second_reset_removes_nothing(self):
        maintenance.reset_logs(self.conn, "admin")
        second = maintenance.reset_logs(self.conn, "admin")
        self.assertEqual(second["removed_total"], 0)

    def test_preview_changes_nothing(self):
        before = {name: self.rows(name) for name in maintenance.LOG_TABLES}
        preview = maintenance.preview(self.conn)
        self.assertEqual({name: self.rows(name) for name in maintenance.LOG_TABLES}, before)
        self.assertEqual(preview["total"], sum(before.values()))
        self.assertEqual(set(preview["counts"]), set(maintenance.LOG_TABLES))

    def test_ids_restart_after_a_reset(self):
        maintenance.reset_logs(self.conn, "admin")
        self.assertEqual(self.rows("events"), 0)
        self.ship_failures()
        lowest = self.conn.execute("SELECT MIN(id) FROM events").fetchone()[0]
        self.assertEqual(lowest, 1, "a fresh store should start again at id 1")


class LogDataApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.client("admin")
        status, minted, _ = self.admin.post("/api/tokens", {"name": "web01-agent"})
        self.assertEqual(status, 201)
        self.token = minted["token"]
        stamp = iso(utcnow())
        lines = "".join(f"{stamp} web01 sshd[1]: Failed password for admin from 203.0.113.5 "
                        f"port {4000 + i} ssh2\n" for i in range(12))
        status, body, _ = self.client().post("/api/ingest/upload?format=authlog&source=web01-auth",
                                            raw=lines.encode(),
                                            headers={"Authorization": f"Bearer {self.token}",
                                                     "Content-Type": "text/plain"}, csrf=False)
        self.assertEqual(status, 201)
        self.assertEqual(body["accepted"], 12)

    def ship_again(self):
        stamp = iso(utcnow())
        line = f"{stamp} web01 sshd[2]: Failed password for dave from 203.0.113.9 port 5000 ssh2\n"
        return self.client().post("/api/ingest/upload?format=authlog&source=web01-auth",
                                  raw=line.encode(),
                                  headers={"Authorization": f"Bearer {self.token}",
                                           "Content-Type": "text/plain"}, csrf=False)

    def test_preview_reports_what_a_reset_would_remove(self):
        status, data, _ = self.admin.get("/api/admin/log-data")
        self.assertEqual(status, 200)
        self.assertEqual(set(data["counts"]), set(maintenance.LOG_TABLES))
        self.assertEqual(data["total"], sum(data["counts"].values()))
        self.assertGreater(data["counts"]["events"], 0)
        self.assertGreater(data["counts"]["alerts"], 0)
        self.assertIn("rules", data["kept_tables"])
        self.assertIn("api_tokens", data["kept_tables"])

    def test_reset_needs_the_confirmation_word(self):
        for payload in ({}, {"confirm": "yes"}, {"confirm": "reset"}):
            with self.subTest(payload=payload):
                status, _, _ = self.admin.post("/api/admin/log-data/reset", payload)
                self.assertEqual(status, 400)
        viewer = self.client("viewer")
        self.assertGreater(viewer.get("/api/events?limit=1")[1]["total"], 0, "nothing was deleted")

    def test_reset_clears_logs_and_keeps_everything_else(self):
        status, result, _ = self.admin.post("/api/admin/log-data/reset", {"confirm": "RESET"})
        self.assertEqual(status, 200)
        self.assertGreater(result["removed_total"], 0)

        self.assertEqual(self.admin.get("/api/events?limit=1")[1]["total"], 0)
        self.assertEqual(self.admin.get("/api/alerts")[1], [])
        self.assertEqual(self.admin.get("/api/incidents")[1], [])
        self.assertEqual(self.admin.get("/api/ingest/batches")[1], [])

        self.assertEqual(len(self.admin.get("/api/rules")[1]), 13, "rules must survive")
        self.assertEqual(self.admin.get("/api/auth/me")[0], 200, "the session must survive")
        self.assertEqual(len(self.admin.get("/api/tokens")[1]), 1, "the token list must survive")

    def test_the_ingest_token_still_works_after_a_reset(self):
        self.admin.post("/api/admin/log-data/reset", {"confirm": "RESET"})
        status, body, _ = self.ship_again()
        self.assertEqual(status, 201, "an agent must not start failing with 401 after a reset")
        self.assertEqual(body["accepted"], 1)
        self.assertEqual(self.admin.get("/api/events?limit=5")[1]["total"], 1)

    def test_the_reset_is_recorded_in_the_audit_log(self):
        self.admin.post("/api/admin/log-data/reset", {"confirm": "RESET"})
        audit = self.admin.get("/api/audit")[1]
        entry = next((a for a in audit if a["action"] == "logs_reset"), None)
        self.assertIsNotNone(entry, "a wipe must be auditable")
        self.assertEqual(entry["actor"], "admin")
        self.assertGreater(json.loads(entry["detail"])["removed"]["events"], 0)

    def test_only_an_admin_may_reset(self):
        for who in ("analyst", "viewer"):
            client = self.client(who)
            status, _, _ = client.post("/api/admin/log-data/reset", {"confirm": "RESET"})
            self.assertEqual(status, 403, f"{who} must not be able to wipe the store")
            self.assertEqual(client.get("/api/admin/log-data")[0], 403)
        self.assertEqual(self.client().post("/api/admin/log-data/reset", {"confirm": "RESET"})[0], 401)
        self.assertGreater(self.admin.get("/api/events?limit=1")[1]["total"], 0, "nothing was deleted")

    def test_a_cleared_store_is_healthy_afterwards(self):
        self.admin.post("/api/admin/log-data/reset", {"confirm": "RESET"})
        status, health, _ = self.admin.get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["checks"]["detection"], "ok")


if __name__ == "__main__":
    unittest.main()
