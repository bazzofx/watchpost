"""Tests for the agents view (watchpost/agents.py and GET /api/agents).

An "agent" is an ingest token plus the batches it sent, so most of this is exercised against an
in-memory database with hand-built rows, which needs no temporary directory and no server.
"""

import unittest
from datetime import timedelta

from tests.helpers import ServerTestCase
from watchpost import agents
from watchpost.db import connect, init_schema, iso, utcnow

NOW = utcnow()


def ago(**kwargs):
    return iso(NOW - timedelta(**kwargs))


def add_token(conn, name, created_at=None, revoked_at=None, last_used_at=None, prefix="wp_abc"):
    conn.execute(
        "INSERT INTO api_tokens(name, token_hash, prefix, created_by, created_at, last_used_at, revoked_at)"
        " VALUES (?,?,?,?,?,?,?)",
        (name, f"hash-{name}", prefix, "admin", created_at or ago(minutes=30), last_used_at, revoked_at))


def add_batch(conn, token_name, source, created_at=None, accepted=1, rejected=0, fmt="authlog",
              detection_status="ok"):
    batch_id = f"{token_name}-{source}-{created_at or 'now'}"
    conn.execute(
        "INSERT INTO ingest_batches(id, created_at, source, format, received, accepted, rejected, errors,"
        " synthetic, submitted_by, detection_status) VALUES (?,?,?,?,?,?,?,'[]',0,?,?)",
        (batch_id, created_at or iso(NOW), source, fmt, accepted + rejected, accepted, rejected,
         f"token:{token_name}", detection_status))
    return batch_id


def add_event(conn, batch_id, source, host="web01", ts=None):
    conn.execute(
        "INSERT INTO events(ts, ingested_at, source, host, event_type, severity, synthetic, batch_id)"
        " VALUES (?,?,?,?,'auth_failure','low',0,?)",
        (ts or iso(NOW), iso(NOW), source, host, batch_id))


class CommonPrefixTests(unittest.TestCase):
    def test_shared_host_prefix_is_extracted(self):
        self.assertEqual(agents._common_prefix(["web01-auth", "web01-firewall", "web01-web"]), "web01")

    def test_a_single_source_has_no_prefix_to_strip(self):
        self.assertEqual(agents._common_prefix(["web01-auth"]), "")

    def test_no_shared_separator_means_no_prefix(self):
        self.assertEqual(agents._common_prefix(["web01auth", "web01firewall"]), "")

    def test_empty_input(self):
        self.assertEqual(agents._common_prefix([]), "")


class AgentPrefixTests(unittest.TestCase):
    """The prefix decides whether the UI shows "auth" or "web01-auth" as the captured log."""

    @staticmethod
    def entries(*sources):
        return [{"source": name} for name in sources]

    def test_two_sources_reveal_the_prefix(self):
        self.assertEqual(agents._agent_prefix(self.entries("web01-auth", "web01-web"), None), "web01")

    def test_a_single_source_uses_the_reported_hostname(self):
        self.assertEqual(agents._agent_prefix(self.entries("web01-auth"), "web01"), "web01")

    def test_a_source_that_does_not_match_the_hostname_is_left_alone(self):
        """--source-prefix can differ from the hostname; then nothing is stripped."""
        self.assertEqual(agents._agent_prefix(self.entries("custom-auth"), "web01"), "")

    def test_an_unknown_hostname_strips_nothing(self):
        self.assertEqual(agents._agent_prefix(self.entries("web01-auth"), None), "")

    def test_no_sources(self):
        self.assertEqual(agents._agent_prefix([], "web01"), "")


class StatusTests(unittest.TestCase):
    def check(self, last_batch_at, revoked_at=None):
        return agents._status(revoked_at, last_batch_at, 600, 3600, NOW)

    def test_recent_batch_is_reporting(self):
        self.assertEqual(self.check(ago(minutes=2)), "reporting")

    def test_between_the_thresholds_is_quiet(self):
        self.assertEqual(self.check(ago(minutes=30)), "quiet")

    def test_older_than_the_quiet_window_is_silent(self):
        self.assertEqual(self.check(ago(hours=5)), "silent")

    def test_no_batches_is_never_reported(self):
        self.assertEqual(self.check(None), "never_reported")

    def test_revoked_wins_over_activity(self):
        self.assertEqual(self.check(ago(minutes=1), revoked_at=ago(minutes=1)), "revoked")


class OverviewTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")
        init_schema(self.conn)

    def tearDown(self):
        self.conn.close()

    def test_agent_row_is_derived_from_its_batches(self):
        add_token(self.conn, "web01-agent")
        add_event(self.conn, add_batch(self.conn, "web01-agent", "web01-auth", accepted=11),
                  "web01-auth")
        add_event(self.conn, add_batch(self.conn, "web01-agent", "web01-firewall", fmt="authlog"),
                  "web01-firewall")

        report = agents.overview(self.conn)
        agent = report["agents"][0]
        self.assertEqual(agent["name"], "web01-agent")
        self.assertEqual(agent["hostname"], "web01", "hostname comes from the events the agent sent")
        self.assertEqual([s["kind"] for s in agent["sources"]], ["auth", "firewall"])
        self.assertEqual(agent["status"], "reporting")
        self.assertEqual(agent["source_count"], 2)
        self.assertEqual(agent["events"], 2)
        self.assertEqual(agent["batches"], 2)
        self.assertEqual(report["summary"]["total"], 1)
        self.assertEqual(report["summary"]["reporting"], 1)

    def test_a_single_source_still_shows_its_short_name(self):
        """Regression: the short name ("auth") needs the prefix even when the agent reports
        only one source, which is the common case for a minimal install."""
        add_token(self.conn, "solo-agent")
        add_event(self.conn, add_batch(self.conn, "solo-agent", "web01-auth"), "web01-auth")
        agent = agents.overview(self.conn)["agents"][0]
        self.assertEqual([s["kind"] for s in agent["sources"]], ["auth"])

    def test_a_custom_source_prefix_is_not_stripped(self):
        """With --source-prefix the source need not start with the hostname, so keep it whole."""
        add_token(self.conn, "custom-agent")
        add_event(self.conn, add_batch(self.conn, "custom-agent", "custom-auth"), "custom-auth")
        agent = agents.overview(self.conn)["agents"][0]
        self.assertEqual([s["kind"] for s in agent["sources"]], ["custom-auth"])
        self.assertEqual(agent["hostname"], "web01", "the hostname still comes from the events")

    def test_unused_token_is_never_reported_and_has_no_host(self):
        add_token(self.conn, "unused-agent")
        agent = agents.overview(self.conn)["agents"][0]
        self.assertEqual(agent["status"], "never_reported")
        self.assertIsNone(agent["hostname"])
        self.assertEqual(agent["sources"], [])
        self.assertIsNone(agent["last_batch_at"])

    def test_revoked_token_is_flagged(self):
        add_token(self.conn, "old-agent", revoked_at=ago(minutes=5))
        add_event(self.conn, add_batch(self.conn, "old-agent", "web01-auth"), "web01-auth")
        self.assertEqual(agents.overview(self.conn)["agents"][0]["status"], "revoked")

    def test_quiet_and_silent_are_distinguished(self):
        add_token(self.conn, "quiet-agent")
        add_event(self.conn, add_batch(self.conn, "quiet-agent", "web01-auth",
                                       created_at=ago(minutes=40)), "web01-auth")
        add_token(self.conn, "silent-agent")
        add_event(self.conn, add_batch(self.conn, "silent-agent", "db01-auth",
                                       created_at=ago(hours=9)), "db01-auth", host="db01")

        report = agents.overview(self.conn)
        found = {a["name"]: a["status"] for a in report["agents"]}
        self.assertEqual(found, {"silent-agent": "silent", "quiet-agent": "quiet"})
        self.assertEqual(report["summary"]["silent"], 1)
        self.assertEqual(report["summary"]["quiet"], 1)

    def test_batches_not_sent_with_a_token_are_not_agents(self):
        """UI uploads and the demo loader are attributed to a username, not a token."""
        self.conn.execute(
            "INSERT INTO ingest_batches(id, created_at, source, format, received, accepted, rejected,"
            " errors, synthetic, submitted_by, detection_status) VALUES"
            " ('b1',?,'demo:brute_force','json',5,5,0,'[]',1,'admin','ok'),"
            " ('b2',?,'syslog','syslog',5,5,0,'[]',0,'syslog-listener','ok')", (iso(NOW), iso(NOW)))
        self.assertEqual(agents.overview(self.conn)["agents"], [])

    def test_rejected_batches_and_detection_failures_are_surfaced(self):
        add_token(self.conn, "broken-agent")
        add_batch(self.conn, "broken-agent", "web01-auth", accepted=3, rejected=2,
                  detection_status="failed")
        agent = agents.overview(self.conn)["agents"][0]
        self.assertEqual(agent["rejected"], 2)
        self.assertEqual(agent["detection_failures"], 1)

    def test_installed_at_comes_from_the_token(self):
        add_token(self.conn, "dated-agent", created_at=ago(days=3))
        agent = agents.overview(self.conn)["agents"][0]
        self.assertEqual(agent["installed_at"], ago(days=3))
        self.assertEqual(agent["installed_by"], "admin")

    def test_custom_thresholds_are_reported_back(self):
        report = agents.overview(self.conn, reporting_seconds=60, quiet_seconds=120)
        self.assertEqual(report["reporting_seconds"], 60)
        self.assertEqual(report["quiet_seconds"], 120)

    def test_thresholds_helper_reads_as_a_sentence(self):
        text = agents.stale_thresholds()
        self.assertIn("reporting", text)
        self.assertIn("silent", text)


class AgentsApiTests(ServerTestCase):
    def setUp(self):
        super().setUp()
        admin = self.client("admin")
        status, minted, _ = admin.post("/api/tokens", {"name": "web01-agent"})
        self.assertEqual(status, 201)
        self.token = minted["token"]

    def _ship_like_the_agent(self, source, text, fmt="authlog"):
        """POST the way scripts/agent.py does: raw lines to /api/ingest/upload with a token."""
        client = self.client()
        return client.post(f"/api/ingest/upload?format={fmt}&source={source}", raw=text.encode(),
                           headers={"Authorization": f"Bearer {self.token}",
                                    "Content-Type": "text/plain"}, csrf=False)

    def test_agents_route_lists_a_reporting_agent(self):
        stamp = iso(utcnow())
        status, body, _ = self._ship_like_the_agent("web01-auth",
            f"{stamp} web01 sshd[12]: Failed password for invalid user admin from 203.0.113.5 port 4001 ssh2\n"
            f"{stamp} web01 sshd[13]: Accepted publickey for dave from 203.0.113.6 port 4002 ssh2: RSA\n")
        self.assertEqual(status, 201)
        self.assertEqual(body["accepted"], 2)

        viewer = self.client("viewer")
        status, report, _ = viewer.get("/api/agents")
        self.assertEqual(status, 200, "viewers may read the fleet, like other read routes")
        self.assertEqual(report["summary"]["total"], 1)
        agent = report["agents"][0]
        self.assertEqual(agent["name"], "web01-agent")
        self.assertEqual(agent["hostname"], "web01")
        self.assertEqual(agent["status"], "reporting")
        self.assertEqual(agent["events"], 2)
        self.assertEqual([s["kind"] for s in agent["sources"]], ["auth"])
        self.assertEqual(agent["sources"][0]["formats"], ["authlog"])
        self.assertEqual(agent["installed_by"], "admin")
        self.assertIsNotNone(agent["installed_at"])
        self.assertIsNotNone(agent["last_batch_at"])
        self.assertEqual(report["summary"]["events"], 2)
        self.assertEqual(report["summary"]["batches"], 1)

    def test_several_sources_appear_as_separate_log_types(self):
        stamp = iso(utcnow())
        self._ship_like_the_agent("web01-auth",
                                  f"{stamp} web01 sshd[12]: Failed password for root from 203.0.113.5 port 4001 ssh2\n")
        self._ship_like_the_agent("web01-firewall",
                                  f"{stamp} web01 kernel: [1.2] [UFW BLOCK] IN=eth0 SRC=192.168.8.50 "
                                  f"DST=192.168.8.178 LEN=60 PROTO=TCP SPT=44 DPT=22\n")
        self._ship_like_the_agent("web01-web",
                                  '192.0.2.10 - - [03/Oct/2026:08:50:02 +0000] "GET /.env HTTP/1.1" '
                                  '404 162 "-" "curl/8.5.0"\n', fmt="weblog")

        viewer = self.client("viewer")
        _, report, _ = viewer.get("/api/agents")
        agent = report["agents"][0]
        self.assertEqual([s["kind"] for s in agent["sources"]], ["auth", "firewall", "web"])
        self.assertEqual(agent["source_count"], 3)
        formats = {s["kind"]: s["formats"] for s in agent["sources"]}
        self.assertEqual(formats["web"], ["weblog"])
        self.assertEqual(formats["auth"], ["authlog"])

    def test_agents_route_is_empty_before_any_agent_reports(self):
        viewer = self.client("viewer")
        status, report, _ = viewer.get("/api/agents")
        self.assertEqual(status, 200)
        self.assertEqual(report["summary"]["total"], 1, "the token exists as an installed agent")
        self.assertEqual(report["agents"][0]["status"], "never_reported")
        self.assertEqual(report["agents"][0]["events"], 0)

    def test_anonymous_access_is_refused(self):
        status, _, _ = self.client().get("/api/agents")
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
