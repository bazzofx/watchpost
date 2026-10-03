"""Tests for scripts/agent.py, the Linux log collection agent.

The agent is a standalone script (it is deployed to log sources that do not have the
watchpost package), so it is loaded here the same way test_live_ingest loads the shipper:
by path. It imports its sibling shipper.py, which is added to sys.path on load.

Most tests are server-free. The checks that matter most are the ones proving the agent and
the server agree on formats: every source's `format` must be one the server accepts, and
every line the agent produces must be accepted by watchpost.normalize.
"""

import importlib.util
import io
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.helpers import ServerTestCase
from watchpost.normalize import FORMATS, parse_payload

ROOT = Path(__file__).resolve().parent.parent
# Committed fixtures: a log root holding auth.log, syslog, and audit/audit.log. Using files
# that already exist keeps these tests free of any runtime temporary directory.
LOGS = ROOT / "tests" / "fixtures" / "logs"

_spec = importlib.util.spec_from_file_location("agent", ROOT / "scripts" / "agent.py")
agent = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(agent)
shipper = agent.shipper

AUDIT_LINE = (b'type=SYSCALL msg=audit(1760000000.123:4567): arch=c000003e syscall=59 success=yes '
              b'exit=0 exe="/usr/bin/id" key="exec"\n')
AUDIT_PATH_LINE = (b'type=PATH msg=audit(1760000000.123:4567): item=0 name="/etc/shadow" inode=1234 '
                   b'dev=08:01 mode=0100640\n')


class CatalogueTests(unittest.TestCase):
    """The source table is data, so it can be validated without a server."""

    def test_every_source_is_well_formed(self):
        for source in agent.SOURCES:
            with self.subTest(source=source["name"]):
                self.assertTrue(source["name"])
                patterns = agent._patterns(source)
                self.assertTrue(patterns, "a source must say what to look for")
                self.assertTrue(source["description"])
                self.assertTrue(source["needs"])
                for relative in patterns:
                    self.assertFalse(relative.startswith("/"),
                                     "patterns must be relative to --log-dir, not absolute")

    def test_source_names_are_unique(self):
        names = [source["name"] for source in agent.SOURCES]
        self.assertEqual(sorted(names), sorted(set(names)))

    def test_formats_are_ones_the_server_accepts(self):
        """Consistency with the application: never send a format the server rejects."""
        for source in agent.SOURCES:
            with self.subTest(source=source["name"]):
                self.assertIn(source["format"], FORMATS)
                for needle, fmt in source.get("filename_formats", ()):
                    self.assertIn(fmt, FORMATS, f"filename rule {needle!r}")
                    self.assertTrue(needle, "a filename rule needs a substring to match")

    def test_every_transform_is_registered(self):
        for source in agent.SOURCES:
            if source.get("transform"):
                with self.subTest(source=source["name"]):
                    self.assertIn(source["transform"], agent.TRANSFORMS)

    def test_overlaps_reference_real_sources(self):
        for source in agent.SOURCES:
            for other in source.get("overlaps", ()):
                with self.subTest(source=source["name"], other=other):
                    self.assertIn(other, agent.SOURCE_NAMES)

    def test_default_sources_omit_syslog(self):
        """rsyslog duplicates auth and firewall lines into syslog, so defaulting to both
        would ingest every matching event twice and halve the effective thresholds."""
        self.assertNotIn("syslog", agent.DEFAULT_SOURCES)
        self.assertIn("syslog", agent.SOURCE_NAMES)

    def test_default_sources_are_real_sources(self):
        for name in agent.DEFAULT_SOURCES:
            self.assertIn(name, agent.SOURCE_NAMES)


class FindPathTests(unittest.TestCase):
    def test_relative_paths_resolve_against_log_dir(self):
        path, reason = agent.find_path(agent._BY_NAME["auth"], ROOT / "samples")
        self.assertIsNone(reason)
        self.assertEqual(Path(path), ROOT / "samples" / "auth.log")

    def test_missing_source_explains_what_it_looked_for(self):
        path, reason = agent.find_path(agent._BY_NAME["firewall"], ROOT / "samples")
        self.assertIsNone(path)
        self.assertIn("ufw.log", reason)
        self.assertIn("kern.log", reason)


class SanitizeSourceTests(unittest.TestCase):
    def test_produces_a_name_the_server_accepts(self):
        self.assertEqual(agent.sanitize_source("host 01/auth!"), "host-01-auth-")

    def test_is_truncated_to_the_server_limit(self):
        self.assertEqual(len(agent.sanitize_source("x" * 200)), 64)


class SelectSourcesTests(unittest.TestCase):
    def test_default_is_used_when_nothing_asked_for(self):
        self.assertEqual(agent.select_sources(None), list(agent.DEFAULT_SOURCES))

    def test_all_expands_to_the_default_set(self):
        self.assertEqual(agent.select_sources(["all"]), list(agent.DEFAULT_SOURCES))

    def test_comma_separated_and_repeated_flags_are_merged_without_duplicates(self):
        self.assertEqual(agent.select_sources(["auth,web", "auth"]), ["auth", "web"])

    def test_syslog_must_be_asked_for_explicitly(self):
        self.assertEqual(agent.select_sources(["syslog"]), ["syslog"])
        self.assertIn("syslog", agent.select_sources(["all", "syslog"]))

    def test_unknown_source_is_fatal(self):
        with self.assertRaises(shipper.FatalError) as caught:
            agent.select_sources(["nope"])
        self.assertIn("nope", str(caught.exception))


class WrapAuditdTests(unittest.TestCase):
    """Raw auditd lines are rejected by the server, so the agent adapts them."""

    def test_server_rejects_a_raw_auditd_line(self):
        events, rejections = parse_payload(AUDIT_LINE.decode(), "authlog", "src")
        self.assertEqual(events, [])
        self.assertIn("not in syslog format", rejections[0]["reason"])

    def test_wrapped_line_is_accepted_as_a_process_start(self):
        wrapped = agent.wrap_auditd(AUDIT_LINE, "host01")
        events, rejections = parse_payload(wrapped.decode(), "authlog", "src")
        self.assertEqual(rejections, [])
        self.assertEqual(events[0]["event_type"], "process_start")
        self.assertEqual(events[0]["host"], "host01")

    def test_wrapped_path_record_becomes_file_access(self):
        wrapped = agent.wrap_auditd(AUDIT_PATH_LINE, "host01")
        events, rejections = parse_payload(wrapped.decode(), "authlog", "src")
        self.assertEqual(rejections, [])
        self.assertEqual(events[0]["event_type"], "file_access")

    def test_the_records_own_time_is_kept(self):
        wrapped = agent.wrap_auditd(AUDIT_LINE, "host01").decode()
        self.assertTrue(wrapped.startswith("2025-10-09T"), wrapped[:40])
        self.assertIn("audit[4567]: type=SYSCALL", wrapped)

    def test_a_line_that_is_not_an_auditd_record_is_dropped(self):
        self.assertIsNone(agent.wrap_auditd(b"not an audit record\n", "host01"))
        self.assertIsNone(agent.wrap_auditd(b"   \n", "host01"))

    def test_an_absurd_epoch_falls_back_to_receipt_time(self):
        record = b'type=SYSCALL msg=audit(99999999999999.1:1): exe="/usr/bin/id"\n'
        wrapped = agent.wrap_auditd(record, "host01")
        self.assertIsNotNone(wrapped)
        events, rejections = parse_payload(wrapped.decode(), "authlog", "src")
        self.assertEqual(rejections, [])
        self.assertEqual(events[0]["event_type"], "process_start")


class DiscoveryTests(unittest.TestCase):
    """Sources with `scan` take every log in a tree; the rest take the first match only."""

    def test_rotated_and_compressed_logs_are_not_live_sources(self):
        for name in ("access.log.1", "error.log.2.gz", "access.log.10", "error.log.1.bz2",
                     "access.log.2.xz", "error.log.1.zst"):
            with self.subTest(name=name):
                self.assertTrue(agent._is_rotated(name))
        for name in ("access.log", "error.log", "shop.access.log", "auth.log"):
            with self.subTest(name=name):
                self.assertFalse(agent._is_rotated(name))

    def test_web_source_takes_every_log_in_the_tree(self):
        paths, reason = agent.discover(agent._BY_NAME["web"], LOGS)
        self.assertIsNone(reason)
        self.assertEqual([os.path.basename(path) for path in paths],
                         ["access.log", "error.log", "shop.access.log"],
                         "per-vhost logs are included, rotated access.log.1 is not")

    def test_error_logs_get_the_nginx_error_format(self):
        source = agent._BY_NAME["web"]
        self.assertEqual(agent._format_for(source, "/var/log/nginx/error.log"), "nginx_error")
        self.assertEqual(agent._format_for(source, "/var/log/nginx/shop.error.log"), "nginx_error")
        self.assertEqual(agent._format_for(source, "/var/log/nginx/access.log"), "weblog")
        self.assertEqual(agent._format_for(source, "/var/log/nginx/shop.access.log"), "weblog")

    def test_source_names_are_stable_and_specific(self):
        source = agent._BY_NAME["web"]
        paths, _ = agent.discover(source, LOGS)
        names = {os.path.basename(path): agent._source_name(source, path, "web01", LOGS)
                 for path in paths}
        self.assertEqual(names, {"access.log": "web01-web",
                                 "error.log": "web01-web-error",
                                 "shop.access.log": "web01-web-shop.access"})

    def test_firewall_takes_only_the_first_existing_log(self):
        """UFW writes the same lines to ufw.log and kern.log: taking both would double every
        firewall event and halve the port-sweep threshold."""
        paths, reason = agent.discover(agent._BY_NAME["firewall"], LOGS)
        self.assertIsNone(reason)
        self.assertEqual([os.path.basename(path) for path in paths], ["ufw.log"])

    def test_a_missing_scan_tree_is_reported_not_crashed(self):
        paths, reason = agent.discover(agent._BY_NAME["web"], ROOT / "docs")
        self.assertEqual(paths, [])
        self.assertIn("nginx", reason)


class ResolveSourcesTests(unittest.TestCase):
    def test_missing_sources_are_skipped_with_a_reason(self):
        files, transforms, skipped, warnings = agent.resolve_sources(
            ["firewall"], "host01", log_dir=ROOT / "samples")
        self.assertEqual(files, [])
        self.assertEqual(transforms, {})
        self.assertEqual(skipped[0][0], "firewall")
        self.assertIn("ufw.log", skipped[0][1])

    def test_source_names_are_host_scoped(self):
        files, _, _, _ = agent.resolve_sources(["auth"], "host01", log_dir=ROOT / "samples")
        self.assertEqual(files, [(str(ROOT / "samples" / "auth.log"), "authlog", "host01-auth")])

    def test_source_prefix_overrides_the_hostname(self):
        files, _, _, _ = agent.resolve_sources(["auth"], "host01", prefix="web01",
                                              log_dir=ROOT / "samples")
        self.assertEqual(files[0][2], "web01-auth")

    def test_the_web_source_expands_to_one_entry_per_file(self):
        """The ask was to watch /var/log/nginx/*, so one source becomes several files, each with
        the right format and its own stable source name."""
        files, transforms, skipped, warnings = agent.resolve_sources(["web"], "web01", log_dir=LOGS)
        self.assertEqual(skipped, [])
        self.assertEqual(warnings, [])
        self.assertEqual(transforms, {})
        self.assertEqual([os.path.basename(f[0]) for f in files],
                         ["access.log", "error.log", "shop.access.log"])
        self.assertEqual([f[1] for f in files], ["weblog", "nginx_error", "weblog"])
        self.assertEqual([f[2] for f in files],
                         ["web01-web", "web01-web-error", "web01-web-shop.access"])

    def test_selecting_both_overlapping_sources_warns(self):
        """auth and syslog both carry the same sshd lines under rsyslog."""
        files, _, skipped, warnings = agent.resolve_sources(["auth", "syslog"], "host01", log_dir=LOGS)
        self.assertEqual([f[2] for f in files], ["host01-auth", "host01-syslog"])
        self.assertEqual(skipped, [])
        self.assertEqual(len(warnings), 1)
        self.assertIn("twice", warnings[0])
        self.assertIn("auth", warnings[0])

    def test_no_warning_when_only_one_of_the_pair_is_selected(self):
        _, _, _, warnings = agent.resolve_sources(["auth"], "host01", log_dir=LOGS)
        self.assertEqual(warnings, [])


class TransformWiringTests(unittest.TestCase):
    """The transform must be picked by source, and bound to the hostname.

    Regression: the first version indexed the catalogue with the host-scoped source name
    ("host01-audit") instead of the catalogue key ("audit"), and stored the auditd transform
    unbound, so the first audit line raised TypeError and killed the run.
    """

    def test_only_transforming_sources_get_a_transform_bound_to_the_hostname(self):
        files, transforms, _, _ = agent.resolve_sources(["auth", "audit"], "host01", log_dir=LOGS)
        self.assertEqual(len(files), 2)
        audit_path = str(LOGS / "audit" / "audit.log")
        self.assertEqual(list(transforms), [audit_path], "only the audit source transforms lines")
        wrapped = transforms[audit_path](AUDIT_LINE)
        self.assertIn(b"host01 audit[4567]", wrapped)

    def test_post_applies_the_transform_and_filters_dropped_lines(self):
        sent = {}

        def capture(self, tailed, lines):
            sent["lines"] = lines
            return 201

        with mock.patch.object(shipper.Shipper, "post", capture):
            instance = agent.AgentShipper("http://127.0.0.1:1", "wp_x", [], "state.json",
                                          transforms={"/l": lambda line: agent.wrap_auditd(line, "host01")})
            status = instance.post(mock.Mock(path="/l"), [AUDIT_LINE, b"junk\n", AUDIT_PATH_LINE])
        self.assertEqual(status, 201)
        self.assertEqual(len(sent["lines"]), 2)
        self.assertTrue(all(line.startswith(b"20") for line in sent["lines"]))

    def test_a_batch_that_becomes_empty_is_not_sent(self):
        with mock.patch.object(shipper.Shipper, "post", side_effect=AssertionError("must not upload")):
            instance = agent.AgentShipper("http://127.0.0.1:1", "wp_x", [], "state.json",
                                          transforms={"/l": lambda line: None})
            status = instance.post(mock.Mock(path="/l"), [b"junk\n"])
        self.assertEqual(status, 201, "the offset must still advance")

    def test_without_a_transform_lines_pass_through_unchanged(self):
        sent = {}

        def capture(self, tailed, lines):
            sent["lines"] = lines
            return 201

        with mock.patch.object(shipper.Shipper, "post", capture):
            instance = agent.AgentShipper("http://127.0.0.1:1", "wp_x", [], "state.json", transforms={})
            instance.post(mock.Mock(path="/l"), [b"as-is\n"])
        self.assertEqual(sent["lines"], [b"as-is\n"])


class CliTests(unittest.TestCase):
    """Inspect-only modes read the filesystem, send nothing, and need no token."""

    def _run(self, argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = agent.main(argv)
        return code, out.getvalue()

    def _run_both(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = agent.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_list_sources_needs_no_url_and_no_token(self):
        """Regression: --url was an argparse-required option, so argparse rejected
        `--list-sources` before the code that returns early for it could run."""
        code, out, _ = self._run_both(["--log-dir", str(LOGS), "--hostname", "testhost",
                                       "--list-sources"])
        self.assertEqual(code, 0)
        self.assertIn("testhost", out)
        self.assertIn("auth", out)

    def test_list_sources_needs_no_token_and_exits_zero(self):
        code, out = self._run(["--url", "http://127.0.0.1:1", "--log-dir", str(ROOT / "samples"),
                               "--list-sources"])
        self.assertEqual(code, 0)
        self.assertIn("auth", out)
        self.assertIn("samples", out.replace("\\", "/"))

    def test_dry_run_needs_no_url(self):
        code, out, _ = self._run_both(["--log-dir", str(LOGS), "--hostname", "testhost",
                                       "--source", "auth", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("no --url given", out)

    def test_dry_run_resolves_the_catalogue_without_a_token(self):
        code, out = self._run(["--url", "http://127.0.0.1:1", "--log-dir", str(LOGS),
                               "--hostname", "testhost", "--source", "auth,audit", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("testhost-auth", out)
        self.assertIn("format=authlog", out)
        self.assertIn("audit", out)

    def test_shipping_without_a_url_says_so(self):
        code, _, err = self._run_both(["--log-dir", str(LOGS), "--hostname", "testhost",
                                       "--source", "auth", "--once"])
        self.assertEqual(code, 2)
        self.assertIn("--url is required", err)

    def test_check_without_a_url_says_so(self):
        code, _, err = self._run_both(["--log-dir", str(LOGS), "--hostname", "testhost", "--check"])
        self.assertEqual(code, 2)
        self.assertIn("--url is required", err)

    def test_unknown_source_exits_two(self):
        code, _ = self._run(["--url", "http://127.0.0.1:1", "--source", "bogus", "--dry-run"])
        self.assertEqual(code, 2)

    def test_no_available_sources_exits_two(self):
        code, _ = self._run(["--url", "http://127.0.0.1:1", "--log-dir", str(ROOT / "docs"),
                             "--source", "auth", "--once"])
        self.assertEqual(code, 2)

    def test_plain_http_to_a_remote_host_is_refused_before_shipping(self):
        code, _ = self._run(["--url", "http://192.0.2.10:8080", "--log-dir", str(LOGS),
                             "--source", "auth", "--once"])
        self.assertEqual(code, 2)


class EndToEndAgentTests(ServerTestCase):
    """The agent ships real lines to a real server, which stores them as non-synthetic."""

    def _run_agent(self, tmp, token_path, extra=(), sources="auth,audit"):
        state = str(Path(tmp) / "positions.json")
        argv = ["--url", self.base, "--log-dir", str(LOGS), "--hostname", "testhost",
                "--source", sources, "--token-file", str(token_path), "--state", state,
                "--from-start", "--once"]
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            return agent.main(argv + list(extra))

    def setUp(self):
        super().setUp()
        admin = self.client("admin")
        status, minted, _ = admin.post("/api/tokens", {"name": "agent-test"})
        self.assertEqual(status, 201)
        self.token_path = Path(self.tmp.name) / "token"
        self.token_path.write_text(minted["token"])

    def test_lines_are_shipped_and_stored_as_real_events(self):
        self.assertEqual(self._run_agent(self.tmp.name, self.token_path), 0)

        viewer = self.client("viewer")
        status, events, _ = viewer.get("/api/events?limit=50")
        self.assertEqual(status, 200)
        self.assertEqual(events["total"], 2, "one sshd line and one auditd record")
        self.assertEqual({e["synthetic"] for e in events["events"]}, {0}, "real logs are not synthetic")

        by_type = {e["event_type"]: e for e in events["events"]}
        self.assertIn("auth_failure", by_type)
        self.assertIn("process_start", by_type, "the auditd line needed the syslog envelope")
        self.assertEqual(sorted({e["source"] for e in events["events"]}),
                         ["testhost-audit", "testhost-auth"])
        self.assertEqual(by_type["auth_failure"]["src_ip"], "203.0.113.5")
        self.assertEqual(by_type["process_start"]["host"], "testhost")

    def test_a_second_run_ships_nothing_twice(self):
        self.assertEqual(self._run_agent(self.tmp.name, self.token_path), 0)
        self.assertEqual(self._run_agent(self.tmp.name, self.token_path), 0)
        viewer = self.client("viewer")
        _, events, _ = viewer.get("/api/events?limit=50")
        self.assertEqual(events["total"], 2, "the position file must stop a resend")

    def test_check_accepts_the_token_and_writes_nothing(self):
        code = self._run_agent(self.tmp.name, self.token_path, extra=["--check"])
        self.assertEqual(code, 0)
        viewer = self.client("viewer")
        _, events, _ = viewer.get("/api/events?limit=50")
        self.assertEqual(events["total"], 0)

    def test_check_works_on_a_host_with_no_logs_at_all(self):
        """--check only exercises the token, so a missing source must not mask a token problem."""
        state = str(Path(self.tmp.name) / "positions.json")
        argv = ["--url", self.base, "--log-dir", str(ROOT / "docs"), "--token-file",
                str(self.token_path), "--state", state, "--check"]
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            self.assertEqual(agent.main(argv), 0)

    def test_check_reports_a_bad_url_rather_than_a_missing_source(self):
        argv = ["--url", "http://127.0.0.1:9", "--log-dir", str(ROOT / "docs"), "--token-file",
                str(self.token_path), "--state", str(Path(self.tmp.name) / "p.json"),
                "--check", "--max-retries", "0"]
        with redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()):
            code = agent.main(argv)
        self.assertEqual(code, 2)
        self.assertIn("could not reach", err.getvalue())

    def test_check_rejects_a_revoked_token(self):
        admin = self.client("admin")
        _, tokens, _ = admin.get("/api/tokens")
        token_id = tokens[0]["id"]
        self.assertEqual(admin.post(f"/api/tokens/{token_id}/revoke")[0], 200)
        self.assertEqual(self._run_agent(self.tmp.name, self.token_path, extra=["--check"]), 2)

    def test_batching_splits_a_file_into_several_batches(self):
        code = self._run_agent(self.tmp.name, self.token_path, extra=["--batch-lines", "1"])
        self.assertEqual(code, 0)
        viewer = self.client("viewer")
        _, events, _ = viewer.get("/api/events?limit=50")
        self.assertEqual(events["total"], 2)

    def test_the_nginx_tree_ships_as_separate_sources(self):
        """End to end for the /var/log/nginx/* ask: access and error logs arrive as real events
        with their own source names and event types."""
        code = self._run_agent(self.tmp.name, self.token_path, sources="web")
        self.assertEqual(code, 0)
        viewer = self.client("viewer")
        _, events, _ = viewer.get("/api/events?limit=50")

        by_source = {}
        for event in events["events"]:
            by_source.setdefault(event["source"], []).append(event)
        self.assertEqual(sorted(by_source), ["testhost-web", "testhost-web-error",
                                            "testhost-web-shop.access"])
        self.assertEqual(len(by_source["testhost-web-error"]), 3)
        self.assertEqual({e["event_type"] for e in by_source["testhost-web-error"]}, {"web_error"})
        self.assertEqual({e["severity"] for e in by_source["testhost-web-error"]},
                         {"high", "critical"}, "severity comes from the nginx level")
        self.assertEqual({e["src_ip"] for e in by_source["testhost-web-error"]},
                         {"203.0.113.80", "198.51.100.9", "192.0.2.10"}, "client IP is extracted")
        self.assertIn("web_scan", {e["event_type"] for e in by_source["testhost-web"]})
        self.assertEqual({e["synthetic"] for e in events["events"]}, {0})


if __name__ == "__main__":
    unittest.main()
