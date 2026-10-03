import unittest
from datetime import datetime, timedelta, timezone

from watchpost import rules
from watchpost.db import iso
from watchpost.improve import evaluate

BASE = datetime(2026, 9, 15, 14, 0, tzinfo=timezone.utc)  # a Tuesday


def params(rule_id, **overrides):
    return rules.validate_params(rule_id, overrides)


def make(events):
    return [{"id": i, **e} for i, e in enumerate(events, start=1)]


def fail(sec, user="admin", ip="203.0.113.1"):
    return {"ts": iso(BASE + timedelta(seconds=sec)), "event_type": "auth_failure", "user": user, "src_ip": ip}


def ok(sec, user="admin", ip="203.0.113.1", base=BASE):
    return {"ts": iso(base + timedelta(seconds=sec)), "event_type": "auth_success", "user": user, "src_ip": ip}


class BruteForceTests(unittest.TestCase):
    def test_threshold_boundary(self):
        p = params("brute_force_ip")
        self.assertEqual(rules.brute_force_ip(make([fail(i) for i in range(9)]), p), [])
        found = rules.brute_force_ip(make([fail(i) for i in range(10)]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertEqual(len(found[0]["event_ids"]), 10)
        self.assertIn("threshold of 10", found[0]["explanation"])

    def test_events_outside_window_do_not_count(self):
        # 10 failures spread over 10 minutes: never 10 inside 300s.
        self.assertEqual(rules.brute_force_ip(make([fail(i * 60) for i in range(10)]), params("brute_force_ip")), [])

    def test_separate_bursts_make_separate_findings(self):
        events = [fail(i) for i in range(10)] + [fail(3600 + i) for i in range(10)]
        self.assertEqual(len(rules.brute_force_ip(make(events), params("brute_force_ip"))), 2)

    def test_ignore_ips_and_users(self):
        events = make([fail(i) for i in range(12)])
        self.assertEqual(rules.brute_force_ip(events, params("brute_force_ip", ignore_ips=["203.0.113.1"])), [])
        self.assertEqual(rules.brute_force_ip(events, params("brute_force_ip", ignore_users=["ADMIN"])), [])

    def test_unordered_input_and_missing_ip(self):
        events = [fail(i) for i in reversed(range(10))] + [{**fail(1), "src_ip": None}]
        self.assertEqual(len(rules.brute_force_ip(make(events), params("brute_force_ip"))), 1)


class OtherRuleTests(unittest.TestCase):
    def test_password_spray(self):
        events = make([fail(i * 30, user=f"u{i}") for i in range(5)])
        self.assertEqual(len(rules.password_spray(events, params("password_spray"))), 1)
        same_user = make([fail(i * 30) for i in range(20)])
        self.assertEqual(rules.password_spray(same_user, params("password_spray")), [])

    def test_account_repeated_failures_across_ips(self):
        events = make([fail(i * 10, ip=f"192.0.2.{i}") for i in range(8)])
        found = rules.account_repeated_failures(events, params("account_repeated_failures"))
        self.assertEqual(len(found), 1)
        self.assertIn("8 source IP", found[0]["explanation"])
        self.assertEqual(rules.brute_force_ip(events, params("brute_force_ip")), [])

    def test_success_after_failures(self):
        p = params("success_after_failures")
        events = make([fail(i * 10, user="dave") for i in range(5)] + [ok(60, user="Dave")])
        found = rules.success_after_failures(events, p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "dave|203.0.113.1")
        self.assertIn("same IP", found[0]["explanation"])
        # Four failures is below the threshold; a success long after is outside the window.
        self.assertEqual(rules.success_after_failures(make([fail(i, user="d") for i in range(4)] + [ok(9, user="d")]), p), [])
        self.assertEqual(rules.success_after_failures(make([fail(i, user="d") for i in range(5)] + [ok(7200, user="d")]), p), [])
        # A success *before* the failures is not "after failures".
        self.assertEqual(rules.success_after_failures(make([ok(0, user="d")] + [fail(10 + i, user="d") for i in range(5)]), p), [])

    def test_off_hours(self):
        p = params("off_hours_privileged_login")
        night = datetime(2026, 9, 15, 3, 0, tzinfo=timezone.utc)
        saturday = datetime(2026, 9, 19, 11, 0, tzinfo=timezone.utc)
        self.assertEqual(len(rules.off_hours_privileged_login(make([ok(0, "root", base=night)]), p)), 1)
        self.assertEqual(len(rules.off_hours_privileged_login(make([ok(0, "root", base=saturday)]), p)), 1)
        self.assertEqual(rules.off_hours_privileged_login(make([ok(0, "root")]), p), [])  # Tuesday 14:00
        self.assertEqual(rules.off_hours_privileged_login(make([ok(0, "alice", base=night)]), p), [])


def ev(sec, event_type, user=None, ip="203.0.113.1", **extra):
    return {"ts": iso(BASE + timedelta(seconds=sec)), "event_type": event_type, "user": user, "src_ip": ip, **extra}


class WebAndFirewallRuleTests(unittest.TestCase):
    def test_web_scanner(self):
        p = params("web_scanner")
        probes = [ev(i * 5, "web_scan", message=f"GET /probe{i} -> 404") for i in range(5)]
        found = rules.web_scanner(make(probes), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertIn("/probe0", found[0]["explanation"])
        self.assertEqual(rules.web_scanner(make(probes[:4]), p), [])
        # Ordinary requests never count, and spread-out probes stay under the window.
        self.assertEqual(rules.web_scanner(make([ev(i, "web_request") for i in range(20)]), p), [])
        self.assertEqual(rules.web_scanner(make([ev(i * 120, "web_scan") for i in range(5)]), p), [])

    def test_firewall_port_sweep(self):
        p = params("firewall_port_sweep")
        sweep = [ev(i, "fw_deny", dest_ip="10.0.0.10", dest_port=1000 + i) for i in range(10)]
        found = rules.firewall_port_sweep(make(sweep), p)
        self.assertEqual(len(found), 1)
        self.assertIn("10 distinct ports", found[0]["explanation"])
        same_port = [ev(i, "fw_deny", dest_port=22) for i in range(30)]
        self.assertEqual(rules.firewall_port_sweep(make(same_port), p), [])
        allowed = [ev(i, "fw_allow", dest_port=1000 + i) for i in range(30)]
        self.assertEqual(rules.firewall_port_sweep(make(allowed), p), [])
        no_port = [ev(i, "fw_deny") for i in range(30)]
        self.assertEqual(rules.firewall_port_sweep(make(no_port), p), [])


def web(sec, path, ip="203.0.113.1", outcome="failure", event_type="web_request", status=404):
    return ev(sec, event_type, None, ip, outcome=outcome, message=f"GET {path} -> {status}")


def coded(sec, path, status, ip="203.0.113.1", event_type="web_request"):
    """An access-log event carrying the code in the `http_status` column, as the parser stores it."""
    return ev(sec, event_type, None, ip, outcome="success" if status < 400 else "failure",
              http_status=status, message=f"GET {path} -> {status}")


def error_line(sec, path, ip="203.0.113.1"):
    """An nginx error.log line naming a request: no response code anywhere, which is the point."""
    return ev(sec, "web_error", None, ip, outcome="failure",
              message=f'GET {path} [error] open() "/var/www{path}" failed (2: No such file or directory), '
                      f"client: {ip}")


def error_line_without_a_request(sec, ip="203.0.113.1"):
    """An error.log line with no request in it, such as a TLS handshake failure."""
    return ev(sec, "web_error", None, ip, outcome="failure",
              message="[crit] SSL_do_handshake() failed (SSL: error:0A000126), client: " + ip)


class WebBehaviourRuleTests(unittest.TestCase):
    """Breadth (path discovery) and volume (request burst) are separate signals on purpose."""

    def test_path_discovery_needs_many_distinct_failing_paths(self):
        p = params("web_path_discovery")
        found = rules.web_path_discovery(make([web(i * 3, f"/dir{i}") for i in range(30)]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertIn("30 distinct paths", found[0]["explanation"])
        self.assertIn("/dir0", found[0]["explanation"])
        self.assertEqual(rules.web_path_discovery(make([web(i * 3, f"/dir{i}") for i in range(29)]), p), [])

    def test_successful_browsing_is_not_discovery(self):
        """Many distinct paths that all succeed is a crawl, not enumeration."""
        p = params("web_path_discovery")
        browsing = make([web(i * 3, f"/page{i}", outcome="success", status=200) for i in range(40)])
        self.assertEqual(rules.web_path_discovery(browsing, p), [])

    def test_repeating_one_path_is_not_discovery(self):
        p = params("web_path_discovery")
        self.assertEqual(rules.web_path_discovery(make([web(i, "/api/orders") for i in range(200)]), p), [])

    def test_discovery_must_happen_inside_the_window(self):
        """A patient walk across an hour is not a burst of enumeration."""
        p = params("web_path_discovery")
        self.assertEqual(rules.web_path_discovery(make([web(i * 120, f"/dir{i}") for i in range(30)]), p), [])

    def test_a_known_scanner_can_be_ignored(self):
        p = params("web_path_discovery", ignore_ips=["10.0.50.5"])
        walk = make([web(i * 3, f"/dir{i}", ip="10.0.50.5") for i in range(40)])
        self.assertEqual(rules.web_path_discovery(walk, p), [])

    def test_nginx_error_log_probes_count_towards_discovery(self):
        """Error lines carry a path and a failure outcome, so a host that only logs errors there
        still gets breadth coverage."""
        p = params("web_path_discovery")
        errors = make([ev(i * 3, "web_error", None, outcome="failure",
                          message=f"GET /dir{i} [error] access forbidden by rule") for i in range(30)])
        self.assertEqual(len(rules.web_path_discovery(errors, p)), 1)

    def test_lines_without_a_parseable_path_never_look_like_discovery(self):
        p = params("web_path_discovery")
        cert_failures = make([ev(i * 3, "web_error", None, outcome="failure",
                                 message="[crit] SSL_do_handshake() failed, client: 198.51.100.9")
                              for i in range(300)])
        self.assertEqual(rules.web_path_discovery(cert_failures, p), [])

    def test_burst_needs_volume_inside_the_window(self):
        p = params("web_request_burst")
        found = rules.web_request_burst(
            make([web(i * 0.2, "/api/orders", outcome="success", status=200) for i in range(200)]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertIn("200 requests", found[0]["explanation"])
        fewer = make([web(i * 0.2, "/api/orders", outcome="success", status=200) for i in range(199)])
        self.assertEqual(rules.web_request_burst(fewer, p), [])

    def test_a_spread_out_reader_is_not_a_burst(self):
        p = params("web_request_burst")
        spread = make([web(i * 5, "/index.html", outcome="success", status=200) for i in range(200)])
        self.assertEqual(rules.web_request_burst(spread, p), [])

    def test_the_rules_are_complementary_not_redundant(self):
        """A fast narrow flood trips only volume; a slow wide walk trips only breadth."""
        discovery, burst = params("web_path_discovery"), params("web_request_burst")
        wide_and_slow = make([web(i * 3, f"/dir{i}") for i in range(36)])
        self.assertEqual(len(rules.web_path_discovery(wide_and_slow, discovery)), 1)
        self.assertEqual(rules.web_request_burst(wide_and_slow, burst), [])
        fast_and_narrow = make([web(i * 0.25, "/health", outcome="success", status=200)
                                for i in range(240)])
        self.assertEqual(len(rules.web_request_burst(fast_and_narrow, burst)), 1)
        self.assertEqual(rules.web_path_discovery(fast_and_narrow, discovery), [])

    def test_a_known_heavy_client_can_be_ignored_for_bursts(self):
        p = params("web_request_burst", ignore_ips=["10.0.1.9"])
        flood = make([web(i * 0.2, "/health", ip="10.0.1.9", outcome="success", status=200)
                      for i in range(240)])
        self.assertEqual(rules.web_request_burst(flood, p), [])


class GeoLoginRuleTests(unittest.TestCase):
    def test_impossible_travel(self):
        p = params("impossible_geo_login")
        events = make([ev(0, "auth_success", "erin", "10.0.1.24"), ev(25 * 60, "vpn_login", "Erin", "203.0.113.150")])
        found = rules.impossible_geo_login(events, p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "erin|10.0.1.24|203.0.113.150")
        self.assertIn("Riverton HQ", found[0]["explanation"])
        self.assertIn("synthetic geo", found[0]["explanation"])

    def test_plausible_or_unknown_travel_is_quiet(self):
        p = params("impossible_geo_login")
        # Same city, or enough time to fly there, or an address the synthetic table does not know.
        cases = [
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(60, "auth_success", "erin", "10.9.9.9")],
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(15 * 3600, "auth_success", "erin", "203.0.113.150")],
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(60, "auth_success", "erin", "8.8.8.8")],
            [ev(0, "auth_success", "erin", "10.0.1.24"), ev(60, "auth_success", "bob", "203.0.113.150")],
            [ev(0, "auth_failure", "erin", "10.0.1.24"), ev(60, "auth_success", "erin", "203.0.113.150")],
        ]
        for case in cases:
            with self.subTest(case=case):
                self.assertEqual(rules.impossible_geo_login(make(case), p), [])

    def test_privilege_escalation_after_login(self):
        p = params("privilege_escalation_after_login")
        attack = [ev(i * 20, "auth_failure", "frank", "192.0.2.140") for i in range(3)]
        attack += [ev(60, "auth_success", "frank", "192.0.2.140"),
                   ev(420, "privilege_escalation", "frank", "192.0.2.140", host="web01")]
        found = rules.privilege_escalation_after_login(make(attack), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "frank|web01")
        self.assertEqual(len(found[0]["event_ids"]), 5)
        # Too few failures; escalation long after the login; escalation with no login at all.
        self.assertEqual(rules.privilege_escalation_after_login(make(attack[1:]), p), [])
        late = attack[:4] + [ev(60 + 3600, "privilege_escalation", "frank", host="web01")]
        self.assertEqual(rules.privilege_escalation_after_login(make(late), p), [])
        self.assertEqual(rules.privilege_escalation_after_login(
            make(attack[:3] + [ev(400, "privilege_escalation", "frank", host="web01")]), p), [])


class CloudRuleTests(unittest.TestCase):
    def test_iam_change_by_new_principal(self):
        p = params("cloud_iam_change_by_new_principal")
        known = [ev(0, "cloud_api_call", "ops-admin"), ev(600, "cloud_iam_change", "ops-admin")]
        new = [ev(900 + i * 30, "cloud_iam_change", "svc-new", message=f"{a} on iam.amazonaws.com")
               for i, a in enumerate(["CreateUser", "CreateAccessKey"])]
        found = rules.cloud_iam_change_by_new_principal(make(known + new), p)
        self.assertEqual([f["group_key"] for f in found], ["svc-new"])
        self.assertEqual(len(found[0]["event_ids"]), 2)
        self.assertIn("CreateAccessKey", found[0]["explanation"])
        # History older than history_seconds does not count as history.
        stale = [ev(0, "cloud_api_call", "ops-admin"), ev(2 * 86400, "cloud_iam_change", "ops-admin")]
        self.assertEqual(len(rules.cloud_iam_change_by_new_principal(make(stale), p)), 1)

    def test_data_exfil_volume(self):
        p = params("data_exfil_volume")
        reads = [ev(i * 10, "cloud_data_access", "svc", bytes=50_000_000) for i in range(20)]
        found = rules.data_exfil_volume(make(reads), p)
        self.assertEqual(len(found), 1)
        self.assertIn("1.0 GB", found[0]["explanation"])
        self.assertEqual(rules.data_exfil_volume(make(reads[:19]), p), [])
        many_small = [ev(i, "cloud_data_access", "svc", bytes=10) for i in range(100)]
        self.assertEqual(len(rules.data_exfil_volume(make(many_small), p)), 1)
        # Outbound firewall bytes count per source IP when there is no account.
        uploads = [ev(i * 60, "fw_allow", None, "10.0.3.15", bytes=600_000_000) for i in range(2)]
        self.assertEqual([f["group_key"] for f in rules.data_exfil_volume(make(uploads), p)], ["10.0.3.15"])
        self.assertEqual(rules.data_exfil_volume(make([ev(0, "fw_allow", None, "10.0.3.15")] * 3), p), [])


class TechniqueMappingTests(unittest.TestCase):
    def test_every_rule_has_techniques_and_a_function(self):
        for rule in rules.DEFAULT_RULES:
            with self.subTest(rule=rule["id"]):
                self.assertIn(rule["id"], rules.RULE_FUNCTIONS)
                self.assertTrue(rule["techniques"])
                for t in rule["techniques"]:
                    self.assertEqual(set(t), {"id", "name", "tactic"})

    def test_lookback_covers_escalation_and_history(self):
        active = [{"params": rules.validate_params(r["id"], {})} for r in rules.DEFAULT_RULES]
        self.assertGreaterEqual(rules.lookback_seconds(active), 600 + 1800)
        self.assertEqual(rules.history_seconds(active), 86400)


class ValidationTests(unittest.TestCase):
    def test_rejects_bad_params(self):
        bad = [
            ("brute_force_ip", {"threshold": 1}),
            ("brute_force_ip", {"threshold": "10"}),
            ("brute_force_ip", {"threshold": True}),
            ("brute_force_ip", {"nope": 1}),
            ("brute_force_ip", {"ignore_ips": ["not-an-ip"]}),
            ("off_hours_privileged_login", {"business_start_hour": 18, "business_end_hour": 8}),
            ("off_hours_privileged_login", {"privileged_users": []}),
            ("firewall_port_sweep", {"distinct_ports": 1}),
            ("impossible_geo_login", {"max_speed_kmh": 10}),
            ("privilege_escalation_after_login", {"escalation_seconds": 5}),
            ("cloud_iam_change_by_new_principal", {"history_seconds": "1d"}),
            ("data_exfil_volume", {"bytes_threshold": 0}),
            ("web_scanner", {"distinct_ports": 5}),
            ("missing_rule", {}),
        ]
        for rule_id, p in bad:
            with self.subTest(rule=rule_id, params=p):
                with self.assertRaises(rules.RuleConfigError):
                    rules.validate_params(rule_id, p)


class EvaluationTests(unittest.TestCase):
    def test_default_rules_on_labeled_scenarios(self):
        defaults = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}
        result = evaluate(defaults)["rules"]
        for rule_id, r in result.items():
            with self.subTest(rule=rule_id):
                self.assertEqual(r["fn"], 0, r)
                self.assertEqual(r["recall"], 1.0)
        # The internal scanner is a deliberate false-positive source for the feedback demo.
        self.assertIn("noisy_scanner", result["brute_force_ip"]["false_positives"])
        self.assertEqual(result["password_spray"]["fp"], 0)

    def test_allowlisting_scanner_removes_false_positive(self):
        defaults = {r["id"]: r["params"] for r in rules.DEFAULT_RULES}
        tuned = rules.validate_params("brute_force_ip", {"ignore_ips": ["10.0.50.5"]})
        after = evaluate({"brute_force_ip": tuned})["rules"]["brute_force_ip"]
        self.assertEqual(after["fp"], 0)
        self.assertEqual(after["tp"], evaluate(defaults)["rules"]["brute_force_ip"]["tp"])


class OwaspWebRuleTests(unittest.TestCase):
    """The OWASP Top 10 web rules: what nginx logs can and cannot show.

    Five of the ten are observable from an access log; the rest are application-level and are
    deliberately not claimed. These cover the boundaries, and the two distinctions the design leans
    on: failure-versus-401 for credential attacks, and 5xx-versus-error-log for the error rules.
    """

    # --- A07: credential attacks -------------------------------------------------------

    def test_login_abuse_threshold_and_endpoints(self):
        p = params("web_login_abuse")
        self.assertEqual(rules.web_login_abuse(make([coded(i, "/login", 401) for i in range(9)]), p), [])
        found = rules.web_login_abuse(make([coded(i, "/login", 401) for i in range(10)]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertIn("10 failed request(s)", found[0]["explanation"])
        self.assertIn("/login", found[0]["explanation"])

    def test_login_abuse_reads_web_scan_as_well_as_web_request(self):
        """ /wp-login.php is a scanner-shaped path, so the parser types those events web_scan.
        A rule that only read web_request would miss WordPress login attacks entirely."""
        p = params("web_login_abuse")
        only_real_form = make([coded(i, "/login", 401) for i in range(6)])
        self.assertEqual(rules.web_login_abuse(only_real_form, p), [])
        with_wordpress = only_real_form + make(
            [coded(100 + i, "/wp-login.php", 403, event_type="web_scan") for i in range(4)])
        found = rules.web_login_abuse(with_wordpress, p)
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]["event_ids"]), 10)

    def test_successful_logins_are_not_abuse(self):
        p = params("web_login_abuse")
        self.assertEqual(rules.web_login_abuse(
            make([coded(i, "/login", 200, event_type="web_request") for i in range(30)]), p), [])

    def test_failures_away_from_a_login_endpoint_are_not_abuse(self):
        p = params("web_login_abuse")
        self.assertEqual(rules.web_login_abuse(make([coded(i, "/product/7", 404) for i in range(40)]), p), [])

    def test_login_abuse_must_happen_inside_the_window(self):
        p = params("web_login_abuse")
        self.assertEqual(rules.web_login_abuse(
            make([coded(i * 60, "/login", 401) for i in range(10)]), p), [])

    def test_a_known_client_can_be_ignored(self):
        p = params("web_login_abuse", ignore_ips=["203.0.113.1"])
        self.assertEqual(rules.web_login_abuse(make([coded(i, "/login", 401) for i in range(20)]), p), [])

    def test_auth_brute_force_counts_one_endpoint_not_one_client(self):
        """Twelve 401s spread over two endpoints is not ten against one, which is the whole
        difference between this rule and web_login_abuse."""
        p = params("web_auth_brute_force")
        spread = make([coded(i, "/login", 401) for i in range(6)]
                      + [coded(60 + i, "/admin/login", 401) for i in range(6)])
        self.assertEqual(rules.web_auth_brute_force(spread, p), [])
        self.assertEqual(len(rules.web_login_abuse(spread, params("web_login_abuse"))), 1)

    def test_auth_brute_force_threshold_and_that_403_is_not_a_401(self):
        p = params("web_auth_brute_force")
        self.assertEqual(rules.web_auth_brute_force(make([coded(i, "/login", 401) for i in range(9)]), p), [])
        found = rules.web_auth_brute_force(make([coded(i, "/login", 401) for i in range(10)]), p)
        self.assertEqual(len(found), 1)
        self.assertIn("/login", found[0]["title"])
        self.assertEqual(rules.web_auth_brute_force(make([coded(i, "/login", 403) for i in range(30)]), p), [])

    # --- A03: injection ---------------------------------------------------------------

    def test_one_request_is_enough(self):
        p = params("web_injection_attempt")
        found = rules.web_injection_attempt(make([coded(0, "/product?id=1%27%20OR%20%271%27=%271", 500,
                                                        event_type="web_scan")]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["group_key"], "203.0.113.1")
        self.assertIn("One request is enough", found[0]["explanation"])

    def test_each_payload_family_is_caught(self):
        p = params("web_injection_attempt")
        payloads = [
            "/product?id=1%20UNION%20SELECT%20password%20FROM%20users",
            "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "/download?file=../../etc/passwd",
            "/api/tools?cmd=%3Bcat%20/etc/shadow",
            "/render?name=%7B%7Bconfig%7D%7D",
            "/index.php?page=php://filter/convert.base64-encode/resource=index",
            "/xml?data=%3C!ENTITY%20xxe%20SYSTEM%20'file:///etc/passwd'%3E",
            "/login?user=admin%27--",
        ]
        for i, payload in enumerate(payloads):
            with self.subTest(payload=payload):
                self.assertEqual(len(rules.web_injection_attempt(make([coded(i, payload, 200)]), p)), 1)

    def test_ordinary_requests_are_not_injections(self):
        p = params("web_injection_attempt")
        ordinary = ["/", "/search?q=shoes", "/product/7", "/api/orders?page=2&size=25",
                    "/assets/app.4f2a1b.js", "/blog/2026/10/03/hello-world", "/users/erin/profile"]
        events = make([coded(i, path, 200) for i, path in enumerate(ordinary * 5)])
        self.assertEqual(rules.web_injection_attempt(events, p), [])

    def test_encoded_payloads_are_decoded_before_matching(self):
        p = params("web_injection_attempt")
        for payload in ["/p?q=%27%20OR%20%271%27%3D%271", "/p?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                        "/p?c=%3Bid"]:
            with self.subTest(payload=payload):
                self.assertEqual(len(rules.web_injection_attempt(make([coded(0, payload, 200)]), p)), 1)

    def test_repeated_attempts_become_one_alert_within_the_window(self):
        p = params("web_injection_attempt")
        burst = make([coded(i * 10, "/p?q=%3Bid", 200) for i in range(5)])
        found = rules.web_injection_attempt(burst, p)
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]["event_ids"]), 5)
        spread = make([coded(i * 600, "/p?q=%3Bid", 200) for i in range(5)])
        self.assertEqual(len(rules.web_injection_attempt(spread, p)), 5)

    def test_injection_is_read_from_the_message_when_the_column_is_absent(self):
        """Events stored before http_status existed still have to be judged."""
        p = params("web_injection_attempt")
        legacy = make([web(0, "/p?id=1'%20OR%20'1'='1", event_type="web_scan", status=500)])
        self.assertNotIn("http_status", legacy[0])
        self.assertEqual(len(rules.web_injection_attempt(legacy, p)), 1)

    # --- A05 / A01: sensitive files ---------------------------------------------------

    def test_a_served_secret_is_a_finding_and_a_refusal_is_not(self):
        p = params("web_sensitive_file_served")
        served = make([coded(0, "/.env", 200, event_type="web_scan")])
        found = rules.web_sensitive_file_served(served, p)
        self.assertEqual(len(found), 1)
        self.assertIn("/.env", found[0]["title"])
        for status in (403, 404):
            with self.subTest(status=status):
                self.assertEqual(rules.web_sensitive_file_served(
                    make([coded(0, "/.env", status, event_type="web_scan")]), p), [])

    def test_a_redirect_is_not_a_disclosure(self):
        """nginx sends unknown paths to the login page with a 302; that must not read as a leak."""
        p = params("web_sensitive_file_served")
        self.assertEqual(rules.web_sensitive_file_served(
            make([coded(0, "/.env", 302, event_type="web_scan")]), p), [])

    def test_ordinary_files_are_not_sensitive(self):
        p = params("web_sensitive_file_served")
        ordinary = ["/", "/assets/app.js", "/downloads/release-notes.txt", "/api/orders",
                    "/.well-known/acme-challenge/token"]
        self.assertEqual(rules.web_sensitive_file_served(
            make([coded(i, path, 200) for i, path in enumerate(ordinary)]), p), [])

    def test_sensitive_paths_cover_the_usual_suspects(self):
        p = params("web_sensitive_file_served")
        for path in ["/.env", "/.git/config", "/.aws/credentials", "/wp-config.php", "/backup/db.sql",
                     "/id_rsa", "/config.php", "/uploads/dump.sql", "/index.php.bak"]:
            with self.subTest(path=path):
                self.assertEqual(len(rules.web_sensitive_file_served(make([coded(0, path, 200)]), p)), 1)

    # --- A01 / A06: denials, breakage, and the error log -------------------------------

    def test_access_denied_burst_threshold_and_that_404_does_not_count(self):
        p = params("web_access_denied_burst")
        self.assertEqual(rules.web_access_denied_burst(make([coded(i, f"/admin/{i}", 403)
                                                             for i in range(19)]), p), [])
        found = rules.web_access_denied_burst(make([coded(i, f"/admin/{i}", 403) for i in range(20)]), p)
        self.assertEqual(len(found), 1)
        self.assertIn("20 403 responses", found[0]["explanation"])
        self.assertEqual(rules.web_access_denied_burst(make([coded(i, f"/x{i}", 404)
                                                             for i in range(60)]), p), [])

    def test_server_error_burst_needs_5xx_not_4xx(self):
        p = params("web_server_error_burst")
        self.assertEqual(rules.web_server_error_burst(make([coded(i, "/checkout", 500)
                                                            for i in range(9)]), p), [])
        found = rules.web_server_error_burst(
            make([coded(i, "/checkout", 500 if i % 2 else 503, event_type="web_error")
                  for i in range(10)]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(rules.web_server_error_burst(make([coded(i, "/checkout", 404)
                                                            for i in range(40)]), p), [])

    def test_error_probe_burst_threshold_and_that_a_request_is_required(self):
        p = params("web_error_probe_burst")
        self.assertEqual(rules.web_error_probe_burst(
            make([error_line(i, f"/dir{i}") for i in range(19)]), p), [])
        found = rules.web_error_probe_burst(make([error_line(i, f"/dir{i}") for i in range(20)]), p)
        self.assertEqual(len(found), 1)
        self.assertEqual(len(found[0]["event_ids"]), 20)
        # A TLS handshake failure names a client but no request, so it is not probing.
        self.assertEqual(rules.web_error_probe_burst(
            make([error_line_without_a_request(i) for i in range(60)]), p), [])

    def test_the_two_error_rules_never_count_the_same_event(self):
        """The split the design rests on: a 5xx from the access log has a status, an error.log line
        never does. Without it, one probe recorded in both logs would be counted twice and whichever
        rule had the lower threshold would fire early."""
        access_five_hundreds = make([coded(i, "/checkout", 500) for i in range(12)])
        error_lines = make([error_line(i, f"/checkout{i}") for i in range(22)])
        self.assertEqual(len(rules.web_server_error_burst(access_five_hundreds,
                                                          params("web_server_error_burst"))), 1)
        self.assertEqual(rules.web_error_probe_burst(access_five_hundreds,
                                                     params("web_error_probe_burst")), [])
        self.assertEqual(rules.web_server_error_burst(error_lines, params("web_server_error_burst")), [])
        self.assertEqual(len(rules.web_error_probe_burst(error_lines,
                                                         params("web_error_probe_burst"))), 1)

    def test_the_web_rules_fall_back_to_the_message_for_the_status(self):
        """Every status rule has to keep working on events stored before the column existed."""
        legacy_denials = make([web(i, f"/admin/{i}", status=403) for i in range(20)])
        self.assertNotIn("http_status", legacy_denials[0])
        self.assertEqual(len(rules.web_access_denied_burst(legacy_denials,
                                                           params("web_access_denied_burst"))), 1)


if __name__ == "__main__":
    unittest.main()
