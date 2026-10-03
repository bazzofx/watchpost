"""Synthetic, clearly labeled demo data and reproducible attack simulations.

Every generated event has source "demo:<scenario>" and is stored with synthetic=1.
External-looking IPs come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so they never refer to real hosts.

Each scenario carries ground-truth labels (which rules *should* fire), which the
evaluation harness uses to measure rule accuracy.

CLI (only sends to loopback unless --allow-remote is given):
    python3 -m watchpost.simulate --list
    python3 -m watchpost.simulate --scenario brute_force --token wp_... [--url http://127.0.0.1:8080]
    python3 -m watchpost.simulate --scenario all --out demo.jsonl
"""

import argparse
import json
import random
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, time, timedelta, timezone

from .db import iso, utcnow
from .normalize import classify_web_request

EMPLOYEES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"]


def demo_day(now=None):
    """Most recent weekday strictly before today (UTC), so 'business hours' is well defined."""
    day = (now or utcnow()).date() - timedelta(days=1)
    while day.weekday() >= 5:
        day -= timedelta(days=1)
    return day


def _at(day, hh, mm, ss=0):
    return datetime.combine(day, time(hh, mm, ss), tzinfo=timezone.utc)


def _event(ts, scenario, event_type, user, ip, host="web01", message=None, **extra):
    return {
        "ts": iso(ts), "source": f"demo:{scenario}", "host": host, "event_type": event_type,
        "user": user, "src_ip": ip, "dest_ip": "10.0.0.10",
        "message": message or f"[SYNTHETIC] {event_type} for {user} from {ip}",
        **extra,
    }


def baseline(day, rng):
    events = []
    for i, user in enumerate(EMPLOYEES):
        ip = f"10.0.1.{20 + i}"
        start = _at(day, 8, 30) + timedelta(minutes=rng.randint(0, 60))
        if rng.random() < 0.4:  # the occasional typo
            events.append(_event(start - timedelta(seconds=20), "baseline", "auth_failure", user, ip))
        events.append(_event(start, "baseline", "auth_success", user, ip))
        events.append(_event(start + timedelta(hours=rng.randint(3, 7)), "baseline", "auth_success", user, ip,
                             host="files01"))
    return events


def brute_force(day, rng):
    ip, start = "203.0.113.45", _at(day, 14, 5)
    return [_event(start + timedelta(seconds=i * 4 + rng.randint(0, 2)), "brute_force", "auth_failure",
                   "admin", ip, message="[SYNTHETIC] Failed password for admin (brute-force simulation)")
            for i in range(40)]


def password_spray(day, rng):
    ip, start = "198.51.100.23", _at(day, 15, 20)
    targets = EMPLOYEES + ["hr_admin", "payroll", "backup", "helpdesk"]
    return [_event(start + timedelta(seconds=i * 35 + rng.randint(0, 5)), "password_spray", "auth_failure",
                   user, ip, message="[SYNTHETIC] Failed password (spray simulation: 'Spring2026!')")
            for i, user in enumerate(targets)]


def compromise(day, rng):
    ip, start = "192.0.2.77", _at(day, 16, 40)
    events = [_event(start + timedelta(seconds=i * 20), "compromise", "auth_failure", "dave", ip)
              for i in range(7)]
    events.append(_event(start + timedelta(seconds=160), "compromise", "auth_success", "dave", ip,
                         message="[SYNTHETIC] Accepted password for dave after repeated failures"))
    return events


def off_hours_admin(day, rng):
    return [_event(_at(day, 3, 12), "off_hours_admin", "auth_success", "root", "10.0.9.9", host="db01",
                   message="[SYNTHETIC] Accepted publickey for root at 03:12 UTC")]


def noisy_scanner(day, rng):
    """Benign but noisy: an internal vulnerability scanner. A deliberate false-positive source."""
    ip, start = "10.0.50.5", _at(day, 11, 0)
    return [_event(start + timedelta(seconds=i * 15), "noisy_scanner", "auth_failure", "svc_scan", ip,
                   message="[SYNTHETIC] Authorized internal scanner credential check")
            for i in range(12)]


def noisy_scanner_repeat(day, rng):
    """The same scanner on its afternoon pass; gives the feedback loop a second false positive."""
    ip, start = "10.0.50.5", _at(day, 13, 0)
    return [_event(start + timedelta(seconds=i * 15), "noisy_scanner", "auth_failure", "svc_scan", ip,
                   message="[SYNTHETIC] Authorized internal scanner credential check")
            for i in range(12)]


SCAN_PROBES = ["/.env", "/.git/config", "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/",
               "/.aws/credentials", "/server-status", "/cgi-bin/test.cgi", "/actuator/env",
               "/index.php?id=1%27%20or%20%271%27=%271", "/search?q=1%20union%20select%20password"]


def web_scan(day, rng):
    ip, start = "203.0.113.80", _at(day, 10, 10)
    events = [_event(start + timedelta(seconds=i * 5 + rng.randint(0, 3)), "web_scan", "web_scan", None, ip,
                     message=f"GET {path} -> 404 [SYNTHETIC scanner probe]", bytes=162)
              for i, path in enumerate(SCAN_PROBES)]
    events += [_event(start + timedelta(seconds=30 * i), "web_scan", "web_request", None, f"10.0.1.{20 + i}",
                      message=f"GET /app/dashboard -> 200 [SYNTHETIC]", bytes=5120) for i in range(4)]
    return events


def port_sweep(day, rng):
    ip, start = "198.51.100.140", _at(day, 12, 15)
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080]
    events = [_event(start + timedelta(seconds=i * 2), "port_sweep", "fw_deny", None, ip, host="fw01",
                     message=f"[SYNTHETIC] firewall deny {ip} -> 10.0.0.10:{port}/tcp", dest_port=port)
              for i, port in enumerate(ports)]
    events.append(_event(start + timedelta(seconds=90), "port_sweep", "fw_allow", None, "10.0.1.20", host="fw01",
                         message="[SYNTHETIC] firewall allow 10.0.1.20 -> 10.0.0.10:443/tcp", dest_port=443,
                         bytes=48_000))
    return events


# Folder and file names a content-discovery wordlist would try. Deliberately none of these is a
# substring of a SCAN_PATHS entry, so this scenario exercises web_path_discovery without also
# tripping web_scanner: the point is enumeration that the scanner-pattern rule cannot see.
DISCOVERY_PATHS = [
    "/admin", "/administrator", "/backup", "/backups", "/old", "/test", "/dev", "/staging",
    "/private", "/tmp", "/logs", "/db", "/database", "/sql", "/uploads", "/files",
    "/download", "/downloads", "/config", "/settings", "/setup", "/install", "/portal",
    "/intranet", "/internal", "/staff", "/users", "/accounts", "/reports", "/export",
    "/api/v1/users", "/api/v2/orders", "/v1", "/docs", "/swagger", "/metrics",
]


def path_discovery(day, rng):
    """One client walking a folder wordlist: many distinct paths, nearly all 404."""
    ip, start = "203.0.113.61", _at(day, 13, 10)
    events = [_event(start + timedelta(seconds=i * 3 + rng.randint(0, 2)), "path_discovery",
                     "web_request", None, ip, outcome="failure", bytes=146,
                     message=f"GET {path} -> 404 [SYNTHETIC] directory enumeration")
              for i, path in enumerate(DISCOVERY_PATHS)]
    # Enumeration finds something every so often.
    events.append(_event(start + timedelta(seconds=45), "path_discovery", "web_request", None, ip,
                         outcome="failure", bytes=153,
                         message="GET /uploads -> 403 [SYNTHETIC] directory listing denied"))
    # Ordinary readers alongside: a few known paths, all successful. These must not alert.
    for i, path in enumerate(["/", "/pricing", "/docs", "/about", "/pricing", "/"]):
        events.append(_event(start + timedelta(seconds=i * 20), "path_discovery", "web_request",
                             None, f"10.0.1.{40 + i}", outcome="success", bytes=8400,
                             message=f"GET {path} -> 200 [SYNTHETIC] normal browsing"))
    return events


def request_burst(day, rng):
    """One client hammering a few URLs: high volume, almost no path variety."""
    ip, start = "198.51.100.77", _at(day, 11, 20)
    paths = ["/api/orders", "/api/orders/1", "/health"]
    events = [_event(start + timedelta(milliseconds=150 * i), "request_burst", "web_request", None, ip,
                     outcome="success", bytes=512,
                     message=f"GET {paths[i % len(paths)]} -> 200 [SYNTHETIC] rapid sequence")
              for i in range(240)]
    # A reader loading one page and its assets: bursty, but nowhere near the threshold.
    for i in range(40):
        events.append(_event(start + timedelta(seconds=i * 0.5), "request_burst", "web_request", None,
                             "10.0.1.55", outcome="success", bytes=2048,
                             message=f"GET /assets/{i % 8}.png -> 200 [SYNTHETIC] page load"))
    return events


def _access(ts, scenario, ip, method, target, status, size=180, note=""):
    """One access-log event, built the way the parser would build it.

    The event type comes from normalize.classify_web_request rather than being written by hand, so a
    scenario cannot claim a type the real parser would never produce — an injection payload is
    `web_scan`, not `web_request`, and a 5xx is `web_error`. `http_status` is set here too, since
    that is what normalize_weblog_line stores.
    """
    return _event(ts, scenario, classify_web_request(target, status), None, ip,
                  outcome="success" if status < 400 else "failure", http_status=status, bytes=size,
                  message=f"{method} {target} -> {status} [SYNTHETIC] {note}".strip())


def web_login_abuse(day, rng):
    """One client working through login endpoints: twelve refusals, two different codes.

    Eight are 401s on a form that exists, four are 403s from a blocked WordPress login. The four are
    deliberately under web_scanner's threshold of five, so this scenario shows the login rule reading
    both `web_request` and `web_scan` events without also tripping the scanner rule.
    """
    ip, start = "203.0.113.90", _at(day, 15, 5)
    events = [_access(start + timedelta(seconds=i * 12), "web_login_abuse", ip, "POST", "/login", 401,
                      note="wrong password")
              for i in range(8)]
    events += [_access(start + timedelta(seconds=120 + i * 15), "web_login_abuse", ip, "POST",
                       "/wp-login.php", 403, size=153, note="login form blocked by rule")
               for i in range(4)]
    return events


def web_auth_brute_force(day, rng):
    """Twelve 401s against one endpoint over two minutes: guesses at a single form."""
    ip, start = "198.51.100.201", _at(day, 15, 30)
    return [_access(start + timedelta(seconds=i * 9), "web_auth_brute_force", ip, "POST", "/login", 401,
                    note="credential guessing")
            for i in range(12)]


def web_injection(day, rng):
    """Three attack payloads in under a minute, two of which land in the request line as web_scan.

    Targets are percent-encoded, as nginx records them. The middle one returns 200 because reflected
    XSS succeeds, and the first returns 500 because the injection broke the query.
    """
    ip, start = "192.0.2.55", _at(day, 16, 0)
    return [
        _access(start, "web_injection", ip, "GET", "/product?id=1%27%20OR%20%271%27=%271", 500, size=210,
                note="SQL injection in the id parameter"),
        _access(start + timedelta(seconds=20), "web_injection", ip, "GET",
                "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, size=1420, note="reflected XSS"),
        _access(start + timedelta(seconds=40), "web_injection", ip, "GET", "/api/tools?cmd=%3Bid", 200,
                size=980, note="command injection"),
    ]


def web_sensitive_files(day, rng):
    """Four secret-bearing files served instead of refused.

    Three of them are scanner-shaped paths, so the events arrive as web_scan — under five of them, so
    web_scanner stays quiet. The fourth is an ordinary request for a file that should not be
    reachable at all.
    """
    ip, start = "203.0.113.111", _at(day, 16, 20)
    targets = ["/.env", "/.git/config", "/.aws/credentials", "/wp-config.php"]
    return [_access(start + timedelta(seconds=i * 8), "web_sensitive_files", ip, "GET", target, 200,
                    size=512 + i * 64, note="served, not refused")
            for i, target in enumerate(targets)]


def web_access_denied(day, rng):
    """One client refused 24 times in two minutes while walking protected paths.

    The paths are deliberately not scanner signatures and not login endpoints: no path looks like a
    known probe, so nothing here is caught by web_scanner or web_login_abuse, and only the rule that
    counts 403s has anything to say. Ten distinct paths, well under the breadth threshold.
    """
    ip, start = "198.51.100.66", _at(day, 16, 45)
    paths = ["/admin/users", "/admin/settings", "/internal/reports", "/internal/keys",
             "/api/v1/tenants", "/api/v1/billing", "/staff/directory", "/reports/export",
             "/settings/security", "/portal/download"]
    return [_access(start + timedelta(seconds=i * 5), "web_access_denied", ip, "GET",
                    paths[i % len(paths)], 403, size=146, note="not authorised")
            for i in range(24)]


def web_server_errors(day, rng):
    """One client answered with twelve 5xx responses: a request that breaks the application."""
    ip, start = "192.0.2.201", _at(day, 17, 5)
    paths = ["/api/checkout", "/api/checkout/submit", "/report/export"]
    return [_access(start + timedelta(seconds=i * 7), "web_server_errors", ip, "POST",
                    paths[i % len(paths)], 500, size=320, note="unhandled error")
            for i in range(12)]


ERROR_PROBE_PATHS = ["/uploads", "/files/private", "/backup", "/.well-known/../config",
                     "/download", "/media", "/assets/private", "/archive"]


def web_error_probe(day, rng):
    """Twenty-two nginx error-log lines naming a request, from one client.

    Access logging is off on this vhost, so the error log is the only record: every event here is
    `web_error` with no response code at all. Eight distinct paths, so the breadth rule stays quiet.
    """
    ip, start = "203.0.113.222", _at(day, 17, 30)
    events = []
    for i in range(22):
        path = ERROR_PROBE_PATHS[i % len(ERROR_PROBE_PATHS)]
        events.append(_event(start + timedelta(seconds=i * 6), "web_error_probe", "web_error", None, ip,
                             outcome="failure",
                             message=f'GET {path} [error] open() "/var/www/html{path}" failed '
                                     f"(2: No such file or directory), client: {ip}, "
                                     f'server: shop.example, request: "GET {path} HTTP/1.1"'))
    return events


def impossible_travel(day, rng):
    return [
        _event(_at(day, 9, 0), "impossible_travel", "auth_success", "erin", "10.0.1.24", host="mail01",
               message="[SYNTHETIC] Accepted password for erin (office, Riverton HQ)"),
        _event(_at(day, 9, 25), "impossible_travel", "vpn_login", "erin", "203.0.113.150", host="vpn01",
               message="[SYNTHETIC] VPN session for erin from Emberfield 25 minutes later"),
    ]


def privilege_escalation(day, rng):
    ip, start = "192.0.2.140", _at(day, 17, 30)
    events = [_event(start + timedelta(seconds=i * 20), "privilege_escalation", "auth_failure", "frank", ip)
              for i in range(3)]
    events.append(_event(start + timedelta(seconds=60), "privilege_escalation", "auth_success", "frank", ip,
                         message="[SYNTHETIC] Accepted password for frank after 3 failures"))
    events.append(_event(start + timedelta(minutes=6), "privilege_escalation", "privilege_escalation", "frank", ip,
                         message="[SYNTHETIC] frank : TTY=pts/0 ; PWD=/home/frank ; USER=root ; COMMAND=/bin/bash"))
    # A normal admin session: login without failures, then sudo. Must not alert.
    events.append(_event(_at(day, 16, 0), "privilege_escalation", "auth_success", "grace", "10.0.1.26"))
    events.append(_event(_at(day, 16, 5), "privilege_escalation", "privilege_escalation", "grace", "10.0.1.26",
                         message="[SYNTHETIC] grace : TTY=pts/1 ; PWD=/home/grace ; USER=root ; "
                                 "COMMAND=/usr/bin/systemctl restart nginx"))
    return events


def cloud_new_principal(day, rng):
    events = [_event(_at(day, 9, i * 5), "cloud_new_principal", "cloud_api_call", "ops-admin", "10.0.1.30",
                     host=None, message=f"[SYNTHETIC] {action} on {service}")
              for i, (action, service) in enumerate([("DescribeInstances", "ec2.amazonaws.com"),
                                                     ("ListBuckets", "s3.amazonaws.com"),
                                                     ("ListUsers", "iam.amazonaws.com")])]
    # A known principal changing IAM is routine.
    events.append(_event(_at(day, 9, 40), "cloud_new_principal", "cloud_iam_change", "ops-admin", "10.0.1.30",
                         host=None, message="[SYNTHETIC] AttachUserPolicy on iam.amazonaws.com"))
    # A principal never seen before creates a user and an access key.
    ip = "203.0.113.150"
    for i, action in enumerate(["CreateUser", "CreateAccessKey", "AttachUserPolicy"]):
        events.append(_event(_at(day, 17, 45) + timedelta(seconds=i * 30), "cloud_new_principal", "cloud_iam_change", "svc-deploy-tmp",
                             ip, host=None, message=f"[SYNTHETIC] {action} on iam.amazonaws.com"))
    return events


def exfiltration(day, rng):
    ip, start = "203.0.113.150", _at(day, 18, 0)
    events = [_event(start + timedelta(seconds=i * 15), "exfiltration", "cloud_data_access", "svc-deploy-tmp", ip,
                     host=None, message="[SYNTHETIC] GetObject on s3.amazonaws.com (customer-exports)",
                     bytes=50_000_000 + rng.randint(0, 1_000_000))
              for i in range(40)]
    events += [_event(_at(day, 11, i * 5), "exfiltration", "cloud_data_access", "analytics", "10.0.1.31",
                      host=None, message="[SYNTHETIC] GetObject on s3.amazonaws.com (reports)", bytes=1_000_000)
               for i in range(10)]
    return events


# expected: rule_id -> group_key the alert should be keyed on. Anything else firing is a false positive.
SCENARIOS = {
    "baseline": {"build": baseline, "malicious": False, "expected": {},
                 "description": "Normal office logins with occasional typos."},
    "brute_force": {"build": brute_force, "malicious": True,
                    "expected": {"brute_force_ip": "203.0.113.45", "account_repeated_failures": "admin"},
                    "description": "40 failed logins for 'admin' from one IP in under 3 minutes."},
    "password_spray": {"build": password_spray, "malicious": True,
                       "expected": {"password_spray": "198.51.100.23"},
                       "description": "One IP tries one password against 12 accounts over 7 minutes."},
    "compromise": {"build": compromise, "malicious": True,
                   "expected": {"success_after_failures": "dave|192.0.2.77"},
                   "description": "7 failures for 'dave', then a successful login from the same IP."},
    "off_hours_admin": {"build": off_hours_admin, "malicious": True,
                        "expected": {"off_hours_privileged_login": None},
                        "description": "root logs in at 03:12 UTC."},
    "noisy_scanner": {"build": noisy_scanner, "malicious": False, "expected": {},
                      "description": "Authorized internal scanner (10.0.50.5) - benign, but trips brute-force."},
    "noisy_scanner_repeat": {"build": noisy_scanner_repeat, "malicious": False, "expected": {},
                             "description": "The scanner's second pass later the same day."},
    "web_scan": {"build": web_scan, "malicious": True,
                 "expected": {"web_scanner": "203.0.113.80", "web_injection_attempt": "203.0.113.80"},
                 "description": "One IP probes /.env, /wp-login.php, .git and injection strings in a minute."},
    "port_sweep": {"build": port_sweep, "malicious": True, "expected": {"firewall_port_sweep": "198.51.100.140"},
                   "description": "The firewall blocks one IP on 20 different ports in 40 seconds."},
    "impossible_travel": {"build": impossible_travel, "malicious": True,
                          "expected": {"impossible_geo_login": "erin|10.0.1.24|203.0.113.150"},
                          "description": "erin logs in at HQ, then over VPN from another continent 25 minutes later."},
    "privilege_escalation": {"build": privilege_escalation, "malicious": True,
                             "expected": {"privilege_escalation_after_login": "frank|web01"},
                             "description": "3 failures, a login, then sudo to root; a normal admin sudo alongside."},
    "cloud_new_principal": {"build": cloud_new_principal, "malicious": True,
                            "expected": {"cloud_iam_change_by_new_principal": "svc-deploy-tmp"},
                            "description": "A never-seen principal creates a user and access key; a known admin's "
                                           "IAM change does not alert."},
    "exfiltration": {"build": exfiltration, "malicious": True,
                     "expected": {"data_exfil_volume": "svc-deploy-tmp"},
                     "description": "About 2 GB read from cloud storage in 10 minutes; normal report reads alongside."},
    # Appended last so the seeded rng sequence for the scenarios above is unchanged.
    "path_discovery": {"build": path_discovery, "malicious": True,
                       "expected": {"web_path_discovery": "203.0.113.61"},
                       "description": "One client walks 37 folder names in under three minutes, almost all "
                                      "404. None of the paths is a known scanner signature, so web_scanner "
                                      "stays quiet and only the breadth rule fires."},
    "request_burst": {"build": request_burst, "malicious": True,
                      "expected": {"web_request_burst": "198.51.100.77"},
                      "description": "One client sends 240 requests in 36 seconds to three URLs, while a "
                                     "reader loads a page and its assets alongside."},
    # The OWASP web rules. Appended last for the same reason as the two above: the shared rng
    # sequence for every scenario before them must not shift, or their synthetic data changes.
    "web_login_abuse": {"build": web_login_abuse, "malicious": True,
                        "expected": {"web_login_abuse": "203.0.113.90"},
                        "description": "One client makes twelve failed login requests in under three "
                                       "minutes, across a real form (401) and a blocked WordPress login "
                                       "(403). Only eight hit the real form, so the narrower "
                                       "per-endpoint 401 rule stays quiet."},
    "web_auth_brute_force": {"build": web_auth_brute_force, "malicious": True,
                             "expected": {"web_auth_brute_force": "198.51.100.201",
                                          "web_login_abuse": "198.51.100.201"},
                             "description": "Twelve 401s against one login endpoint in under two "
                                            "minutes. Labelled for both credential rules, because "
                                            "repeated failed logins on one form are both."},
    "web_injection": {"build": web_injection, "malicious": True,
                      "expected": {"web_injection_attempt": "192.0.2.55"},
                      "description": "SQL injection, reflected XSS, and command injection in one "
                                     "request each. The classifier types two of them web_scan and one "
                                     "web_request, so a rule that read only one type would miss some. "
                                     "Under web_scanner's threshold of five, so the single-request "
                                     "rule is the only thing here that fires."},
    "web_sensitive_files": {"build": web_sensitive_files, "malicious": True,
                            "expected": {"web_sensitive_file_served": "203.0.113.111"},
                            "description": "/.env, /.git/config, /.aws/credentials and wp-config.php "
                                           "all answered 200 with content. The probe-only version of "
                                           "this traffic is the web_scan scenario, where every one of "
                                           "those paths is a 404 and this rule stays quiet."},
    "web_access_denied": {"build": web_access_denied, "malicious": True,
                          "expected": {"web_access_denied_burst": "198.51.100.66"},
                          "description": "One client refused 24 times with 403 in two minutes, across "
                                         "ten protected paths that match no scanner signature and no "
                                         "login endpoint."},
    "web_server_errors": {"build": web_server_errors, "malicious": True,
                          "expected": {"web_server_error_burst": "192.0.2.201"},
                          "description": "Twelve 5xx responses to one client in under two minutes, "
                                         "from the access log, so the error-log rule stays quiet."},
    "web_error_probe": {"build": web_error_probe, "malicious": True,
                        "expected": {"web_error_probe_burst": "203.0.113.222"},
                        "description": "Twenty-two nginx error-log lines naming a request from one "
                                       "client, on a vhost with access logging off: no response codes "
                                       "at all, so only the error-log rule can see them."},
}


def build(scenario_names=None, seed=7, now=None):
    """Return {scenario: [events]} for the requested scenarios (default: all)."""
    rng = random.Random(seed)
    day = demo_day(now)
    names = scenario_names or list(SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        raise ValueError(f"unknown scenario(s): {', '.join(unknown)}")
    return {name: SCENARIOS[name]["build"](day, rng) for name in names}


# --- CLI ---------------------------------------------------------------------------

def _is_loopback(url):
    host = urllib.parse.urlparse(url).hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Send labeled synthetic attack scenarios to a local Watchpost.")
    parser.add_argument("--scenario", default="all", help="scenario name or 'all'")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    parser.add_argument("--token", help="ingest API token (or set SIEM_INGEST_TOKEN)")
    parser.add_argument("--out", help="write JSONL to this file instead of sending")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--allow-remote", action="store_true",
                        help="permit a non-loopback URL (only for a Watchpost instance you own)")
    args = parser.parse_args(argv)

    if args.list:
        for name, spec in SCENARIOS.items():
            print(f"{name:22} {'malicious' if spec['malicious'] else 'benign':9}  {spec['description']}")
        return 0

    names = None if args.scenario == "all" else [args.scenario]
    batches = build(names, seed=args.seed)

    if args.out:
        with open(args.out, "w") as handle:
            for events in batches.values():
                for event in events:
                    handle.write(json.dumps(event) + "\n")
        print(f"wrote {sum(map(len, batches.values()))} synthetic events to {args.out}")
        return 0

    import os
    token = args.token or os.environ.get("SIEM_INGEST_TOKEN")
    if not token:
        parser.error("an ingest token is required (--token or SIEM_INGEST_TOKEN)")
    if not _is_loopback(args.url) and not args.allow_remote:
        parser.error("refusing to send to a non-loopback URL without --allow-remote")

    for name, events in batches.items():
        body = json.dumps({"source": f"demo:{name}", "synthetic": True, "events": events}).encode()
        request = urllib.request.Request(
            args.url.rstrip("/") + "/api/ingest", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            print(f"{name}: HTTP {exc.code} {exc.read().decode()[:200]}", file=sys.stderr)
            return 1
        det = result["detection"]
        print(f"{name:22} accepted={result['accepted']:3} rejected={result['rejected']} "
              f"detection={det['status']} alerts_created={det.get('alerts_created', 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
