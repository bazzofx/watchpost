"""Detection rule logic.

Each rule is a pure function: (events, params) -> list of findings.
Events are dicts with at least id, ts, event_type, user, src_ip (and, for the 2.0 rules,
host, dest_ip, dest_port, bytes, http_status, message).
A finding is {"group_key", "event_ids", "first_seen", "last_seen", "title", "explanation"}.
Every rule also lists the MITRE ATT&CK techniques it maps to (see attack.py).

Rules are deliberately simple, threshold-based, and explainable. No machine learning.
"""

from collections import Counter, defaultdict, deque
from urllib.parse import unquote_plus

import re

from . import geo
from . import search_rules
from . import sigma
from .attack import techniques
from .sources import log_source_silent
from .db import parse_iso

LOGIN_SUCCESS_TYPES = ("auth_success", "vpn_login")

DEFAULT_RULES = [
    {
        "id": "brute_force_ip",
        "name": "Brute-force login attempts from one IP",
        "description": "Fires when a single source IP produces at least `threshold` failed logins "
                       "within `window_seconds`. Typical of password guessing against one or a few accounts.",
        "techniques": techniques("T1110.001"),
        "severity": "high",
        "params": {"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "password_spray",
        "name": "Password spraying across many accounts",
        "description": "Fires when a single source IP fails to log in as at least `distinct_users` "
                       "different accounts within `window_seconds`. Spraying tries a few common passwords "
                       "across many users to stay under per-account lockout limits.",
        "techniques": techniques("T1110.003"),
        "severity": "high",
        "params": {"distinct_users": 5, "window_seconds": 600, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "account_repeated_failures",
        "name": "Repeated failures against one account",
        "description": "Fires when one account has at least `threshold` failed logins within "
                       "`window_seconds`, from any number of IPs. Catches distributed guessing that "
                       "per-IP rules miss.",
        "techniques": techniques("T1110"),
        "severity": "medium",
        "params": {"threshold": 8, "window_seconds": 900, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "success_after_failures",
        "name": "Successful login after repeated failures",
        "description": "Fires when an account logs in successfully after at least `failures` failed "
                       "attempts for that account within the preceding `window_seconds`. A likely sign "
                       "that guessing succeeded; treat as possible account compromise.",
        "techniques": techniques("T1110", "T1078"),
        "severity": "critical",
        "params": {"failures": 5, "window_seconds": 600, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "off_hours_privileged_login",
        "name": "Privileged login outside business hours",
        "description": "Fires when an account in `privileged_users` logs in successfully outside "
                       "`business_start_hour`-`business_end_hour` (UTC). Unusual timing for admin "
                       "access deserves a second look.",
        "techniques": techniques("T1078.003"),
        "severity": "medium",
        "params": {
            "privileged_users": ["root", "admin", "administrator"],
            "business_start_hour": 8, "business_end_hour": 18,
            "ignore_ips": [], "ignore_users": [],
        },
    },
    {
        "id": "web_scanner",
        "name": "Web vulnerability scanning from one IP",
        "description": "Fires when one source IP sends at least `threshold` requests that look like scanning "
                       "(probes for /.env, /wp-login.php, .git, injection strings, or scanner user agents) "
                       "within `window_seconds`. Usually the reconnaissance step before an exploit attempt.",
        "techniques": techniques("T1595.002", "T1595.003", "T1190"),
        "severity": "medium",
        "params": {"threshold": 5, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_path_discovery",
        "name": "Brute-force path discovery on the web server",
        "description": "Fires when one source IP requests at least `distinct_paths` different paths within "
                       "`window_seconds` and at least `min_failure_percent` of those requests did not "
                       "succeed. That combination is what directory and file enumeration looks like: a "
                       "wordlist walk over /admin, /backup, /uploads and so on, nearly all of them 404. "
                       "Ordinary browsing asks for a handful of known paths and mostly succeeds, so it "
                       "does not reach the threshold. Catches enumeration that never touches a path in "
                       "web_scanner's pattern list, which is most of it.",
        "techniques": techniques("T1083", "T1595"),
        "severity": "medium",
        "params": {"distinct_paths": 30, "min_failure_percent": 70, "window_seconds": 300,
                   "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_rapid_discovery",
        "name": "Rapid path discovery on the web server",
        "description": "Fires when one source IP requests at least `distinct_paths` different paths within "
                       "`window_seconds` — a short, fast window — and at least `min_failure_percent` of "
                       "those requests did not succeed. This is the fast companion to web_path_discovery, "
                       "which catches a patient walk across 300 seconds; a content-discovery tool fires a "
                       "wordlist of hundreds of paths in seconds, so the short window is what separates the "
                       "two. A browser loading a page and its assets cannot open this many different, "
                       "mostly-missing paths in so little time.",
        "techniques": techniques("T1083", "T1595"),
        "severity": "medium",
        "params": {"distinct_paths": 25, "window_seconds": 15, "min_failure_percent": 90,
                   "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_request_burst",
        "name": "Rapid request burst from one IP",
        "description": "Fires when one source IP sends at least `threshold` requests to the web server "
                       "within `window_seconds`. A person clicking through a site, or a browser loading "
                       "one page and its assets, does not sustain a rate like this; a flood, a fast "
                       "scanner, or credential stuffing against a login form does. Complements "
                       "web_path_discovery: this one catches volume, that one catches breadth, so a "
                       "patient attacker is caught by the other rule.",
        "techniques": techniques("T1499"),
        "severity": "medium",
        "params": {"threshold": 200, "window_seconds": 60, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_login_abuse",
        "name": "Failed logins against a login endpoint from one address",
        "description": "Fires when one source IP makes at least `threshold` failed requests to a login "
                       "endpoint within `window_seconds`. Any refusal counts — 401, 403, or 404 on a "
                       "login path that was never there — because an attacker working through a list of "
                       "login URLs produces all three. `web_auth_brute_force` is the narrower rule that "
                       "insists on 401s against a single endpoint.",
        "techniques": techniques("T1110.001", "T1078"),
        "severity": "high",
        "params": {"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_injection_attempt",
        "name": "Attack payload in a web request",
        "description": "Fires on a single request whose path or query string carries an injection "
                       "payload: SQL injection, cross-site scripting, path traversal, command injection, "
                       "template injection, or XXE, encoded or plain. One request is enough, because a "
                       "payload like that is never part of using the site; before this rule the only "
                       "thing watching injection strings was web_scanner, which needs five requests in "
                       "five minutes, so a lone SQL injection was silent. Attempts from one address "
                       "within `window_seconds` are gathered into one alert.",
        "techniques": techniques("T1190", "T1059"),
        "severity": "high",
        "params": {"window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_sensitive_file_served",
        "name": "Sensitive file served to a client",
        "description": "Fires when a request for a secret-bearing file (.env, .git/config, "
                       ".aws/credentials, id_rsa, wp-config.php, a .sql or .bak backup, and similar) is "
                       "answered with content instead of a refusal. Success is the whole rule: a refused "
                       "request is only probing, which web_scanner and web_path_discovery cover, while a "
                       "200 means the file was served and the secret is out. A 3xx is not counted, so a "
                       "redirect to a login page does not read as a disclosure.",
        "techniques": techniques("T1552.001", "T1190"),
        "severity": "critical",
        "params": {"window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_access_denied_burst",
        "name": "Repeated access denials to one client",
        "description": "Fires when one source IP receives at least `threshold` responses with status 403 "
                       "within `window_seconds`. Each refusal confirms that something exists, so a run of "
                       "them is how broken access control is discovered by hand. Needs the http_status "
                       "column: an outcome of 'failure' alone cannot tell 403 from 404, and 404s across "
                       "many paths are ordinary enumeration.",
        "techniques": techniques("T1083", "T1078"),
        "severity": "medium",
        "params": {"threshold": 20, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_auth_brute_force",
        "name": "Password guessing against one login endpoint",
        "description": "Fires when one endpoint answers at least `threshold` requests from one source IP "
                       "with status 401 within `window_seconds`. The threshold is per endpoint, not per "
                       "client, which is what separates this from web_login_abuse: a scanner collecting "
                       "404s across hundreds of paths never reaches it, and a form being guessed at does. "
                       "A 401 is the server saying the credentials were wrong, so the count is a count of "
                       "guesses.",
        "techniques": techniques("T1110"),
        "severity": "high",
        "params": {"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_server_error_burst",
        "name": "Server errors caused by one client",
        "description": "Fires when one source IP is answered with at least `threshold` 5xx responses "
                       "within `window_seconds`: either requests that break the application are being "
                       "sent deliberately, or a fault is being exercised while it is still exploitable. "
                       "nginx error.log lines are excluded here (they carry no status) and counted by "
                       "web_error_probe_burst, so a probe recorded in both logs cannot be counted twice.",
        "techniques": techniques("T1190"),
        "severity": "medium",
        "params": {"threshold": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "web_error_probe_burst",
        "name": "Probing visible only in the error log",
        "description": "Fires when one source IP appears in at least `threshold` nginx error-log lines "
                       "that name a request, within `window_seconds`. Access logging can be switched off "
                       "per vhost while error logging stays on, and then the error log is the only record "
                       "that a probe happened. Those lines have no response code, which is what keeps this "
                       "rule from overlapping web_server_error_burst.",
        "techniques": techniques("T1595.003"),
        "severity": "medium",
        "params": {"threshold": 20, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "firewall_port_sweep",
        "name": "Port sweep blocked by the firewall",
        "description": "Fires when the firewall denies one source IP on at least `distinct_ports` different "
                       "destination ports within `window_seconds`. Looks for services to attack.",
        "techniques": techniques("T1046", "T1595.001"),
        "severity": "medium",
        "params": {"distinct_ports": 10, "window_seconds": 300, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "impossible_geo_login",
        "name": "Impossible travel between logins",
        "description": "Fires when the same account logs in (SSH, VPN, or other success) from two places at "
                       "least `min_distance_km` apart, faster than `max_speed_kmh` allows, within "
                       "`window_seconds`. Positions come from Watchpost's synthetic geo table for demo "
                       "address ranges only; unmapped addresses are never guessed and never alert.",
        "techniques": techniques("T1078", "T1133"),
        "severity": "high",
        "params": {"max_speed_kmh": 900, "min_distance_km": 500, "window_seconds": 21600,
                   "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "privilege_escalation_after_login",
        "name": "Privilege escalation soon after a suspicious login",
        "description": "Fires when an account elevates privileges (sudo, su, runas) within "
                       "`escalation_seconds` of a successful login that followed at least `failures` failed "
                       "attempts in the preceding `window_seconds`. Catches the step after a guessed password.",
        "techniques": techniques("T1548.003", "T1078"),
        "severity": "critical",
        "params": {"failures": 3, "window_seconds": 600, "escalation_seconds": 1800,
                   "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "cloud_iam_change_by_new_principal",
        "name": "Cloud IAM change by a new principal",
        "description": "Fires when a cloud principal changes IAM (creates users, access keys, or policies) "
                       "without any cloud activity of its own in the preceding `history_seconds`. Further "
                       "IAM changes by that principal within `window_seconds` join the same alert.",
        "techniques": techniques("T1098.001", "T1136.003", "T1078.004"),
        "severity": "high",
        "params": {"history_seconds": 86400, "window_seconds": 3600, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "data_exfil_volume",
        "name": "Large data transfer by one principal",
        "description": "Fires when one account (or, without an account, one source IP) moves at least "
                       "`bytes_threshold` bytes out through allowed firewall connections and cloud storage "
                       "reads, or makes at least `access_threshold` cloud data reads, within `window_seconds`. "
                       "By default the thresholds are flat: history and analyst verdicts never quiet this rule. "
                       "A principal that has an approved, unexpired tuning exception for this rule is not skipped: "
                       "the exception turns on a baseline for it instead. Its burst must then also be at least "
                       "`baseline_multiplier` times its own busiest `window_seconds` in the preceding "
                       "`history_seconds` (all of that history counts), so an excepted nightly backup that always "
                       "moves this much stays quiet and still alerts when it moves several times more. "
                       "`baseline_multiplier` 0 keeps the thresholds flat even for an excepted principal.",
        "techniques": techniques("T1530", "T1048"),
        "severity": "high",
        "params": {"bytes_threshold": 1_000_000_000, "access_threshold": 100, "window_seconds": 3600,
                   "baseline_multiplier": 3, "history_seconds": 604800, "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "unsanctioned_cloud_service",
        "name": "Use of an unsanctioned cloud service (shadow IT)",
        "description": "Fires when an account uses a cloud service that is not in `sanctioned_services`. A "
                       "listed name also covers its subdomains. The service is read from cloud audit events of "
                       "the form '<action> on <service>' (CloudTrail-style JSON, or a proxy/CASB feed sent as "
                       "JSON); events that name no service are skipped. Uses of one service by one account "
                       "within `window_seconds` join the same alert. Unsanctioned is not the same as hostile: "
                       "a newly approved tool alerts until the list is changed through review.",
        "techniques": techniques("T1567"),
        "severity": "medium",
        "params": {"sanctioned_services": ["amazonaws.com", "corp-drive.example"], "window_seconds": 3600,
                   "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "cloud_logging_disabled",
        "name": "Cloud audit logging stopped or deleted",
        "description": "Fires when a cloud audit event records an action in `logging_actions` (by default stopping or "
                       "deleting a CloudTrail trail, or deleting VPC flow logs). The action is read from messages of "
                       "the form '<action> on <service>'. A denied attempt is recorded the same way and also alerts: "
                       "check the trail status to see whether logging is off. UpdateTrail and PutEventSelectors are "
                       "not listed by default because the event carries only the action name, not the new settings, "
                       "so the rule cannot tell a change that turns logging off from one that leaves it on. Such "
                       "actions by one account within `window_seconds` join the same alert.",
        "techniques": techniques("T1562.008"),
        "severity": "high",
        "params": {"logging_actions": ["StopLogging", "DeleteTrail", "DeleteFlowLogs"], "window_seconds": 3600,
                   "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "admin_action_from_new_source",
        "name": "Privileged action from a new source address",
        "description": "Fires when an account makes a privileged action (privilege use or escalation, or a cloud IAM "
                       "change) from a source IP it used for none of its privileged actions in the preceding "
                       "`history_seconds`, and it made at least `min_prior_actions` privileged actions in that span. "
                       "Cold start: an account with less history has no baseline and never alerts, which includes "
                       "every account on a new install and an account whose first privileged action is the attack "
                       "(cloud_iam_change_by_new_principal covers a never-seen cloud principal). Events without a "
                       "source IP, such as most local sudo lines, are skipped and never guessed. Later privileged "
                       "actions from the same new source within `window_seconds` join the same alert.",
        "techniques": techniques("T1078", "T1078.004"),
        "severity": "medium",
        "params": {"history_seconds": 604800, "min_prior_actions": 3, "window_seconds": 3600,
                   "ignore_ips": [], "ignore_users": []},
    },
    {
        "id": "log_source_silent",
        "name": "Log source went silent",
        "description": "Fires when a log source (one source and host) that had a learned cadence stops sending: quiet "
                       "for more than 6x its median gap between arrivals, at least an hour, and twice its longest "
                       "recent gap (thresholds in watchpost/sources.py). Silence is measured by arrival time against "
                       "the wall clock, so it reads arrivals, not the events of the scanned time range. Sources still "
                       "learning (fewer than 10 gaps, or under 2 hours of history) never alert, and time inside an "
                       "approved maintenance window is not counted. One silence is one alert, however often detection "
                       "runs. A silent source is an outage or someone blocking logs; the alert cannot tell which.",
        "techniques": techniques("T1562.006"),
        "severity": "medium",
        "params": {"window_seconds": 3600},
    },
]

# Allowed parameters and validators, used to reject malformed rule change proposals.
PARAM_SCHEMA = {
    "threshold": ("int", 2, 10000),
    "distinct_users": ("int", 2, 10000),
    "failures": ("int", 1, 10000),
    "window_seconds": ("int", 10, 86400 * 7),
    "business_start_hour": ("int", 0, 23),
    "business_end_hour": ("int", 1, 24),
    "ignore_ips": ("list", 0, 500),
    "ignore_users": ("list", 0, 500),
    "privileged_users": ("list", 1, 500),
    "distinct_ports": ("int", 2, 65536),
    "distinct_paths": ("int", 3, 100000),
    "min_failure_percent": ("int", 1, 100),
    "max_speed_kmh": ("int", 100, 50000),
    "min_distance_km": ("int", 1, 20000),
    "escalation_seconds": ("int", 10, 86400),
    "history_seconds": ("int", 60, 86400 * 30),
    "bytes_threshold": ("int", 1, 10 ** 15),
    "access_threshold": ("int", 2, 1_000_000),
    "baseline_multiplier": ("int", 0, 1000),
    "sanctioned_services": ("list", 1, 500),
    "logging_actions": ("list", 1, 500),
    "min_prior_actions": ("int", 1, 10000),
}


class RuleConfigError(ValueError):
    pass


def validate_params(rule_id, params):
    import ipaddress

    if sigma.is_sigma(rule_id):  # an imported Sigma rule: its params are the compiled detection, not tunable
        try:
            return sigma.validate_params(params)
        except sigma.SigmaError as exc:
            raise RuleConfigError(str(exc))
    if search_rules.is_search(rule_id):  # a promoted saved search: only threshold and window_seconds are tunable
        try:
            return search_rules.validate_params(params)
        except search_rules.SearchRuleError as exc:
            raise RuleConfigError(str(exc))
    defaults = next((r["params"] for r in DEFAULT_RULES if r["id"] == rule_id), None)
    if defaults is None:
        raise RuleConfigError(f"unknown rule {rule_id!r}")
    if not isinstance(params, dict):
        raise RuleConfigError("params must be an object")
    unknown = set(params) - set(defaults)
    if unknown:
        raise RuleConfigError(f"unknown parameter(s) for {rule_id}: {', '.join(sorted(unknown))}")
    merged = dict(defaults)
    for key, value in params.items():
        kind, low, high = PARAM_SCHEMA[key]
        if kind == "int":
            if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
                raise RuleConfigError(f"{key} must be an integer between {low} and {high}")
        else:
            if not isinstance(value, list) or not low <= len(value) <= high:
                raise RuleConfigError(f"{key} must be a list with {low}-{high} entries")
            if not all(isinstance(v, str) and 0 < len(v) <= 128 for v in value):
                raise RuleConfigError(f"{key} entries must be non-empty strings")
            if key == "ignore_ips":
                for v in value:
                    try:
                        ipaddress.ip_address(v)
                    except ValueError:
                        raise RuleConfigError(f"ignore_ips entry {v!r} is not an IP address")
        merged[key] = value
    if merged.get("business_start_hour", 0) >= merged.get("business_end_hour", 24):
        raise RuleConfigError("business_start_hour must be before business_end_hour")
    return merged


def _epoch(event):
    if "_epoch" not in event:
        event["_epoch"] = parse_iso(event["ts"]).timestamp()
    return event["_epoch"]


# List parameters that decide which events a rule looks at, and the edit to each that hides activity.
# `list_entry` and `covers` are the only definition of what an entry matches: the rules below use them,
# and so does the review gate in improve.py, so the gate cannot read an entry differently from the rule.
HIDING_EDITS = {"ignore_ips": "added", "ignore_users": "added", "sanctioned_services": "added",
                "privileged_users": "removed", "logging_actions": "removed"}


def list_entry(param, value):
    """One list entry in the form the rules compare it in."""
    if param == "ignore_ips":
        return value
    return value.lower().lstrip(".") if param == "sanctioned_services" else value.lower()


def covers(param, entries, event):
    """Whether `event` matches any of `entries` (already passed through list_entry) of a list parameter."""
    if param == "ignore_ips":
        return event.get("src_ip") in entries
    if param == "sanctioned_services":  # the service itself or any subdomain of an entry
        service = _service(event)
        return bool(service) and any(service == s or service.endswith("." + s) for s in entries)
    if param == "logging_actions":
        return (_action(event) or "").lower() in entries
    return (event.get("user") or "").lower() in entries


def _filtered(events, params, event_type):
    types = {event_type} if isinstance(event_type, str) else set(event_type)
    ignore_ips = {list_entry("ignore_ips", v) for v in params.get("ignore_ips", [])}
    ignore_users = {list_entry("ignore_users", u) for u in params.get("ignore_users", [])}
    out = [
        e for e in events
        if e["event_type"] in types
        and not covers("ignore_ips", ignore_ips, e)
        and not covers("ignore_users", ignore_users, e)
    ]
    out.sort(key=lambda e: (_epoch(e), e["id"]))
    return out


def _clusters(events, window, qualifies, span=None):
    """Return clusters of events that fall inside at least one qualifying sliding window.

    `qualifies(window_events)` decides whether the window ending at each event meets the rule.
    `span(first, last)`, when given, decides the same for events[first:last + 1] by index, so a rule can
    answer from running totals instead of re-reading every window.
    Qualifying events closer than `window` seconds to each other are merged into one cluster.
    """
    marked = set()
    dq = deque()
    for idx, event in enumerate(events):
        dq.append(idx)
        while _epoch(event) - _epoch(events[dq[0]]) > window:
            dq.popleft()
        if span(dq[0], idx) if span else qualifies([events[i] for i in dq]):
            marked.update(dq)
    clusters, current = [], []
    for idx in sorted(marked):
        if current and _epoch(events[idx]) - _epoch(current[-1]) > window:
            clusters.append(current)
            current = []
        current.append(events[idx])
    if current:
        clusters.append(current)
    return clusters


def _finding(group_key, cluster, title, explanation):
    return {
        "group_key": group_key,
        "event_ids": [e["id"] for e in cluster],
        "first_seen": cluster[0]["ts"],
        "last_seen": cluster[-1]["ts"],
        "title": title,
        "explanation": explanation,
    }


def _group(events, key):
    groups = defaultdict(list)
    for event in events:
        value = event.get(key)
        if value:
            groups[value].append(event)
    return groups


def _group_users(events):
    """Group by account name, ignoring case."""
    groups = defaultdict(list)
    for event in events:
        if event.get("user"):
            groups[event["user"].lower()].append(event)
    return groups


def brute_force_ip(events, params):
    threshold, window = params["threshold"], params["window_seconds"]
    findings = []
    for ip, group in _group(_filtered(events, params, "auth_failure"), "src_ip").items():
        for cluster in _clusters(group, window, lambda w: len(w) >= threshold):
            users = Counter(e.get("user") or "?" for e in cluster)
            top = ", ".join(f"{u} ({n})" for u, n in users.most_common(3))
            findings.append(_finding(
                ip, cluster,
                f"Brute force from {ip}: {len(cluster)} failed logins",
                f"{ip} produced {len(cluster)} failed logins between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']}, meeting the threshold of {threshold} within {window}s. "
                f"Most targeted accounts: {top}.",
            ))
    return findings


def password_spray(events, params):
    needed, window = params["distinct_users"], params["window_seconds"]
    findings = []
    for ip, group in _group(_filtered(events, params, "auth_failure"), "src_ip").items():
        qualifies = lambda w: len({e.get("user") for e in w if e.get("user")}) >= needed
        for cluster in _clusters(group, window, qualifies):
            users = sorted({e.get("user") for e in cluster if e.get("user")})
            findings.append(_finding(
                ip, cluster,
                f"Password spray from {ip}: {len(users)} accounts targeted",
                f"{ip} failed to log in as {len(users)} different accounts "
                f"({', '.join(users[:8])}{'…' if len(users) > 8 else ''}) between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']}. Threshold: {needed} distinct accounts within {window}s.",
            ))
    return findings


def account_repeated_failures(events, params):
    threshold, window = params["threshold"], params["window_seconds"]
    findings = []
    for user, group in _group(_filtered(events, params, "auth_failure"), "user").items():
        for cluster in _clusters(group, window, lambda w: len(w) >= threshold):
            ips = sorted({e.get("src_ip") or "unknown" for e in cluster})
            findings.append(_finding(
                user.lower(), cluster,
                f"Repeated failures for account {user}: {len(cluster)} attempts",
                f"Account {user} had {len(cluster)} failed logins from {len(ips)} source IP(s) "
                f"({', '.join(ips[:5])}) between {cluster[0]['ts']} and {cluster[-1]['ts']}. "
                f"Threshold: {threshold} within {window}s.",
            ))
    return findings


def success_after_failures(events, params):
    needed, window = params["failures"], params["window_seconds"]
    failures = _group(_filtered(events, params, "auth_failure"), "user")
    failures = {u.lower(): v for u, v in failures.items()}
    findings = []
    for success in _filtered(events, params, LOGIN_SUCCESS_TYPES):
        user = (success.get("user") or "").lower()
        if not user or user not in failures:
            continue
        t = _epoch(success)
        prior = [f for f in failures[user] if 0 <= t - _epoch(f) <= window]
        if len(prior) < needed:
            continue
        ips = sorted({f.get("src_ip") or "unknown" for f in prior})
        same_ip = success.get("src_ip") in ips
        cluster = prior + [success]
        findings.append(_finding(
            f"{user}|{success.get('src_ip') or 'unknown'}", cluster,
            f"Possible compromise of {success.get('user')}: login from "
            f"{success.get('src_ip') or 'an unknown IP'} after {len(prior)} failures",
            f"{success.get('user')} logged in successfully from {success.get('src_ip') or 'an unknown IP'} "
            f"at {success['ts']} after {len(prior)} failed attempts in the preceding {window}s "
            f"(threshold {needed}). The failures came from {', '.join(ips[:5])}"
            f"{' — including the same IP as the success' if same_ip else ''}.",
        ))
    return findings


def off_hours_privileged_login(events, params):
    privileged = {list_entry("privileged_users", u) for u in params["privileged_users"]}
    start, end = params["business_start_hour"], params["business_end_hour"]
    findings = []
    for event in _filtered(events, params, LOGIN_SUCCESS_TYPES):
        user = (event.get("user") or "").lower()
        if not covers("privileged_users", privileged, event):
            continue
        dt = parse_iso(event["ts"])
        if start <= dt.hour < end and dt.weekday() < 5:
            continue
        when = "on a weekend" if dt.weekday() >= 5 else f"at {dt.strftime('%H:%M')} UTC"
        findings.append(_finding(
            f"{user}|{event.get('src_ip') or 'unknown'}|{dt.date().isoformat()}", [event],
            f"Off-hours privileged login: {event.get('user')}",
            f"Privileged account {event.get('user')} logged in from {event.get('src_ip') or 'an unknown IP'} "
            f"{when}, outside business hours ({start:02d}:00-{end:02d}:00 UTC, Mon-Fri).",
        ))
    return findings


# Event types the web parsers produce: the combined access log and the nginx error log.
WEB_TYPES = ("web_request", "web_scan", "web_error")

# Both web parsers begin the message with "METHOD PATH": the access parser appends " -> STATUS",
# the nginx error parser appends " [level]". Rules read path and status from here because the
# events table has no dedicated columns for them.
_WEB_MESSAGE = re.compile(r"^(?P<method>[A-Z]{3,10}) (?P<path>\S+?)(?: -> (?P<status>\d{3}))?(?=\s|$)")


def _web_request(event):
    """(method, path, status) from a web event's message. Any piece that is absent comes back None."""
    match = _WEB_MESSAGE.match(event.get("message") or "")
    if match is None:
        return None, None, None
    status = match.group("status")
    return match.group("method"), match.group("path"), int(status) if status else None


def _request_path(event):
    return _web_request(event)[1] or "?"


def web_scanner(events, params):
    threshold, window = params["threshold"], params["window_seconds"]
    findings = []
    for ip, group in _group(_filtered(events, params, "web_scan"), "src_ip").items():
        for cluster in _clusters(group, window, lambda w: len(w) >= threshold):
            paths = Counter(_request_path(e) for e in cluster)
            top = ", ".join(p[:60] for p, _ in paths.most_common(5))
            findings.append(_finding(
                ip, cluster,
                f"Web scanning from {ip}: {len(cluster)} probe requests",
                f"{ip} sent {len(cluster)} scanner-like requests between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']} ({len(paths)} distinct paths, e.g. {top}). "
                f"Threshold: {threshold} within {window}s.",
            ))
    return findings


def web_path_discovery(events, params):
    """Directory and file brute force: one client asking for many paths that mostly do not exist.

    Two conditions together, because either alone is normal: many *distinct* paths (browsing
    repeats a few known ones) that mostly *failed* (a site crawl succeeds). Events are counted
    per path, so the same request recorded in both access.log and error.log does not inflate the
    path count the way it would inflate an event count.
    """
    needed, window = params["distinct_paths"], params["window_seconds"]
    percent = params["min_failure_percent"]
    findings = []
    web = [e for e in _filtered(events, params, WEB_TYPES) if _web_request(e)[1]]
    for ip, group in _group(web, "src_ip").items():
        def qualifies(scope):
            if len({_web_request(e)[1] for e in scope}) < needed:
                return False
            failed = sum(1 for e in scope if e.get("outcome") == "failure")
            return failed * 100 >= percent * len(scope)

        for cluster in _clusters(group, window, qualifies):
            paths = sorted({_web_request(e)[1] for e in cluster})
            samples = ", ".join(paths[:8]) + (" …" if len(paths) > 8 else "")
            findings.append(_finding(
                ip, cluster,
                f"Path discovery from {ip}: {len(paths)} distinct paths",
                f"{ip} asked for {len(paths)} different paths in {len(cluster)} request(s) between "
                f"{cluster[0]['ts']} and {cluster[-1]['ts']}, and at least {percent}% of those requests "
                f"did not succeed — the shape of directory and file enumeration rather than browsing. "
                f"Paths included: {samples}. Threshold: {needed} distinct paths within {window}s.",
            ))
    return findings


def web_rapid_discovery(events, params):
    """Rapid directory/file enumeration: a burst of distinct, mostly-refused paths.

    This is the *fast* companion to `web_path_discovery`, which catches a patient walk (30+ distinct
    paths across 300 s). A content-discovery tool is not patient: it fires a wordlist of hundreds of
    paths in seconds, so this rule keys on a short window — `distinct_paths` different paths inside
    `window_seconds` (default 25 in 15 s) with at least `min_failure_percent` refused. A browser cannot
    open 25 different, mostly-missing paths in 15 s; a gobuster/ffuf run does exactly that.

    Efficiency is the second point. The breadth rule re-parses every web event's message on every
    window slide; on a busy host that is most of the traffic for no reason. Here each event is first
    split on `outcome` (a field set at ingest, no parsing): successful requests are only *counted*
    toward the failure ratio and never have their message regex-parsed. The path is extracted once per
    failing event, and the window advances with running counts and a per-path refcount, so the scan is
    one pass over the source's requests with memory proportional to the requests inside the window,
    not to every request the source ever made.
    """
    needed, window, percent = params["distinct_paths"], params["window_seconds"], params["min_failure_percent"]
    findings = []
    web = _filtered(events, params, WEB_TYPES)
    for ip, group in _group(web, "src_ip").items():
        # One lightweight record per event. The message regex runs here, exactly once per failing
        # event; a success is a bare time-stamp marker with no path, so ordinary browsing never
        # pays the parse cost. An error-log line that names no request is skipped entirely.
        series = []
        for event in group:
            if event.get("outcome") == "failure":
                path = _web_request(event)[1]
                if path is None:
                    continue  # e.g. an nginx error line with no request in it
                series.append((_epoch(event), path, event))
            else:
                series.append((_epoch(event), None, event))

        marked = set()
        window_paths = Counter()
        failed = 0
        left = 0
        for right, (t, path, _event) in enumerate(series):
            if path is not None:
                failed += 1
                window_paths[path] += 1
            while t - series[left][0] > window:
                expired = series[left][1]
                if expired is not None:
                    failed -= 1
                    window_paths[expired] -= 1
                    if window_paths[expired] == 0:
                        del window_paths[expired]
                left += 1
            total = right - left + 1
            if len(window_paths) >= needed and failed * 100 >= percent * total:
                marked.update(range(left, right + 1))

        clusters, current = [], []
        for idx in sorted(marked):
            if current and series[idx][0] - series[current[-1]][0] > window:
                clusters.append(current)
                current = []
            current.append(idx)
        if current:
            clusters.append(current)

        for cluster in clusters:
            chosen = [series[i][2] for i in cluster]
            paths = sorted({series[i][1] for i in cluster if series[i][1] is not None})
            attempts_failed = sum(1 for i in cluster if series[i][1] is not None)
            samples = ", ".join(paths[:8]) + (" …" if len(paths) > 8 else "")
            findings.append(_finding(
                ip, chosen,
                f"Rapid path discovery from {ip}: {len(paths)} paths in {len(chosen)} attempts",
                f"{ip} requested {len(paths)} different paths in {len(chosen)} attempts "
                f"({attempts_failed} of them refused) between {chosen[0]['ts']} and {chosen[-1]['ts']} — "
                f"at least {percent}% refused within a {window}s window, the shape of a directory/file "
                f"brute-force tool rather than browsing. Paths included: {samples}. Threshold: {needed} "
                f"distinct paths within {window}s. Every attempt is attached as evidence; the "
                f"{len(chosen)} attempts are the count to compare against the wordlist size.",
            ))
    return findings


def web_request_burst(events, params):
    """Volumetric: one client sending far more requests than a person or a browser would."""
    threshold, window = params["threshold"], params["window_seconds"]
    findings = []
    for ip, group in _group(_filtered(events, params, WEB_TYPES), "src_ip").items():
        for cluster in _clusters(group, window, lambda scope: len(scope) >= threshold):
            paths = {_web_request(e)[1] for e in cluster} - {None}
            findings.append(_finding(
                ip, cluster,
                f"Request burst from {ip}: {len(cluster)} requests",
                f"{ip} sent {len(cluster)} requests between {cluster[0]['ts']} and {cluster[-1]['ts']} "
                f"across {len(paths)} distinct path(s), meeting the threshold of {threshold} within "
                f"{window}s. Rates like this are automated: a flood, a fast scanner, or credential "
                f"stuffing against a login form. Add known heavy clients to ignore_ips.",
            ))
    return findings


# --- What the request asked for, and what came back -------------------------------------
#
# The rules below read two things the earlier web rules did not need: the *response code*, and the
# shape of the request target. `http_status` is a column now (added after 1.0), so the code is a
# field rather than something re-parsed out of the message.
#
# Note which event types each rule reads. A request to a scanner-shaped path (/.env, /wp-login.php)
# or one carrying an injection payload is classified `web_scan` by normalize.classify_web_request,
# not `web_request` — so a rule about *what was requested* has to read both, or it would miss the
# very requests it exists to catch. A 5xx from the access log is `web_error`, and so is every line
# from the nginx error log, so the status-based rules read all three.

WEB_ACCESS_TYPES = ("web_request", "web_scan")

# Endpoints a credential attack is aimed at. Matched against the path without its query string.
LOGIN_PATHS = ("/login", "/signin", "/sign-in", "/signon", "/logon", "/log-in", "/session",
               "/api/auth", "/api/login", "/api/session", "/auth/login", "/users/sign_in",
               "/wp-login.php", "/wp-admin", "/administrator", "/admin/login")

# Files that should never be downloadable. A *successful* request for one is a finding in its own
# right; a refused one is only probing, which the scanner and discovery rules already cover.
SENSITIVE_NAMES = ("/.env", "/.git/config", "/.git/head", "/.svn/", "/.aws/credentials",
                   "/.ssh/id_rsa", "/id_rsa", "/.htpasswd", "/.htaccess", "/.ds_store",
                   "/wp-config.php", "/configuration.php", "/config.php", "/settings.py",
                   "/web.config", "/phpinfo", "/credentials", "/secrets.yml", "/credentials.json",
                   "/dump.sql", "/backup.sql", "/db.sql", "/database.sql")
# Backups of a real file, by extension. Deliberately not every archive: a .zip under /downloads is
# ordinary, whereas index.php.bak is a copy of source that nobody meant to publish.
_SENSITIVE_SUFFIX = re.compile(r"\.(?:sql|sql\.gz|bak|old|orig|save|swp)$")

# Payloads that appear in a request target when someone is attacking the application rather than
# using it. Broad on purpose: a false positive here costs an analyst one alert, a false negative
# costs them the SQL injection. Matched against the target as written *and* URL-decoded, because a
# pattern that looked only at the decoded form would miss `%00` (which decodes to a NUL byte).
_INJECTION_PATTERNS = re.compile(
    r"union\s+(?:all\s+)?select"                       # SQLi
    r"|'\s*or\s+'?\d|\)\s*or\s*\(?\d|\bor\s+1\s*=\s*1|\band\s+1\s*=\s*1"
    r"|sleep\(\s*\d|benchmark\(|pg_sleep\(|waitfor\s+delay"
    r"|information_schema|extractvalue\(|updatexml\(|load_file\("
    r"|;\s*(?:--|#)|'\s*(?:--|#)|/\*!\d"               # statement terminators, MySQL version comments
    r"|<script|javascript:|onerror\s*=|onload\s*=|alert\(\s*\d|\"><img|<svg/onload"
    r"|\.\./|\.\.%2f|%2e%2e(?:%2f|/)|\.\.\\"           # traversal, plain and encoded
    r"|/etc/passwd|/etc/shadow|/proc/self"
    r"|php://(?:filter|input|expect)|data://|phar://|zip://"   # PHP stream wrappers (local file read)
    r"|;\s*(?:cat|id|whoami|uname|wget|curl|nc|bash|sh|python|chmod|rm)\b"
    r"|\|\s*(?:cat|id|whoami|nc|bash|sh)\b"
    r"|\$\(|`\s*(?:id|cat|whoami)"
    r"|\{\{|\}\}|<%=|%7b%7b"                           # template injection
    r"|<!entity|<!doctype\s+[^>]*\["                   # XXE
    r"|\*\)\(|\)\(cn=|\(cn="                           # LDAP filter injection
    r"|%00|%0d%0a"                                     # null byte, header splitting
)


def _web_status(event):
    """The HTTP response code for a web event, or None if there is none.

    The `http_status` column is authoritative. The "-> 404" suffix in the message is the fallback,
    for events stored before the column existed. None means the event carries no response code at
    all, which is exactly what an nginx error.log line looks like.
    """
    status = event.get("http_status")
    if status is not None:
        return status
    return _web_request(event)[2]


def _web_events(events, params, types=WEB_TYPES):
    """Web events that carry a request path, in time order, with the ignores already applied."""
    return [e for e in _filtered(events, params, types) if _web_request(e)[1]]


def _request_target(event):
    """The request target as written and URL-decoded, lowercased, for payload matching."""
    path = _web_request(event)[1] or ""
    return f"{path} {unquote_plus(path)}".lower()


def _path_only(target):
    """The path part of a request target: the query string is not part of the endpoint."""
    return (target or "").split("?", 1)[0]


def _is_login_path(target):
    path = _path_only(target).lower().rstrip("/")
    return any(path == p or path.startswith(p + "/") or path.endswith(p) for p in LOGIN_PATHS)


def _is_sensitive_path(target):
    path = _path_only(target).lower()
    return any(name in path for name in SENSITIVE_NAMES) or bool(_SENSITIVE_SUFFIX.search(path))


def _web_served(event):
    """True when the server returned content (2xx).

    A 3xx is not a disclosure: nginx commonly redirects an unknown path to a login page, so treating
    every non-4xx as "served" would make each probe look like a leaked file.
    """
    status = _web_status(event)
    return status is not None and 200 <= status < 300


def web_login_abuse(events, params):
    """Repeated failed logins against a login endpoint from one address.

    Counts failed requests rather than 401s alone, because a blocked login form answers 403 and a
    login URL that was never there answers 404 — an attacker working through a list of login paths
    produces all of them, and the shape of the campaign is the count, not the code.
    `web_auth_brute_force` is the narrower rule that insists on 401s against a single endpoint.
    """
    threshold, window = params["threshold"], params["window_seconds"]
    attempts = [e for e in _web_events(events, params, WEB_ACCESS_TYPES)
                if e.get("outcome") == "failure" and _is_login_path(_web_request(e)[1])]
    findings = []
    for ip, group in _group(attempts, "src_ip").items():
        for cluster in _clusters(group, window, lambda scope: len(scope) >= threshold):
            paths = Counter(_path_only(_request_path(e)) for e in cluster)
            top = ", ".join(p[:60] for p, _ in paths.most_common(4))
            findings.append(_finding(
                ip, cluster,
                f"Repeated failed logins from {ip}: {len(cluster)} attempts",
                f"{ip} made {len(cluster)} failed request(s) to login endpoints between "
                f"{cluster[0]['ts']} and {cluster[-1]['ts']}, across {len(paths)} endpoint(s): {top}. "
                f"Threshold: {threshold} within {window}s. A user who mistyped a password twice is "
                f"not this; check whether the attempts name the same account, which the event detail "
                f"shows.",
            ))
    return findings


def web_injection_attempt(events, params):
    """A request carrying an attack payload: SQLi, XSS, traversal, command or template injection.

    One request is enough, which is the point of the rule. An injection string is classified
    `web_scan` (see normalize.classify_web_request), and until this rule existed the only thing
    watching those was `web_scanner`, which needs five requests in five minutes — so a single SQL
    injection was silent. Repeated attempts from one address inside `window_seconds` are gathered
    into one alert rather than one per request.
    """
    window = params["window_seconds"]
    hits = [e for e in _web_events(events, params, WEB_ACCESS_TYPES)
            if _INJECTION_PATTERNS.search(_request_target(e))]
    findings = []
    for ip, group in _group(hits, "src_ip").items():
        for cluster in _clusters(group, window, lambda scope: scope):
            samples = ", ".join(sorted({_request_path(e)[:80] for e in cluster})[:3])
            findings.append(_finding(
                ip, cluster,
                f"Injection payload from {ip}: {len(cluster)} request(s)",
                f"{ip} sent {len(cluster)} request(s) carrying an attack payload between "
                f"{cluster[0]['ts']} and {cluster[-1]['ts']}: {samples}. One request is enough to "
                f"alert, because a payload like this is never part of using the site. The pattern set "
                f"covers SQL injection, cross-site scripting, path traversal, command injection, "
                f"template injection, XXE, and their URL-encoded forms.",
            ))
    return findings


def web_sensitive_file_served(events, params):
    """A request for a secret-bearing file that was answered with content.

    Success is the whole rule. A refused request for /.env is probing, and probing is what
    `web_scanner` and `web_path_discovery` are for; a 200 on /.env means the file was served, and
    the only question left is what it contained. That is also why nothing here counts 3xx: nginx
    redirecting an unknown path to a login page must not read as a disclosure.
    """
    window = params["window_seconds"]
    hits = [e for e in _web_events(events, params, WEB_ACCESS_TYPES)
            if _is_sensitive_path(_web_request(e)[1]) and _web_served(e)]
    findings = []
    for ip, group in _group(hits, "src_ip").items():
        for cluster in _clusters(group, window, lambda scope: scope):
            paths = sorted({_request_path(e) for e in cluster})
            codes = sorted({_web_status(e) for e in cluster if _web_status(e) is not None})
            findings.append(_finding(
                ip, cluster,
                f"Sensitive file served to {ip}: {paths[0][:60]}",
                f"{ip} asked for {len(paths)} sensitive path(s) between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']} and the server answered "
                f"{', '.join(str(c) for c in codes) or 'with content'} instead of refusing: "
                f"{', '.join(p[:80] for p in paths)}. This is a disclosure rather than an attempt: "
                f"treat whatever those files held as exposed and rotate it.",
            ))
    return findings


def web_access_denied_burst(events, params):
    """Many 403s to one client: authorisation probing that keeps finding things that exist."""
    threshold, window = params["threshold"], params["window_seconds"]
    denied = [e for e in _web_events(events, params) if _web_status(e) == 403]
    findings = []
    for ip, group in _group(denied, "src_ip").items():
        for cluster in _clusters(group, window, lambda scope: len(scope) >= threshold):
            paths = Counter(_path_only(_request_path(e)) for e in cluster)
            top = ", ".join(p[:60] for p, _ in paths.most_common(4))
            findings.append(_finding(
                ip, cluster,
                f"Access denied to {ip} {len(cluster)} times",
                f"{ip} received {len(cluster)} 403 responses between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']} across {len(paths)} path(s): {top}. Repeated refusals are how "
                f"broken access control is found: each 403 confirms that something is there, and the "
                f"client keeps asking. Threshold: {threshold} within {window}s. A page that loads "
                f"several forbidden assets can also produce 403s, so an authorised integration "
                f"belongs in ignore_ips.",
            ))
    return findings


def web_auth_brute_force(events, params):
    """401s against one endpoint from one address: guesses at a real login form.

    The threshold is per endpoint rather than per client, which is what separates this from
    `web_login_abuse`. A scanner collecting 404s across hundreds of paths never reaches it; a form
    being guessed at does. A 401 is the server saying the credentials were wrong, so the count is a
    count of guesses.
    """
    threshold, window = params["threshold"], params["window_seconds"]
    rejected = [e for e in _web_events(events, params) if _web_status(e) == 401]
    grouped = defaultdict(list)
    for event in rejected:
        grouped[(event["src_ip"], _path_only(_request_path(event))[:120])].append(event)
    findings = []
    for (ip, endpoint), group in grouped.items():
        # _filtered sorted the whole list by time, so each group kept that order.
        for cluster in _clusters(group, window, lambda scope: len(scope) >= threshold):
            findings.append(_finding(
                ip, cluster,
                f"Password guessing against {endpoint} from {ip}: {len(cluster)} rejections",
                f"{ip} received {len(cluster)} 401 responses on {endpoint} between "
                f"{cluster[0]['ts']} and {cluster[-1]['ts']}, so this is one form being guessed at "
                f"rather than a scan across many paths. Threshold: {threshold} within {window}s.",
            ))
    return findings


def web_server_error_burst(events, params):
    """Many 5xx answers to one client: requests that break the application.

    Only access-log events carry a response code, so nginx error.log lines are excluded here and
    counted by `web_error_probe_burst` instead. That split is deliberate: a probe recorded in both
    logs must not be counted by two rules, or the first of them to have a low threshold fires early.
    """
    threshold, window = params["threshold"], params["window_seconds"]
    broken = [e for e in _web_events(events, params) if (_web_status(e) or 0) >= 500]
    findings = []
    for ip, group in _group(broken, "src_ip").items():
        for cluster in _clusters(group, window, lambda scope: len(scope) >= threshold):
            paths = Counter(_path_only(_request_path(e)) for e in cluster)
            top = ", ".join(p[:60] for p, _ in paths.most_common(4))
            findings.append(_finding(
                ip, cluster,
                f"Server errors caused by {ip}: {len(cluster)} responses",
                f"{ip} was answered with {len(cluster)} 5xx response(s) between {cluster[0]['ts']} "
                f"and {cluster[-1]['ts']} across {len(paths)} path(s): {top}. Either a request that "
                f"breaks the application is being sent deliberately, or a fault is being exercised "
                f"while it is still exploitable. Threshold: {threshold} within {window}s.",
            ))
    return findings


def web_error_probe_burst(events, params):
    """Many nginx error-log lines that name a request, from one client.

    Access logging can be switched off per vhost while error logging stays on, and then the error
    log is the only record that a probe happened at all. Those lines carry no response code, which
    is also what separates this rule from `web_server_error_burst`: a 5xx from the access log has a
    status and an error.log line never does, so no event is counted by both.
    """
    threshold, window = params["threshold"], params["window_seconds"]
    probes = [e for e in _web_events(events, params, ("web_error",)) if _web_status(e) is None]
    findings = []
    for ip, group in _group(probes, "src_ip").items():
        for cluster in _clusters(group, window, lambda scope: len(scope) >= threshold):
            paths = Counter(_path_only(_request_path(e)) for e in cluster)
            top = ", ".join(p[:60] for p, _ in paths.most_common(4))
            findings.append(_finding(
                ip, cluster,
                f"Error-log probing from {ip}: {len(cluster)} failed requests",
                f"{ip} appears in {len(cluster)} nginx error-log line(s) between "
                f"{cluster[0]['ts']} and {cluster[-1]['ts']}, across {len(paths)} distinct path(s): "
                f"{top}. Missing and forbidden files are recorded here even where access logging is "
                f"off, so on such a vhost this is the only sight of the probe. Threshold: "
                f"{threshold} within {window}s.",
            ))
    return findings


def firewall_port_sweep(events, params):
    needed, window = params["distinct_ports"], params["window_seconds"]
    denied = [e for e in _filtered(events, params, "fw_deny") if e.get("dest_port") is not None]
    findings = []
    for ip, group in _group(denied, "src_ip").items():
        qualifies = lambda w: len({e["dest_port"] for e in w}) >= needed
        for cluster in _clusters(group, window, qualifies):
            ports = sorted({e["dest_port"] for e in cluster})
            targets = sorted({e.get("dest_ip") or "?" for e in cluster})
            findings.append(_finding(
                ip, cluster,
                f"Port sweep from {ip}: {len(ports)} ports denied",
                f"The firewall denied {ip} on {len(ports)} distinct ports "
                f"({', '.join(map(str, ports[:12]))}{'…' if len(ports) > 12 else ''}) of "
                f"{', '.join(targets[:3])} between {cluster[0]['ts']} and {cluster[-1]['ts']}. "
                f"Threshold: {needed} ports within {window}s.",
            ))
    return findings


def impossible_geo_login(events, params):
    max_speed, min_km, window = params["max_speed_kmh"], params["min_distance_km"], params["window_seconds"]
    findings = []
    for user, group in _group_users(_filtered(events, params, LOGIN_SUCCESS_TYPES)).items():
        previous = None
        for login in group:
            where = geo.locate(login.get("src_ip"))
            if where is None:
                continue  # unmapped address: never guessed
            if previous is not None:
                before, before_where = previous
                seconds = _epoch(login) - _epoch(before)
                km = geo.distance_km(before_where, where)
                speed = km / max(seconds / 3600, 1 / 60)  # floor at one minute
                if seconds <= window and km >= min_km and speed > max_speed:
                    findings.append(_finding(
                        f"{user}|{before['src_ip']}|{login['src_ip']}", [before, login],
                        f"Impossible travel for {login['user']}: {before_where['city']} to {where['city']}",
                        f"{login['user']} logged in from {before_where['city']} ({before['src_ip']}) at {before['ts']} "
                        f"and from {where['city']} ({login['src_ip']}) at {login['ts']}: {km:,.0f} km in "
                        f"{seconds / 60:,.0f} min, about {speed:,.0f} km/h (limit {max_speed} km/h). "
                        f"Locations come from the synthetic geo table.",
                    ))
            previous = (login, where)
    return findings


def privilege_escalation_after_login(events, params):
    needed, window, reach = params["failures"], params["window_seconds"], params["escalation_seconds"]
    failures = _group_users(_filtered(events, params, "auth_failure"))
    logins = _group_users(_filtered(events, params, LOGIN_SUCCESS_TYPES))
    findings = []
    for esc in _filtered(events, params, "privilege_escalation"):
        user = (esc.get("user") or "").lower()
        t = _epoch(esc)
        recent = [l for l in logins.get(user, []) if 0 <= t - _epoch(l) <= reach]
        for login in reversed(recent):  # most recent qualifying login first
            prior = [f for f in failures.get(user, []) if 0 <= _epoch(login) - _epoch(f) <= window]
            if len(prior) < needed:
                continue
            host = esc.get("host") or "unknown"
            minutes = (t - _epoch(login)) / 60
            findings.append(_finding(
                f"{user}|{host}", prior + [login, esc],
                f"Privilege escalation by {esc.get('user')} on {host} after suspicious login",
                f"{esc.get('user')} elevated privileges on {host} at {esc['ts']}, {minutes:,.0f} min after "
                f"logging in from {login.get('src_ip') or 'an unknown IP'} at {login['ts']}. That login followed "
                f"{len(prior)} failed attempts within {window}s (threshold {needed}; escalation window {reach}s).",
            ))
            break
    return findings


CLOUD_TYPES = ("cloud_api_call", "cloud_iam_change", "cloud_data_access")


def cloud_iam_change_by_new_principal(events, params):
    history, window = params["history_seconds"], params["window_seconds"]
    findings = []
    for principal, group in _group_users(_filtered(events, params, CLOUD_TYPES)).items():
        index = 0
        while index < len(group):
            change = group[index]
            t = _epoch(change)
            seen_before = any(t - _epoch(p) <= history for p in group[:index])
            if change["event_type"] != "cloud_iam_change" or seen_before:
                index += 1
                continue
            cluster = [e for e in group[index:] if e["event_type"] == "cloud_iam_change" and _epoch(e) - t <= window]
            actions = Counter((e.get("message") or "change").split(" on ")[0] for e in cluster)
            findings.append(_finding(
                principal, cluster,
                f"IAM change by new principal {change['user']}",
                f"{change['user']} made {len(cluster)} IAM change(s) ({', '.join(a for a, _ in actions.most_common(5))}) "
                f"starting {change['ts']} from {change.get('src_ip') or 'an unknown IP'}, with no cloud activity "
                f"of its own in the preceding {history}s.",
            ))
            while index < len(group) and _epoch(group[index]) - t <= window:
                index += 1
    return findings


def _peak(events, window, measure):
    """The largest `measure` over any `window`-second span of time-ordered events (0 if none)."""
    best, dq = 0, deque()
    for event in events:
        dq.append(event)
        while _epoch(event) - _epoch(dq[0]) > window:
            dq.popleft()
        best = max(best, measure(dq))
    return best


def _human_bytes(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1000


EXFIL_TYPES = ("cloud_data_access", "fw_allow", "network_connection")


def data_exfil_volume(events, params):
    limit, reads, window = params["bytes_threshold"], params["access_threshold"], params["window_seconds"]
    groups = defaultdict(list)
    for e in _filtered(events, params, EXFIL_TYPES):
        if e["event_type"] != "cloud_data_access" and not e.get("bytes"):
            continue
        key = (e.get("user") or "").lower() or e.get("src_ip")
        if key:
            groups[key].append(e)
    multiplier, history = params["baseline_multiplier"], params["history_seconds"]
    # Supplied by the engine from approved, unexpired tuning exceptions (see exception_params); never saved.
    excepted = set(params.get("baseline_principals", ()))
    findings = []
    volume = lambda w: sum(e.get("bytes") or 0 for e in w)
    accesses = lambda w: sum(e["event_type"] == "cloud_data_access" for e in w)
    for principal, group in groups.items():
        # Running totals make each window's sums O(1): an ingest rescan reads a week of a busy account's
        # transfers, and summing every window of it was most of the detection time in the load test.
        sent, read = [0], [0]
        for e in group:
            sent.append(sent[-1] + (e.get("bytes") or 0))
            read.append(read[-1] + (e["event_type"] == "cloud_data_access"))
        span = lambda lo, hi: sent[hi + 1] - sent[lo] >= limit or read[hi + 1] - read[lo] >= reads
        for cluster in _clusters(group, window, None, span):
            total, count = volume(cluster), accesses(cluster)
            if not multiplier or principal not in excepted:
                mode = ("Flat thresholds applied: " + ("baseline_multiplier is 0." if principal in excepted else
                        f"{principal} has no approved tuning exception, so its history is not compared."))
            else:
                # Baseline: this principal's own busiest window before the burst, inside the history span.
                t0 = _epoch(cluster[0])
                before = [e for e in group if 0 < t0 - _epoch(e) <= history]
                peak_bytes, peak_reads = _peak(cluster, window, volume), _peak(cluster, window, accesses)
                base_bytes, base_reads = _peak(before, window, volume), _peak(before, window, accesses)
                if not ((peak_bytes >= limit and peak_bytes >= multiplier * base_bytes)
                        or (peak_reads >= reads and peak_reads >= multiplier * base_reads)):
                    continue  # comparable to what this excepted principal normally moves
                mode = f"Baseline mode (approved tuning exception for {principal}): "
                if not before:
                    mode += (f"no earlier transfers by {principal} in the preceding {history}s, so there is "
                             f"nothing to compare against.")
                else:
                    ratio = f"{peak_bytes / base_bytes:,.1f}x" if base_bytes else "no bytes before"
                    mode += (f"its busiest {window}s in the preceding {history}s moved "
                             f"{_human_bytes(base_bytes)} ({base_reads} reads); this burst peaked at "
                             f"{_human_bytes(peak_bytes)} ({peak_reads} reads), {ratio} the baseline "
                             f"(alerts at {multiplier}x or more).")
            findings.append(_finding(
                principal, cluster,
                f"Large data transfer by {principal}: {_human_bytes(total)}",
                f"{principal} moved {_human_bytes(total)} across {len(cluster)} events ({count} cloud data "
                f"reads) between {cluster[0]['ts']} and {cluster[-1]['ts']}. Thresholds: "
                f"{_human_bytes(limit)} or {reads} reads within {window}s. {mode}",
            ))
    return findings


def _service(event):
    """The cloud service named by an '<action> on <service>' message, or None. Never guessed."""
    _, found, rest = (event.get("message") or "").partition(" on ")
    name = rest.split()[0].strip(".,;()").lower() if found and rest.split() else ""
    return name if "." in name else None


def _action(event):
    """The action named by an '<action> on <service>' message (the word before ' on '), or None."""
    before, found, _ = (event.get("message") or "").partition(" on ")
    return before.split()[-1] if found and before.split() else None


def unsanctioned_cloud_service(events, params):
    sanctioned = [list_entry("sanctioned_services", s) for s in params["sanctioned_services"]]
    window = params["window_seconds"]
    groups = defaultdict(list)
    for e in _filtered(events, params, CLOUD_TYPES):
        service, user = _service(e), (e.get("user") or "").lower()
        if not service or not user or covers("sanctioned_services", sanctioned, e):
            continue
        groups[(user, service)].append(e)
    findings = []
    for (user, service), group in groups.items():
        for cluster in _clusters(group, window, lambda w: True):
            total = sum(e.get("bytes") or 0 for e in cluster)
            ips = sorted({e.get("src_ip") or "unknown" for e in cluster})
            findings.append(_finding(
                f"{user}|{service}", cluster,
                f"Unsanctioned cloud service: {cluster[0]['user']} used {service}",
                f"{cluster[0]['user']} used {service} {len(cluster)} time(s) between {cluster[0]['ts']} and "
                f"{cluster[-1]['ts']} from {', '.join(ips[:5])}, moving {_human_bytes(total)}. {service} is "
                f"not on the sanctioned list ({', '.join(sanctioned[:8])}{'…' if len(sanctioned) > 8 else ''}). "
                f"This is a policy finding: it shows use of an unapproved service, not intent.",
            ))
    return findings


def cloud_logging_disabled(events, params):
    actions = {list_entry("logging_actions", a) for a in params["logging_actions"]}
    window = params["window_seconds"]
    groups = defaultdict(list)
    for e in _filtered(events, params, CLOUD_TYPES):
        key = (e.get("user") or "").lower() or e.get("src_ip")
        if key and covers("logging_actions", actions, e):
            groups[key].append(e)
    findings = []
    for principal, group in groups.items():
        for cluster in _clusters(group, window, lambda w: True):
            done = Counter(_action(e) for e in cluster)
            ips = sorted({e.get("src_ip") or "unknown" for e in cluster})
            findings.append(_finding(
                principal, cluster,
                f"Cloud audit logging disabled by {principal}: {', '.join(done)}",
                f"{principal} called {', '.join(f'{a} ({n})' for a, n in done.items())} between {cluster[0]['ts']} "
                f"and {cluster[-1]['ts']} from {', '.join(ips[:5])}. These actions stop or delete cloud audit "
                f"logging, which hides what happens next. A denied attempt is recorded the same way, so check "
                f"whether logging is actually off.",
            ))
    return findings


PRIVILEGED_TYPES = ("privilege_use", "privilege_escalation", "cloud_iam_change")


def admin_action_from_new_source(events, params):
    history, needed, window = params["history_seconds"], params["min_prior_actions"], params["window_seconds"]
    actions = [e for e in _filtered(events, params, PRIVILEGED_TYPES) if e.get("src_ip")]
    findings = []
    for user, group in _group_users(actions).items():
        # Sources of this account's privileged actions inside the history span before each action.
        known, start = Counter(), 0
        for index, event in enumerate(group):
            t = _epoch(event)
            while _epoch(group[start]) < t - history:
                known[group[start]["src_ip"]] -= 1
                start += 1
            prior, ip = index - start, event["src_ip"]
            if prior >= needed and known[ip] <= 0:
                cluster = [e for e in group[index:] if e["src_ip"] == ip and _epoch(e) - t <= window]
                sources = sorted(s for s, n in known.items() if n > 0)
                what = Counter(_action(e) or e["event_type"] for e in cluster)
                findings.append(_finding(
                    f"{user}|{ip}", cluster,
                    f"Privileged action by {event['user']} from new source {ip}",
                    f"{event['user']} made {len(cluster)} privileged action(s) "
                    f"({', '.join(a for a, _ in what.most_common(5))}) from {ip} starting {event['ts']}. In the "
                    f"preceding {history}s it made {prior} privileged actions, all from "
                    f"{', '.join(sources[:5])}{'…' if len(sources) > 5 else ''}; never from {ip}. Accounts with "
                    f"fewer than {needed} earlier privileged actions have no baseline and are not judged.",
                ))
            known[ip] += 1
    return findings


RULE_FUNCTIONS = {
    "brute_force_ip": brute_force_ip,
    "password_spray": password_spray,
    "account_repeated_failures": account_repeated_failures,
    "success_after_failures": success_after_failures,
    "off_hours_privileged_login": off_hours_privileged_login,
    "web_scanner": web_scanner,
    "web_path_discovery": web_path_discovery,
    "web_rapid_discovery": web_rapid_discovery,
    "web_request_burst": web_request_burst,
    "web_login_abuse": web_login_abuse,
    "web_injection_attempt": web_injection_attempt,
    "web_sensitive_file_served": web_sensitive_file_served,
    "web_access_denied_burst": web_access_denied_burst,
    "web_auth_brute_force": web_auth_brute_force,
    "web_server_error_burst": web_server_error_burst,
    "web_error_probe_burst": web_error_probe_burst,
    "firewall_port_sweep": firewall_port_sweep,
    "impossible_geo_login": impossible_geo_login,
    "privilege_escalation_after_login": privilege_escalation_after_login,
    "cloud_iam_change_by_new_principal": cloud_iam_change_by_new_principal,
    "data_exfil_volume": data_exfil_volume,
    "unsanctioned_cloud_service": unsanctioned_cloud_service,
    "cloud_logging_disabled": cloud_logging_disabled,
    "admin_action_from_new_source": admin_action_from_new_source,
    "log_source_silent": log_source_silent,
}


# How far back a rule can look. The scan window is sized from these.
def rule_span(rule):
    """Seconds this rule alone can look back from an event: its window plus any escalation reach."""
    params = rule["params"]
    return params.get("window_seconds", 0) + params.get("escalation_seconds", 0)


def rule_history(rule):
    """Extra context this rule alone needs *before* its window (e.g. 'no prior activity' checks)."""
    return rule["params"].get("history_seconds", 0)


def rule_function(rule_id):
    """The function that runs a rule: a built-in from RULE_FUNCTIONS, the Sigma evaluator, or the search-rule
    evaluator. None if none of them."""
    if sigma.is_sigma(rule_id):
        return sigma.run
    if search_rules.is_search(rule_id):
        return search_rules.run
    return RULE_FUNCTIONS.get(rule_id)


# Rules where a tuning exception does not skip findings but turns on the principal's baseline instead.
EXCEPTION_ENABLES_BASELINE = ("data_exfil_volume",)


def exception_params(rule_id, params, suppressions):
    """The params to hand a rule function, given active exceptions as a set of (rule_id, group_key).

    `baseline_principals` exists only here: validate_params rejects it, so it cannot be saved or proposed.
    """
    if rule_id not in EXCEPTION_ENABLES_BASELINE:
        return params
    return {**params, "baseline_principals": sorted(key for rid, key in suppressions if rid == rule_id)}


# The largest time span a rule can look across; used to pick the rescan window after ingest.
def lookback_seconds(rules):
    return max([rule_span(r) for r in rules] + [3600])


def history_seconds(rules):
    return max([rule_history(r) for r in rules] + [0])


# The event types each rule with a `history_seconds` param reads. On an ingest rescan the engine fetches only
# these types from the history span before the scan window, instead of every event of the past week per
# batch. A history rule missing here would lose its history, so a test checks the list is complete.
HISTORY_EVENT_TYPES = {
    "cloud_iam_change_by_new_principal": CLOUD_TYPES,
    "data_exfil_volume": EXFIL_TYPES,
    "admin_action_from_new_source": PRIVILEGED_TYPES,
}
