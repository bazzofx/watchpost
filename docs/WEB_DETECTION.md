# Web attack detection from nginx logs

What Watchpost can detect in nginx access and error logs, what it cannot, and the rules planned next.
The rule set is tuned by the normal reviewed-change workflow (see [API.md](API.md)), so every
number below is a starting default rather than a fixed truth.

## What the rules detect today

| Rule | Signal | Severity |
|---|---|---|
| `web_scanner` | ≥ 5 requests whose **path or user agent matches a known signature** (`/.env`, `/.git`, `/wp-login.php`, injection strings, `sqlmap`/`nikto`/`nmap` user agents) from one IP in 300 s | medium |
| `web_path_discovery` | one IP asks for **≥ 30 distinct paths** in 300 s and **≥ 70 % of those requests failed** — directory and file brute force | medium |
| `web_request_burst` | one IP sends **≥ 200 requests in 60 s**, whatever the paths — a flood, a fast scanner, or credential stuffing | medium |

`web_scanner` and `web_path_discovery` are complements, not duplicates. A signature list only catches
paths someone already wrote down; a wordlist walk over `/admin`, `/backup`, `/uploads`, `/config` is
invisible to it, which is exactly why the breadth rule exists. And breadth and volume are separate
axes: a patient scanner at 1 request/s trips the breadth rule, a fast one hammering three URLs trips
the volume rule, and neither rule substitutes for the other.

## The gap that limits every further web rule

**Events carry no HTTP status code.** The weblog parser knows it (`GET /x -> 404`) and writes it into
the message, where rules recover it with a regex, but there is no column. That is enough for
"did this request fail" (the existing `outcome` column is `failure` for any 4xx/5xx) and not enough
for anything that must tell statuses apart:

- `401` vs `403` vs `404` — repeated **401** is credential stuffing; many **403** is access-control
  probing that found something protected; many **404** is enumeration.
- `5xx` — error spikes from a broken deployment, or from probing that is breaking the app.
- A **2xx on a sensitive path** — the difference between "someone probed `/.env`" (routine noise) and
  "the web server served `/.env`" (a real misconfiguration worth waking someone for).

**Recommended next change, before more rules:** add `http_status INTEGER` to `events`.

- Name it `http_status`, not `status`: `FIELD_ALIASES` already maps `status` onto `outcome`, and
  reusing the name would silently change what the alias picks up.
- Add it to `db.ADDED_COLUMNS` so existing databases gain it in place on startup.
- Set it in `normalize_weblog_line`; nginx error lines have no status, so they stay `NULL`.
- Add it to `engine.RULE_EVENT_FIELDS` so rules can read it, and to `queries.EVENT_FIELDS` so the
  events table and filters can show it.
- Roughly six files plus tests. It is additive, so no route contract changes.

Without it, the tier-2 rules below cannot be written properly.

## OWASP Top 10 (2021) against what nginx actually logs

| OWASP | Visible in nginx logs? | How |
|---|---|---|
| **A01** Broken Access Control | Partly | Traversal attempts (`../`, encoded variants), repeated `403`/`401`, forced browsing of `/admin`, `/internal`, sequential object IDs |
| **A02** Cryptographic Failures | No | nginx does not log protocol or cipher per request. Only `[crit] SSL_do_handshake() failed` in error.log, which is a client or config fault, not a weakness |
| **A03** Injection | Yes | Payloads land in the request line and query string: SQLi, XSS, command injection, template injection, LDAP, XXE |
| **A04** Insecure Design | No | A design property, not a request pattern |
| **A05** Security Misconfiguration | Partly | `2xx` on dotfiles and backups (`.env`, `.git/config`, `.sql`, `wp-config.php`), directory listings, `TRACE`, verbose errors |
| **A06** Vulnerable Components | Partly | Probing for known component paths (`/actuator`, `/wp-json`, `phpunit`) — but versions are not in the access log |
| **A07** Auth Failures | Yes | Repeated `401`/`403` on a login endpoint; credential stuffing looks like many accounts from one IP, brute force like many attempts on one account |
| **A08** Integrity Failures | No | Deserialisation and supply-chain issues happen inside the app |
| **A09** Logging/Monitoring Failures | Yes, by construction | This is what Watchpost is. The [Agents page](../README.md#agents) shows whether each log source is still reporting, and Health covers ingestion and detection |
| **A10** SSRF | Mostly no | The server's outbound request does not traverse the public nginx. Only visible if nginx proxies the same host, or via upstream errors in error.log |

So five of the ten are genuinely observable from nginx logs. Claiming the other five would be
dishonest; they need application-level logging, and this document does not pretend otherwise.

## Planned rules

**Tier 1 — writable with the data available today**

| Rule | Fires when | OWASP | ATT&CK |
|---|---|---|---|
| `web_login_abuse` | ≥ 10 failed requests to a login endpoint (`/login`, `/signin`, `/api/auth`, `/wp-login.php`, `/admin`) from one IP in 300 s | A07 | T1110.001, T1078 |
| `web_injection_attempt` | a single request whose path or query matches an injection pattern — SQLi, XSS, traversal, command injection | A03 | T1190, T1059 |
| `web_sensitive_file_served` | a request for a sensitive path (`.env`, `.git/config`, `.aws/credentials`, `.sql`, `wp-config.php`, `id_rsa`) that **succeeded** | A05, A01 | T1552.001, T1190 |

`web_injection_attempt` is deliberately a low-threshold, single-event rule: today an injection string
is classified as `web_scan` and must reach 5 requests in 300 s before anything alerts, so one SQLi
attempt on its own is silent. One attempt is enough signal to alert on.

**Tier 2 — needs the `http_status` column**

| Rule | Fires when | OWASP | ATT&CK |
|---|---|---|---|
| `web_access_denied_burst` | ≥ 20 responses with status 403 for one IP in 300 s — probing that keeps finding protected things | A01 | T1083, T1078 |
| `web_auth_brute_force` | ≥ 10 responses with status 401 on one endpoint from one IP in 300 s, distinguishing it from the 404 noise above | A07 | T1110 |
| `web_server_error_burst` | ≥ 10 responses with status 5xx for one IP in 300 s — probing that breaks the app, or a regression being exploited | A05, A06 | T1190 |
| `web_error_probe_burst` | ≥ 20 nginx **error.log** lines with a request path for one IP in 300 s | A01, A06 | T1595.003 |

`web_error_probe_burst` exists because access logs can be disabled per vhost while error logging
stays on. It is a separate rule rather than feeding `web_path_discovery` so that one probe recorded
in both logs cannot count twice and make a threshold fire early.

**Not planned, on purpose**

- Anything requiring response *bodies*, TLS parameters, or application internals.
- Any rule that would auto-block. See below.

## Detection is not mitigation

**Watchpost cannot block anything.** It reads logs; it has no path to the traffic. Saying a rule
"mitigates" an attack would be wrong. Mitigation belongs in nginx and its neighbours, and the same
logs feed both:

```nginx
# Per-IP request rate and connection limits (the mitigation for web_request_burst).
limit_req_zone  $binary_remote_addr zone=perip:10m rate=10r/s;
limit_conn_zone $binary_remote_addr zone=addr:10m;
server {
    limit_req  zone=perip burst=20 nodelay;
    limit_conn addr 20;
    client_max_body_size 1m;          # caps large-body probe attempts
    autoindex off;                    # no directory listings
    location ~ /\.(?!well-known) { deny all; }   # dotfiles, including .env and .git
}
```

Plus, as appropriate: `fail2ban` on the same log files for automatic temporary bans, and
**ModSecurity with the OWASP Core Rule Set** if you want request inspection and blocking rather than
detection after the fact. Watchpost's role is to tell you what happened, with evidence and an ATT&CK
mapping, and to record that someone reviewed it.

Automatically blocking on a Watchpost alert is possible but is deliberately not implemented: these
rules are medium-confidence heuristics over shared-IP log data, and an unattended block action on a
false positive is an outage. If you want that later, it should be an allow-list-first, time-boxed ban
driven by a single high-confidence rule, with a review path.

## Tuning without breaking things

Every threshold above is a parameter, changeable only through a reviewed proposal, and every change
is scored against the labeled scenarios before and after
(`POST /api/rules/{id}/proposals`, then an admin who is not the proposer approves it). Practical notes:

- `ignore_ips` is the honest escape hatch for known heavy clients (uptime monitors, internal
  scanners, CI). Add them rather than raising a global threshold for everyone.
- `web_request_burst` is the rule most likely to need tuning down on a busy site. A single page load
  with many assets is bursty; the default (200 in 60 s) is chosen to sit above that, and the labeled
  `request_burst` scenario includes a 40-request page load that must not fire.
- The scenario evaluation measures recall and precision **against hand-written synthetic scenarios
  only**. It says nothing about accuracy on your traffic. Treat the numbers as a regression check,
  not as evidence that a rule is right for your site.
