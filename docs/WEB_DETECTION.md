# Web attack detection from nginx logs

What Watchpost can detect in nginx access and error logs, what it cannot, and how each rule earns its
threshold. The rule set is tuned by the normal reviewed-change workflow (see [API.md](API.md)), so
every number below is a starting default rather than a fixed truth.

## What the rules detect today

| Rule | Signal | Severity |
|---|---|---|
| `web_scanner` | ≥ 5 requests whose **path or user agent matches a known signature** (`/.env`, `/.git`, `/wp-login.php`, injection strings, `sqlmap`/`nikto`/`nmap` user agents) from one IP in 300 s | medium |
| `web_path_discovery` | one IP asks for **≥ 30 distinct paths** in 300 s and **≥ 70 % of those requests failed** — directory and file brute force | medium |
| `web_request_burst` | one IP sends **≥ 200 requests in 60 s**, whatever the paths — a flood, a fast scanner, or credential stuffing | medium |
| `web_login_abuse` | one IP makes **≥ 10 failed requests to a login endpoint** in 300 s, whatever the code | high |
| `web_auth_brute_force` | **≥ 10 responses with status 401 on one endpoint** from one IP in 300 s | high |
| `web_injection_attempt` | **one request** whose path or query carries an injection payload — SQLi, XSS, traversal, command or template injection, XXE | high |
| `web_sensitive_file_served` | a request for a secret-bearing file (`.env`, `.git/config`, `.aws/credentials`, `id_rsa`, `wp-config.php`, `.sql`/`.bak` backups) answered with **2xx content** | critical |
| `web_access_denied_burst` | **≥ 20 responses with status 403** to one IP in 300 s | medium |
| `web_server_error_burst` | **≥ 10 responses with status 5xx** from the access log to one IP in 300 s | medium |
| `web_error_probe_burst` | **≥ 20 nginx error.log lines naming a request** from one IP in 300 s | medium |

`web_scanner` and `web_path_discovery` are complements, not duplicates. A signature list only catches
paths someone already wrote down; a wordlist walk over `/admin`, `/backup`, `/uploads`, `/config` is
invisible to it, which is exactly why the breadth rule exists. And breadth and volume are separate
axes: a patient scanner at 1 request/s trips the breadth rule, a fast one hammering three URLs trips
the volume rule, and neither rule substitutes for the other.

## The status column every further web rule needed

Every rule added after the original three needed the HTTP status code, and until recently events had
none. The weblog parser knew it (`GET /x -> 404`) and wrote it into the message, where rules recovered
it with a regex — enough for "did this request fail" (the `outcome` column is `failure` for any
4xx/5xx) and not enough for anything that must tell statuses apart:

- `401` vs `403` vs `404` — repeated **401** is credential guessing; many **403** is access-control
  probing that found something protected; many **404** is enumeration.
- `5xx` — error spikes from a broken deployment, or from probing that is breaking the app.
- A **2xx on a sensitive path** — the difference between "someone probed `/.env`" (routine noise) and
  "the web server served `/.env`" (a real misconfiguration worth waking someone for).

So `http_status INTEGER` was added to `events`, as planned:

- Named `http_status`, not `status`: `FIELD_ALIASES` already maps `status` onto `outcome`, and reusing
  the name would have silently changed what that alias picks up. The accepted aliases are
  `http_status`, `status_code`, and `response_code`.
- Added to `db.ADDED_COLUMNS`, so an existing database gains it in place on startup. Nothing to migrate.
- Set by `normalize_weblog_line` from the access log. nginx error-log lines carry no code, so theirs
  stay `NULL` — which is exactly what `web_error_probe_burst` keys on, below.
- In `engine.RULE_EVENT_FIELDS` so rules can read it, in `queries.EVENT_FIELDS` so the API returns it,
  and shown in the event detail dialog in the UI.

Rules prefer the column and fall back to the `-> 404` in the message, so events stored before the
column existed are still judged correctly rather than silently skipping the status rules.

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

## The added rules, and why each threshold sits where it does

All seven planned rules are implemented. The four credential, injection, and disclosure rules needed
nothing new; the four status rules needed the column above.

| Rule | Fires when | OWASP | ATT&CK |
|---|---|---|---|
| `web_login_abuse` | ≥ 10 failed requests to a login endpoint from one IP in 300 s | A07 | T1110.001, T1078 |
| `web_auth_brute_force` | ≥ 10 responses with status **401** on **one endpoint** from one IP in 300 s | A07 | T1110 |
| `web_injection_attempt` | a single request whose path or query carries an injection payload | A03 | T1190, T1059 |
| `web_sensitive_file_served` | a request for a sensitive path answered with **2xx content** | A05, A01 | T1552.001, T1190 |
| `web_access_denied_burst` | ≥ 20 responses with status **403** for one IP in 300 s | A01 | T1083, T1078 |
| `web_server_error_burst` | ≥ 10 responses with status **5xx** from the access log for one IP in 300 s | A05, A06 | T1190 |
| `web_error_probe_burst` | ≥ 20 nginx **error.log** lines naming a request for one IP in 300 s | A01, A06 | T1595.003 |

Four decisions are worth knowing about:

- **`web_injection_attempt` alerts on a single request.** An injection string is classified `web_scan`,
  and before this rule the only thing watching those was `web_scanner`, which needs five requests in
  five minutes — so one SQL injection on its own was silent. One attempt is signal enough. Repeated
  attempts from one address inside the window are gathered into one alert rather than one per request.
- **`web_login_abuse` counts failures; `web_auth_brute_force` counts 401s per endpoint.** A login form
  that is blocked answers 403 and one that was never there answers 404, so an attacker working through
  a list of login paths produces all three codes: the wider rule catches the campaign, the narrower one
  catches a single form being guessed at. Neither substitutes for the other.
- **`web_sensitive_file_served` requires success.** A refused request for `/.env` is probing, and
  probing is already covered by `web_scanner` and `web_path_discovery`. A 3xx is not success either:
  nginx redirecting an unknown path to a login page must not read as a disclosure.
- **The two error rules split on whether a code exists.** An access-log 5xx has a status; an error.log
  line never does. So one probe recorded in both logs is counted by one rule and not two, and neither
  threshold fires early. `web_error_probe_burst` exists at all because access logging can be switched
  off per vhost while error logging stays on — on such a host the error log is the only record that a
  probe happened.

Which event types each rule reads matters more than it looks. A request to `/wp-login.php` or `/.env`
is classified `web_scan`, not `web_request`, and a 5xx is `web_error`. The rules about *what was
requested* therefore read `web_request` **and** `web_scan`, and there is a test for each pair that a
rule reading only one type would miss.

**Not implemented, on purpose**

- Anything requiring response *bodies*, TLS parameters, or application internals — OWASP A02, A08, A10
  above are not observable here at all.
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
- `web_injection_attempt` has **no threshold to raise**: it alerts on one payload, because a payload is
  never ordinary traffic. If you run an authorised scanner or a WAF test suite against your own site,
  put its address in `ignore_ips` — that is the intended control. A higher threshold would be the wrong
  fix, since one payload reaching a real client should still be reported.
- `web_login_abuse` and `web_auth_brute_force` overlap on purpose. If either turns out noisy on real
  traffic, tune the narrower one (401s on one endpoint) or allow-list the client; raising the wider
  rule's threshold costs you the campaign-level view without buying much quiet.
- The scenario evaluation measures recall and precision **against hand-written synthetic scenarios
  only**. It says nothing about accuracy on your traffic. Treat the numbers as a regression check,
  not as evidence that a rule is right for your site.
