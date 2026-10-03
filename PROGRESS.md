# Watchpost progress log

Hand-off notes so any session can continue the work.

## Starting point (2026-09-16)

The brief asked me to continue an existing SOC/SIEM project on Replit. That project was **not reachable from this machine**: the `cybersecurity` workspace had only notes and resumes, and a search of the home directory found no SIEM code or `.replit` file. So Watchpost was built new, in `labs/siem/`, using only the Python standard library, so it runs unchanged on Replit (`.replit` included).
**If the original Replit project has features worth keeping, merge them in or port this code into it. Nothing here depends on the old project.**

## Milestones completed

| # | Milestone | Evidence |
|---|---|---|
| 0 | Baseline: nothing existed; set up test harness and smoke script | `tests/`, `scripts/smoke.py` |
| 1 | Storage + normalized schema (SQLite, WAL, indexes) | `watchpost/db.py` |
| 2 | Ingestion: JSON/JSONL/CSV/auth.log/Windows, validation, redaction, per-record rejection reasons, batch audit | `test_normalize.py` (16 tests), `IngestTests` |
| 3 | Detection: 5 explainable rules, sliding windows, dedup/extension of open alerts, run records | `test_rules.py` (12 tests), dedup test in `IngestTests` |
| 4 | Analyst workflow: alert detail, evidence, related timeline, notes, status, verdicts, activity log | `EndToEndTests.test_full_analyst_flow` |
| 5 | Search + metrics | `SearchTests` (filters, paging, validation, injection attempts) |
| 6 | Security: PBKDF2, lockout, sessions, CSRF, roles, hashed ingest-only tokens, CSP/security headers, body limits, static path-traversal guard, loopback default bind, generated creds file with mode 0600 | `AuthTests` (9 tests), `test_generated_credentials_file_is_private` |
| 7 | Self-diagnosis: 4 health checks, public/private health endpoints, redacted error log, failure → backlog → recovery | `HealthRecoveryTests` (8 tests) |
| 8 | Continuous improvement: verdict-based precision, heuristic suggestions, scenario evaluation before and after, two-person review for rules *and* security settings, rule history, evaluation history | `test_full_analyst_flow` steps 5–8, `test_manual_rule_proposal_review_rules`, `test_security_setting_change_requires_second_admin` |
| 9 | Synthetic data + simulations: 7 labeled scenarios, loopback-only simulator CLI, 3 sample files | `EvaluationTests`, smoke steps 4–5 |
| 10 | Web UI (dashboard, alerts, events, ingest, rules, health, admin) | Browser verification below |
| 11 | Docs: README, API reference, demo script, LinkedIn text | this folder |

## Verification (latest run: 2026-09-16)

- `./run_tests.sh` → **57 tests OK** (Python 3.14.2), then **SMOKE OK**, all 12 steps. The smoke check starts a real server process, uploads the 3 sample files, runs the simulator CLI with an API token, confirms the simulator refuses a non-loopback URL and the token can't read data, searches, and checks that all 5 rules fired (13 alerts). It then resolves an alert, turns false-positive feedback into a proposal, has a second user approve it, checks health, and confirms no password or token appears in the server log.
- Also passes on Python 3.13. No syntax that requires 3.12 or later (checked with a tokenizer scan).
- **Browser check** (Playwright, real Chromium, against a scratch database):
  - Login screen hides the navigation. Admin sign-in works.
  - Admin → Load demo data: 7 scenarios, detection `ok`.
  - Dashboard: 9 open alerts, 105 events (all synthetic), activity chart, breakdowns.
  - Alerts list sorted with the critical alert first, synthetic tags visible.
  - On the compromise alert, Start investigating → Add note → Resolve (true positive). The database confirmed `resolved | true_positive | admin` and the note text.
  - Rules, Health, Ingest, and Events pages all render. No console errors besides the expected 401 from the pre-login session check.
  - Breaking a rule and running detection showed `failing`, the guidance text, and a red banner. Restoring the rule and running detection again returned everything to `ok`.
- **Bugs found and fixed during verification:**
  - Redaction let a bearer token through ("Authorization: Bearer x" matched the generic key=value pattern first).
  - The failing-health banner never showed, because the UI treated HTTP 503 as a fetch error.
  - Status and enabled pills rendered as nothing.
  - A literal "null" appeared on the dashboard.
  - The nav bar was visible before login (CSS overrode `hidden`).
  - A Windows sample file had invalid timestamps.

## Acceptance criteria status

| Requirement | Status |
|---|---|
| Documented ingest API + sample uploads | ✅ `docs/API.md`, `samples/` |
| Normalized, persistent storage | ✅ |
| Search by time/source/severity/user/IP/type | ✅ (plus host, message text, synthetic flag) |
| Brute force / suspicious auth / repeated failures rules | ✅ 5 rules |
| Alerts with evidence, severity, explanation | ✅ |
| Investigate / notes / status / resolve | ✅ |
| SOC metrics + related-event timeline | ✅ |
| Labeled synthetic data + reproducible simulations | ✅ seeded, `demo:*`, `synthetic=1` |
| Auth, validation, secret handling, access control | ✅ |
| Health checks for ingestion/storage/detection/dependencies with guidance | ✅ |
| Honest degraded/failing states; redacted errors; recovery tested | ✅ |
| TP/FP feedback, rule performance, proposals, history, evaluation results | ✅ |
| Review required for rule and security-setting changes | ✅ two-person rule |
| No ML claims | ✅ stated in UI and docs |
| README, demo script, LinkedIn text, real/synthetic/future separation | ✅ |

## Watchpost 2.0 / D: incident reports (2026-09-28, branch `ws/d-reports`)

Shipped:
- `watchpost/pdfwriter.py`: a hand-written PDF 1.4 writer (Helvetica and Helvetica-Bold with WinAnsi encoding,
  word wrap from the standard AFM widths, headings, rules, a highlighted banner, tables with a repeating header
  and truncated cells, automatic page breaks, "Page n of N" footers, byte-exact xref table). Under 300 lines.
- `watchpost/report.py`: `build(conn, incident_id)` and `build_from_alert(conn, alert_id)` return one report model;
  `to_markdown(model)` and `to_pdf_bytes(model)` render it. Recommended actions come from a static table keyed by
  ATT&CK technique id (sub-techniques fall back to the parent), with generic actions when no technique is mapped.
  Techniques come from the `rules.techniques` column (falling back to `DEFAULT_RULES`), resolved through the
  ATT&CK catalog in `watchpost/attack.py` and grouped by tactic in kill-chain order.
- After A merged: `build(conn, incident_id)` reads the real incident through `incidents.get_incident` (status,
  severity with escalation, span, kill-chain stages, entities, techniques per tactic with the alerts behind each),
  then adds every member alert's evidence, timeline, and notes. Unknown incidents are a 404 `incident not found`.
- Routes `GET /api/alerts/{id}/report.{md,pdf}` and `GET /api/incidents/{id}/report.{md,pdf}` (analyst+), audited.
- UI: "Report (PDF)" and "Report (Markdown)" links on the alert detail view and the incident detail view.
- Tests: `tests/test_pdfwriter.py` (6), `tests/test_report.py` (15, eight on incidents built by the real
  correlation engine), `ReportApiTests` in `tests/test_api.py` (3), plus a tiny PDF reader in `tests/pdfparse.py`
  that follows the xref table and extracts page text. The smoke check downloads alert and incident reports in both
  formats and checks the incident Markdown lists every kill-chain tactic.
- Verified outside the test suite (scratch venv, not a project dependency): qpdf (via pikepdf) reports no syntax
  problems, pypdf opens the files in strict mode, and PDFium (the engine inside Chrome) renders every page.

Not done:
- The HTML print view from the spec ("third option via the dashboard") belongs with the dashboard rework (B).
- Not opened in macOS Preview (no Mac in the cloud session). The file passes qpdf's checks and renders in PDFium.

Decision for the owner: none required.

## Open items and blockers

- **Not yet done by a human:** deploying to the user's Replit account (needs their login) and recording the demo video.
- **Needs the user's decision:** whether to replace or merge the original Replit project.
- Not run: Replit's own environment. The `.replit` file is written for its Python 3.11 module but untested there.

## Next concrete tasks (optional improvements)

1. Push `labs/siem/` to the Replit project, set the two password Secrets, click Run, and walk through DEMO_SCRIPT.md there.
2. Add a user-management endpoint and UI (admin creates and disables accounts). Today, extra accounts need `watchpost.auth.create_user`.
3. Add a retention job (delete events older than N days) behind a reviewed setting.
4. Add a syslog UDP/TCP listener on loopback for live shipping.
5. Add a Sigma-style YAML rule loader for simple field-match rules.

## Watchpost 2.0 / A: correlation engine and MITRE ATT&CK (2026-09-28, branch `ws/a-correlation-attack`)

**Shipped**
- `watchpost/attack.py`: static ATT&CK Enterprise subset (17 techniques, all 14 tactics in kill-chain order), `technique(id)`, `tactics()`, `coverage()`. No network fetch.
- Every rule carries `techniques`; new `rules.techniques` JSON column (added in place on existing databases), written by `seed_rules`, returned by `GET /api/rules` and in alert detail.
- Parsers: nginx/Apache combined (`weblog`, auto-detected) → `web_request`/`web_scan`/`web_error`; firewall CSV (`action` column) and UFW/iptables syslog → `fw_deny`/`fw_allow`; OpenVPN → `vpn_login`; CloudTrail-style JSON → `cloud_api_call`/`cloud_iam_change`/`cloud_data_access`; sudo/su/runas (4648) → `privilege_escalation`; useradd, auditd process (`exe=`) and file (`type=PATH`, 4663) records. New event columns `dest_port`, `bytes`.
- Six new rules with tests and labeled scenarios: `web_scanner`, `firewall_port_sweep`, `impossible_geo_login`, `privilege_escalation_after_login`, `cloud_iam_change_by_new_principal`, `data_exfil_volume`. Evaluation: every rule recall 1.0, no new false positives.
- `watchpost/geo.py`: synthetic geo table (`locate(ip) -> {city, lat, lon, synthetic}` or `None`), documentation + RFC 1918 ranges only.
- `watchpost/correlate.py` + `engine.correlate_alerts`: incidents and `incident_alerts` tables, run after every detection run, idempotent. Correlation failures leave alerts alone, are logged under component `correlation`, and mark detection health `degraded` until the next good run.
- Routes: `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents/{id}/status`, `GET /api/attack/coverage`. UI: active incidents table on the Alerts page, incident detail view (`#incidents/{id}`), ATT&CK chips on rules and alerts.
- Samples: `nginx_access.log`, `firewall.csv`, `cloudtrail.json`, `linux_host.log`. Smoke check uploads them and gained incident and coverage steps.
- Verification: `./run_tests.sh` → 97 tests OK, SMOKE OK (14 steps), run as a non-root user.

**Decisions made (owner may revisit)**
- Linking uses each alert's evidence-event times per entity, not the alert's whole span. With spans, one multi-hour impossible-travel alert chained 9 unrelated demo alerts on host `web01` into one incident.
- A new incident needs ≥ 2 related alerts or 1 critical alert; window 30 min (`correlate.DEFAULT_WINDOW_SECONDS`, not yet a setting).
- `vpn_login` counts as a successful login for `success_after_failures` and `off_hours_privileged_login` too.
- Detection now reads up to 24 h of extra history before each batch (for "new principal" checks); findings made only from that history are ignored, so older behaviour is unchanged.
- Rule tuning suggestions still only propose `threshold`/`ignore_*` changes; the new parameters are tunable via manual proposals.

**Not done / notes**
- `test_storage_unavailable_is_failing_not_a_crash` fails when the suite runs as root (root ignores directory permissions). Pre-existing, identical on `main`; passes as a normal user.
- No incident notes/assignment UI beyond status; reports (D) and dashboard panels (B) consume these routes.

## Watchpost 2.0 / E: live ingestion (2026-09-28, branch `ws/e-live-ingest`)

**Shipped**
- `watchpost/syslog_listener.py`: a UDP and TCP syslog receiver.
  - Parses RFC 3164 and RFC 5424 messages and RFC 6587 TCP framing (octet-counted and newline).
  - Each line goes through the existing auth.log parser first. Anything it doesn't recognize becomes a new `syslog` event type, with severity from PRI.
  - Batches into `engine.ingest` every 2 seconds and bounds the queue at 50,000 frames. Optional `SIEM_SYSLOG_ALLOW` IP/CIDR allow list.
  - Loopback by default. Started from `main.py` when `SIEM_SYSLOG=1`.
  - Reported as the `syslog` health component. A bind failure is failing health plus an error_log entry, never a crash.
- `watchpost/health.py`: `register_check` / `unregister_check`, so optional components can add a health check while they run. The four core checks are unchanged. Workstream C (storyline) can reuse this.
- `scripts/shipper.py`: a stdlib-only tailer that posts to `/api/ingest/upload` with an ingest token.
  - Batches by line count and size, retries with exponential backoff and jitter, and keeps an atomic position file (inode and offset).
  - Follows rename rotation (drains the old file first) and copytruncate.
  - Skips batches the server refuses as invalid instead of stalling. Refuses plain HTTP to non-loopback hosts. The token comes from an env var or a file only.
- `docs/LIVE_INGEST.md`: listener setup, rsyslog forwarding for Debian 12 (install rsyslog first) and Ubuntu, remote options (SSH tunnel or allow list plus ufw), shipper install with a systemd unit, and limits.
- Tests: `tests/test_live_ingest.py` has 29 tests: parsing, framing, a listener on random ports over UDP and TCP, allow list, bind failure, the health API, the shipper against a fake HTTP server, and the shipper CLI against a real server. The smoke check gained step 11 (a syslog frame plus a shipper run against the real server process), and step 12 now checks that `syslog` health is ok.

**Verification:** `./run_tests.sh` gives 86 tests OK and SMOKE OK (13 steps), run as an unprivileged user. As root, the pre-existing `test_storage_unavailable_is_failing_not_a_crash` fails on `main` too, because a read-only directory does not stop root. Nothing in this workstream touches it.

**Not done / limits**
- No TLS syslog (RFC 5425). Syslog is unauthenticated, so use loopback, an SSH tunnel, or an allow list.
- BSD syslog timestamps are treated as UTC (the existing rule). The docs recommend the RFC 5424 rsyslog template.

**Merge with workstream A (2026-09-28)**
- Merged `origin/main` (A: correlation, incidents, ATT&CK, new parsers) into this branch. Conflicts in `normalize.py` (`EVENT_TYPES` keeps both `syslog` and A's new types), `README.md`, and this file were resolved keeping both sides.
- The syslog listener now tries A's nginx/Apache combined parser when the auth.log parser does not recognize a message, so a forwarded access line becomes `web_request`/`web_scan`/`web_error` (host from the syslog header) instead of `syslog`. UFW/iptables firewall and OpenVPN lines already get `fw_deny`/`fw_allow`/`vpn_login` because A added them to the auth.log parser the listener uses.
- The shipper passes `weblog` through to the server; docs and `--file` help list it.
- New tests: nginx and firewall frames parsed to specific types, a UDP+TCP listener test asserting they land as `web_scan` and `fw_deny` (not `syslog`), and a shipper CLI test shipping an nginx access log to a real server with `weblog` and `auto`.
- Verification after the merge: `./run_tests.sh` gives 130 tests OK and SMOKE OK (15 steps), run as an unprivileged user.

**Decisions for the owner**
- Default syslog port is 5514, not 514, so Watchpost never needs root. Change it with `SIEM_SYSLOG_PORT`.
- For the public demo VM (workstream F), the recommended live feed is the VM's own rsyslog forwarding to `127.0.0.1:5514`. It needs no open port.
## Watchpost 2.0 / B: SOC dashboard (2026-09-28, branch `ws/b-soc-dashboard`)

**Shipped**
- `GET /api/stream` (SSE): `watchpost/stream.py` broker with bounded per-client queues (overflow turns into a `resync` frame), 64-connection cap, heartbeat every 15 s, clean unsubscribe on disconnect. The engine publishes `event` after each stored batch and `alert`, `incident` (once A's `incidents` table exists), and partial `health` after each detection run. Publishing is skipped when nobody is connected and can never fail an ingest.
- `GET /api/dashboard` (one aggregate read) and `GET /api/geo`. `GET /api/events` gained an additive `since_id` filter for the polling fallback.
- `watchpost/geo.py`: A merged first, so A's table and `locate()` are kept unchanged (its `impossible_geo_login` rule and tests depend on them). B adds `LABEL` and `is_internal(ip)` (RFC 1918 only); `/api/geo` adds an `internal` flag per address so the map can draw internal sites as the HQ target.
- Merged with A: A's incident detail view in `app.js` is kept (built on the real payload); B adds the Incidents board page, and the dashboard reads A's `/api/incidents` and `/api/attack/coverage`, including A's `covered` flag (enabled rules only).
- `static/charts.js` (sparkline, line, bars, stacked bars, ranked bars, heat matrix: pure data-to-SVG-string functions), `static/map.js` (hand-drawn continent rings, dot-matrix world map, arcs), `static/dashboard.js` (panels, live client, incident board, incidents pages), dark theme in `static/style.css`. All earlier views are still in the left nav; the 1.0 dashboard is now "Metrics".
- Graceful degradation: `/api/incidents`, `/api/attack/coverage`, `/api/storyline/status` returning 404 show "pending" panels; the incident board falls back to alerts by status. Checked in a browser both ways (real 404s, and mocked A/C payloads).
- Tests: `tests/test_dashboard.py` (raw-socket SSE reads of the first frames, ingest → event/health/alert frames, heartbeat and disconnect cleanup, broker overflow and cap, geo table and route, dashboard aggregates, `since_id`, static-asset/CSP checks for the JS). Smoke step 12 checks dashboard, geo, and the stream's first frames.

**Verification.** `./run_tests.sh` ends with SMOKE OK and no failures when run as a non-root user. Browser check with Playwright/Chromium at 1280×800: no page errors on any view; SSE mode shows LIVE, and blocking `/api/stream` switches to POLLING 3s and still delivers new events.

**Not done / notes for the owner**
- `tests/test_workflow.py::test_storage_unavailable_is_failing_not_a_crash` fails when the suite runs as **root** (as in the cloud container), on `main` too: it relies on `chmod` blocking writes, which root ignores. Not changed here. Decide whether to skip it under root or run CI as a normal user.
- The tolerant readers for A's `/api/incidents` and `/api/attack/coverage` accept a list or `{incidents|techniques: [...]}` and several field spellings (`kill_chain`/`stages`/`tactics`, `hits`/`hit_count`/`alerts`). Check them against A's final shapes after merge.
- C's storyline status tile appears only when `/api/storyline/status` exists; it reads `running`, `stage`, `progress`.

## Watchpost 2.0 / C: attack storyline (2026-09-28, branch `ws/c-storyline`)

**Shipped**
- `watchpost/storyline.py`: deterministic timeline `build(seed, speed)` of `(offset_seconds, event, stage)` covering six stages (recon, credential_attack, foothold, escalation, lateral_cloud, exfiltration) plus baseline employee traffic; ~2 minutes of story time at speed 1. One attacker IP (`203.0.113.80`), one VPN egress (`198.51.100.140`), victim `dave`, rogue principal `svc-deploy-tmp`, so alerts correlate into multi-stage incidents (a 7-tactic Reconnaissance → Exfiltration incident in tests).
- `Runner`: one background thread per `App`, batches records by story time, sleeps to wall-clock, feeds `parse_payload` → `engine.ingest(synthetic=True, source="demo:storyline")` so detection, correlation, SSE, and reports all see the data. Status dict, stop event, `storyline` health check, audit entries `storyline_started/finished/stopped`, errors recorded via `diagnostics.record_error` and never propagate.
- Routes: `POST /api/storyline/start` (admin, 202/409), `POST /api/storyline/stop` (admin), `GET /api/storyline/status` (viewer; matches the shape `static/dashboard.js` already polls). Admin view gains an "Attack storyline (synthetic)" card with speed presets, start/stop, and live progress.
- `SIEM_DEMO_LOOP=<minutes>` / `SIEM_DEMO_LOOP_SPEED`: `storyline.DemoLoop` restarts the story on a timer; `main.py` now starts both the syslog listener and the demo loop through one `before_serve` wrapper.
- Tests: `tests/test_storyline.py` (determinism, ordering, RFC 5737-only sources, full replay at 2000x asserting all ten rules fire and a ≥3-stage incident exists, synthetic-only storage, audit entries, 403/400/409 handling, stop and restart, health check). Smoke step runs the replay at 1000x.

**Verification.** `./run_tests.sh` ends with SMOKE OK.

**Not done / notes for the owner**
- Written locally after two cloud sessions were stopped by the model's safety classifier while drafting this module (defensive, synthetic-only content; the block was a false positive but not worth fighting).
- The rogue principal's first cloud event is the IAM change itself (the rule requires no prior cloud activity by that principal); a preceding `sts:GetCallerIdentity` was dropped for that reason.

## Watchpost 2.0 / F: viewer role, rate limits, deploy kit, LinkedIn kit (2026-09-28, branch `ws/f-demo-kit`)

**Shipped**
- **Read-only `viewer` role, enforced by the server.** `Handler._authorize` refuses any non-GET request from a viewer
  (403 `viewer accounts are read-only`), except logout, whatever role a route declares. A future write route that
  keeps the default role is still closed to viewers. Viewers can read the dashboard, SSE stream, events, alerts,
  incidents, **reports** (now open to every signed-in role; they were analyst-only), ATT&CK coverage, metrics, rules,
  and health details. Admin-only reads (tokens, audit) stay 403. The UI shows report links to viewers and labels the
  account "(read-only)".
- `SIEM_VIEWER_PASSWORD` seeds a `viewer` account on start when set and no `viewer` user exists, so an existing
  database can gain one. It is never generated and never resets an existing viewer's password.
- **Rate limiting** (`watchpost/ratelimit.py`): in-memory per-IP token buckets. Login gets a burst of 10, then
  10/min. Everything else, static files included, gets a burst of 300, then 1200/min. Over the limit: 429 JSON with
  `retry_after` and a `Retry-After` header. Configured with `SIEM_RATE_LIMIT`, `SIEM_LOGIN_RATE_BURST`,
  `SIEM_LOGIN_RATE_PER_MIN`, `SIEM_RATE_BURST`, `SIEM_RATE_PER_MIN`, and `SIEM_TRUST_PROXY` (the last
  `X-Forwarded-For` entry, only from a loopback peer). Memory is bounded (10,000 keys, pruned).
- **`deploy/`** for Debian 12: `watchpost.service` (dedicated `watchpost` user, `SIEM_HOST=127.0.0.1` forced in
  `ExecStart`, StateDirectory `/var/lib/watchpost`, systemd sandboxing), an idempotent `install.sh` (apt deps, system
  user, rsync to `/opt/watchpost`, `/etc/watchpost.env` from a secret-free template written once, enable and
  restart, optional `--caddy DOMAIN` or `--nginx-selfsigned [IP]`, health wait), a `Caddyfile` with a domain
  placeholder, `nginx-selfsigned.conf`, and `deploy/README.md` with the exact steps.
- Rewrote `LINKEDIN.md` (project entry, a 1,220-character post, honest limits) and `DEMO_SCRIPT.md` (30-second shot
  list plus a 2-minute walkthrough built around C's **Start storyline** button). Added the 2.0 feature table,
  architecture diagram, configuration rows, and screenshot placeholders to the README. Documented the viewer rules
  and rate limiting in `docs/API.md`.
- Tests: `tests/test_viewer.py` (9) walks **every** registered route. Each GET must answer a viewer 200 (403 for
  admin-only reads). Each POST except login and logout must answer 403 and leave events, notes, tokens, change
  requests, evaluations, rule history, and alert and incident statuses unchanged. It also covers the read-only
  backstop and account seeding. `tests/test_ratelimit.py` (11) covers bucket math with a fake clock, per-key
  isolation, bounded memory, env parsing, login 429 with `Retry-After`, independent buckets, proxy trust (spoofed
  first entries ignored), and disabling. The existing report-access test now expects viewers to get 200. A smoke
  step signs in as the seeded viewer, reads an incident and its PDF, is refused four writes, and sees login
  return 429.
- `tests/test_workflow.py::test_storage_unavailable_is_failing_not_a_crash` used `chmod` to make storage
  unwritable, which root ignores, so it failed in the cloud container (noted by B). It now puts a regular file where
  the database directory should be, which fails for every user. Same assertions, no skip.

**Verification.** `./run_tests.sh` as root in the cloud container: 194 tests OK, then SMOKE OK (18 steps); after merging C from `main`, 199 tests OK and SMOKE OK (19 steps).
`bash -n` passes on `deploy/install.sh`, `start.sh`, and `run_tests.sh`. `systemd-analyze verify` accepts
`watchpost.service`. `install.sh` ran three times in the container (Ubuntu 24.04, no systemd, `systemctl`
stubbed to launch the app as the `watchpost` user with the env file). Each run was idempotent: the env file was kept
at root:watchpost 0640, the app ran as `watchpost`, and adding `SIEM_VIEWER_PASSWORD` and re-running created a
working viewer login. With `--nginx-selfsigned 203.0.113.10` and nginx 1.24: the certificate SAN is that IP, HTTP
redirects to HTTPS, the cookie carries `Secure`, SSE streams through without buffering, and the login bucket
returned 429 with `Retry-After` while spoofed `X-Forwarded-For` values made no difference. With `--caddy`: `caddy
validate` passes on Caddy 2.6.2, the Debian 12 version, and `caddy fmt` reports no changes.

**Not done**
- Not run on the real VM: that needs the owner's access. Run `sudo ./deploy/install.sh --caddy <domain>` or
  `--nginx-selfsigned <public IP>` there, per `deploy/README.md`. Real systemd sandboxing and Let's Encrypt
  issuance are untested.
- The storyline and `SIEM_DEMO_LOOP` come from workstream C (merged into this branch from `main`, not written here).
  The env template lists `SIEM_DEMO_LOOP` commented out; `DEMO_SCRIPT.md` uses C's button and stage tile.
- No video recorded and no new screenshots. README has placeholders for `incident-detail.png`,
  `incident-report-pdf.png`, and `storyline-running.png`.
- nginx listens on `[::]` as well as IPv4. In the container, which has no IPv6, those two lines had to be removed;
  Debian 12 on GCP supports IPv6 sockets. The fix is in the deploy README's troubleshooting section.

**Decisions for the owner**
- Reports are now readable by viewers (the spec lists reports among what viewers see). Reports of synthetic incidents
  contain only synthetic data, but every public visitor can download them. Revert by setting the two report routes
  back to `role="analyst"`.
- Pick the public viewer password (12+ characters) and put it in `/etc/watchpost.env` on the VM, not in the post
  draft in the repo.
- Rate-limit defaults suit a small public demo. Visitors behind one corporate NAT share a bucket. Raise
  `SIEM_RATE_PER_MIN` if that becomes a problem.

## Linux collection agent (2026-10-03, `scripts/agent.py`)

Goal: get *real* logs from a real Linux host into a running Watchpost, instead of only synthetic
demo data. First step of a larger "deployable agent" effort; a Windows collector is not written yet.

**Shipped**
- `scripts/agent.py`: a stdlib-only collection agent. It **reuses `scripts/shipper.py`** for the whole
  transport (tailing, rotation and truncation handling, atomic position file, batching,
  exponential backoff, skipping refused batches, token from env/file, plain-HTTP guard) and adds:
  - a source catalogue (`auth`, `firewall`, `web`, `audit`, `syslog`) whose paths are relative to a
    `--log-dir` (default `/var/log`), with per-host availability detection and read-permission checks;
  - stable, host-scoped source names (`<hostname>-auth`) that satisfy the server's
    `normalize.validate_source` pattern;
  - an **auditd line adapter**: raw `/var/log/audit/audit.log` records have no syslog prefix and the
    server rejects them (`line is not in syslog format`), so the agent prefixes the envelope the
    parser expects, using the record's own `msg=audit(<epoch>)` time. Non-records are dropped and
    counted instead of poisoning a batch;
  - `--list-sources`, `--dry-run`, and `--check` (a token probe that posts an empty body: the server
    authenticates first, so `400 upload is empty` means the token is valid and nothing is stored);
  - `--source syslog` deliberately **not** in `--source all`, plus a startup warning, because
    rsyslog duplicates auth/firewall lines into syslog on Debian and Ubuntu and shipping both would
    double every event and halve the effective detection thresholds.
- `deploy/agent/`: `watchpost-agent.service` (unprivileged user in the `adm` group, `StateDirectory`
  for the position file, sandboxed like the server unit), `agent.env.example`, and an idempotent
  `install-agent.sh` (installs `agent.py` **and** `shipper.py` together, since the agent imports its
  sibling; prompts for the token with hidden input; never overwrites an existing env file).
- `docs/AGENT.md`: sources, quick start, CLI reference, the syslog overlap and auditd caveats,
  security posture, a troubleshooting table, and honest limits. `README.md` and
  `docs/LIVE_INGEST.md` now list the agent as the recommended third ingestion path.
- `tests/test_agent.py`: 47 tests. The load-bearing ones assert **agreement with the server**: every
  source's `format` is in `normalize.FORMATS`, and every line the agent produces is accepted by
  `normalize.parse_payload` with the expected `event_type`. `tests/fixtures/logs/` holds committed
  fixtures so these tests need no runtime temporary directory. Includes regressions for four real
  bugs found while building and installing (below).

**Bugs found and fixed before shipping**
- The transform map was keyed by host-scoped source name (`host01-audit`) while the catalogue is
  keyed by source (`audit`), so the first run died with `KeyError`.
- The auditd transform was stored unbound, so the first audit line died with
  `TypeError: wrap_auditd() missing 1 required positional argument: 'hostname'`.
- `--list-sources`/`--dry-run` ran the plain-HTTP guard first and failed on a purely local check
  that sends no token; the guard now applies only when the agent is about to transmit.
- Resolved paths mixed separators on Windows; they are normalized with `os.path.abspath`, matching
  `shipper.parse_file_spec`.
- `--check` sat *after* the "no sources available" guard, so on a host with no readable logs the
  token was never probed and setup could not tell "wrong token" apart from "no sources". It now runs
  before that guard, which is correct because it ships nothing.
- `--url` was declared `required=True` to argparse, so `agent.py --list-sources` was rejected by
  argparse before the early-return path for that mode could run. The mode was implemented but
  unreachable, and it is the first command a new user tries. Reported by the owner during the first
  real install. `--url` is now optional at the parser level and validated in `main()` only for the
  modes that transmit, with a message that also says the URL is an option rather than a bare
  argument. Four tests cover the no-`--url` paths.

**Verification**
- `python -m unittest tests.test_agent` → 47 tests OK (40 need no server; the 7 server-backed ones
  need real temporary directories).
- Verified against the owner's live server: `agent.py --check --allow-insecure-http` on
  `http://192.168.8.178:8080` exited 0 with "token accepted by http://192.168.8.178:8080 (nothing
  was stored)". That confirms the network path, the ingest token, and the probe against a real
  deployment. It writes nothing: the probe posts an empty body, which the server rejects with
  `400 upload is empty` *after* authenticating. No events were sent to the live instance.
- No regressions: the **199 pre-existing tests fail on exactly the same 25 tests with and without
  `scripts/agent.py` present** (Windows-only artifacts: `WinError 32` on temp-dir cleanup, the
  `shipper.parse_file_spec` path-separator assertion, and a `charmap` decode). Those 25 are the
  known Linux-verified suite failing on Windows, not new breakage.
- End-to-end against a real server on an ephemeral port with a real ingest token: 5 sources
  resolved; 22 events stored, all `synthetic=0`; event types confirmed as `auth_failure`×12,
  `auth_success`, `privilege_use`/`privilege_escalation`, `user_created`, `fw_deny` (with
  `dest_port=22`), `fw_allow`, `web_scan`×2, `web_request`, `process_start`, `file_access`; the
  auditd non-record was dropped; a second run re-sent nothing (position file); and real detection
  fired `brute_force_ip` (high) and `account_repeated_failures` (medium) on the shipped failures.
- `bash -n` passes on `deploy/agent/install-agent.sh`.

**Not done / notes for the owner**
- The agent was not run on the real target host (`192.168.8.178`, Ubuntu 24.04). That needs the
  owner's SSH access, an ingest token, and `sudo ./deploy/agent/install-agent.sh --url ...`.
  `systemd-analyze verify` has not been run on the agent unit (no systemd on the build machine).
- The target server is plain HTTP on a LAN, so the agent will refuse to send the token until
  `WATCHPOST_AGENT_EXTRA_ARGS=--allow-insecure-http` is set in `/etc/watchpost-agent/agent.env`.
  That is a deliberate opt-in; HTTPS in front of Watchpost is the better fix.
- No journald source yet, so a stock Debian 12 (no rsyslog, no `/var/log/auth.log`) has nothing for
  the `auth` source. Install rsyslog, or use the syslog listener.
- No Windows collector, no local disk buffering during a long outage, and no smoke-check step for
  the agent yet.

## Agents page: the collection fleet (2026-10-03)

Goal: see, in the UI, which agents are installed and whether they are still feeding data.

**Shipped**
- **No new data model and no agent change.** An agent *is* an ingest token plus the batches it sent,
  so the fleet is derived from data already stored: `ingest_batches.submitted_by` records
  `token:<name>` for anything sent with `Authorization: Bearer wp_...`. The page therefore works for
  agents that are already deployed, with nothing to re-deploy.
- `watchpost/agents.py` + `GET /api/agents` (viewer, like the other read routes). Per agent: name,
  token prefix, `installed_at` (the token's `created_at`, i.e. when the agent was provisioned) and
  `installed_by`, hostname, per-source breakdown (source, short `kind`, formats, batches, accepted,
  rejected, events, last log), totals, `first_batch_at`, `last_batch_at`, `last_token_use_at`, and a
  `status`, plus a summary. Four grouped queries assembled in Python, so no per-agent N+1.
  - `hostname` is taken from the events the agent delivered (the most frequent non-empty `host`),
    not from anything the agent declares, so it is the hostname the logs themselves claim.
  - The short source `kind` ("auth") is derived from the shared prefix of an agent's source names.
    With a single source there is nothing to compare, so the agent's `<host>-<source>` convention is
    used *only* when that source literally starts with the hostname its own events reported;
    otherwise the full source name is shown rather than a guess.
  - `status` is `reporting` / `quiet` / `silent` / `never_reported` / `revoked`, from the age of the
    last batch, with both thresholds returned by the API.
- `static/`: an **Agents** nav entry and view — KPI tiles (installed, reporting, quiet, silent, never
  reported, events received) and a fleet table (agent, host, status, logs captured, installed by,
  installed, last received, events) with a per-source detail modal on row click. Reuses the existing
  `.kpi`/`.pill`/`table()` conventions and the `st-ok`/`st-degraded`/`st-failing` status classes, so
  no new CSS. A small `ago()` helper renders relative ages next to absolute timestamps.
- `tests/test_agents.py`: 29 tests. 26 run against an **in-memory** database with hand-built rows
  (no temporary directory, so they run anywhere); 3 go through a real server using the same
  `/api/ingest/upload?format=authlog` path the agent uses.

**The honest limit, stated in the API, the docs, and the UI**
- Every available signal is *activity* based. An agent only contacts the server when it has new lines
  to ship, so an idle host and a stopped agent are indistinguishable. The page says this plainly and
  describes `status` as "the last log received", not as agent liveness. A real heartbeat endpoint
  (which would need an agent change) is the next step if process-level liveness is wanted.

**Verification**
- `python -m unittest tests.test_agents` → 29 tests OK.
- No regressions: `discover` runs **275 tests** with the **same 25 pre-existing Windows-only
  failures** as the 199-test baseline — no new failures. That matters here because
  `tests/test_viewer.py` sweeps every registered route, so an added route is a real risk; the new
  route answers a viewer 200 and stays closed to anonymous access.
- `node --check static/app.js` passes; `static/index.html` parses and the nav now exposes
  `['dashboard','incidents','alerts','events','overview','ingest','agents','rules','health','admin']`.
- End to end: a token created the way an agent uses one, real lines shipped through
  `scripts/agent.py`, then `GET /api/agents` reports `web01-agent` on host `web01`, sources
  `auth`/`firewall`/`web`/`audit`, 14 events, status `reporting` (and `quiet` once the data aged past
  the 10-minute threshold, which is the intended behaviour).

**Not done / notes for the owner**
- No agent-side heartbeat, so `silent` cannot distinguish "no logs to send" from "service stopped".
- The page is read-only: no way to rename or revoke an agent from it (use Admin > API tokens).
- Source `kind` is presentational only. The exact stored `source` is always shown in the row tooltip
  and the detail modal, and is what `GET /api/events?source=` filters on.

## Monitoring /var/log/nginx/* (2026-10-03)

Goal: watch the whole nginx log directory for suspicious activity, not just `access.log`.

**What already existed:** nginx/Apache **combined access** logs (`format=weblog`, auto-detected),
classified into `web_request`/`web_scan`/`web_error` by `normalize.classify_web_request`, with the
`web_scanner` rule (≥5 scan-like requests from one IP in 300 s) alerting on probes. The agent's
`web` source watched **only** `nginx/access.log`.

**Two gaps, both verified before changing anything**
- **`error.log` was not just unparsed, it was silently discarded.** A realistic error line was
  rejected by the `weblog` parser ("not in combined access log format") and by `authlog` ("not in
  syslog format") — and `auto` **misdetected it as CSV**, because the line contains commas. A
  `csv.DictReader` on a single error line yields *zero records and zero rejections*, and on a whole
  file yields 0 accepted and 5 rejected. So an agent pointed at `error.log` would report a clean run
  while shipping nothing at all.
- **Only one file was watched.** Per-vhost logs (`shop.access.log`) and `error.log` were invisible.

**Shipped**
- `watchpost/normalize.py`: new **`nginx_error`** format (in `FORMATS`, so it is a first-class
  choice for uploads, the shipper, and the agent). `normalize_nginx_error_line` maps each line to
  `web_error`, takes severity from the nginx level (`crit`→critical, `error`→high, `warn`→medium,
  `notice`→low), extracts the `client:` address into `src_ip` (validated, so a malformed value costs
  the field and not the line), and prefixes the message with `METHOD PATH` when the line carries a
  request, so error and access events read alike in the UI and in reports. `detect_format` now
  recognises error lines **before** the CSV fallback, which fixes the misdetection. Timestamps are
  read as UTC, the documented rule for zone-less input.
- **Deliberate decision:** error lines are never classified as `web_scan`. A probe is normally
  recorded in `access.log` *and* `error.log`, so counting both would make `web_scanner` fire at half
  the real number of requests — a rule that alerts at 3 when it says 5 is not explainable to an
  analyst. Scanner detection stays on access logs, which see every request. Error-log probes are
  still stored, with their client IP and severity, so they are searchable and visible.
- `scripts/agent.py`: the `web` source now **scans the tree** (`nginx/*.log`, `apache2/*.log`)
  instead of naming one file. New source keys: `scan` (globs), `primary` (the file that keeps the
  plain source name), and `filename_formats` (filename substring → server format). Rotated and
  compressed files (`access.log.1`, `*.gz`, `*.bz2`, `*.xz`, `*.zst`, `*.10`) are skipped as
  history. `web.log` yields `access.log`→`weblog`, `error.log`→`nginx_error`, and per-vhost logs →
  `weblog`, each with a stable source name: `<host>-web` for access.log (unchanged, so an upgrade
  does not re-attribute existing events), `<host>-web-error`, `<host>-web-<stem>`. `--list-sources`
  now prints one line per file that would be tailed.
  - Sources *without* `scan` keep first-existing-wins semantics. That is load-bearing for
    `firewall`: UFW writes the same lines to `ufw.log` and `kern.log`, so expanding it would double
    every firewall event and halve the port-sweep threshold. There is a test asserting exactly that.
- Fixtures: `tests/fixtures/logs/nginx/{access,error,shop.access}.log` plus `access.log.1` (which
  must be skipped), and `ufw.log`/`kern.log` for the no-expansion rule.

**Verification**
- `tests/test_normalize.py`: 36 tests OK (+12: field mapping, severity per level, the missing-client
  and malformed-client cases, the older nginx format without the `*connection` field, rejection of
  non-error lines, redaction, and two tests pinning auto-detection to `nginx_error` rather than CSV).
- `tests/test_agent.py`: 55 tests OK (+8: rotated/compressed detection, tree discovery, per-file
  formats, stable source names, the firewall no-expansion rule, a missing tree reporting rather than
  crashing, and an end-to-end run of the nginx tree through a real server).
- No regressions: **294 tests**, the **same 25 pre-existing Windows-only failures** as the baseline,
  with an empty diff of the failure sets. `test_shipper_cli_delivers_nginx_access_log_as_web_events`
  was already failing before this change.
- End to end against a real server: the nginx tree shipped as three distinct sources
  (`web01-web`, `web01-web-error`, `web01-web-shop.access`); 3 `web_scan` (including a `nikto`
  traversal probe found in the **per-vhost** log), 1 `web_request`, 3 `web_error` with severities
  {high, critical} and client IPs {203.0.113.80, 198.51.100.9, 192.0.2.10}; `access.log.1` was not
  shipped; all events `synthetic=0`. Uploading a whole six-line error.log with `format=auto` now
  gives 6 accepted / 0 rejected (was 0 accepted / 5 rejected).

**Not done / notes for the owner**
- **`error.log` does not feed an alert rule yet.** Probes there are stored with `client` IP and
  severity (high for `[error]`) and so are searchable, but no rule fires on them, deliberately, to
  avoid the double-count above. Alerting on error-log-only probes needs either a dedicated rule
  (for example an "nginx error probe burst") or a dedupe-aware `web_scanner` that counts a request
  once when it appears in both logs. Worth doing; not done here.
- Rotated logs are skipped, so probes from before the agent started are only visible via a manual
  upload (`format=nginx_error` handles them).
- `nginx_error` is not wired into the syslog listener, which tries `authlog` then `weblog` on a
  forwarded frame. Forwarding `error_log syslog:...` would land those lines as generic `syslog`
  events. Only matters for hosts that forward rather than tail.

## Web attack rules: path discovery and request bursts (2026-10-03)

Goal: detect web attacks from the nginx logs now arriving, starting with the two the owner asked
for — brute-force path discovery and rapid request sequences — plus a plan for the rest.

**The gap that motivated this**
`web_scanner` only counts requests whose **path or user agent matches a known signature**
(`SCAN_PATHS`, `_SCAN_PATTERN`, `_SCANNER_AGENT`). A wordlist walk over `/admin`, `/backup`,
`/uploads`, `/config` matches none of those, and `classify_web_request` labels such a request
`web_request`, so a directory brute-force of a few hundred paths was simply invisible.

**Shipped — two new rules (13 total, up from 11)**
- **`web_path_discovery`** (medium): one IP asks for ≥ `distinct_paths` (30) different paths within
  `window_seconds` (300) **and** ≥ `min_failure_percent` (70) of those requests failed. Two conditions
  because either alone is normal: browsing repeats a few known paths, and a site crawl succeeds. The
  metric is a **set of paths**, so one probe recorded in both access.log and error.log cannot inflate
  it the way it would inflate an event count. Mapped to **T1083** (File and Directory Discovery) and
  **T1595** (Active Scanning).
- **`web_request_burst`** (medium): one IP sends ≥ `threshold` (200) requests within
  `window_seconds` (60), whatever the paths. Mapped to **T1499** (Endpoint Denial of Service).
- Both are deliberate complements: breadth catches a patient scanner, volume catches a fast one, and
  a test asserts neither substitutes for the other.
- `rules.py` gained `_web_request(event) -> (method, path, status)`, parsing the leading
  `METHOD PATH [-> STATUS]` that **both** web parsers write into the message, so the new rules need
  no schema change. `_request_path` now delegates to it.
- `attack.py` catalog grew 17 → 20 techniques (`T1595`, `T1083`, `T1499`), all referenced by rules
  and within the 15–25 bound the catalog test enforces.
- Two labeled scenarios: `path_discovery` (37 folder names, all 404/403, none matching a scanner
  signature, plus four normal readers that must stay quiet) and `request_burst` (240 requests in 36 s
  across three URLs, plus a 40-request page load that must stay quiet). Appended **last** in
  `SCENARIOS` so the seeded rng sequence for existing scenarios is unchanged.
- New params in `PARAM_SCHEMA`: `distinct_paths` (3–100000) and `min_failure_percent` (1–100).
- `docs/WEB_DETECTION.md`: the OWASP Top 10 mapped onto what nginx logs can and cannot show (five of
  the ten are genuinely observable), the planned tier-1 and tier-2 rules, and the honest note that
  Watchpost detects rather than mitigates — blocking belongs in nginx (`limit_req`, `deny`, CRS).

**Verification**
- `tests/test_rules.py`: 32 tests OK (+11): threshold boundaries, successful browsing and repeated
  single-path requests must not look like discovery, the window must be honoured, allow-listing,
  nginx error lines counting towards breadth, status-less error lines never counting, burst
  boundaries, a spread-out reader, and the complementarity test.
- The project's own evaluation over all 15 labeled scenarios: **every one of the 13 rules has
  recall 1.0 and 0 misses**; the two new rules detect exactly their scenario with **0 false
  positives**; and the new scenarios introduce **no** false positives for any existing rule. The only
  false positives anywhere remain the two intentional `noisy_scanner` ones.
- No regressions: **305 tests**, the **same 25 pre-existing Windows-only failures**, empty diff of
  the failure sets.
- `test_api.py` no longer hard-codes the rule count (it compares against `rules.DEFAULT_RULES`), and
  `scripts/smoke.py` now expects the two new rules among those that fire.

**Not done / notes for the owner**
- **`http_status` column not added yet.** This is the top recommendation in
  `docs/WEB_DETECTION.md`: rules that must tell 401 from 403 from 404, or alert on a **2xx for
  `/.env`**, cannot be written properly while the status only lives inside the message text. The name
  must be `http_status`, because `FIELD_ALIASES` already maps `status` onto `outcome`.
- Neither rule is wired into the storyline replay, and the two new rules are not yet mapped in any
  incident narrative.
- `web_request_burst` is the rule most likely to need tuning on a busy site; it is medium severity
  and reviewed-change only, like every other threshold.

## Ingest backpressure: the `--from-start` flood (2026-10-03)

**Reported by the owner:** the agent was re-shipping 500-line batches of
`cybersamurai_security.log` back to back, and the database was overloaded. This was the
`--from-start` replay recommended two days earlier, running against a file with a real backlog.

**Root cause, measured rather than guessed.** `engine.ingest` calls `run_detection` **once per
batch**, and each run loads every event in `[batch start − lookback − history, batch end + lookback]`
— 6 h of lookback plus 24 h of history, so about **30 hours of events per batch**. Total work grows
with the square of the backfill. On a 20,000-event, 40-batch replay: 40 detection runs, each scanning
a mean of 5,102 events, **204,100 event-rule evaluations for 20,000 events** (10× amplification), and
`ship_once()` drained the whole backlog with no pause between batches.

**Shipped**
- `shipper.Shipper(max_batches_per_pass=N)`: `ship_once` stops after N batches and returns, so the
  existing `run()` loop's `--interval` sleep throttles the drain. `None` (default) keeps the old
  behaviour. Stopping between batches is safe because each batch commits its offset first.
- `scripts/agent.py` and `scripts/shipper.py` both expose `--max-batches-per-pass N` (0 = no limit),
  so the two CLIs stay aligned.
- The agent now **warns before it starts** when `--from-start` would replay more than 32 MB, quoting
  the size, an estimated line count and batch count, and printing both ways out: skip history (drop
  `--from-start`, delete the position file) or trickle it (`--max-batches-per-pass`).

**Verification**
- `tests/test_live_ingest.py`: the cap is asserted to bound one pass and resume exactly where it
  stopped (4/4/2 lines across three passes), and the uncapped path is asserted to still send
  everything in one pass.
- `tests/test_agent.py`: `BackfillWarningTests` (silent below the threshold, names both remedies
  above it, reports the cap in force) plus two end-to-end tests proving `--max-batches-per-pass 1`
  stops a run after a single batch while the same command without the cap drains everything.
- Measured against a real server: 4,000 lines at `--batch-lines 500` = 8 batches / 8 detection passes
  / 18,000 events scanned; at `--batch-lines 2000` = 2 passes / 6,000 scanned. **Bigger batches are
  the single biggest lever**, because each batch costs one ~30 h scan.
- No regressions: 312 tests, and the failure set is unchanged apart from the two new shipper tests,
  which error only under this machine's Windows limitation (it cannot rename an open file, and
  `tempfile` cleanup fails) and pass when run with a writable temporary directory.

**Not done / notes for the owner**
- **The per-batch detection pass is the underlying inefficiency and is unchanged.** A proper fix is
  for a backfill to skip detection per batch and run it once at the end (an opt-out on the ingest
  path), which would make large historical loads linear. Not implemented; it changes the ingest
  contract, so it wants a decision first.
- No retention or rollup exists, so events shipped by a backfill stay in SQLite forever. If a
  backfill is ever wanted, retention matters more than ingest speed.
- `--max-batches-per-pass` throttles by POST, not by bytes or events; with a large `--batch-lines`
  the effective rate is correspondingly higher.

## Admin UI: reset the log data (2026-10-03)

Goal: recover from the backfill without hand-run SQL. The owner had 25 MB of ingested data from an
accidental historical replay and asked for a control in the Admin view that clears the logs but not
the rules.

**Shipped**
- `watchpost/maintenance.py`: `preview(conn)` and `reset_logs(conn, actor)`. `LOG_TABLES` (10) and
  `KEPT_TABLES` (11) partition the schema explicitly, and a test asserts the two together cover every
  table, so a future table cannot be added without deciding which side it belongs on.
  - **Kept deliberately:** `users` and `sessions` (a reset must not sign anyone out), `api_tokens` (an
    agent must not start failing with 401), `rules` and `rule_history` (tuned thresholds survive),
    `settings`, `change_requests`, `evaluation_runs`, `audit_log`, and internal bookkeeping.
  - Held under the engine's detection lock — renamed from `_detection_lock` to public
    `detection_lock` for this — because a detection run reads events before writing the alerts it
    derives from them, and deleting those events mid-run would leave alerts with no evidence.
  - The deletes and the audit entry share one transaction, so a reset happens completely or not at
    all. `AUTOINCREMENT` counters are reset so a fresh store starts at id 1.
  - `VACUUM` afterwards returns the space to the filesystem. If it fails (no room for the rewrite)
    the deletion still stands and the result reports `vacuumed: false` with a note, rather than
    failing the request after the data is already gone.
- Routes: `GET /api/admin/log-data` (preview, read-only) and `POST /api/admin/log-data/reset`
  (admin only). The POST body must be exactly `{"confirm": "RESET"}`; anything else is a 400, so a
  stray or replayed request cannot wipe the store.
- Admin view: a **Reset log data** card showing the per-table row counts and exactly which tables are
  kept, and a dialog that requires the word `RESET` to be typed rather than clicked. The success
  toast states what was removed and whether the file was compacted.

**Verification**
- `tests/test_maintenance.py`: 16 tests OK — 9 against an in-memory schema seeded through the real
  ingest path (so alerts, evidence, activity **and** an incident come from genuine correlation), and
  7 through a real server.
  - The narrowness is what is tested: after a reset the rules count is still 13, `/api/auth/me` still
    answers 200, the token list is intact, and **the same ingest token still ships events (201)**.
  - Also covered: wrong or missing confirmation words delete nothing, only admins may reset
    (analyst/viewer 403, anonymous 401), a second reset removes 0, ids restart at 1, the preview
    changes nothing, and health is `ok` on an empty store.
  - One test asserts the reset is audited with per-table counts, because the data it removed is gone.
- No regressions: **328 tests**, the **same 27 pre-existing Windows-only failures**, empty diff of
  the failure sets — which matters here because `tests/test_viewer.py` sweeps every registered route
  and now covers both new ones.

**Not done / notes for the owner**
- **No undo.** The UI says so and recommends copying the database file first; there is no automatic
  backup before a reset. A `--keep-backup` style pre-reset copy would be a reasonable addition.
- Resetting does not reduce the *cost* of future ingestion, and there is still **no retention
  policy**, so an instance will grow unbounded from live logs alone. Retention (delete events older
  than N days, as a reviewed setting) remains the more useful follow-up.
- The reset is logs-only by design; a "factory reset" that also clears rules, tokens and accounts is
  not offered, because deleting the database file (documented in `docs/AGENT.md`) already does that
  and is the operation that should require shell access.

## Ingest overload: "database is locked" and broken pipes (2026-10-03)

**Reported by the owner**, from the Health page:

```
api  OperationalError: database is locked        on POST /api/auth/login
api  OperationalError: database is locked        on POST /api/ingest/upload
api  BrokenPipeError: [Errno 32] Broken pipe     on POST /api/ingest/upload
```

**Diagnosis.** Three causes, only one of which was "the logs arrive too fast":

1. **Journal mode was set per connection.** `db.connect()` ran `PRAGMA journal_mode = WAL`, and the
   server opens a connection for **every HTTP request** (`App.conn()`), so every ingest, login and
   health poll took a lock on the database header. WAL is a property of the file and persists, so all
   of that locking bought nothing. This is the most likely direct source of `database is locked` on a
   request as trivial as a login.
2. **Rules ran inside the write transaction.** `run_detection` opened `BEGIN IMMEDIATE` and then
   evaluated all thirteen rules — pure Python over a large event list — inside it. SQLite has a
   single writer, so the write lock was held for the whole evaluation, which is what made unrelated
   requests fail.
3. **Every rule re-read a ~30-hour window.** One global window (longest lookback 6 h + longest
   history 24 h) was read once and handed to every rule, so a 300-second rule cost the same as a
   24-hour one and the cost of an ingest grew with the whole store. Combined with the agent's
   500-line batches this is what pushed a single ingest past the shipper's 30 s timeout, and the
   resulting client disconnect is the `BrokenPipeError`.
4. The broken pipes then **amplified** the problem: each one reached the generic handler, which wrote
   an `error_log` row (a write to a database that was already too busy) and then tried to answer the
   dead socket, raising again.

**Shipped**
- `db.connect()` no longer touches the journal mode and stays lock-free; `init_schema()` sets
  `journal_mode = WAL` and `synchronous = NORMAL` once per database. WAL with NORMAL is the usual
  pairing: an fsync at checkpoints rather than every commit, so sustained ingest is much cheaper, at
  the cost of losing the last transactions only on power loss or a kernel panic. `busy_timeout` went
  from 10 s to 20 s — deliberately **below** the shipper's 30 s request timeout, so a caller gets a
  real error rather than a broken pipe.
- `engine.run_detection` now **evaluates every rule before opening the write transaction**, collects
  the findings, and applies them in one short transaction. The write lock is held only for the
  inserts. (An explicit full scan still reads every event once for all rules, because that is cheaper
  than one read per rule and a full scan is deliberate.)
- **Per-rule scan windows.** `rules.rule_span(rule)` and `rules.rule_history(rule)` size each rule's
  read, and `engine._rule_scan` uses them, so a 300-second rule reads 300 seconds of events. The
  global `lookback_seconds`/`history_seconds` are kept as the worst case for reporting and remain
  covered by their existing tests.
- `detection.events_scanned` counts **distinct** events examined, not the sum per rule. The sum was
  tried first and is misleading: it rises while the system gets faster, because thirteen rules each
  reading a small window adds up to more than one shared window. Distinct events keeps the number
  comparable with the single-window scans it replaces.
- `Handler._handle` is now a thin wrapper that swallows `BrokenPipeError`, `ConnectionResetError`, and
  `ConnectionAbortedError` at debug level, with the request logic moved to `_dispatch`. A client that
  hangs up is normal; it no longer writes an `error_log` row and no longer attempts a reply to a dead
  socket.

**Verification**
- Measured against the same fixture as the earlier backfill benchmark (20,000 events, 40 batches of
  500): **19.5 s → 8.6 s (2.3× faster)**, per-batch detection ~0.49 s → ~0.12 s, distinct events
  examined per run 5,102 → 4,438. The larger share of the win is rule-evaluation work falling from
  13 rules × one window to each rule over its own window.
- `tests/test_engine.py` (new, 11 tests): each rule reads only its own window (a 60-second rule does
  not see an event 20 hours old, a 6-hour rule does, a 24-hour-history rule sees all three); a full
  scan still reads everything; `events_scanned` counts distinct events; detection still creates
  alerts; and — the lock regression — **a second connection writing with `busy_timeout = 0`
  succeeds while rules are evaluating**, which fails immediately if the write lock were held.
- `tests/test_db.py` (new, 12 tests): `connect()` alone leaves the journal mode at `delete` and takes
  no lock; `init_schema()` sets WAL and `synchronous = NORMAL`; WAL persists to later connections;
  `busy_timeout` is 20 s on every connection and stays under the shipper's timeout; `:memory:` is
  left alone; the schema version is recorded and `init_schema` is idempotent.
- `tests/test_api.py` gained `ConnectionHandlingTests` (4 tests): the three connection errors are
  swallowed by `_handle`, and any other exception still propagates.
- No regressions: **354 tests**, the **same 27 pre-existing Windows-only failures**, empty diff of
  the failure sets. `EndToEndTests.test_full_analyst_flow` passes, which exercises the whole
  detect → alert → correlate → report path through the restructured code.

**Not done / notes for the owner**
- **The dominant read is still two rules.** Per-rule windows cut the total, but
  `impossible_geo_login` (6 h) and `cloud_iam_change_by_new_principal` (24 h of history) set the
  floor: one run still reads ~25 hours of events. The lever that needs no code is a reviewed change
  to those two parameters (`docs/AGENT.md` and the Rules page); the cleaner fix is to answer "has
  this principal been seen in the last 24 h" with a targeted indexed query instead of loading the
  events, which would turn that rule from a pure function into one that reads the database — a design
  change worth deciding deliberately, since every rule is currently a pure function.
- **Detection still runs once per batch.** Coalescing bursts (one pass per N batches) would help
  further, and would not have helped this particular incident because a single agent ships
  sequentially. Bigger `--batch-lines` remains the cheapest lever and is the agent-side advice.
- **SQLite still has one writer.** These fixes move the ceiling a long way, but concurrent multi-host
  ingest is where the architecture, not the queries, becomes the limit.
- `synchronous = NORMAL` and the 20 s `busy_timeout` are hard-coded, not configurable. If either
  trade-off is wrong for a deployment, they want to become settings.

## Regression: capping the agent starved whole log files (2026-10-03)

**Reported by the owner:** "we are no longer digesting logs from the nginx folder."

**Cause — mine.** `--max-batches-per-pass`, which I added two turns earlier and recommended as the fix
for the ingest overload, walked `self.files` from the top on every pass and returned the moment the
budget was spent. Since the file list is ordered auth → firewall → web → audit (and within `web`,
nginx files sorted by name), any file whose backlog exceeded one pass's budget starved **every file
after it**. Not slowly — at all. The user had set `--max-batches-per-pass 4`, so if an earlier source
(auth, or a busy firewall log) had a backlog, all four nginx logs and the audit log received nothing.

Reproduced before changing anything, with the AiSwarm layout and the settings in use:

```
agent settings: --batch-lines 120 --max-batches-per-pass 4
after 4 passes:
    events stored, by source: aiswarm-auth  1920
    STARVED: ufw.log, nginx/access.log, nginx/cybersamurai_error.log,
             nginx/cybersamurai_security.log, nginx/error.log, audit/audit.log
```

**Shipped**
- `shipper.Shipper.ship_once` now serves files **round-robin, one batch each per cycle**, until the
  budget is spent or a whole cycle finds nothing. A single file with a huge backlog can no longer
  monopolise a pass.
- The rotation position is saved with the positions under a `__cursor__` key and restored on start, so
  separate invocations (cron, `--once`) stay fair across restarts and not just within one process.
  The key cannot collide with a real entry, which is always an absolute path.
- With no cap the rotation is cleared once every file is drained, so the state file stays as it was.

**Verification**
- The same repro after the fix: every source ships, with the earlier backlogs still draining fairly —
  `auth` 480, `firewall` 480, `web-cybersamurai_security` 480, and 60 each for `access.log`,
  `cybersamurai_error.log`, `error.log` and `audit`. No file starved.
- Four new tests in `tests/test_live_ingest.py`: a capped pass serves every file in one pass; a long
  backlog elsewhere delays a small file by at most a pass; the rotation survives a restart (a new
  process resumes at the recorded file, verified through the state file); and an uncapped pass clears
  the rotation.
- No regressions: **358 tests**, the same failure set in both the full run and the baseline. (The four
  new tests error in this machine's plain runner for the same reason every other `ShipperTests` does —
  `tempfile` directories are unwritable here — and pass under a workspace temporary directory.)

**Notes for the owner**
- **Re-check the agent after updating.** On the affected host, `--max-batches-per-pass` should be kept
  now that it is fair, but confirm from the journal that nginx files are being sent, not just that the
  service is running.
- Anything the agent skipped while starved was **skipped, not queued**: the batch was never sent, so
  the position file never advanced past it. It will therefore be sent on the next pass from that
  offset — nothing was lost, but the backlog is still there.
- The same head-of-line risk exists in principle for any future per-pass budget: the fairness property
  is now covered by tests rather than by inspection.

## The agent installer (2026-10-03, `deploy/agent/install-agent.sh`)

The owner's report was that the installer was missing `--dry-run` and `--allow-insecure-http` and that
it needed to be "working perfect and sending the correct data to our dashboard". Both flags were
indeed absent. The deeper problem was that the installer had two habits which produce exactly the
symptom of a broken agent: it **discarded** what it had been given, and it **said nothing** when it
did.

**Shipped**
- `--dry-run` prints the whole plan, asks whether the agent would accept the URL, runs the agent's own
  `--list-sources` and `--dry-run`, and changes nothing. It needs no root, so it is safe to run first.
  `--uninstall` (`--yes` skips the prompt) removes the unit, the installed files, the env file, the
  state, and the service user, and reminds the owner to revoke the token. `--agent-args "FLAGS"` stores
  extra agent flags in `WATCHPOST_AGENT_EXTRA_ARGS`, which is where the unit picks them up;
  `--allow-insecure-http` is accepted as a first-class flag.
- **A supplied token is always stored.** When `/etc/watchpost-agent/agent.env` already existed, the
  installer prompted for a token, threw it away, and then printed "no token is set" in the next line.
- **The env file is written with `set_env_value`, not `sed -i`.** A token or a flag list containing `&`
  or `|` was substituted instead of stored literally, because those are sed's replacement
  metacharacters. The file is rewritten in place, so its inode (and therefore its owner and mode)
  survive a re-run.
- **An option that cannot be applied is now reported.** On a re-run the env file owns `--url`,
  `--sources`, and `--log-dir`, which is what keeps local edits from being overwritten. Silently
  keeping the old value is how a service ends up shipping to the wrong place after an install that
  reported success, so `warn_if_ignored` names the flag that was dropped and what the file says instead.
- **The plain-HTTP verdict is the agent's own.** The installer used to guess from the host with glob
  patterns, and that guess disagreed with `shipper.check_url()` in both directions:
  `http://127.0.1.1:8080` is loopback to the agent but drew a false crash-loop warning, while
  `http://127.0.0.1.example.com:8080` is *not* loopback to the agent but kept the installer quiet --
  the exact crash loop the warning exists to prevent. It now asks the agent's own `check_url()` through
  a small Python shim, so the two cannot disagree; the literal comparison survives only as a fallback
  for when that cannot be run, and errs towards warning.
- **`--agent-args` is validated, because the service restarts forever.** `--check`, `--list-sources`,
  and `--dry-run` print something and exit, and under `Restart=always` that is a unit reporting
  "running" while ingesting nothing -- the hardest install failure to notice, and easy to create by
  passing `--agent-args "--check"` in order to "just test the token". Those three and `--url` are
  refused; `--once` and `--state` warn, since they work but not as intended.
- Smaller: `--help` is now the header comment block itself, self-terminating at the script's first real
  command, so adding a flag can no longer leave the help stale (it was a hand-maintained line range);
  the "that is an agent flag" hint distinguishes flags that take a value from those that do not (it
  used to suggest `--agent-args "--from-start <value>"`, which argparse rejects); a copy of the
  installer without its checkout is refused up front instead of failing later somewhere confusing; the
  post-install listing is run against the env file, so it reports the URL and log directory the service
  will actually use; and the `--help` output no longer prints an empty `--url` when none was given.

**Verification**
- 65 assertions in a temporary harness (deleted afterwards), all passing. It was built by **extracting
  the real functions out of the script** and exercising them, so the checks cannot drift from the code.
  It covers `bash -n`, `--help`, every flag-hint path, the `--agent-args` refusals, `set_env_value`
  (replace, append, `&` and `|` stored literally, mode and inode preserved), `warn_if_ignored`, and
  `--dry-run` end to end.
- The URL verdict was compared against the agent's own `check_url` for nine hosts -- loopback,
  `localhost`, `127.0.1.1`, `[::1]`, https, a LAN address, a DNS name, and the `127.0.0.1.example.com`
  trap -- installer answer against agent answer, not against a hand-written expectation. All nine agree.
- `tests/test_agent.py` gained two cases for the fallback-source warning, using a new committed fixture
  (`tests/fixtures/logs-kern-only/`) instead of a temporary directory, so they run in this machine's
  sandbox as well. 42 tests across the module's server-free classes pass locally; the module's
  `EndToEndAgentTests` error here for the usual reason.
- The full suite is **360 tests**, of which 150 fail **in this sandbox only**: 110
  `sqlite3.OperationalError: unable to open database file` and 38 `PermissionError` under the temporary
  directory, plus the two known Windows-only failures (`test_file_spec_parsing` and a `charmap` decode
  in the static-asset test). None of the 150 is in a file this work touched.
- **Not yet done, and worth saying plainly:** this session has still never run the installer end to end
  on a real host. Everything above is verified at the level of the script's own logic. The parts that
  need root, systemd, and a live Watchpost -- service start, the token check, and data arriving in the
  Agents view -- remain unverified here and need the owner's host.

**Notes for the owner**
- The behavioural fixes are the real answer to "is it sending the correct data": the token is now
  stored, a URL is either applied or reported, and a `--agent-args` mistake fails loudly at install
  time instead of leaving a service that looks healthy and sends nothing.
- Re-running the installer on AiSwarm is safe. The env file is only rewritten for the token and
  `--agent-args`, so `WATCHPOST_AGENT_SOURCES`, the log directory, and any other edit you made stay as
  they are -- and if a `--url` you pass does not match the file, it now tells you instead of ignoring
  you.
- `scripts/agent.py` had picked up a double-space shebang (`#!/usr/bin/env  python3`) in an earlier
  commit. Harmless, since `env` skips the extra space, but corrected.
- These changes were written while the tree was on a **detached HEAD** and are re-applied here on
  `main`, so they now sit on the branch that also carries the nginx starvation fix (above) and the
  ingest-overload work. The two scratch logs (`.base.log`, `.full.log`) that were committed by mistake
  in that detached line are deliberately **not** carried across; they still exist in the dangling
  commit `49488ad` if anyone ever cherry-picks it.

