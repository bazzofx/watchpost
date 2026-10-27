# Security logging practices (OWASP Logging Cheat Sheet)

This page maps the [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
onto concrete Watchpost behaviour — what already holds, and what is added by the project plan.

Status markers: ✅ already implemented, 🔜 planned in a phase (see [project plan](project-plan.md)).

| Cheat-sheet guidance | Watchpost behaviour | Status |
|---|---|---|
| Log security-relevant events | Auth failures/successes, sudo/su escalation, privilege use, account creation are normalized and detected; config/rule/security-setting changes are recorded in `audit_log`. | ✅ (extend to token create/revoke, retention/archive, quarantine) |
| Don't log secrets | `normalize.redact()` scrubs `password=…` and similar before storage; ingest tokens are never logged and never in `ps`. | ✅ → 🔜 configurable patterns + a test asserting no `wp_…` token/password in `message`/`raw` |
| Structured, standard format | Common `events` schema; UTC ISO-8601 timestamps kept distinct from `ingested_at`. | ✅ → 🔜 `parser_name`/`parser_version`/`source_event_id` |
| Log-injection (CRLF) defense | `normalize.clean_text` strips control characters from every field; the UI renders text as text nodes (no `innerHTML`/`eval`). | ✅ → 🔜 explicit CRLF-injection test |
| Correlation IDs | Detections → incidents already linked (`alert_events`, `incident_alerts`). | ✅ → 🔜 propagate batch/agent session id |
| Central store + access control | One central server; roles viewer < analyst < admin; viewers read-only; raw evidence restricted. | ✅ |
| Integrity | WAL + append-only-by-convention. **Not tamper-proof** — WAL is crash safety, not an integrity seal; state this honestly, don't claim otherwise. | ✅ (documented as-is) |
| Retention by category | None today (manual reset only). | 🔜 Phase 3/4: per-tier retention, evidence pinning, audited deletion |
| Monitor the logs themselves | Health endpoint covers ingestion/detection; agent fleet view shows per-source reporting. | ✅ → 🔜 Phase 4/6 metrics, gap reporting |
| Fail-safe, no silent drop | Ingest acks only after commit; agent retries 5xx/429 with backoff. | ✅ → 🔜 bounded spool + explicit dropped/lost counters |

## Redaction, and what not to log

Watchpost deliberately does **not** store request bodies (nginx access logs carry none), which avoids
the largest class of "don't log the body" mistakes. The remaining sensitive surface is query strings,
tokens and credentials, which are redacted in both `message` and `raw` where they are recognised.

Redaction must not destroy detection context: the same rule set that matches injection and traversal
patterns runs on the *redacted* text, so redaction patterns must only ever remove secret values, never
structural markers the rules need. This trade-off is tested, not assumed.

## Access control

- **Viewer** — read-only.
- **Analyst** — triage: alert/incident status, notes, reports.
- **Admin** — rules, settings, tokens, retention/reset.

Raw evidence and quarantine are restricted to roles that need them; archive files inherit the same
filesystem ownership model as the hot database.

## Honest guarantees

- WAL gives crash-consistency, not tamper-evidence.
- The store is single-host, single-writer; "centralised" here means "one server the agents push to",
  not a distributed log.
- Retention deletes are recorded in `audit_log`, so an operator can reconstruct *that* data was
  removed and when — not the deleted content itself.
