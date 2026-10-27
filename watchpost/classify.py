"""Value tiers: how long an event is worth keeping at full fidelity.

Five categories, from the retention policy:

| Tier | Meaning | Stored how |
|---|---|---|
| A | high-value security events (auth, privilege, accounts, process, file, IAM) | full record, longest retention |
| B | suspicious, needs review (web probes and errors, firewall denials, cloud data reads) | full record |
| C | repetitive and low-risk (routine web traffic, allowed firewall flows) | full record, **shortest** retention; folded into rollups when it ages out |
| D | operational telemetry | never an event row (metrics) — not classified here |
| E | malformed / irrelevant | rejected before storage — not classified here |

Two rules this module is careful about:

- **Classification never gates detection.** It is consulted only when deciding how long a record
  stays in the hot tier. Detection reads every event first; a tier is not a verdict on whether
  something is interesting.
- **A severe event is never routine.** A type that is normally Category C but arrives with `high` or
  `critical` severity is promoted to B, so a flood of unusual severity cannot be aged out early
  merely because its type is usually boring.

Defaults are overridable per deployment with `SIEM_TIER_A` / `SIEM_TIER_B`, each a comma-separated
list of event types. Anything named in neither list is Category C.
"""

import os

TIER_A = ("auth_failure", "auth_success", "account_lockout", "user_created", "privilege_use",
          "privilege_escalation", "process_start", "file_access", "network_connection",
          "cloud_iam_change", "vpn_login")
TIER_B = ("web_scan", "web_error", "fw_deny", "cloud_data_access")

SEVERE = ("high", "critical")


def _configured(name, default):
    raw = os.environ.get(name)
    if not raw:
        return frozenset(default)
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def tier_lists():
    """(A, B) as frozensets, honouring SIEM_TIER_A / SIEM_TIER_B when set."""
    return _configured("SIEM_TIER_A", TIER_A), _configured("SIEM_TIER_B", TIER_B)


def tier_for(event):
    """The value tier of a normalized event: 'A', 'B', or 'C'."""
    event_type = event.get("event_type")
    high, suspicious = tier_lists()
    if event_type in high:
        return "A"
    if event_type in suspicious:
        return "B"
    if (event.get("severity") or "").lower() in SEVERE:
        return "B"          # a normally-routine type that turns severe is not routine
    return "C"
