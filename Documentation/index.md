# Watchpost — Documentation

Watchpost is a small, self-hosted security-analytics pipeline (a working SIEM): it ingests security
logs, normalizes them, runs threshold-based detection rules, groups findings into alerts and
incidents, and presents them in a dashboard. It is Python standard-library only (3.10+) with a single
SQLite database and a vanilla-JS front end — no frameworks, no external services, no outbound network
calls from the application.

This folder is the documentation site. It is written as plain Markdown so it can be rendered by a
static site generator or GitHub Pages; every link is a relative `./path.md` link so pages redirect to
each other no matter where the site is hosted.

## Read first

- [Architecture](architecture.md) — what the components are, the lifecycle of a log line, and the
  current storage model.
- [Project plan](project-plan.md) — the phased scalability plan, its status, and the acceptance
  criteria.
- [Security logging practices](security-logging.md) — how the OWASP Logging Cheat Sheet is applied.

## Feature documentation

Each feature gets its own subfolder, with a page explaining **what it does, why, how it works,
examples, sources, and its current status** (implemented / planned). As features land, they are added
here and linked from the project plan.

| Area | Page | Status |
|---|---|---|
| Search | [FTS5 full-text](search/fts5.md) | ✅ implemented (Phase 1) |
| Ingestion idempotency | [Batch idempotency](ingestion/idempotency.md) | ✅ implemented (Phase 2) |
| Retention & archive | `retention/` | planned (Phase 3) |
| Classification & aggregation | `processing/` | planned (Phase 4) |
| Metrics & quarantine | `observability/` | planned (Phase 4) |
| Detection scheduling | `detection/` | planned (Phase 5) |

## Existing documentation

The repository also has a legacy `docs/` folder for the pieces that already work. The site links into
it rather than duplicating it:

- [API reference](../docs/API.md) — endpoints, the ingest contract, field aliases.
- [Agent](../docs/AGENT.md) — the Linux log collector and its installer.
- [Web detection](../docs/WEB_DETECTION.md) — the OWASP web rules and their thresholds.
- [Live ingest](../docs/LIVE_INGEST.md) — the syslog listener and file shipper.
- [Dashboard](../docs/DASHBOARD.md) — what the dashboard shows.

> **Note on naming.** The folder is spelled `Documentation` (the request said "Documantation"). If the
> site generator or your preference requires the other spelling, `git mv Documentation Documantation`
> is the only change needed — all internal links are relative, so they survive a rename.
