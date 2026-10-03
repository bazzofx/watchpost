# The Watchpost agent (Linux log collection)

`scripts/agent.py` is a small, dependency-free collector that runs on a Linux host, reads that
host's logs, and ships them to a Watchpost server with an ingest token. It is how a real machine
becomes a real data source, so events from it are stored with `synthetic=0`.

It is the same idea as `scripts/shipper.py` and it **reuses that code** for the transport: the
tailing, rotation handling, atomic position file, batching, retry/backoff, bad-batch skipping,
token handling, and plain-HTTP guard all come from `shipper.py`. The agent adds a catalogue of
known sources, a source-availability check, one line adapter for auditd, and a service installer.

Nothing is parsed on the agent. It sends lines in the formats the server already understands, so
event types, severities, rejection reasons, and secret redaction are identical to uploading the
same file from the UI. That keeps one implementation of every parser (`watchpost/normalize.py`).

## Quick start

0. **See what this host has to offer** before configuring anything. This needs no URL and no
   token, because it only reads the local filesystem:

   ```bash
   python3 scripts/agent.py --list-sources
   ```

   If a source shows `missing`, that log is not on this host (or not readable); if it shows a
   different path is used, set `--log-dir`. Sources that are missing are simply skipped later.

1. **Create an ingest token** on the Watchpost server: sign in as admin, open **Admin > API
   tokens**, name it after the host (for example `web01-agent`), and copy the `wp_...` value.
   It is shown once. It can only ingest; it cannot read data.

2. **Install the agent** on the log source:

   ```bash
   git clone <this repo> && cd watchpost
   sudo ./deploy/agent/install-agent.sh --url http://192.168.8.178:8080
   ```

   It prompts for the token with input hidden (or take it from a file with
   `--token-file /root/wp.token`, which keeps it out of your shell history).

3. **Confirm data is arriving.** On the server, open **Ingest > Recent batches**; you should see
   sources named `<hostname>-auth`, `<hostname>-firewall`, and so on, and **Events** should fill
   up with `synthetic=0` rows.

Check the agent's own log with `journalctl -u watchpost-agent -f`.

## Sources

| Name | File | Format sent | Produces |
|---|---|---|---|
| `auth` | `auth.log` | `authlog` | `auth_failure`, `auth_success`, `privilege_use`, `privilege_escalation`, `user_created` |
| `firewall` | `ufw.log`, else `kern.log` | `authlog` | `fw_deny`, `fw_allow` (with `dest_port`) |
| `web` | `nginx/access.log`, else `apache2/access.log` | `weblog` | `web_request`, `web_scan`, `web_error` |
| `audit` | `audit/audit.log` | `authlog` (adapted) | `process_start`, `file_access` |
| `syslog` | `syslog` | `authlog` | mostly generic `other` events, plus anything the firewall and sshd patterns match |

All paths are relative to `--log-dir` (default `/var/log`), so a container or a non-standard
layout works with `--log-dir /opt/logs`.

The default selection is **`auth,firewall,web,audit`**. A source whose file does not exist is
skipped with a reason, so the same command works on a web server and on a database host.

Run `agent.py --list-sources` to see what the current host actually offers:

```
$ sudo -u watchpost-agent python3 /usr/local/bin/agent.py --url http://192.168.8.178:8080 --list-sources
Watchpost agent sources (host prefix: web01, log root: /var/log)

  source    status   path                             format    events
  --------- -------- -------------------------------- --------- --------------------------------------------------
  auth      ok       /var/log/auth.log                authlog   SSH logins and failures, sudo/su, account creation
  firewall  ok       /var/log/ufw.log                 authlog   UFW/iptables denials and allows (fw_deny, fw_allow)
  web       missing  /var/log/nginx/access.log        weblog    nginx/Apache combined access log (web_request, ...
                     -> not present on this host (/var/log/nginx/access.log or /var/log/apache2/access.log)
  ...
```

### Do not collect `syslog` and `auth`/`firewall` together

`syslog` is deliberately **not** in the default set. On Debian and Ubuntu, rsyslog writes the same
sshd and UFW lines into `/var/log/syslog` that it writes to `auth.log` and `ufw.log`. Shipping both
means every matching event is ingested **twice**, so `brute_force_ip` (10 failures in 300 s) fires
after five real failures, and every count on the dashboard is doubled. The agent prints a warning
at startup if you select both.

Pick one approach per host:

- `auth,firewall,web,audit` — precise, low volume, recommended.
- `syslog` alone — everything in one file, including cron and systemd noise.

### auditd needs a syslog envelope

A raw `/var/log/audit/audit.log` record looks like this and has **no syslog prefix**:

```
type=SYSCALL msg=audit(1760000000.123:4567): ... exe="/usr/bin/id" ...
```

Watchpost's parser rejects it (`line is not in syslog format`), because that parser reads syslog
lines. The agent therefore prefixes each record with the envelope the parser expects, using the
record's **own** timestamp from `msg=audit(<epoch>)`, so events keep their true time and a
backfill stays accurate:

```
2025-10-09T09:46:40.123Z web01 audit[4567]: type=SYSCALL msg=audit(1760000000.123:4567): ... exe="/usr/bin/id" ...
```

Lines that are not auditd records are dropped and counted in the log, rather than poisoning a
batch. To get a username on these events, set `log_format = ENRICHED` in `/etc/audit/auditd.conf`;
otherwise they arrive with no `user` and no `src_ip`.

## Command line

| Option | Meaning |
|---|---|
| `--url` | Watchpost base URL, passed as an option (`--url URL`). Required to ship and for `--check`; not needed for `--list-sources` or `--dry-run`. Use `https://` for anything that is not loopback |
| `--source NAME` | Source to collect; repeatable, comma-separated, or `all`. Default: `all` = `auth,firewall,web,audit` |
| `--log-dir` | Root the source paths resolve against (default `/var/log`) |
| `--hostname` / `--source-prefix` | Override the host prefix used in source names (default: the short hostname) |
| `--token-env` / `--token-file` | Where the token comes from (default env `WATCHPOST_AGENT_TOKEN`) |
| `--state` | Position file (default `./watchpost-agent-positions.json`) |
| `--interval`, `--batch-lines` | Poll interval (default 2 s) and lines per request (default 500) |
| `--from-start` | Ship the existing content of a file seen for the first time. Default: only new lines |
| `--year` | Year for BSD syslog lines, which carry none. Leave unset for live tailing |
| `--cafile` | CA bundle, for a self-signed HTTPS certificate |
| `--allow-insecure-http` | Permit plain HTTP to a non-loopback host (the token travels in clear text) |
| `--list-sources` | Show the catalogue and what this host has, then exit |
| `--dry-run` | Show what would be shipped, then exit |
| `--check` | Verify the token against the server (writes nothing, needs no log sources), then exit |
| `--once` / `--max-retries` | Ship what is there and exit, giving up after N retries. For cron and tests |

`--list-sources`, `--dry-run`, and `--check` are safe to run any time: the first two read only the
filesystem, and `--check` sends an empty upload, which the server rejects with `400 upload is
empty` **after** authenticating, so a `400` means the token is valid and nothing was stored.

Exit codes: `0` success, `2` a configuration problem (unknown source, no readable sources, a
rejected token, or plain HTTP to a remote host).

## How it behaves

- **Position file.** After every accepted batch, the byte offset and inode of each file are written
  atomically. A restart resumes where it stopped. Watchpost has no de-duplication for ingested
  events, so this file is what prevents double-counting across restarts — keep it on persistent
  storage (`/var/lib/watchpost-agent/positions.json` in the systemd unit).
- **Rotation and truncation.** Rename rotation is followed by draining the old file first;
  truncation in place (`copytruncate`) is detected and read from the start.
- **Retries.** Network errors, 5xx, 401, and 403 retry the same batch with exponential backoff from
  1 s to 60 s with jitter. A batch the server refuses as invalid (400, 413, 415, 422) is logged and
  skipped, so one malformed line cannot stall a file forever.
- **Backfills are throttled by the server.** Watchpost rate-limits per client IP (default burst
  300, then 1200/min). A large `--from-start` backfill will hit `429` and the agent backs off
  automatically; it finishes, just more slowly.
- **Time.** RFC 3339 timestamps (what Ubuntu 24.04 writes by default) carry an offset and are used
  as-is. BSD syslog lines (`Oct  3 08:50:02`) have no year: the agent passes none, and the server
  treats them as UTC in the current year.

## Security

- The token is read from the environment or a file, **never** from the command line, and is never
  logged. In the systemd install it lives in `/etc/watchpost-agent/agent.env`, root-owned mode
  `0640`.
- Plain HTTP to a non-loopback host is refused unless you pass `--allow-insecure-http`, because the
  token would travel unencrypted. On a trusted LAN that is a conscious trade-off; the better fix is
  HTTPS (Caddy or nginx) in front of Watchpost, then an `https://` URL.
- The agent runs as an unprivileged system user. It needs no capabilities, only membership of the
  `adm` group, because `/var/log/auth.log` is `root:adm 0640`. Run as root only if a specific log
  requires it.
- The unit is sandboxed: `ProtectSystem=strict`, `NoNewPrivileges`, empty capability sets,
  `PrivateTmp`, `PrivateDevices`, restricted address families and namespaces, with the state
  directory as the only writable path.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `refusing to send the token over plain HTTP to a non-loopback host` | Expected. Add `WATCHPOST_AGENT_EXTRA_ARGS=--allow-insecure-http` to `/etc/watchpost-agent/agent.env`, or use HTTPS |
| `token accepted` but no events appear | Check `--list-sources`: the file may be unreadable. Confirm the user is in `adm` (`id -nG watchpost-agent`) and that the source has new lines |
| `server refused the token (401)` | The token was revoked or copied wrongly. Create a new one in **Admin > API tokens** |
| `line is not in syslog format` rejections in **Ingest > Recent batches** | A file that is not syslog-shaped was pointed at an `authlog` source. For auditd use the `audit` source, not a hand-written `--file` |
| Every count looks doubled | Both `syslog` and `auth`/`firewall` are selected. Use one or the other, and clear the state file after changing `--source` if files were already shipped |
| `no sources are available on this host` | Nothing in `--log-dir` matched. Use `--log-dir` for a non-standard layout, or install rsyslog on Debian 12 (which ships without it) |

## Limits

- **Files only.** There is no journald reader yet, so on a host without rsyslog (a stock Debian 12)
  `/var/log/auth.log` does not exist and `auth` is skipped. Install `rsyslog`, or forward to the
  syslog listener instead (see [LIVE_INGEST.md](LIVE_INGEST.md)).
- **Async, best effort.** Lines are shipped after they are written, so a rotation that happens
  twice between two polls, or a truncation that grows past the saved offset, can lose lines. These
  are the same cases documented for the shipper.
- **No local buffering.** If the server is down, the agent retries the current batch in place and
  the tail grows behind it; it does not spill to disk. A long outage means the position file stays
  put until the server returns.
- **No compression or TLS termination.** Use a reverse proxy for HTTPS, and a VPN or SSH tunnel if
  the path between the host and the server is not trusted.
