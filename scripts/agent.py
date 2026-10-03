#!/usr/bin/env  python3
# added new comment
"""Watchpost Linux agent: collect this host's logs and ship them to a Watchpost server.

Standard library only (Python 3.10+), so it runs as-is on Debian 12 and Ubuntu 22.04+.

The agent adds a **source catalogue** on top of `scripts/shipper.py`, which already implements
the transport: tailing files across rotation, an atomic position file, batched uploads with
exponential backoff, bad-batch skipping, and ingest-token handling. None of that is
re-implemented here. The agent decides *what* to send, in which of the server's existing
formats, and under which source name.

    export WATCHPOST_AGENT_TOKEN=wp_...        # ingest-only token, created by an admin
    ./agent.py --list-sources                  # no --url needed: this reads only this host
    ./agent.py --url http://192.168.8.178:8080 --dry-run
    ./agent.py --url http://192.168.8.178:8080 --check
    ./agent.py --url http://192.168.8.178:8080 --state /var/lib/watchpost-agent/positions.json

`--url` is passed as an option (`--url URL`), not as a bare argument. It is required to ship and
to run `--check`, and not needed for `--list-sources` or `--dry-run`, which only read this host.

Sources (`--source`, default: auth, firewall, web, audit — see SOURCES):

    auth      /var/log/auth.log          SSH logins and failures, sudo/su, account creation
    firewall  /var/log/ufw.log           UFW/iptables denials and allows -> fw_deny / fw_allow
    web       /var/log/nginx/*.log       access and error logs -> web_request / web_scan / web_error
    audit     /var/log/audit/audit.log   auditd records -> process_start / file_access
    syslog    /var/log/syslog            everything else, as generic events (opt-in: see below)

`web` takes every `*.log` under nginx/ and apache2/ (per-vhost files included) and skips rotated
ones (`access.log.1`, `*.gz`). Each file gets its own source name — `access.log` keeps
`<host>-web`, `error.log` becomes `<host>-web-error` — and its own server format: `weblog` for
access logs, `nginx_error` for error logs, which are not in the combined access format.

`syslog` is deliberately **not** part of `--source all`. On Ubuntu and Debian, rsyslog copies
auth and firewall lines into `/var/log/syslog` as well, so shipping `auth` and `syslog`
together would ingest every SSH line twice and detection thresholds would fire at half the
real count. Pass `--source syslog` explicitly (and normally without `auth`/`firewall`) if you
want it.

No parsing happens on the agent. It sends lines in the format the server already understands
(`watchpost/normalize.py`), so event types, severities, rejection reasons, and secret
redaction are identical to uploading the same file from the UI.

The token is read from an environment variable or a file, never from the command line, and it
is never logged. Plain HTTP to a non-loopback host is refused unless `--allow-insecure-http`
is given, because the token would travel in clear text.
"""

import argparse
import functools
import glob
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# Reuse the shipped transport. agent.py sits beside shipper.py in scripts/ and both files are
# installed together, so a plain sibling import works whether this is run directly or imported.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import shipper  # noqa: E402  (path set up immediately above)

# --- Source catalogue -------------------------------------------------------------------

SOURCES = [
    {
        "name": "auth",
        "paths": ["auth.log"],
        "format": "authlog",
        "description": "SSH logins and failures, sudo/su, account creation",
        "needs": "read access to auth.log (the 'adm' group, or root)",
    },
    {
        "name": "firewall",
        "paths": ["ufw.log", "kern.log"],
        "format": "authlog",
        "description": "UFW/iptables denials and allows (fw_deny, fw_allow)",
        "needs": "read access to the log (the 'adm' group); UFW logging enabled",
    },
    {
        "name": "web",
        # Every log in these trees, not just access.log: error.log carries probes, TLS failures
        # and upstream errors, and per-vhost configs write their own files here.
        "scan": ["nginx/*.log", "apache2/*.log"],
        # access.log keeps the plain <host>-web source name, so upgrading an existing install
        # does not re-attribute its events to a new source.
        "primary": ["nginx/access.log", "apache2/access.log"],
        "format": "weblog",
        # error.log is not in the access format and needs its own parser.
        "filename_formats": [("error", "nginx_error")],
        "description": "nginx/Apache access and error logs (web_request, web_scan, web_error)",
        "needs": "read access to /var/log/nginx (the 'adm' group); skipped when no web server is installed",
    },
    {
        "name": "audit",
        "paths": ["audit/audit.log"],
        "format": "authlog",
        "transform": "auditd",
        "description": "auditd execve and file records (process_start, file_access)",
        "needs": "read access to the log (the 'adm' group); auditd running",
    },
    {
        "name": "syslog",
        "paths": ["syslog"],
        "format": "authlog",
        "description": "everything else (cron, systemd, kernel) as generic events",
        "needs": "read access to the log (the 'adm' group); rsyslog installed",
        "overlaps": ("auth", "firewall"),
    },
]
DEFAULT_SOURCES = ("auth", "firewall", "web", "audit")
DEFAULT_LOG_DIR = "/var/log"
SOURCE_NAMES = tuple(source["name"] for source in SOURCES)
_BY_NAME = {source["name"]: source for source in SOURCES}

# A raw auditd record: `type=SYSCALL msg=audit(1760000000.123:4567): ...`
_AUDIT_RECORD = re.compile(r"^type=(\w+) msg=audit\((\d+(?:\.\d+)?):(\d+)\)")


def log(message):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} agent: {message}", file=sys.stderr, flush=True)


# --- Source resolution ------------------------------------------------------------------


def find_path(source, log_dir=DEFAULT_LOG_DIR):
    """First existing path for a source. Returns (absolute path, None), or (None, reason)."""
    candidates = [os.path.join(log_dir, relative) for relative in source["paths"]]
    for candidate in candidates:
        if os.path.isfile(candidate):
            if os.access(candidate, os.R_OK):
                # Normalized the same way shipper.parse_file_spec does, so the path is a stable
                # key for the transform map and never mixes separators.
                return os.path.abspath(candidate), None
            return None, f"{candidate} exists but is not readable (add the agent's user to the 'adm' group)"
    return None, "not present on this host (" + " or ".join(candidates) + ")"


# access.log.1, error.log.2.gz, ... : history, not a live stream.
_ROTATED = re.compile(r"\.(?:gz|bz2|xz|zst|[0-9]+)$", re.IGNORECASE)


def _patterns(source):
    """The globs or paths a source looks for."""
    return source.get("scan") or source.get("paths") or []


def _is_rotated(path):
    return bool(_ROTATED.search(os.path.basename(path)))


def discover(source, log_dir=DEFAULT_LOG_DIR):
    """Every file this source should tail right now, plus a reason when there are none.

    Sources with `scan` take every matching log (nginx writes per-vhost files next to access.log);
    the rest take the first existing of their `paths`, which matters for the firewall: UFW logs
    to ufw.log *and* kern.log, so taking both would double every firewall event.
    """
    patterns = source.get("scan")
    if not patterns:
        path, reason = find_path(source, log_dir)
        return ([path] if path else []), reason

    found = []
    for pattern in patterns:
        for candidate in glob.glob(os.path.join(log_dir, pattern)):
            if os.path.isfile(candidate) and not _is_rotated(candidate) and candidate not in found:
                found.append(candidate)
    if not found:
        return [], "no files matched " + " or ".join(
            os.path.join(log_dir, pattern) for pattern in patterns)
    unreadable = sorted(path for path in found if not os.access(path, os.R_OK))
    if unreadable:
        return [], f"{unreadable[0]} is not readable (add the agent's user to the 'adm' group)"
    return sorted(os.path.abspath(path) for path in found), None


def _format_for(source, path):
    """The server format for one file: filename rules first, then the source default."""
    name = os.path.basename(path).lower()
    for needle, fmt in source.get("filename_formats", ()):
        if needle in name:
            return fmt
    return source["format"]


def _source_name(source, path, host, log_dir):
    """A stable source name: <host>-<source>, or <host>-<source>-<file> for the extra files.

    Only a source that declares `primary` can produce more than one file, and only then do the
    extra files get a suffix — so a single-file source such as `auth` keeps the plain
    `<host>-auth` name it has always had.
    """
    base = f"{sanitize_source(host)}-{source['name']}"
    primary = source.get("primary")
    if not primary:
        return sanitize_source(base)
    for relative in primary:
        if path == os.path.abspath(os.path.join(log_dir, relative)):
            return sanitize_source(base)
    stem = os.path.splitext(os.path.basename(path))[0]
    return sanitize_source(f"{base}-{stem}")


BACKFILL_WARN_BYTES = 32 * 1024 * 1024
LOG_LINE_BYTES = 200          # only used to turn a byte count into a rough line estimate


def sanitize_source(value):
    """Watchpost requires 1-64 chars of letters, digits, and _ . : - (normalize.validate_source)."""
    return "".join(c if c.isalnum() or c in "_.:-" else "-" for c in value)[:64]


def resolve_sources(selected, hostname, prefix="", log_dir=DEFAULT_LOG_DIR):
    """Turn source names into shipper file tuples.

    Returns (files, transforms, skipped, warnings):
      files       [(path, format, source_name)] ready for shipper.Shipper
      transforms  {path: callable} for the sources that need a line adapter
      skipped     [(name, reason)] sources that cannot be used on this host
      warnings    [str] notices worth showing the operator
    """
    files, transforms, skipped, warnings = [], {}, [], []
    chosen = []
    for name in selected:
        source = _BY_NAME[name]
        paths, reason = discover(source, log_dir)
        if not paths:
            skipped.append((name, reason))
            continue
        for path in paths:
            files.append((path, _format_for(source, path),
                          _source_name(source, path, prefix or hostname, log_dir)))
            if source.get("transform"):
                # Bind the hostname now: the shipper calls a transform with the line only.
                transforms[path] = functools.partial(TRANSFORMS[source["transform"]], hostname=hostname)
        chosen.append(name)

    for name in chosen:
        for other in _BY_NAME[name].get("overlaps", ()):
            if other in chosen:
                warnings.append(
                    f"'{name}' and '{other}' overlap: rsyslog writes the same lines to both, so every "
                    f"matching event is ingested twice and detection counts are doubled. "
                    f"Use one or the other."
                )
    return files, transforms, skipped, warnings


# --- The auditd adapter -----------------------------------------------------------------


def wrap_auditd(line, hostname, now=None):
    """Give a raw auditd record the syslog envelope Watchpost's parser expects.

    `/var/log/audit/audit.log` holds bare `type=... msg=audit(<epoch>:<id>): ...` records with
    no syslog prefix, and the server rejects those with "line is not in syslog format". The
    record's own epoch is used as the timestamp, so events keep their real time and backfills
    stay accurate. Returns the encoded line, or None when it is not an auditd record.
    """
    try:
        text = line.decode("utf-8", "replace").rstrip("\r\n")
    except AttributeError:
        text = str(line).rstrip("\r\n")
    match = _AUDIT_RECORD.match(text)
    if match is None or not text.strip():
        return None
    try:
        moment = datetime.fromtimestamp(float(match.group(2)), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        moment = now or datetime.now(timezone.utc)  # absurd epoch: fall back to receipt time
    stamp = moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return f"{stamp} {hostname} audit[{match.group(3)}]: {text}\n".encode("utf-8")


TRANSFORMS = {"auditd": wrap_auditd}


class AgentShipper(shipper.Shipper):
    """shipper.Shipper with a per-file line transform applied just before upload."""

    def __init__(self, *args, transforms=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.transforms = transforms or {}

    def post(self, tailed, lines):
        transform = self.transforms.get(tailed.path)
        if transform is None:
            return super().post(tailed, lines)
        converted, dropped = [], 0
        for line in lines:
            result = transform(line)
            if result is None:
                dropped += 1
            else:
                converted.append(result)
        if not converted:
            log(f"{tailed.path}: {dropped} line(s) did not match the source format; nothing to send")
            # Reported as a success: there is nothing for the server to reject, and the
            # position file must advance past these lines so they are not retried forever.
            return 201
        if dropped:
            log(f"{tailed.path}: dropped {dropped} line(s) that did not match the source format")
        return super().post(tailed, converted)


# --- Token probe ------------------------------------------------------------------------


def check_token(url, token, cafile=None, timeout=30):
    """Confirm the server accepts the token without writing anything.

    `POST /api/ingest/upload` authenticates *before* it inspects the body, so an empty upload
    answers 400 "upload is empty" when the token is valid and 401/403 when it is not. Nothing
    is stored either way, which makes this a safe health check for the agent.
    """
    context = ssl.create_default_context(cafile=cafile) if url.startswith("https:") else None
    request = urllib.request.Request(
        f"{url.rstrip('/')}/api/ingest/upload", data=b"", method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "text/plain"})
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read()[:200]
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read()[:200]
    except (OSError, ValueError) as exc:
        return None, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}".encode()


# --- Reporting --------------------------------------------------------------------------


def warn_about_backfill(files, batch_lines, max_batches_per_pass, warn_bytes=BACKFILL_WARN_BYTES):
    """Say how big a first --from-start replay is, before it starts.

    Watchpost runs a full detection pass on every batch, and each pass rescans a window padded by
    the longest rule lookback plus history — about 30 hours. The cost of a backfill therefore grows
    with the square of its size, so replaying a large log can keep a single SQLite database busy for
    a long time. Worth warning about rather than discovering from a support ticket.
    """
    total = sum(os.path.getsize(path) for path, _, _ in files if os.path.exists(path))
    if total < warn_bytes:
        return
    lines = total // LOG_LINE_BYTES
    batches = max(1, lines // max(batch_lines, 1))
    log(f"WARNING: --from-start replays about {total / 1048576:.0f} MB of existing logs, roughly "
        f"{lines:,} lines in {batches:,} batches.")
    log("         Watchpost runs a detection pass per batch and each one rescans ~30 h of events, so "
        "a large replay is heavy work for one SQLite database.")
    log("         To skip history: drop --from-start and delete the position file, so every file "
        "starts at its end.")
    log(f"         To replay gently: --max-batches-per-pass 20 (currently "
        f"{max_batches_per_pass or 'unlimited'}) and a larger --batch-lines.")


def list_sources(hostname, prefix="", log_dir=DEFAULT_LOG_DIR):
    """Print the catalogue with this host's availability, one line per file that would be tailed."""
    print(f"Watchpost agent sources (host prefix: {prefix or hostname}, log root: {log_dir})\n")
    print(f"  {'source':<9} {'path':<38} {'format':<12} events")
    print(f"  {'-' * 9} {'-' * 38} {'-' * 12} {'-' * 50}")
    for source in SOURCES:
        paths, reason = discover(source, log_dir)
        if not paths:
            shown = os.path.join(log_dir, _patterns(source)[0])
            print(f"  {source['name']:<9} {shown:<38} {'-':<12} {source['description']}")
            print(f"  {'':<9} -> {reason}")
            continue
        for index, path in enumerate(paths):
            name = source["name"] if index == 0 else ""
            description = source["description"] if index == 0 else ""
            print(f"  {name:<9} {path:<38} {_format_for(source, path):<12} {description}")
    print("\n  Default (--source all): " + ", ".join(DEFAULT_SOURCES))
    print("  Opt-in only:             syslog  (overlaps auth/firewall — see the module docstring)")
    print("\n  Read access usually comes from the 'adm' group:")
    print("    sudo usermod -aG adm watchpost-agent")


def describe_plan(files, skipped, warnings, hostname, url=None):
    print(f"agent on {hostname} -> {url or '(no --url given)'}")
    if not files:
        print("  no sources available: nothing would be shipped")
    for path, fmt, name in files:
        print(f"  {name:<28} {path}  (format={fmt})")
    for name, reason in skipped:
        print(f"  skipped {name}: {reason}")
    for warning in warnings:
        print(f"  WARNING: {warning}")


# --- CLI --------------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        description="Collect this Linux host's logs and ship them to a Watchpost server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Sources: " + ", ".join(SOURCE_NAMES) + "  (or 'all' for the default set)")
    parser.add_argument("--url", help="Watchpost base URL, e.g. http://192.168.8.178:8080 "
                                      "(required to ship, or to run --check; not needed for "
                                      "--list-sources or --dry-run)")
    parser.add_argument("--source", action="append", metavar="NAME",
                        help="source to collect; repeatable, or 'all' (default: all)")
    parser.add_argument("--hostname", help="override the detected hostname used in source names")
    parser.add_argument("--source-prefix", default="", help="prefix for source names (default: the hostname)")
    parser.add_argument("--log-dir", default=DEFAULT_LOG_DIR,
                        help="log root the source paths are resolved against (default: %(default)s)")
    parser.add_argument("--state", default="watchpost-agent-positions.json",
                        help="position file (default: %(default)s)")
    parser.add_argument("--token-env", default="WATCHPOST_AGENT_TOKEN", help="env var holding the token")
    parser.add_argument("--token-file", help="file holding the token (mode 0600 recommended)")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    parser.add_argument("--batch-lines", type=int, default=500,
                        help="lines per request (default: %(default)s); a bigger batch means fewer "
                             "detection runs on the server")
    parser.add_argument("--max-batches-per-pass", type=int, default=0, metavar="N",
                        help="send at most N batches per pass, then wait --interval (0 = no limit). "
                             "Use it to trickle a large --from-start backlog instead of flooding. "
                             "Files take turns, so one file's backlog cannot starve the others")
    parser.add_argument("--year", type=int, help="year for BSD syslog lines (default: the server decides)")
    parser.add_argument("--from-start", action="store_true",
                        help="ship existing content of files seen for the first time (default: new lines only)")
    parser.add_argument("--cafile", help="CA bundle for a self-signed HTTPS certificate")
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="allow plain HTTP to a non-loopback host (the token travels in clear text)")
    parser.add_argument("--list-sources", action="store_true", help="show available sources and exit")
    parser.add_argument("--dry-run", action="store_true", help="show what would be shipped and exit")
    parser.add_argument("--check", action="store_true", help="verify the token with the server and exit")
    parser.add_argument("--once", action="store_true", help="ship what is there now, then exit")
    parser.add_argument("--max-retries", type=int, help="with --once: give up after this many retries")
    return parser


def select_sources(requested):
    if not requested:
        return list(DEFAULT_SOURCES)
    selected = []
    for item in requested:
        for name in item.split(","):
            name = name.strip().lower()
            if name == "all":
                selected += [n for n in DEFAULT_SOURCES if n not in selected]
            elif name in _BY_NAME:
                if name not in selected:
                    selected.append(name)
            else:
                raise shipper.FatalError(f"unknown source {name!r}; choose from {', '.join(SOURCE_NAMES)} or 'all'")
    return selected


def main(argv=None):
    args = build_parser().parse_args(argv)
    hostname = args.hostname or socket.gethostname().split(".")[0]

    try:
        # Inspect-only modes first: they read the local filesystem, send nothing, and so must
        # not be blocked by the transport guard or need a token.
        if args.list_sources:
            list_sources(hostname, args.source_prefix, args.log_dir)
            return 0

        files, transforms, skipped, warnings = resolve_sources(
            select_sources(args.source), hostname, args.source_prefix, args.log_dir)

        if args.dry_run:
            describe_plan(files, skipped, warnings, hostname, args.url)
            return 0

        # Everything below talks to the server, so a URL is required from here on.
        if not args.url:
            log("--url is required to ship or to run --check, for example "
                "--url http://192.168.8.178:8080 . Pass it as an option, not on its own: "
                "--list-sources works without it.")
            return 2

        shipper.check_url(args.url, args.allow_insecure_http)

        token = shipper.read_token(args)

        # --check probes the token and ships nothing, so it must not depend on this host having
        # any logs: it is the way to tell "wrong token" apart from "no sources" during setup.
        if args.check:
            status, body = check_token(args.url, token, cafile=args.cafile)
            if status == 400:
                log(f"token accepted by {args.url} (nothing was stored)")
                return 0
            if status is None:
                log(f"could not reach {args.url}: {body.decode('utf-8', 'replace')}")
                return 2
            if status in (401, 403):
                log(f"server refused the token ({status}). Check that it is current and not revoked.")
                return 2
            if status == 429:
                log("server is rate-limiting this client; try the check again shortly")
                return 2
            log(f"unexpected response from {args.url}: {status} {body.decode('utf-8', 'replace')[:200]}")
            return 2

        for warning in warnings:
            log(f"WARNING: {warning}")
        for name, reason in skipped:
            log(f"source '{name}' skipped: {reason}")
        if not files:
            log("no sources are available on this host; nothing to ship. "
                "Run with --list-sources to see what was expected.")
            return 2

        if args.from_start:
            warn_about_backfill(files, args.batch_lines, args.max_batches_per_pass)

        agent = AgentShipper(args.url, token, files, args.state, batch_lines=args.batch_lines,
                             year=args.year, from_start=args.from_start, cafile=args.cafile,
                             max_batches_per_pass=args.max_batches_per_pass or None,
                             transforms=transforms)
        try:
            if args.once:
                sent = agent.ship_once(max_retries=args.max_retries)
                log(f"done: {sent} line(s) processed, {agent.stats['skipped_batches']} batch(es) skipped")
                return 0
            log(f"shipping {len(files)} source(s) to {args.url} every {args.interval}s")
            agent.run(args.interval)
        finally:
            agent.close()
    except shipper.FatalError as exc:
        log(str(exc))
        return 2
    except OSError as exc:  # an unreadable file or a socket problem should not print a traceback
        log(f"{type(exc).__name__}: {exc}")
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
