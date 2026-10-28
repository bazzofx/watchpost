#!/usr/bin/env python3
"""Watchpost file shipper: tail log files and post new lines to Watchpost with an ingest token.

Standard library only (Python 3.10+), so it runs as-is on Debian 12 and Ubuntu 22.04+.

    export WATCHPOST_TOKEN=wp_...          # an ingest-only token created by an admin
    python3 shipper.py --url https://siem.example.internal \\
        --file /var/log/auth.log:authlog --state /var/lib/watchpost-shipper/positions.json

Each --file is PATH[:FORMAT[:SOURCE]]. FORMAT is passed to /api/ingest/upload (default
"auto"); SOURCE defaults to "<hostname>-<file stem>". Only complete lines are sent.
The byte offset of every file is saved in the position file after each accepted batch,
so a restart resumes where it stopped. Rotation (rename + new file) is followed: the
old file is drained before switching to the new one.

Network and 5xx errors retry the same batch with exponential backoff. A batch the
server refuses as invalid (400, 413, 415, 422) is logged and skipped so one bad
line cannot block a file forever. The token is read from an environment variable or
a file, never from the command line, and is never logged.
"""

import argparse
import collections
import datetime
import ipaddress
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

DEFAULT_STATE = "watchpost-shipper-positions.json"
SKIP_STATUSES = {400, 413, 415, 422}   # the batch itself is bad; retrying cannot help
MAX_BACKOFF = 60.0


def log(message):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} shipper: {message}", file=sys.stderr, flush=True)


class FatalError(Exception):
    pass


class TailedFile:
    """Follows one path across rotations and yields complete lines as bytes."""

    def __init__(self, path, fmt, source, state, from_start):
        self.path, self.fmt, self.source = path, fmt, source
        self.handle, self.inode, self.offset = None, None, 0
        self.pending = b""
        saved = state.get(path)
        try:
            st = os.stat(path)
        except FileNotFoundError:
            return  # opened later when it appears
        if saved and saved.get("inode") == st.st_ino and saved.get("offset", 0) <= st.st_size:
            self._open(saved["offset"])
        else:
            # New file, or rotated while the shipper was down: start over (or at the end if tailing).
            self._open(0 if (saved or from_start) else st.st_size)

    def _open(self, offset):
        if not os.path.isfile(self.path):  # follows symlinks; rejects directories, devices, FIFOs
            raise FatalError(f"{self.path}: not a regular file")
        self.handle = open(self.path, "rb")
        self.inode = os.fstat(self.handle.fileno()).st_ino
        self.handle.seek(offset)
        self.offset, self.pending = offset, b""

    def read_lines(self, max_lines, max_bytes):
        """Return up to max_lines complete lines (without committing the offset) and the end offset."""
        if self.handle is None:
            if not os.path.exists(self.path):
                return [], self.offset
            self._open(0)
        lines, size = [], 0
        self.handle.seek(self.offset)
        position = self.offset
        while len(lines) < max_lines and size < max_bytes:
            line = self.handle.readline(max_bytes)
            if not line:
                break
            position += len(line)
            if not line.endswith(b"\n"):
                if len(line) < max_bytes:
                    position -= len(line)
                    break  # partial line: wait for the writer to finish it
                line += b"\n"  # an over-long line is sent in pieces rather than blocking the file
            if line.strip():
                lines.append(line)
                size += len(line)
        if not lines and position == self.offset and self._check_rotation():
            return self.read_lines(max_lines, max_bytes)
        return lines, position

    def _check_rotation(self):
        """At EOF: if the path now names a different or truncated file, switch to it. True if switched."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return False
        if st.st_ino != self.inode:
            self.handle.close()
            self._open(0)
            return True
        if st.st_size < self.offset:  # truncated in place (copytruncate)
            self.offset = 0
            return True
        return False

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def commit(self, offset):
        self.offset = offset

    def state(self):
        return {"inode": self.inode, "offset": self.offset} if self.inode is not None else None


class BurstGuard:
    """Turn a flood from one client into one summary event instead of thousands of rows.

    Web logs are the case this exists for: a scanner walking paths produces hundreds of lines from a
    single address in seconds, and every one of them ends up as a stored event, as evidence on an
    alert, and as work for correlation. Counting belongs on the agent, where it is cheap; the server
    then receives one event that says what happened.

    The rule: more than `threshold` lines from the same source address within `window` seconds is a
    burst. Once a burst starts, its lines are swallowed (they are *not* sent) and one summary is
    emitted when the burst goes quiet. The first `threshold` lines of a burst are sent normally — the
    agent cannot know a flood is starting until it has seen it.

    Kept pure (a clock in, no I/O) so the thresholds can be tested without a server.
    """

    def __init__(self, threshold=50, window=5.0, clock=time.monotonic, max_paths=200):
        self.threshold = max(1, int(threshold))
        self.window = max(0.1, float(window))
        self.clock = clock
        self.max_paths = max(1, int(max_paths))
        self._recent = {}      # (source, ip) -> deque of sighting times within the window
        self._bursts = {}      # (source, ip) -> {"count", "suppressed", "last", "paths"}
        self.stats = {"bursts": 0, "suppressed": 0}

    @staticmethod
    def web_fields(line):
        """(client address, request target) from an nginx/Apache combined line, else None.

        Deliberately tolerant: anything that does not look like a combined access-log line returns
        None and is passed through untouched, so a mixed-format file is never silently mangled.
        """
        text = line.decode("utf-8", "replace") if isinstance(line, bytes) else line
        try:
            address = text.split(" ", 1)[0]
            if not address or address.count(".") != 3 and ":" not in address:
                return None
            quoted = text.split('"')
            if len(quoted) < 2:
                return None
            parts = quoted[1].split()
            if len(parts) < 2 or parts[0] not in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS",
                                                  "PATCH", "TRACE", "CONNECT"):
                return None
            return address, parts[1]
        except (ValueError, IndexError):
            return None

    def filter(self, lines, fmt, source):
        """Return the lines to send. Burst lines are counted here and dropped from the batch."""
        if fmt not in ("weblog", "auto"):
            return lines
        kept = []
        now = self.clock()
        for line in lines:
            fields = self.web_fields(line)
            if fields is None:
                kept.append(line)          # not a web line: never coalesce what we cannot read
                continue
            address, path = fields
            key = (source, address)
            burst = self._bursts.get(key)
            if burst is not None:
                burst["count"] += 1
                burst["suppressed"] += 1
                burst["last"] = now
                if len(burst["paths"]) < self.max_paths:
                    burst["paths"].add(path)
                self.stats["suppressed"] += 1
                continue
            recent = self._recent.setdefault(key, collections.deque())
            recent.append(now)
            while recent and now - recent[0] > self.window:
                recent.popleft()
            if len(recent) > self.threshold:
                # The flood threshold is crossed: this line and everything after it is summarised.
                self._recent.pop(key, None)
                self._bursts[key] = {"count": len(recent), "suppressed": 1, "last": now,
                                     "paths": {path}}
                self.stats["bursts"] += 1
                self.stats["suppressed"] += 1
                continue
            kept.append(line)
        return kept

    def collect(self, now=None):
        """Summaries for bursts that have gone quiet, as (source, address, summary) tuples."""
        now = self.clock() if now is None else now
        finished = [key for key, burst in self._bursts.items() if now - burst["last"] >= self.window]
        summaries = []
        for key in finished:
            burst = self._bursts.pop(key)
            source, address = key
            paths = burst["paths"]
            summaries.append((source, address, {
                "ts": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                "source": source,
                "src_ip": address,
                "event_type": "web_scan",
                "severity": "medium",
                "message": (f"Rapid asset discovery: {burst['count']} requests to {len(paths)} "
                            f"distinct paths in {self.window:g}s from {address} "
                            f"({burst['suppressed']} line(s) suppressed by the agent)"),
            }))
        return summaries


class Shipper:
    def __init__(self, url, token, files, state_path, batch_lines=500, batch_bytes=1024 * 1024,
                 year=None, from_start=False, cafile=None, timeout=30, sleep=time.sleep,
                 burst_threshold=50, burst_window=5.0):
        if urllib.parse.urlparse(url).scheme not in ("http", "https"):
            raise FatalError(f"url must be http(s), got {url!r}")  # urlopen would also take file:// and ftp://
        self.url, self.token = url.rstrip("/"), token
        self.state_path = Path(state_path)
        self.batch_lines, self.batch_bytes, self.year = batch_lines, batch_bytes, year
        self.timeout, self.sleep = timeout, sleep
        self.context = ssl.create_default_context(cafile=cafile) if url.startswith("https:") else None
        state = self._load_state()
        self.files = [TailedFile(path, fmt, source, state, from_start) for path, fmt, source in files]
        self.burst = BurstGuard(burst_threshold, burst_window) if burst_threshold > 0 else None
        self.stats = {"batches": 0, "lines": 0, "skipped_batches": 0, "retries": 0, "summaries": 0,
                      "suppressed": 0}

    def _load_state(self):
        try:
            return json.loads(self.state_path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            log(f"ignoring unreadable position file {self.state_path}: {type(exc).__name__}")
            return {}

    def save_state(self):
        state = {f.path: f.state() for f in self.files if f.state()}
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
        os.replace(tmp, self.state_path)

    def post(self, tailed, lines):
        """Send one batch. Returns the HTTP status; raises OSError on network failure."""
        query = {"format": tailed.fmt, "source": tailed.source}
        if self.year:
            query["year"] = str(self.year)
        request = urllib.request.Request(
            f"{self.url}/api/ingest/upload?{urllib.parse.urlencode(query)}", data=b"".join(lines),
            method="POST", headers={"Authorization": f"Bearer {self.token}", "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as resp:
                body = json.loads(resp.read() or b"null")
                status = resp.status
        except urllib.error.HTTPError as exc:
            with exc:
                try:
                    body = json.loads(exc.read() or b"null")
                except ValueError:
                    body = None
            status = exc.code
        if status in (201, 207):
            log(f"{tailed.path}: sent {len(lines)} line(s), accepted {body.get('accepted')}, "
                f"rejected {body.get('rejected')}")
        elif status in SKIP_STATUSES:
            reason = body.get("error") if isinstance(body, dict) and body.get("error") else \
                f"{body.get('rejected') if isinstance(body, dict) else '?'} record(s) rejected"
            log(f"{tailed.path}: server refused a batch of {len(lines)} line(s) ({status}: {reason}); skipping it")
        return status

    def post_summary(self, tailed, event):
        """Send one coalesced burst summary through the JSON ingest endpoint.

        One request per burst, not per line: the whole point is that the server sees a single event
        saying "this address did rapid asset discovery" instead of hundreds of rows.
        """
        payload = json.dumps({"source": tailed.source, "events": [event]}).encode()
        request = urllib.request.Request(
            f"{self.url}/api/ingest", data=payload, method="POST",
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=self.context) as resp:
                resp.read()
                return resp.status
        except urllib.error.HTTPError as exc:
            with exc:
                exc.read()
            return exc.code

    def _tailed_for(self, source):
        for tailed in self.files:
            if tailed.source == source:
                return tailed
        return None

    def _deliver_summary(self, tailed, address, event, attempts=3):
        delay, problem = 1.0, None
        for _ in range(attempts):
            try:
                status = self.post_summary(tailed, event)
            except (OSError, ValueError) as exc:
                status, problem = None, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
            else:
                problem = f"HTTP {status}"
            if status in (201, 207):
                self.stats["summaries"] += 1
                log(f"{tailed.path}: burst summary accepted for {address}")
                return True
            if status in SKIP_STATUSES:
                log(f"{tailed.path}: server refused a burst summary ({status}); dropping it")
                return False
            self.sleep(delay)
            delay = min(delay * 2, 8)
        log(f"{tailed.path}: burst summary for {address} not delivered ({problem})")
        return False

    def _flush_summaries(self):
        """Send the summary for every burst that has gone quiet, then forget it."""
        if not self.burst:
            return
        for source, address, event in self.burst.collect():
            tailed = self._tailed_for(source)
            if tailed is not None:
                self._deliver_summary(tailed, address, event)
        self.stats["suppressed"] = self.burst.stats["suppressed"]
        self.stats["bursts"] = self.burst.stats["bursts"]

    def ship_once(self, max_retries=None):
        """Send everything currently available. Returns the number of lines sent or skipped."""
        total = 0
        self._flush_summaries()
        for tailed in self.files:
            while True:
                lines, end = tailed.read_lines(self.batch_lines, self.batch_bytes)
                if not lines:
                    if end != tailed.offset:  # only blank lines: just advance
                        tailed.commit(end)
                        self.save_state()
                    break
                if self.burst:
                    lines = self.burst.filter(lines, tailed.fmt, tailed.source)
                if lines:
                    self._send_with_backoff(tailed, lines, max_retries)
                    total += len(lines)
                # The position advances even when every line was suppressed into a burst, otherwise
                # the same lines would be re-read (and re-suppressed) forever.
                tailed.commit(end)
                self.save_state()
        self._flush_summaries()
        return total

    def _send_with_backoff(self, tailed, lines, max_retries):
        delay, attempt = 1.0, 0
        while True:
            try:
                status = self.post(tailed, lines)
            except (OSError, ValueError) as exc:  # URLError, timeouts, resets, bad JSON from a proxy
                status, problem = None, f"{type(exc).__name__}: {getattr(exc, 'reason', exc)}"
            else:
                problem = f"HTTP {status}"
            if status in (201, 207):
                self.stats["batches"] += 1
                self.stats["lines"] += len(lines)
                return
            if status in SKIP_STATUSES:
                self.stats["skipped_batches"] += 1
                return
            if status in (401, 403):
                problem += " (check the ingest token; it may be revoked)"
            attempt += 1
            if max_retries is not None and attempt > max_retries:
                raise FatalError(f"{tailed.path}: giving up after {max_retries} retries ({problem})")
            self.stats["retries"] += 1
            wait = min(delay, MAX_BACKOFF) * (0.5 + random.random() / 2)
            log(f"{tailed.path}: {problem}; retrying in {wait:.1f}s")
            self.sleep(wait)
            delay *= 2

    def close(self):
        for tailed in self.files:
            tailed.close()

    def run(self, interval=2.0):
        while True:
            self.ship_once()
            self.sleep(interval)


def parse_file_spec(spec, hostname=None):
    path, _, rest = spec.partition(":")
    fmt, _, source = rest.partition(":")
    hostname = (hostname or socket.gethostname().split(".")[0])[:40]
    source = source or f"{hostname}-{Path(path).stem}"
    safe = "".join(c if c.isalnum() or c in "_.:-" else "-" for c in source)[:64]
    return os.path.abspath(path), fmt or "auto", safe


def check_url(url, allow_insecure):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise FatalError(f"--url must be an http(s) URL, got {url!r}")
    if parsed.scheme == "http" and not allow_insecure:
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if not loopback:
            raise FatalError("refusing to send the token over plain HTTP to a non-loopback host; "
                             "use https:// or pass --allow-insecure-http")


def read_token(args):
    if args.token_file:
        token = Path(args.token_file).read_text().strip()
    else:
        token = os.environ.get(args.token_env, "").strip()
    if not token.startswith("wp_"):
        raise FatalError(f"no ingest token: set ${args.token_env} or pass --token-file (tokens start with wp_)")
    return token


def main(argv=None):
    parser = argparse.ArgumentParser(description="Tail log files and ship them to Watchpost.")
    parser.add_argument("--url", required=True, help="Watchpost base URL, e.g. https://siem.example.internal")
    parser.add_argument("--file", action="append", required=True, metavar="PATH[:FORMAT[:SOURCE]]",
                        help="file to tail; repeat for several (FORMAT: auto, authlog, weblog, json, jsonl, csv, ...)")
    parser.add_argument("--state", default=DEFAULT_STATE, help="position file (default: %(default)s)")
    parser.add_argument("--token-env", default="WATCHPOST_TOKEN", help="env var holding the token")
    parser.add_argument("--token-file", help="file holding the token (mode 0600 recommended)")
    parser.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    parser.add_argument("--batch-lines", type=int, default=500)
    parser.add_argument("--burst-threshold", type=int, default=50,
                        help="web lines from one client within --burst-window before the rest are "
                             "coalesced into one summary event (0 disables)")
    parser.add_argument("--burst-window", type=float, default=5.0,
                        help="seconds that define a burst (default: %(default)s)")
    parser.add_argument("--year", type=int, help="year for BSD syslog lines (default: server decides)")
    parser.add_argument("--from-start", action="store_true",
                        help="ship existing content of files seen for the first time (default: only new lines)")
    parser.add_argument("--once", action="store_true", help="ship what is there now, then exit")
    parser.add_argument("--max-retries", type=int, help="with --once: give up after this many retries")
    parser.add_argument("--cafile", help="CA bundle for a self-signed HTTPS certificate")
    parser.add_argument("--allow-insecure-http", action="store_true",
                        help="allow plain HTTP to a non-loopback host (the token travels in clear text)")
    args = parser.parse_args(argv)
    try:
        check_url(args.url, args.allow_insecure_http)
        token = read_token(args)
        files = [parse_file_spec(spec) for spec in args.file]
        shipper = Shipper(args.url, token, files, args.state, batch_lines=args.batch_lines, year=args.year,
                          from_start=args.from_start, cafile=args.cafile,
                          burst_threshold=args.burst_threshold, burst_window=args.burst_window)
        try:
            if args.once:
                sent = shipper.ship_once(max_retries=args.max_retries)
                log(f"done: {sent} line(s) processed, {shipper.stats['skipped_batches']} batch(es) "
                    f"skipped, {shipper.stats['suppressed']} line(s) suppressed across "
                    f"{shipper.stats['bursts']} burst(s)")
                return 0
            log(f"shipping {len(files)} file(s) to {args.url} every {args.interval}s")
            shipper.run(args.interval)
        finally:
            shipper.close()
    except FatalError as exc:
        log(str(exc))
        return 2
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
