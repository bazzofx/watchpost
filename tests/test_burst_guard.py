"""Agent-side burst coalescing: a flood from one client becomes one summary event.

`scripts/shipper.py` is loaded by path, the same way test_live_ingest.py does it, because nothing
under `scripts/` is a package. The guard itself is pure (clock injected), so these need no server and
no temporary directory.
"""

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("shipper", ROOT / "scripts" / "shipper.py")
shipper = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shipper)

WEB = ('203.0.113.9 - - [03/Oct/2026:10:00:{second:02d} +0000] "GET {path} HTTP/1.1" 404 153 '
       '"-" "Mozilla/5.0"\n')


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def web_line(second, path="/a.css", ip="203.0.113.9"):
    return (WEB.format(second=second % 60, path=path).replace("203.0.113.9", ip, 1)).encode()


class BurstGuardTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.guard = shipper.BurstGuard(threshold=5, window=5.0, clock=self.clock)

    def test_normal_traffic_passes_through(self):
        lines = [web_line(i) for i in range(5)]
        self.assertEqual(self.guard.filter(lines, "weblog", "web01"), lines)
        self.assertEqual(self.guard.stats["bursts"], 0)
        self.assertEqual(self.guard.collect(), [])

    def test_crossing_the_threshold_starts_a_burst(self):
        lines = [web_line(i) for i in range(5)]
        self.assertEqual(len(self.guard.filter(lines, "weblog", "web01")), 5)
        # The sixth line inside the window is where the flood becomes visible.
        self.assertEqual(self.guard.filter([web_line(5)], "weblog", "web01"), [])
        self.assertEqual(self.guard.stats["bursts"], 1)
        # Everything after it is swallowed.
        self.assertEqual(self.guard.filter([web_line(6), web_line(7)], "weblog", "web01"), [])
        self.assertEqual(self.guard.stats["suppressed"], 3)

    def test_the_summary_describes_the_burst(self):
        self.guard.filter([web_line(i) for i in range(5)], "weblog", "web01")
        self.guard.filter([web_line(5, path="/x"), web_line(6, path="/y")], "weblog", "web01")
        self.clock.now += 6          # the burst goes quiet
        summaries = self.guard.collect()
        self.assertEqual(len(summaries), 1)
        source, address, event = summaries[0]
        self.assertEqual((source, address), ("web01", "203.0.113.9"))
        self.assertEqual(event["event_type"], "web_scan")
        self.assertEqual(event["src_ip"], "203.0.113.9")
        self.assertIn("Rapid asset discovery", event["message"])
        self.assertIn("7 requests", event["message"])
        self.assertIn("2 distinct paths", event["message"])
        self.assertTrue(event["ts"].endswith("Z"))
        # Collected once, then forgotten.
        self.assertEqual(self.guard.collect(), [])

    def test_collect_waits_for_the_window(self):
        self.guard.filter([web_line(i) for i in range(6)], "weblog", "web01")
        self.assertEqual(self.guard.collect(), [], "a live burst must not be summarised yet")
        self.clock.now += 5.1
        self.assertEqual(len(self.guard.collect()), 1)

    def test_bursts_are_per_address(self):
        self.guard.filter([web_line(i) for i in range(5)], "weblog", "web01")
        self.guard.filter([web_line(5)], "weblog", "web01")            # starts a burst
        other = [web_line(5, ip="198.51.100.4")]
        self.assertEqual(self.guard.filter(other, "weblog", "web01"), other,
                         "a different client is unaffected")

    def test_non_web_formats_are_never_touched(self):
        lines = [b"Oct  3 10:00:00 web01 sshd[1]: Failed password for admin\n"] * 20
        self.assertEqual(self.guard.filter(lines, "authlog", "auth01"), lines)
        self.assertEqual(self.guard.stats["suppressed"], 0)

    def test_unparseable_lines_pass_through_even_in_a_weblog_file(self):
        junk = [b"this is not a web log line\n"] * 10
        self.assertEqual(self.guard.filter(junk, "weblog", "web01"), junk)

    def test_defaults_match_the_documented_policy(self):
        guard = shipper.BurstGuard()
        self.assertEqual((guard.threshold, guard.window), (50, 5.0))


class FakeTailed:
    """Just enough of TailedFile for ship_once: batches in, committed offset out."""

    def __init__(self, batches, fmt="weblog", source="web01"):
        self.path = "/fake/access.log"
        self.fmt, self.source = fmt, source
        self.batches = list(batches)
        self.offset = 0
        self.committed = None

    def read_lines(self, max_lines, max_bytes):
        if not self.batches:
            return [], self.offset
        batch = self.batches.pop(0)
        self.offset += len(batch)
        return batch, self.offset

    def commit(self, end):
        self.committed = end

    def state(self):
        return self.committed


class ShipOnceTests(unittest.TestCase):
    """The whole point: many lines in, few lines out, one summary, and the offset still advances."""

    def build(self, lines, threshold=5, window=5.0):
        instance = shipper.Shipper("http://127.0.0.1:9", "wp_test", [(__file__, "weblog", "web01")],
                                   "/nonexistent/state.json", burst_threshold=threshold,
                                   burst_window=window, sleep=lambda _s: None)
        instance.save_state = lambda: None
        instance.files = [FakeTailed([lines])]
        clock = Clock()
        if instance.burst is not None:
            instance.burst.clock = clock      # control time from the start, not half-way through
        sent, delivered = [], []

        def fake_send(tailed, batch, max_retries=None):
            sent.append(list(batch))

        instance._send_with_backoff = fake_send

        def fake_post(tailed, event):
            delivered.append(event)
            return 201

        instance.post_summary = fake_post
        return instance, sent, delivered, clock

    def test_a_burst_sends_only_the_threshold_and_then_one_summary(self):
        lines = [web_line(i, path=f"/p{i}") for i in range(20)]
        instance, sent, delivered, clock = self.build(lines, threshold=5)
        instance.ship_once()
        self.assertEqual(len(sent), 1)
        self.assertEqual(len(sent[0]), 5, "only the lines before the flood are uploaded")
        self.assertEqual(instance.stats["suppressed"], 15)
        self.assertEqual(delivered, [], "the summary waits until the burst goes quiet")
        self.assertEqual(instance.files[0].committed, instance.files[0].offset,
                         "the read position must advance even though lines were suppressed")

        clock.now += 6                                 # the burst has gone quiet
        instance.ship_once()
        self.assertEqual(len(delivered), 1)
        self.assertIn("Rapid asset discovery", delivered[0]["message"])
        self.assertEqual(instance.stats["summaries"], 1)

    def test_traffic_below_the_threshold_is_uploaded_whole(self):
        lines = [web_line(i) for i in range(4)]
        instance, sent, delivered, _clock = self.build(lines, threshold=50)
        instance.ship_once()
        self.assertEqual([len(b) for b in sent], [4])
        self.assertEqual(delivered, [])

    def test_disabling_the_guard_uploads_everything(self):
        lines = [web_line(i, path=f"/p{i}") for i in range(20)]
        instance, sent, _delivered, _clock = self.build(lines, threshold=0)
        self.assertIsNone(instance.burst)
        instance.ship_once()
        self.assertEqual([len(b) for b in sent], [20])


if __name__ == "__main__":
    unittest.main()
