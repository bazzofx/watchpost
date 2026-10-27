"""Value tiers: which events are worth keeping at full fidelity.

Tiering decides how long a row stays in the hot tier. It never decides whether a row is detected, so
these tests are only about the classification rules.
"""

import os
import unittest
from unittest import mock

from watchpost import classify


class TierTests(unittest.TestCase):
    def test_auth_and_privilege_are_high_value(self):
        for event_type in ("auth_failure", "auth_success", "privilege_escalation", "user_created",
                           "cloud_iam_change", "file_access", "process_start"):
            with self.subTest(event_type=event_type):
                self.assertEqual(classify.tier_for({"event_type": event_type}), "A")

    def test_probes_and_denials_are_suspicious(self):
        for event_type in ("web_scan", "web_error", "fw_deny", "cloud_data_access"):
            with self.subTest(event_type=event_type):
                self.assertEqual(classify.tier_for({"event_type": event_type}), "B")

    def test_routine_traffic_is_low_value(self):
        for event_type in ("web_request", "fw_allow", "other", "syslog"):
            with self.subTest(event_type=event_type):
                self.assertEqual(classify.tier_for({"event_type": event_type}), "C")

    def test_a_severe_routine_event_is_promoted_to_suspicious(self):
        """A flood of high-severity events must not be aged out early just because the type is dull."""
        for severity in ("high", "critical", "CRITICAL"):
            with self.subTest(severity=severity):
                self.assertEqual(
                    classify.tier_for({"event_type": "web_request", "severity": severity}), "B")

    def test_low_severity_does_not_promote(self):
        self.assertEqual(classify.tier_for({"event_type": "web_request", "severity": "low"}), "C")

    def test_missing_severity_and_type_are_routine(self):
        self.assertEqual(classify.tier_for({}), "C")

    def test_lists_are_configurable_by_environment(self):
        with mock.patch.dict(os.environ, {"SIEM_TIER_A": "process_start",
                                          "SIEM_TIER_B": "auth_failure"}):
            self.assertEqual(classify.tier_for({"event_type": "auth_failure"}), "B")
            self.assertEqual(classify.tier_for({"event_type": "web_request"}), "C")
            self.assertEqual(classify.tier_for({"event_type": "process_start"}), "A")


if __name__ == "__main__":
    unittest.main()
