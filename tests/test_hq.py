"""The map's HQ marker is a setting: Admin > Map location picks the country.

The map used to place its HQ wherever the demo 10.0.0.0/8 entry happened to be mapped, which is a
property of the sample data rather than of the installation. It is now a stored country, the dashboard
payload carries its centroid, and the marker moves with it.
"""

import unittest

from tests.helpers import ServerTestCase
from watchpost import geo
from watchpost.db import connect


class HqSettingTests(ServerTestCase):
    def test_the_default_country_is_used_until_something_is_saved(self):
        admin = self.client("admin")
        status, data, _ = admin.get("/api/settings/hq")
        self.assertEqual(status, 200)
        self.assertEqual(data["current"]["country"], geo.DEFAULT_COUNTRY)
        self.assertGreater(len(data["countries"]), 40, "the dropdown needs a useful country list")
        names = [c["name"] for c in data["countries"]]
        self.assertEqual(names, sorted(names), "the dropdown is alphabetical")

    def test_an_admin_moves_the_hq_and_the_dashboard_follows(self):
        admin = self.client("admin")
        status, saved, _ = admin.post("/api/settings/hq", {"country": "DE"})
        self.assertEqual(status, 200)
        self.assertEqual((saved["current"]["country"], saved["current"]["name"]), ("DE", "Germany"))

        status, dashboard, _ = self.client("viewer").get("/api/dashboard")
        self.assertEqual(status, 200)
        self.assertEqual(dashboard["hq"]["country"], "DE")
        self.assertAlmostEqual(dashboard["hq"]["lat"], geo.COUNTRIES["DE"][1])
        self.assertAlmostEqual(dashboard["hq"]["lon"], geo.COUNTRIES["DE"][2])

    def test_the_change_is_audited(self):
        admin = self.client("admin")
        admin.post("/api/settings/hq", {"country": "FR"})
        _, entries, _ = admin.get("/api/audit")
        self.assertTrue(any(e.get("action") == "hq_country_changed" for e in entries),
                        "an admin action should leave a trace")

    def test_an_unknown_country_is_rejected(self):
        status, data, _ = self.client("admin").post("/api/settings/hq", {"country": "ZZ"})
        self.assertEqual(status, 400)
        self.assertIn("country must be one of", str(data.get("error", "")))

    def test_only_admins_may_move_it(self):
        for who in ("analyst", "viewer"):
            with self.subTest(role=who):
                status, _, _ = self.client(who).post("/api/settings/hq", {"country": "DE"})
                self.assertEqual(status, 403)

    def test_a_hand_edited_value_falls_back_instead_of_breaking_the_map(self):
        admin = self.client("admin")
        admin.post("/api/settings/hq", {"country": "DE"})
        conn = connect(self.db_path)
        try:
            conn.execute("UPDATE settings SET value = 'NOT-A-COUNTRY' WHERE key = ?", (geo.HQ_SETTING,))
        finally:
            conn.close()
        _, data, _ = admin.get("/api/settings/hq")
        self.assertEqual(data["current"]["country"], geo.DEFAULT_COUNTRY)

    def test_every_country_has_a_plausible_centroid(self):
        for code, (name, lat, lon) in geo.COUNTRIES.items():
            with self.subTest(country=code):
                self.assertTrue(name)
                self.assertGreaterEqual(lat, -90)
                self.assertLessEqual(lat, 90)
                self.assertGreaterEqual(lon, -180)
                self.assertLessEqual(lon, 180)


if __name__ == "__main__":
    unittest.main()
