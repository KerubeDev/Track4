import os
import tempfile
import unittest

from app.emulator.mapping import ZoneMapping, ZoneMappingError

_SAMPLE_CSV = """ip_cidr,pop_id,zone_id,client_name,latency_mean_ms,latency_std_ms,nx_rate,qps_baseline
10.0.0.0/8,PAN-PAC-01,BANCO-PA-Z1,BANCO-PA,5.0,2.0,0.005,20
190.14.0.0/16,PAN-ATL-01,BANCO-PA-Z1,BANCO-PA,22.0,8.0,0.020,80
190.14.128.0/17,PAN-ATL-01,BANCO-PA-Z2,BANCO-PA,20.0,7.0,0.015,40
0.0.0.0/0,PAN-ATL-01,DEFAULT-Z0,DEFAULT,90.0,45.0,0.080,60
"""


class ZoneMappingTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "zone_mapping.csv")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(_SAMPLE_CSV)
        self.mapping = ZoneMapping.from_csv(self.path)

    def tearDown(self):
        self.dir.cleanup()

    def test_longest_prefix_wins(self):
        profile = self.mapping.resolve("190.14.200.5")
        self.assertEqual(profile.zone_id, "BANCO-PA-Z2")

    def test_shorter_prefix_flags_banned_ip(self):
        profile = self.mapping.resolve("190.14.120.5")
        self.assertEqual(profile.zone_id, "BANCO-PA-Z1")
        self.assertEqual(profile.pop_id, "PAN-ATL-01")

    def test_private_range(self):
        profile = self.mapping.resolve("10.66.66.253")
        self.assertEqual(profile.zone_id, "BANCO-PA-Z1")
        self.assertEqual(profile.pop_id, "PAN-PAC-01")

    def test_fallback_default(self):
        profile = self.mapping.resolve("8.8.8.8")
        self.assertEqual(profile.zone_id, "DEFAULT-Z0")

    def test_exposes_catalog(self):
        self.assertIn("PAN-ATL-01", self.mapping.pop_ids)
        self.assertIn("BANCO-PA-Z2", self.mapping.zone_ids)
        self.assertIn("BANCO-PA", self.mapping.client_names)

    def test_invalid_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            ZoneMapping.from_csv("/nonexistent/zone_mapping.csv")


if __name__ == "__main__":
    unittest.main()