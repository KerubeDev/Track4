import unittest
from datetime import datetime, timedelta, timezone

from app.agent.filter import DeterministicFilter, FilterConfig


def event(at, qname="normal.example", rcode="NOERROR", client="10.0.0.1"):
    return {"timestamp": at.isoformat().replace("+00:00", "Z"), "qname": qname, "rcode": rcode, "client_ip": client}


class FilterTest(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_nxdomain_ratio_escalates_alone(self):
        f = DeterministicFilter()
        result = None
        for i in range(5):
            result = f.process(event(self.start + timedelta(seconds=i), rcode="NXDOMAIN"))
        self.assertIn("nxdomain_ratio", result["signals"])

    def test_entropy_without_rarity_does_not_escalate(self):
        f = DeterministicFilter()
        result = f.process(event(self.start, "a8zfj2m1x.example"))
        self.assertIsNone(result)

    def test_long_label_requires_repetition(self):
        f = DeterministicFilter()
        qname = "a8zfj2m1xq8v7b6n5m4l3k2j1h0g9f8d7s6x5r4t3.example"
        self.assertIsNone(f.process(event(self.start, qname)))
        result = f.process(event(self.start + timedelta(seconds=1), qname))
        self.assertIn("long_high_entropy_repetition", result["signals"])

    def test_expiry_forgets_old_nxdomain(self):
        f = DeterministicFilter()
        f.process(event(self.start, rcode="NXDOMAIN"))
        result = f.process(event(self.start + timedelta(seconds=61), rcode="NOERROR"))
        self.assertIsNone(result)

    def test_rarity_never_escalates_alone(self):
        f = DeterministicFilter()
        result = f.process(event(self.start, "micrpsoft.com"))
        self.assertIsNone(result)

    def test_typosquat_is_evidence_against_client_vocabulary(self):
        f = DeterministicFilter(FilterConfig(entropy=0))
        result = f.process(event(self.start, "micrpsoft.com"))
        self.assertTrue(result["signals"]["rarity"]["typosquat"])


if __name__ == "__main__":
    unittest.main()
