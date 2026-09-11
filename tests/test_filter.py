import unittest
from datetime import datetime,timedelta,timezone
from app.agent.filter import DeterministicFilter,FilterConfig

def event(at,qname="normal.example",rcode="NOERROR",client="10.0.0.1"):
    return {"timestamp":at.isoformat().replace("+00:00","Z"),"qname":qname,"rcode":rcode,"client_ip":client}
class FilterTest(unittest.TestCase):
    def setUp(self):self.start=datetime(2026,1,1,tzinfo=timezone.utc)
    def test_nxdomain_requires_minimum_sample(self):
        f=DeterministicFilter(); self.assertIsNone(f.process(event(self.start,rcode="NXDOMAIN")))
        r=None
        for i in range(1,5):r=f.process(event(self.start+timedelta(seconds=i),rcode="NXDOMAIN"))
        self.assertIn("nxdomain_ratio",r["signals"])
    def test_entropy_without_rarity_does_not_escalate(self):
        f=DeterministicFilter(); self.assertIsNone(f.process(event(self.start,"a8zfj2m1x.example")))
    def test_long_label_requires_repetition(self):
        f=DeterministicFilter(); q="a8zfj2m1xq8v7b6n5m4l3k2j1h0g9f8d7s6x5r4t3.example"; self.assertIsNone(f.process(event(self.start,q))); self.assertIn("long_high_entropy_repetition",f.process(event(self.start+timedelta(seconds=1),q))["signals"])
    def test_expiry_forgets_old_nxdomain(self):
        f=DeterministicFilter(); f.process(event(self.start,rcode="NXDOMAIN")); self.assertIsNone(f.process(event(self.start+timedelta(seconds=61))))
    def test_rarity_never_escalates_alone(self):self.assertIsNone(DeterministicFilter().process(event(self.start,"ordinary-new-domain.test")))
    def test_typosquat_escalates_directly(self):
        r=DeterministicFilter().process(event(self.start,"micros0ft.com")); self.assertIsNotNone(r); self.assertTrue(r["signals"]["rarity"]["typosquat"])
    def test_beaconing_supports_sixty_second_periods(self):
        f=DeterministicFilter(FilterConfig(beacon_window_seconds=300)); q="cdn-metrics-update.example"; r=None
        for i in range(4):r=f.process(event(self.start+timedelta(seconds=i*60),q))
        self.assertIn("beaconing",r["signals"]); self.assertEqual(r["signals"]["beaconing"]["mean_interval_seconds"],60)
    def test_expired_client_keys_are_removed(self):
        f=DeterministicFilter(); f.process(event(self.start,client="10.0.0.1")); f.process(event(self.start+timedelta(seconds=601),client="10.0.0.2")); self.assertNotIn("10.0.0.1",f._windows)
if __name__=="__main__":unittest.main()
