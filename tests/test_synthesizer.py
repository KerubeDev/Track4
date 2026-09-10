import random
import unittest
from datetime import datetime

from app.emulator.events import SCHEMA_VERSION, TelemetryEvent
from app.emulator.mapping import ZoneProfile
from app.emulator.parser import QueryRecord
from app.emulator.synthesizer import DnstapSynthesizer

_PROFILE = ZoneProfile(
    ip_cidr="0.0.0.0/0",
    pop_id="PAN-ATL-01",
    zone_id="BANCO-PA-Z1",
    client_name="BANCO-PA",
    latency_mean_ms=22.0,
    latency_std_ms=4.0,
    nx_rate=0.0,
    qps_baseline=60,
)

_RECORD = QueryRecord(
    timestamp=datetime(2026, 9, 9, 8, 4, 59, 901000),
    client_ip="190.102.59.241",
    client_port=35082,
    qname="www.apple.com",
    qtype="A",
    resolver_ip="172.19.1.2",
    source_file="queries.0",
)


class SynthesizerTest(unittest.TestCase):
    def test_event_carries_schema_and_mapping(self):
        event = DnstapSynthesizer(random.Random(7)).synthesize(_RECORD, _PROFILE)
        self.assertEqual(event.schema_version, SCHEMA_VERSION)
        self.assertEqual(event.pop_id, "PAN-ATL-01")
        self.assertEqual(event.zone_id, "BANCO-PA-Z1")
        self.assertEqual(event.rcode, "NOERROR")
        self.assertEqual(event.ground_truth, None)

    def test_latency_in_plausible_range(self):
        synth = DnstapSynthesizer(random.Random(1))
        values = [synth.synthesize(_RECORD, _PROFILE).latency_ms for _ in range(2000)]
        self.assertGreaterEqual(min(values), 0.5)
        self.assertLess(abs(sum(values) / len(values) - 22.0), 0.5)

    def test_rcode_respects_nx_rate(self):
        profile = ZoneProfile(
            ip_cidr="0.0.0.0/0",
            pop_id="PAN-ATL-01",
            zone_id="GOB-PA-Z1",
            client_name="GOB-PA",
            latency_mean_ms=15.0,
            latency_std_ms=3.0,
            nx_rate=0.25,
            qps_baseline=12,
        )
        synth = DnstapSynthesizer(random.Random(3))
        rcodes = [synth.synthesize(_RECORD, profile).rcode for _ in range(4000)]
        nx = sum(1 for r in rcodes if r == "NXDOMAIN")
        self.assertAlmostEqual(nx / 4000, 0.25, delta=0.04)

    def test_ground_truth_carried_through(self):
        gt = {"attack": "dga", "episode": "E1"}
        event = DnstapSynthesizer(random.Random(5)).synthesize(_RECORD, _PROFILE, ground_truth=gt)
        self.assertEqual(event.ground_truth, gt)

    def test_deterministic_under_seed(self):
        synth = DnstapSynthesizer(random.Random(42))
        first = [synth.synthesize(_RECORD, _PROFILE).to_json() for _ in range(10)]
        synth = DnstapSynthesizer(random.Random(42))
        second = [synth.synthesize(_RECORD, _PROFILE).to_json() for _ in range(10)]
        self.assertEqual(first, second)


class EventSerializationTest(unittest.TestCase):
    def test_json_shape(self):
        import json

        event = DnstapSynthesizer(random.Random(7)).synthesize(_RECORD, _PROFILE)
        data = json.loads(event.to_json())
        self.assertEqual(data["schema_version"], SCHEMA_VERSION)
        self.assertEqual(data["ts"], "2026-09-09T08:04:59.901Z")
        self.assertIn("rcode", data)
        self.assertIn("latency_ms", data)
        self.assertIn("pop_id", data)
        self.assertIn("zone_id", data)
        self.assertIsNone(data["ground_truth"])


if __name__ == "__main__":
    unittest.main()
