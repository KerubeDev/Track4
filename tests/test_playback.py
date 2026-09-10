import random
import unittest
from datetime import datetime

from app.emulator.events import TelemetryEvent
from app.emulator.mapping import ZoneMapping
from app.emulator.parser import QueryRecord, iter_file
from app.emulator.playback import Playback, merge_event_streams, synthesize_stream
from app.emulator.replay import ReplayConfig, Replayer, find_dataset_files, merged_stream
from app.emulator.synthesizer import DnstapSynthesizer

from tests.helpers import Sleeper

_FIXTURE = "tests/fixtures/queries.sample"


class FakeEmitter:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def flush(self):
        pass


def _records():
    return list(iter_file(_FIXTURE, "queries.sample"))


class DatasetOrderingTest(unittest.TestCase):
    def test_merged_stream_orders_out_of_order_files(self):
        merged = list(merged_stream([_FIXTURE, _FIXTURE]))
        for i in range(len(merged) - 1):
            self.assertLessEqual(merged[i].timestamp, merged[i + 1].timestamp)

    def test_find_dataset_files_natural_sort(self):
        self.assertIn(_FIXTURE, find_dataset_files("tests/fixtures"))


class ReplayerTest(unittest.TestCase):
    def test_pace_compresses_wall_clock_at_rate_20(self):
        sleeper = Sleeper()
        replayer = Replayer(ReplayConfig(replay_rate=20.0), sleeper=sleeper)
        replayer.pace(
            datetime(2026, 9, 9, 8, 0, 0, 0),
            datetime(2026, 9, 9, 8, 0, 1, 0),
        )
        self.assertAlmostEqual(sleeper.total, 0.05)

    def test_pace_rate_one_is_linear(self):
        sleeper = Sleeper()
        replayer = Replayer(ReplayConfig(replay_rate=1.0), sleeper=sleeper)
        replayer.pace(datetime(2026, 9, 9, 8, 0, 0, 500000), datetime(2026, 9, 9, 8, 0, 0, 700000))
        self.assertAlmostEqual(sleeper.total, 0.2)

    def test_no_wait_mode_skips_pacing(self):
        sleeper = Sleeper()
        replayer = Replayer(ReplayConfig(replay_rate=0.0), sleeper=sleeper)
        replayer.pace(datetime(2026, 9, 9, 8, 0, 0, 0), datetime(2026, 9, 9, 8, 0, 10, 0))
        self.assertEqual(sleeper.total, 0.0)


class PlaybackTest(unittest.TestCase):
    def setUp(self):
        self.mapping = ZoneMapping.from_csv()
        self.synth = DnstapSynthesizer(random.Random(7))

    def test_playback_emits_all_events_in_logical_order(self):
        emitter = FakeEmitter()
        background = synthesize_stream(_records(), self.mapping, self.synth)
        stats = Playback(ReplayConfig(replay_rate=0.0)).run(background, emitter)
        self.assertEqual(stats.events, 6)
        self.assertEqual(stats.attack_events, 0)
        timestamps = [e.ts for e in emitter.events]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_playback_merges_attack_stream(self):
        background = synthesize_stream(_records(), self.mapping, self.synth)
        attack_host = [_mk_attack("2026-09-09T08:04:59.950Z")]
        emitter = FakeEmitter()
        stats = Playback(ReplayConfig(replay_rate=0.0)).run(
            background, emitter, attack_stream=iter(attack_host)
        )
        self.assertEqual(stats.events, 7)
        self.assertEqual(stats.attack_events, 1)
        labeled = [e for e in emitter.events if e.ground_truth is not None]
        self.assertEqual(len(labeled), 1)
        self.assertEqual(labeled[0].ground_truth["episode"], "E1")
        timestamps = [e.ts for e in emitter.events]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_merge_event_streams_keeps_chronological_order(self):
        records = _records()
        background = synthesize_stream(iter(records[:2]), self.mapping, self.synth)
        attack = list(synthesize_stream(iter(records[2:3]), self.mapping, self.synth))
        merged = list(merge_event_streams(background, iter(attack)))
        self.assertEqual(len(merged), 3)
        for i in range(len(merged) - 1):
            self.assertLessEqual(merged[i].ts, merged[i + 1].ts)


def _mk_attack(timestamp):
    return TelemetryEvent(
        ts=timestamp,
        client_ip="10.99.50.97",
        qname="evil.example",
        qtype="A",
        rcode="NOERROR",
        latency_ms=1.0,
        pop_id="PAN-PAC-01",
        zone_id="BANCO-PA-Z1",
        ground_truth={"attack": "dga", "episode": "E1"},
    )


if __name__ == "__main__":
    unittest.main()
