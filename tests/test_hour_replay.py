import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

from app.emulator.mapping import ZoneMapping
from app.emulator.parser import iter_file
from app.emulator.playback import Playback, synthesize_stream
from app.emulator.replay import ReplayConfig
from app.emulator.synthesizer import DnstapSynthesizer

from tests.helpers import Collector, Sleeper, iso

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_HOUR_START = datetime(2026, 9, 9, 8, 0, 0, 0)
_SPACING = timedelta(seconds=30)
_EVENT_COUNT = 121


def _write_hour_file(directory):
    path = os.path.join(directory, "queries.0")
    with open(path, "w", encoding="utf-8") as handle:
        for i in range(_EVENT_COUNT):
            ts = _HOUR_START + i * _SPACING
            stamp = f"{ts:%d-%b-%Y} {ts:%H:%M:%S}.{ts.microsecond // 1000:03d}"
            handle.write(
                f"{stamp} queries: info: client @0x7fa2c438edf0 "
                f"190.102.59.241#35082 (www.apple.com): query: www.apple.com "
                f"IN A + (172.19.1.2)\n"
            )
    return path


class HourReplayX1Test(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = _write_hour_file(self.tmp.name)
        self.expected = [iso(r.timestamp) for r in iter_file(self.path, "queries.0")]

    def test_cli_replays_hour_with_count_and_logical_order(self):
        out = os.path.join(self.tmp.name, "events.json")
        result = subprocess.run(
            [sys.executable, "-m", "app.emulator", "--dataset", self.tmp.name,
             "--emit", "json", "--out", out, "--rate", "0", "--seed", "1"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("replayed=121", result.stdout)
        self.assertIn("decode_errs=0", result.stdout)
        with open(out, "r", encoding="utf-8") as handle:
            events = [json.loads(line) for line in handle if line.strip()]
        self.assertEqual(len(events), _EVENT_COUNT)
        timestamps = [e["timestamp"] for e in events]
        self.assertEqual(timestamps, self.expected)
        self.assertEqual(timestamps, sorted(timestamps))

    def test_x1_pacing_spans_source_hour_and_keeps_order(self):
        mapping = ZoneMapping.from_csv()
        records = iter_file(self.path, "queries.0")
        background = synthesize_stream(records, mapping, DnstapSynthesizer(random.Random(1)))
        collector = Collector()
        sleeper = Sleeper()
        stats = Playback(ReplayConfig(replay_rate=1.0), sleeper=sleeper).run(
            background, collector
        )
        self.assertEqual(stats.events, _EVENT_COUNT)
        self.assertAlmostEqual(sleeper.total, 3600.0, places=4)
        self.assertEqual(stats.first_ts, self.expected[0])
        self.assertEqual(stats.last_ts, self.expected[-1])
        timestamps = [e.timestamp for e in collector.events]
        self.assertEqual(timestamps, sorted(timestamps))


if __name__ == "__main__":
    unittest.main()
