import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run_emulator(args):
    return subprocess.run(
        [sys.executable, "-m", "app.emulator"] + args,
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )


class CliTest(unittest.TestCase):
    def test_replays_fixture_with_logical_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "events.json")
            result = _run_emulator(
                ["--dataset", "tests/fixtures", "--emit", "json", "--out", out, "--rate", "1", "--seed", "7"]
            )
            with open(out, "r", encoding="utf-8") as handle:
                events = [json.loads(line) for line in handle if line.strip()]
            self.assertEqual(len(events), 6)
            timestamps = [e["timestamp"] for e in events]
            self.assertEqual(timestamps, sorted(timestamps))
            self.assertEqual(timestamps[0], "2026-09-09T08:04:59.901Z")
            self.assertIn("replayed=6", result.stdout)
            for event in events:
                self.assertEqual(event["schema_version"], 1)
                self.assertIn("pop_id", event)
                self.assertIn("zone_id", event)
                self.assertIn("latency_ms", event)
                self.assertIn("rcode", event)
                self.assertIn("ground_truth", event)

    def test_same_seed_produces_identical_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_a = os.path.join(tmp, "a.json")
            out_b = os.path.join(tmp, "b.json")
            _run_emulator(["--dataset", "tests/fixtures", "--emit", "json", "--out", out_a, "--rate", "0", "--seed", "42"])
            _run_emulator(["--dataset", "tests/fixtures", "--emit", "json", "--out", out_b, "--rate", "0", "--seed", "42"])
            with open(out_a, "rb") as a, open(out_b, "rb") as b:
                self.assertEqual(a.read(), b.read())

    def test_different_seed_changes_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_a = os.path.join(tmp, "a.json")
            out_b = os.path.join(tmp, "b.json")
            _run_emulator(["--dataset", "tests/fixtures", "--emit", "json", "--out", out_a, "--rate", "0", "--seed", "42"])
            _run_emulator(["--dataset", "tests/fixtures", "--emit", "json", "--out", out_b, "--rate", "0", "--seed", "43"])
            with open(out_a, "rb") as a, open(out_b, "rb") as b:
                self.assertNotEqual(a.read(), b.read())

    def test_limit_stops_early(self):
        result = _run_emulator(["--dataset", "tests/fixtures", "--emit", "null", "--rate", "0", "--seed", "1", "--limit", "3"])
        self.assertIn("replayed=3", result.stdout)


if __name__ == "__main__":
    unittest.main()
