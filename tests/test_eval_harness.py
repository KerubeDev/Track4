import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from app.eval.harness import (
    agent_view,
    evaluate,
    ground_truth_label,
    percentile,
)
from app.eval.qvac import MockQVAC
from tests.helpers import iso

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


class SeqClock:
    """Deterministic monotonic clock: every call advances ``step`` seconds."""

    def __init__(self, step=0.005):
        self._t = 0.0
        self._step = step

    def __call__(self):
        self._t += self._step
        return self._t


def make_event(offset_s, qname, rcode, client, *, gt=None, zone="Z1", pop="P1", qtype="A"):
    return {
        "ts": iso(BASE + timedelta(seconds=offset_s)),
        "client_ip": client,
        "qname": qname,
        "qtype": qtype,
        "rcode": rcode,
        "latency_ms": 10.0,
        "pop_id": pop,
        "zone_id": zone,
        "schema_version": 1,
        "ground_truth": {"attack": gt} if gt else None,
    }


LONG_LABEL = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w"
TUNNEL_QNAME = f"{LONG_LABEL}.tun.example"


def golden_events():
    """16-query fixture with hand-computable expectations.

    Plan (per client so filter windows do not mix):

    * A 10.0.0.10 NXDOMAIN x4 (t=0..3): every one escalates (nx_ratio 1.0)
      -> MockQVAC verdict dga. GT: dga, dga, benign, dga.
    * B 10.0.0.11 (t=100..101): repeated long high-entropy label -> tunnel.
      B1 alone does not escalate; B2 repeats the qname so it escalates.
      GT: tunnel, tunnel.
    * C 10.0.0.12 (t=200,206,212,218): beacon bursts; the first two do not
      yet have two >=5s gaps so only C3, C4 escalate -> beaconing. GT all.
    * D 10.0.0.13 (t=300..301): D1 typosquat (entropy below threshold -> no
      escalate); D2 benign. GT: typosquat, benign.
    * E 10.0.0.14 (t=400..401): E1 NXDOMAIN benign -> escalates as dga (FP);
      E2 benign clean.
    * F 10.0.0.20/.21 (zone Z2, pop P2, t=500/501): benign, never escalated.
    """
    events = [
        make_event(0, "zzx1.a.com", "NXDOMAIN", "10.0.0.10", gt="dga"),
        make_event(1, "yyx2.b.com", "NXDOMAIN", "10.0.0.10", gt="dga"),
        make_event(2, "wqx3.c.com", "NXDOMAIN", "10.0.0.10", gt="benign"),
        make_event(3, "kqz4.d.com", "NXDOMAIN", "10.0.0.10", gt="dga"),
        make_event(100, TUNNEL_QNAME, "NOERROR", "10.0.0.11", gt="tunnel"),
        make_event(101, TUNNEL_QNAME, "NOERROR", "10.0.0.11", gt="tunnel"),
        make_event(200, "beacon1.example", "NOERROR", "10.0.0.12", gt="beaconing"),
        make_event(206, "beacon1.example", "NOERROR", "10.0.0.12", gt="beaconing"),
        make_event(212, "beacon1.example", "NOERROR", "10.0.0.12", gt="beaconing"),
        make_event(218, "beacon1.example", "NOERROR", "10.0.0.12", gt="beaconing"),
        make_event(300, "micrsfot.com", "NOERROR", "10.0.0.13", gt="typosquat"),
        make_event(301, "normal.example", "NOERROR", "10.0.0.13", gt="benign"),
        make_event(400, "xzv1.hosp-pa.example", "NXDOMAIN", "10.0.0.14", gt="benign"),
        make_event(401, "www.spotify.com", "NOERROR", "10.0.0.14", gt="benign"),
        make_event(500, "www.apple.com", "NOERROR", "10.0.0.20", gt="benign", zone="Z2", pop="P2"),
        make_event(501, "qwert1.example", "NOERROR", "10.0.0.21", gt="benign", zone="Z2", pop="P2"),
    ]
    return events


def run_golden():
    return evaluate(
        golden_events(),
        filter=None,
        qvac=MockQVAC(latency_ms=12.0),
        clock=SeqClock(),
    )


def assert_class(report, label, tp, fp, fn, tn, precision, recall, f1):
    cls = report.classes[label]
    for name, expected, actual in (
        ("tp", tp, cls.tp), ("fp", fp, cls.fp), ("fn", fn, cls.fn),
        ("tn", tn, cls.tn), ("precision", precision, cls.precision),
        ("recall", recall, cls.recall), ("f1", f1, cls.f1),
    ):
        if isinstance(expected, float):
            delta = abs(expected - actual)
            assert delta < 1e-6, f"{label}.{name}: expected {expected}, got {actual}"
        else:
            assert expected == actual, f"{label}.{name}: expected {expected}, got {actual}"


class PercentileTest(unittest.TestCase):
    def test_nearest_rank_exact(self):
        values = [1.0, 2.0, 3.0, 4.0]
        self.assertEqual(percentile(values, 50.0), 2.0)
        self.assertEqual(percentile(values, 95.0), 4.0)
        self.assertEqual(percentile([5.0], 50.0), 5.0)

    def test_empty_sample_is_zero(self):
        self.assertEqual(percentile([], 50.0), 0.0)


class GoldenFixtureTest(unittest.TestCase):
    def test_confusion_matrix_and_per_class_metrics_match_hand_calculation(self):
        report = run_golden()
        self.assertEqual(report.total_queries, 16)
        self.assertEqual(report.matrix, (
            (4, 2, 0, 0, 0, 0),   # true benign
            (0, 3, 0, 0, 0, 0),   # true dga
            (1, 0, 1, 0, 0, 0),   # true tunnel
            (2, 0, 0, 2, 0, 0),   # true beaconing
            (1, 0, 0, 0, 0, 0),   # true typosquat
            (0, 0, 0, 0, 0, 0),   # true unverified
        ))

        assert_class(report, "benign", 4, 4, 2, 6, 0.5, 2 / 3, 4 / 7)
        assert_class(report, "dga", 3, 2, 0, 11, 0.6, 1.0, 0.75)
        assert_class(report, "tunnel", 1, 0, 1, 14, 1.0, 0.5, 2 / 3)
        assert_class(report, "beaconing", 2, 0, 2, 12, 1.0, 0.5, 2 / 3)
        assert_class(report, "typosquat", 0, 0, 1, 15, 0.0, 0.0, 0.0)

    def test_macro_and_accuracy_match_hand_calculation(self):
        report = run_golden()
        self.assertEqual(report.macro.classes, ("dga", "tunnel", "beaconing", "typosquat"))
        self.assertAlmostEqual(report.macro.precision, (0.6 + 1.0 + 1.0 + 0.0) / 4)
        self.assertAlmostEqual(report.macro.recall, (1.0 + 0.5 + 0.5 + 0.0) / 4)
        self.assertAlmostEqual(report.macro.f1, (0.75 + 2 / 3 + 2 / 3 + 0.0) / 4)
        self.assertAlmostEqual(report.accuracy, 10 / 16)

    def test_elimination_and_latency(self):
        report = run_golden()
        self.assertEqual(report.elimination.total, 16)
        self.assertEqual(report.elimination.escalated, 8)
        self.assertEqual(report.elimination.eliminated, 8)
        self.assertAlmostEqual(report.elimination.overall_rate, 0.5)
        self.assertEqual(report.elimination.benign_total, 6)
        self.assertEqual(report.elimination.benign_escalated, 2)
        self.assertAlmostEqual(report.elimination.benign_elimination_rate, 4 / 6)

        fp, qp = report.latency["filter_path"], report.latency["qvac_path"]
        self.assertEqual(fp.n, 16)
        self.assertEqual((fp.p50_ms, fp.p95_ms, fp.max_ms), (5.0, 5.0, 5.0))
        self.assertEqual(qp.n, 8)
        self.assertEqual((qp.p50_ms, qp.p95_ms, qp.max_ms), (17.0, 17.0, 17.0))

    def test_splits_by_zone_and_pop(self):
        report = run_golden()
        self.assertEqual(set(report.by_zone), {"Z1", "Z2"})
        self.assertEqual({g.total for g in report.by_zone.values()}, {2, 14})
        z2 = report.by_zone["Z2"]
        self.assertEqual(z2.elimination.benign_elimination_rate, 1.0)
        self.assertEqual(z2.classes["benign"].tp, 2)
        self.assertEqual(report.by_pop["P1"].total, 14)
        self.assertEqual(report.by_pop["P2"].total, 2)

    def test_report_serializes_to_json(self):
        report = run_golden()
        payload = json.loads(report.to_json())
        self.assertEqual(payload["schema"], "sentinel-dns.eval.report.v1")
        self.assertEqual(payload["total_queries"], 16)
        self.assertEqual(payload["confusion_matrix"][0][:2], [4, 2])
        self.assertIn("summary", payload)
        self.assertIn("Benign never reaching QVAC: 66.7%", payload["summary"])


class GroundTruthIsolationTest(unittest.TestCase):
    def test_agent_view_strips_ground_truth(self):
        event = make_event(0, "zzx1.a.com", "NXDOMAIN", "10.0.0.10", gt="dga")
        view = agent_view(event)
        self.assertNotIn("ground_truth", view)
        self.assertEqual(view["timestamp"], event["ts"])

    def test_ground_truth_label_defaults(self):
        self.assertEqual(ground_truth_label(make_event(0, "a.com", "NOERROR", "10.0.0.1")), "benign")
        self.assertEqual(ground_truth_label(make_event(0, "a.com", "NOERROR", "10.0.0.1", gt="tunnel")), "tunnel")
        self.assertEqual(ground_truth_label({"ground_truth": {"attack": "nonsense"}}), "unverified")

    def test_filter_and_qvac_never_receive_ground_truth(self):
        from app.agent.filter import DeterministicFilter

        seen_by_filter = []

        class SpyFilter(DeterministicFilter):
            def process(self, event, *args, **kwargs):
                seen_by_filter.append(dict(event))
                return super().process(event, *args, **kwargs)

        captured_evidence = []

        class SpyQVAC(MockQVAC):
            def infer(self, qname, signal_evidence, context=None):
                captured_evidence.append(dict(signal_evidence or {}))
                return super().infer(qname, signal_evidence, context)

        evaluate(
            golden_events(),
            filter=SpyFilter(),
            qvac=SpyQVAC(),
            clock=SeqClock(),
        )
        self.assertTrue(seen_by_filter)
        self.assertTrue(captured_evidence)
        for view in seen_by_filter:
            self.assertNotIn("ground_truth", view)
        for evidence in captured_evidence:
            self.assertNotIn("ground_truth", evidence)


class EvalCliTest(unittest.TestCase):
    def _run_eval(self, args):
        return subprocess.run(
            [sys.executable, "-m", "app.eval"] + args,
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        )

    def test_cli_writes_single_json_report_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = os.path.join(tmp, "run.jsonl")
            report_path = os.path.join(tmp, "report.json")
            with open(run_path, "w", encoding="utf-8") as handle:
                for event in golden_events():
                    handle.write(json.dumps(event) + "\n")

            result = self._run_eval(["--run", run_path, "--out", report_path])
            self.assertIn("Queries: 16 | QVAC calls: 8", result.stdout)
            with open(report_path, "r", encoding="utf-8") as handle:
                report = json.load(handle)
            self.assertEqual(report["total_queries"], 16)
            self.assertIn("summary", report)
            self.assertEqual(report["elimination"]["benign_elimination_rate"], 4 / 6)

    def test_cli_threshold_check_fails_below_required_rate(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_path = os.path.join(tmp, "run.jsonl")
            report_path = os.path.join(tmp, "report.json")
            with open(run_path, "w", encoding="utf-8") as handle:
                for event in golden_events():
                    handle.write(json.dumps(event) + "\n")

            result = subprocess.run(
                [sys.executable, "-m", "app.eval", "--run", run_path,
                 "--out", report_path, "--min-benign-elimination", "0.8"],
                cwd=REPO, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("below required 80.0%", result.stderr)


if __name__ == "__main__":
    unittest.main()
