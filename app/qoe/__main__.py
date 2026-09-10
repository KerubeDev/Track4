#!/usr/bin/env python3
"""
QoE engine CLI — Sentinel-DNS Track4
Issue #12 (S2-T2)

Usage:
    python -m app.qoe --help
    python -m app.qoe --demo          # run demo with sample data
    python -m app.qoe --file events.jsonl  # process aggregated events
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from .config import load_config
from .engine import MinuteAggregates, QoEScore, compute_qoe, load_zone_mapping


def _print_score(score: QoEScore) -> None:
    """Pretty-print a QoE score."""
    print(
        f"  [{score.label:>9}] {score.site} @ {score.ts}  "
        f"score={score.score}  "
        f"lat={score.latency_component} ({score.latency_points:.1f}pts)  "
        f"nx={score.nxdomain_component} ({score.nxdomain_points:.1f}pts)  "
        f"sat={score.saturation_component} ({score.saturation_points:.1f}pts)"
    )


def run_demo() -> None:
    """Run the engine with fabricated demo data to verify correctness."""
    config = load_config()
    baselines = load_zone_mapping()

    print("=== QoE Engine Demo ===")
    print(f"Config weights: latency={config.weights['latency']}, "
          f"nxdomain={config.weights['nxdomain']}, "
          f"saturation={config.weights['saturation']}")
    print(f"Loaded {len(baselines)} site baselines from zone_mapping.csv")
    print()

    # Hand-crafted test cases
    cases: List[MinuteAggregates] = [
        # Z1-PAN-PAC-01: Excellent — low latency, no NXDOMAIN, moderate QPS
        MinuteAggregates(
            site="Z1-PAN-PAC-01",
            ts="2026-09-09T10:00:00",
            query_count=120,
            distinct_clients=15,
            p95_latency_ms=30.0,
            nxdomain_rate=0.02,
            qps=2.0,
        ),
        # Z2-COL-BOG-01: Poor — high latency, high NXDOMAIN, high QPS
        MinuteAggregates(
            site="Z2-COL-BOG-01",
            ts="2026-09-09T10:01:00",
            query_count=400,
            distinct_clients=50,
            p95_latency_ms=280.0,
            nxdomain_rate=0.45,
            qps=25.0,
        ),
        # Z3-PAN-PAC-01: Fair — moderate latency, some NXDOMAIN
        MinuteAggregates(
            site="Z3-PAN-PAC-01",
            ts="2026-09-09T10:02:00",
            query_count=80,
            distinct_clients=10,
            p95_latency_ms=150.0,
            nxdomain_rate=0.15,
            qps=3.0,
        ),
        # Z4-SAL-SAL-01: Good — reasonable latency, low NXDOMAIN, moderate QPS
        MinuteAggregates(
            site="Z4-SAL-SAL-01",
            ts="2026-09-09T10:03:00",
            query_count=100,
            distinct_clients=12,
            p95_latency_ms=60.0,
            nxdomain_rate=0.05,
            qps=4.0,
        ),
    ]

    results: List[QoEScore] = []
    for agg in cases:
        score = compute_qoe(agg, config, baselines)
        results.append(score)
        _print_score(score)

    print()
    print("=== Results JSON ===")
    for r in results:
        print(json.dumps({
            "site": r.site,
            "score": r.score,
            "label": r.label,
            "latency_component": r.latency_component,
            "nxdomain_component": r.nxdomain_component,
            "saturation_component": r.saturation_component,
        }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel-DNS QoE scoring engine (Issue #12)"
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run demo with fabricated sample data"
    )
    parser.add_argument(
        "--file", type=str, default=None,
        help="Path to JSONL file with MinuteAggregates (one JSON object per line)"
    )
    parser.add_argument(
        "--config", type=str, default=None,
        help="Path to qoe.yaml config (default: config/qoe.yaml)"
    )
    args = parser.parse_args()

    if args.demo:
        run_demo()
        return

    if args.file:
        config = load_config(args.config)
        baselines = load_zone_mapping()

        with open(args.file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                agg = MinuteAggregates(**data)
                score = compute_qoe(agg, config, baselines)
                print(json.dumps({
                    "site": score.site,
                    "ts": score.ts,
                    "score": score.score,
                    "label": score.label,
                    "latency_component": score.latency_component,
                    "nxdomain_component": score.nxdomain_component,
                    "saturation_component": score.saturation_component,
                    "latency_points": score.latency_points,
                    "nxdomain_points": score.nxdomain_points,
                    "saturation_points": score.saturation_points,
                }))
        return

    parser.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
