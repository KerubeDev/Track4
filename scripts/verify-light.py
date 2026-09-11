#!/usr/bin/env python3
"""Verify the lightweight SHIELD runtime against the operator's real local QVAC."""
from __future__ import annotations

import argparse
import json
import math
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib import request


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1)]


def qvac_models(base_url: str) -> dict:
    with request.urlopen(base_url.rstrip("/") + "/v1/models", timeout=5) as response:  # nosec B310: CLI defaults to loopback
        return json.loads(response.read())


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SHIELD local acceptance checks")
    parser.add_argument("--dataset", default="tests/fixtures")
    parser.add_argument("--qvac-url", default="http://127.0.0.1:11434")
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--report", default="data/validation-report.json")
    args = parser.parse_args()

    report: dict = {"status": "FAIL", "qvac_url": args.qvac_url, "checks": {}}
    try:
        models = qvac_models(args.qvac_url)
        report["checks"]["qvac_reachable"] = True
        report["qvac_models"] = [item.get("id") for item in models.get("data", []) if isinstance(item, dict)]
    except Exception as exc:
        report["checks"]["qvac_reachable"] = False
        report["error"] = f"local QVAC is not reachable: {exc}"
        return finish(report, args.report)

    dataset = Path(args.dataset)
    if not dataset.exists():
        report["checks"]["dataset_present"] = False
        report["error"] = f"dataset not found: {dataset}"
        return finish(report, args.report)
    report["checks"]["dataset_present"] = True

    with tempfile.TemporaryDirectory(prefix="shield-verify-") as temp:
        root = Path(temp)
        stream = root / "events.jsonl"
        db = root / "shield.db"
        subprocess.run([
            sys.executable, "-m", "app.emulator.cli", "--dataset", str(dataset), "--rate", "0",
            "--seed", "42", "--attack", "--emit", "json", "--out", str(stream), "--limit", str(args.limit),
        ], check=True)
        subprocess.run([
            sys.executable, "-m", "app.light.runtime", "--input", str(stream), "--db", str(db),
            "--qvac-url", args.qvac_url,
        ], check=True)

        conn = sqlite3.connect(db)
        try:
            events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            candidates = conn.execute("SELECT COUNT(*) FROM events WHERE verdict IS NOT NULL").fetchone()[0]
            alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            unverified = conn.execute("SELECT COUNT(*) FROM alerts WHERE verdict='unverified'").fetchone()[0]
            qoe = conn.execute("SELECT COUNT(*) FROM qoe").fetchone()[0]
            latencies = [float(row[0]) for row in conn.execute("SELECT qvac_latency_ms FROM alerts WHERE qvac_latency_ms IS NOT NULL")]
            verdicts = {row[0]: row[1] for row in conn.execute("SELECT verdict, COUNT(*) FROM alerts GROUP BY verdict")}
        finally:
            conn.close()

    report.update({
        "events_processed": events,
        "qvac_candidates": candidates,
        "alerts": alerts,
        "unverified": unverified,
        "qoe_windows": qoe,
        "filter_reduction_percent": round(100 * (1 - candidates / events), 3) if events else 0.0,
        "qvac_latency_ms": {"p50": round(percentile(latencies, .50), 1), "p95": round(percentile(latencies, .95), 1)},
        "verdicts": verdicts,
    })
    report["checks"].update({
        "events_processed": events > 0,
        "qvac_exercised": candidates > 0,
        "qvac_contract_valid": candidates > 0 and unverified == 0,
        "qoe_generated": qoe > 0,
    })
    report["status"] = "PASS" if all(report["checks"].values()) else "FAIL"
    return finish(report, args.report)


def finish(report: dict, output: str) -> int:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("status") == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
