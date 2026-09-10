"""CLI: score a recorded emulator run and emit an evaluation report.

Usage::

    python -m app.eval --run run.jsonl [--qvac mock|adapter] [--out report.json]

``--run`` is a JSON-lines file of emulator events (``--emit json`` output of
``python -m app.emulator --attack ...``). The report is a single JSON document
plus a human-readable summary on stdout.
"""

from __future__ import annotations

import argparse
import sys

from app.eval.harness import evaluate, load_run
from app.eval.qvac import AdapterQVAC, MockQVAC


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="sentinel-dns-eval",
        description="Score a recorded emulator run against its ground truth.",
    )
    parser.add_argument("--run", required=True, help="JSON-lines file of emulator events (--emit json)")
    parser.add_argument("--qvac", choices=("mock", "adapter"), default="mock",
                        help="QVAC source for escalated queries (default: deterministic mock)")
    parser.add_argument("--qvac-url", default="http://localhost:11434",
                        help="local QVAC endpoint for --qvac adapter")
    parser.add_argument("--out", default="eval-report.json", help="JSON report output path")
    parser.add_argument("--no-summary", action="store_true",
                        help="suppress the human-readable summary on stdout")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    try:
        events = load_run(args.run)
    except OSError as exc:
        print(f"FATAL: cannot read run {args.run!r}: {exc}", file=sys.stderr)
        return 1
    if not events:
        print(f"FATAL: run {args.run!r} is empty", file=sys.stderr)
        return 1

    if args.qvac == "adapter":
        from app.agent.qvac_adapter import QVACAdapter

        qvac = AdapterQVAC(QVACAdapter(args.qvac_url))
    else:
        qvac = MockQVAC()

    report = evaluate(events, filter=None, qvac=qvac)

    with open(args.out, "w", encoding="utf-8") as handle:
        handle.write(report.to_json(indent=2) + "\n")

    if not args.no_summary:
        print(report.summary_text())
    print(f"report written to {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())