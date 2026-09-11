"""Single-process SHIELD runtime for workstations and product demonstrations."""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterable

from app.agent.filter import DeterministicFilter
from app.agent.qvac_adapter import QVACAdapter
from app.light.store import LocalStore
from app.qoe.config import load_config
from app.qoe.engine import MinuteAggregates, compute_qoe, load_zone_mapping

log = logging.getLogger("shield.light")


class LocalQoE:
    def __init__(self, store: LocalStore):
        self.store = store
        self.config = load_config()
        self.baselines = load_zone_mapping()
        self.groups: dict[tuple[str, str], list[dict]] = defaultdict(list)

    def add(self, event: dict) -> None:
        raw = event.get("ts", event.get("timestamp"))
        if not raw:
            return
        minute = datetime.fromisoformat(str(raw).replace("Z", "+00:00")).replace(second=0, microsecond=0).isoformat()
        site = f"{event.get('zone_id', '')}-{event.get('pop_id', '')}"
        self.groups[(site, minute)].append(event)

    def flush(self) -> None:
        for (site, minute), events in list(self.groups.items()):
            latencies = sorted(float(e.get("latency_ms", 0) or 0) for e in events)
            idx = max(0, min(len(latencies) - 1, int((len(latencies) - 1) * .95)))
            nx = sum(str(e.get("rcode", "")).upper() == "NXDOMAIN" for e in events) / len(events)
            score = compute_qoe(MinuteAggregates(site, minute, len(events), len({e.get("client_ip") for e in events}), latencies[idx], nx, len(events) / 60.0), self.config, self.baselines)
            self.store.upsert_qoe({
                "site": score.site, "ts": score.ts, "score": score.score, "label": score.label,
                "latency_component": score.latency_component, "nxdomain_component": score.nxdomain_component,
                "saturation_component": score.saturation_component, "qps": score.qps,
                "query_count": score.query_count, "distinct_clients": score.distinct_clients,
                "nxdomain_rate": score.nxdomain_rate, "p95_latency_ms": score.p95_latency_ms,
            })
        self.groups.clear()


def process(events: Iterable[dict], store: LocalStore, qvac_url: str) -> tuple[int, int]:
    detector, qvac, qoe = DeterministicFilter(), QVACAdapter(qvac_url), LocalQoE(store)
    count = alerts = 0
    for event in events:
        count += 1
        candidate = detector.process(event)
        alert = None
        if candidate:
            verdict = qvac.infer(candidate["qname"], candidate["signals"], {"client_ip": candidate["client_ip"]})
            alert = {**candidate, "verdict": verdict.verdict, "confidence": verdict.confidence,
                     "reasoning_short": verdict.reasoning_short, "recommended_action": verdict.recommended_action,
                     "qvac_latency_ms": verdict.latency_ms}
            alerts += int(verdict.verdict != "benign")
        store.write_event(event, alert)
        qoe.add(event)
    qoe.flush()
    return count, alerts


def _events(handle) -> Iterable[dict]:
    for line_no, line in enumerate(handle, 1):
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            log.warning("Skipping malformed JSONL line %d: %s", line_no, exc)
            continue
        if isinstance(event, dict):
            yield event


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Run SHIELD without Kafka, ClickHouse, Grafana or Wazuh")
    p.add_argument("--input", default="-", help="normalized JSONL input; '-' reads stdin")
    p.add_argument("--db", default="data/shield.db")
    p.add_argument("--qvac-url", default="http://127.0.0.1:11434")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    store = LocalStore(args.db)
    try:
        handle = sys.stdin if args.input == "-" else Path(args.input).open("r", encoding="utf-8")
        try:
            count, alerts = process(_events(handle), store, args.qvac_url)
        finally:
            if handle is not sys.stdin:
                handle.close()
        log.info("processed=%d alerts=%d db=%s", count, alerts, args.db)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
