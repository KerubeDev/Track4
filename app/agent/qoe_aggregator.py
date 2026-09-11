"""Streaming per-site/minute QoE aggregation."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime
import json
from urllib import request

from app.qoe.config import load_config
from app.qoe.engine import MinuteAggregates, compute_qoe, load_zone_mapping


class QoEAggregator:
    def __init__(self, host="clickhouse", port=8123, database="sentinel_dns", config_path=None, transport=None):
        self.url = f"http://{host}:{port}/?database={database}"
        self.config = load_config(config_path)
        self.baselines = load_zone_mapping()
        self._groups = defaultdict(list)
        self._transport = transport or self._send

    @staticmethod
    def _send(url, body):
        req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=10) as response:
            response.read()

    def add(self, event):
        ts = event.get("ts", event.get("timestamp"))
        minute = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(second=0, microsecond=0).isoformat()
        site = f"{event.get('zone_id', '')}-{event.get('pop_id', '')}"
        self._groups[(site, minute)].append(event)

    def flush(self, final=False):
        if not self._groups:
            return
        rows = []
        keys = list(self._groups) if final else list(self._groups)[:-1]
        for key in keys:
            site, minute = key
            events = self._groups.pop(key)
            latencies = sorted(float(e.get("latency_ms", 0)) for e in events)
            p95 = latencies[max(0, int(len(latencies) * .95 + .999999) - 1)]
            nx = sum(e.get("rcode") == "NXDOMAIN" for e in events) / len(events)
            score = compute_qoe(MinuteAggregates(site, minute, len(events), len({e.get("client_ip") for e in events}), p95, nx, len(events) / 60), self.config, self.baselines)
            rows.append({"site": score.site, "ts": score.ts, "score": score.score, "label": score.label,
                         "latency_component": score.latency_component, "nxdomain_component": score.nxdomain_component,
                         "saturation_component": score.saturation_component, "qps": score.qps,
                         "query_count": score.query_count, "distinct_clients": score.distinct_clients,
                         "nxdomain_rate": score.nxdomain_rate, "p95_latency_ms": score.p95_latency_ms})
        if rows:
            body = ("INSERT INTO site_qoe_minute FORMAT JSONEachRow\n" + "\n".join(json.dumps(r, separators=(",", ":")) for r in rows)).encode()
            self._transport(self.url, body)
