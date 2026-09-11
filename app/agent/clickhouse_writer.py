"""Dependency-free batched ClickHouse HTTP writer."""
from __future__ import annotations
import json
import logging
from urllib.error import HTTPError
from urllib import parse, request

logger = logging.getLogger(__name__)


class ClickHouseWriter:
    def __init__(self, host="clickhouse", port=8123, database="sentinel_dns", batch_size=500, timeout=10, transport=None):
        self.url = f"http://{host}:{port}/"
        self.database, self.batch_size, self.timeout = database, batch_size, timeout
        self._transport = transport or self._send
        self._rows = []

    @staticmethod
    def _send(url, body, timeout):
        req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with request.urlopen(req, timeout=timeout) as response:
                response.read()
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            logger.error("ClickHouse rejected batch (%s): %s", exc.code, detail[:500])
            raise

    def write(self, event, alert=None):
        alert = alert or {}
        timestamp = event.get("ts", event.get("timestamp"))
        if isinstance(timestamp, str):
            timestamp = timestamp.replace("T", " ").rstrip("Z")
        self._rows.append({"ts": timestamp, "client_ip": event.get("client_ip", ""),
            "qname": event.get("qname", ""), "qtype": event.get("qtype", ""), "rcode": event.get("rcode", ""),
            "latency_ms": event.get("latency_ms", 0), "zone_id": event.get("zone_id", ""), "pop_id": event.get("pop_id", ""),
            "schema_version": event.get("schema_version", 1), "verdict": alert.get("verdict"),
            "confidence": alert.get("confidence"), "signal": list(alert.get("signals", {}).keys())})
        if len(self._rows) >= self.batch_size:
            self.flush()

    def flush(self):
        if not self._rows:
            return
        body = ("INSERT INTO dns_events_raw FORMAT JSONEachRow\n" + "\n".join(
            json.dumps(row, separators=(",", ":"), default=str) for row in self._rows)).encode()
        self._transport(self.url + "?" + parse.urlencode({"database": self.database}), body, self.timeout)
        self._rows.clear()

    close = flush
