"""SQLite-backed local event, alert and QoE storage."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, client_ip TEXT, qname TEXT, qtype TEXT, rcode TEXT,
  latency_ms REAL, zone_id TEXT, pop_id TEXT, verdict TEXT, confidence REAL,
  signals_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_qname ON events(qname);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL, client_ip TEXT, qname TEXT, verdict TEXT NOT NULL,
  confidence REAL NOT NULL, reasoning TEXT, recommended_action TEXT,
  signals_json TEXT NOT NULL DEFAULT '{}', qvac_latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE TABLE IF NOT EXISTS qoe (
  site TEXT NOT NULL, ts TEXT NOT NULL, score INTEGER NOT NULL, label TEXT NOT NULL,
  latency_component INTEGER, nxdomain_component INTEGER, saturation_component INTEGER,
  qps REAL, query_count INTEGER, distinct_clients INTEGER, nxdomain_rate REAL,
  p95_latency_ms REAL, PRIMARY KEY(site, ts)
);
"""


class LocalStore:
    def __init__(self, path: str | Path = "data/shield.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def write_event(self, event: dict[str, Any], alert: dict[str, Any] | None = None) -> None:
        alert = alert or {}
        ts = str(event.get("ts", event.get("timestamp", "")))
        self.db.execute(
            "INSERT INTO events(ts,client_ip,qname,qtype,rcode,latency_ms,zone_id,pop_id,verdict,confidence,signals_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (ts, event.get("client_ip"), event.get("qname"), event.get("qtype"), event.get("rcode"),
             float(event.get("latency_ms", 0) or 0), event.get("zone_id"), event.get("pop_id"),
             alert.get("verdict"), alert.get("confidence"), json.dumps(alert.get("signals", {}), separators=(",", ":"))),
        )
        if alert and alert.get("verdict") != "benign":
            self.db.execute(
                "INSERT INTO alerts(ts,client_ip,qname,verdict,confidence,reasoning,recommended_action,signals_json,qvac_latency_ms) VALUES(?,?,?,?,?,?,?,?,?)",
                (ts, alert.get("client_ip"), alert.get("qname"), alert.get("verdict", "unverified"),
                 float(alert.get("confidence", 0) or 0), alert.get("reasoning_short", ""),
                 alert.get("recommended_action", ""), json.dumps(alert.get("signals", {}), separators=(",", ":")),
                 float(alert.get("qvac_latency_ms", 0) or 0)),
            )
        self.db.commit()

    def upsert_qoe(self, row: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO qoe(site,ts,score,label,latency_component,nxdomain_component,saturation_component,qps,query_count,distinct_clients,nxdomain_rate,p95_latency_ms) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(row[k] for k in ("site","ts","score","label","latency_component","nxdomain_component","saturation_component","qps","query_count","distinct_clients","nxdomain_rate","p95_latency_ms")),
        )
        self.db.commit()

    def snapshot(self) -> dict[str, Any]:
        total = self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        candidates = self.db.execute("SELECT COUNT(*) FROM events WHERE verdict IS NOT NULL").fetchone()[0]
        alerts = self.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        qvac = self.db.execute("SELECT COALESCE(AVG(qvac_latency_ms),0) FROM alerts").fetchone()[0]
        recent = [dict(r) for r in self.db.execute("SELECT ts,qname,client_ip,verdict,confidence,reasoning,recommended_action,signals_json FROM alerts ORDER BY id DESC LIMIT 30")]
        for item in recent:
            item["signals"] = json.loads(item.pop("signals_json") or "{}")
        qoe = [dict(r) for r in self.db.execute("SELECT * FROM qoe ORDER BY ts DESC, site LIMIT 60")]
        verdicts = [dict(r) for r in self.db.execute("SELECT verdict,COUNT(*) AS count FROM alerts GROUP BY verdict ORDER BY count DESC")]
        reduction = 100 * (1 - candidates / total) if total else 0.0
        return {
            "events": total, "candidates": candidates, "alerts": alerts,
            "filter_reduction_percent": round(reduction, 2), "avg_qvac_ms": round(float(qvac), 1),
            "recent_alerts": recent, "qoe": qoe, "verdicts": verdicts,
        }

    def close(self) -> None:
        self.db.close()
