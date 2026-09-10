import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

SCHEMA_VERSION = 1
TOPIC = "dns.telemetry.v1"


@dataclass(frozen=True)
class TelemetryEvent:
    ts: str
    client_ip: str
    qname: str
    qtype: str
    rcode: str
    latency_ms: float
    pop_id: str
    zone_id: str
    schema_version: int = SCHEMA_VERSION
    ground_truth: Optional[dict] = None

    @classmethod
    def new(
        cls,
        ts,
        client_ip,
        qname,
        qtype,
        rcode,
        latency_ms,
        pop_id,
        zone_id,
        ground_truth=None,
    ):
        return cls(
            ts=_iso8601(ts),
            client_ip=client_ip,
            qname=qname,
            qtype=qtype,
            rcode=rcode,
            latency_ms=round(float(latency_ms), 3),
            pop_id=pop_id,
            zone_id=zone_id,
            ground_truth=ground_truth,
        )

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


def _iso8601(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
