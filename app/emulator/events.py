import json
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Optional

SCHEMA_VERSION = 1
TOPIC = "dns.telemetry.v1"


@dataclass(frozen=True)
class TelemetryEvent:
    timestamp: str
    client_ip: str
    client_port: int
    qname: str
    qtype: str
    resolver_ip: str
    rcode: str
    latency_ms: float
    pop_id: str
    zone_id: str
    schema_version: int = SCHEMA_VERSION
    ground_truth: Optional[dict] = None
    synthesis: bool = True
    source: str = "bind9"

    @classmethod
    def new(
        cls,
        timestamp,
        client_ip,
        client_port,
        qname,
        qtype,
        resolver_ip,
        rcode,
        latency_ms,
        pop_id,
        zone_id,
        ground_truth=None,
        source="bind9",
    ):
        return cls(
            timestamp=_iso8601(timestamp),
            client_ip=client_ip,
            client_port=client_port,
            qname=qname,
            qtype=qtype,
            resolver_ip=resolver_ip,
            rcode=rcode,
            latency_ms=round(float(latency_ms), 3),
            pop_id=pop_id,
            zone_id=zone_id,
            ground_truth=ground_truth,
            source=source,
        )

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


def _iso8601(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
