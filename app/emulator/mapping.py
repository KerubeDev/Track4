import csv
import ipaddress
import os
from dataclasses import dataclass

DEFAULT_MAPPING_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "zone_mapping.csv"
)


class ZoneMappingError(ValueError):
    pass


@dataclass(frozen=True)
class ZoneProfile:
    ip_cidr: str
    pop_id: str
    zone_id: str
    client_name: str
    latency_mean_ms: float
    latency_std_ms: float
    nx_rate: float
    qps_baseline: float

    @classmethod
    def from_row(cls, row):
        return cls(
            ip_cidr=row["ip_cidr"].strip(),
            pop_id=row["pop_id"].strip(),
            zone_id=row["zone_id"].strip(),
            client_name=row["client_name"].strip(),
            latency_mean_ms=float(row["latency_mean_ms"]),
            latency_std_ms=float(row["latency_std_ms"]),
            nx_rate=float(row["nx_rate"]),
            qps_baseline=float(row["qps_baseline"]),
        )

    @property
    def network(self):
        return ipaddress.ip_network(self.ip_cidr, strict=False)


class ZoneMapping:
    def __init__(self, profiles):
        self._profiles = sorted(
            profiles,
            key=lambda p: (p.network.prefixlen, int(p.network.network_address)),
            reverse=True,
        )
        self._default = next(
            (p for p in profiles if p.network.prefixlen == 0), None
        )

    @classmethod
    def from_csv(cls, path=None):
        path = path or DEFAULT_MAPPING_PATH
        with open(path, "r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
        if not rows or not all(
            set(ZoneProfile.__dataclass_fields__) <= set(row) for row in rows
        ):
            raise ZoneMappingError(f"zone_mapping.csv missing columns in {path}")
        return cls([ZoneProfile.from_row(row) for row in rows])

    def resolve(self, client_ip):
        address = ipaddress.ip_address(client_ip)
        for profile in self._profiles:
            if address in profile.network:
                return profile
        if self._default is not None:
            return self._default
        raise ZoneMappingError(f"no mapping for {client_ip}")

    @property
    def pop_ids(self):
        return sorted({p.pop_id for p in self._profiles})

    @property
    def zone_ids(self):
        return sorted({p.zone_id for p in self._profiles})

    @property
    def client_names(self):
        return sorted({p.client_name for p in self._profiles})