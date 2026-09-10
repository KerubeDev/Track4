import random

from app.emulator.events import TelemetryEvent
from app.emulator.mapping import ZoneProfile
from app.emulator.parser import QueryRecord


class DnstapSynthesizer:
    def __init__(self, rng=None):
        self._rng = rng if rng is not None else random.Random()

    def synthesize(self, record: QueryRecord, profile: ZoneProfile, ground_truth=None):
        latency = self._latency(profile)
        rcode = self._rcode(profile)
        return TelemetryEvent.new(
            timestamp=record.timestamp,
            client_ip=record.client_ip,
            client_port=record.client_port,
            qname=record.qname,
            qtype=record.qtype,
            resolver_ip=record.resolver_ip,
            rcode=rcode,
            latency_ms=latency,
            pop_id=profile.pop_id,
            zone_id=profile.zone_id,
            ground_truth=ground_truth,
        )

    def _latency(self, profile):
        samples = self._rng.gauss(profile.latency_mean_ms, profile.latency_std_ms)
        return max(0.5, round(samples, 3))

    def _rcode(self, profile):
        if self._rng.random() < profile.nx_rate:
            return "NXDOMAIN"
        return "NOERROR"