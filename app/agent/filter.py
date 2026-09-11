"""Bounded, explainable DNS signals and escalation rules."""

from __future__ import annotations

import math
import os
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from app.common.domain import DEFAULT_CLIENT_VOCABULARY, edit_distance_at_most_one, effective_tld_plus_one


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _seconds(timestamp: Any) -> float:
    if isinstance(timestamp, (int, float)):
        return float(timestamp)
    value = str(timestamp).strip().replace("Z", "+00:00")
    if not value:
        raise ValueError("DNS event is missing a timestamp")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


@dataclass(frozen=True)
class FilterConfig:
    window_seconds: float = 60.0
    min_window_events: int = 5
    nxdomain_ratio: float = 0.6
    entropy: float = 3.5
    long_label: int = 40
    rarity: float = 0.2
    beacon_variance: float = 4.0
    beacon_min_gap_seconds: float = 5.0

    @classmethod
    def from_env(cls) -> "FilterConfig":
        return cls(
            window_seconds=float(os.getenv("FILTER_WINDOW_SECONDS", "60")),
            min_window_events=int(os.getenv("FILTER_MIN_WINDOW_EVENTS", "5")),
            nxdomain_ratio=float(os.getenv("FILTER_NXDOMAIN_RATIO", "0.6")),
            entropy=float(os.getenv("FILTER_ENTROPY", "3.5")),
            long_label=int(os.getenv("FILTER_LONG_LABEL", "40")),
            rarity=float(os.getenv("FILTER_RARITY", "0.2")),
            beacon_variance=float(os.getenv("FILTER_BEACON_VARIANCE", "4")),
            beacon_min_gap_seconds=float(os.getenv("FILTER_BEACON_MIN_GAP_SECONDS", "5")),
        )


class DeterministicFilter:
    """Maintain bounded per-client windows and emit escalation evidence."""

    def __init__(self, config: FilterConfig | None = None, vocabulary: Iterable[str] | None = None):
        self.config = config or FilterConfig.from_env()
        self.vocabulary = tuple(v.lower() for v in (vocabulary or DEFAULT_CLIENT_VOCABULARY))
        self._windows: dict[str, deque[tuple[float, dict]]] = defaultdict(deque)

    def _expire(self, cutoff: float) -> None:
        for client, client_window in list(self._windows.items()):
            while client_window and client_window[0][0] < cutoff:
                client_window.popleft()
            if not client_window:
                del self._windows[client]

    def process(self, event: dict) -> dict | None:
        now = _seconds(event.get("ts", event.get("timestamp")))
        client_ip = str(event.get("client_ip", "")).strip()
        qname = str(event.get("qname", "")).rstrip(".").lower()
        if not client_ip or not qname:
            return None

        cutoff = now - self.config.window_seconds
        self._expire(cutoff)
        window = self._windows[client_ip]
        window.append((now, event))
        events = [item for _, item in window]
        signals: dict[str, dict] = {}

        if len(events) >= self.config.min_window_events:
            nx_ratio = sum(str(e.get("rcode", "")).upper() == "NXDOMAIN" for e in events) / len(events)
            if nx_ratio >= self.config.nxdomain_ratio:
                signals["nxdomain_ratio"] = {
                    "ratio": round(nx_ratio, 3), "threshold": self.config.nxdomain_ratio, "samples": len(events)
                }

        label = qname.split(".")[0]
        entropy = _entropy(label)
        if entropy >= self.config.entropy:
            signals["entropy"] = {"value": round(entropy, 3), "threshold": self.config.entropy}

        repeated = sum(str(e.get("qname", "")).rstrip(".").lower() == qname for e in events) > 1
        if len(label) > self.config.long_label and entropy > self.config.entropy and repeated:
            signals["long_high_entropy_repetition"] = {"label_length": len(label), "entropy": round(entropy, 3)}

        e2ld = effective_tld_plus_one(qname)
        e2ld_count = sum(effective_tld_plus_one(str(e.get("qname", ""))) == e2ld for e in events)
        rarity = 1 / max(1, e2ld_count)
        typo_target = next(
            (known for known in self.vocabulary if e2ld != known and edit_distance_at_most_one(e2ld, known)), None
        )
        if (rarity >= self.config.rarity and len(label) <= self.config.long_label) or typo_target:
            signals["rarity"] = {
                "e2ld": e2ld, "rarity": round(rarity, 3), "typosquat": bool(typo_target),
                "nearest_known_domain": typo_target,
            }

        timestamps = [stamp for stamp, e in window if str(e.get("qname", "")).rstrip(".").lower() == qname]
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
        gaps = [gap for gap in intervals if gap >= self.config.beacon_min_gap_seconds]
        if len(gaps) >= 2:
            mean = sum(gaps) / len(gaps)
            variance = sum((gap - mean) ** 2 for gap in gaps) / len(gaps)
            if variance <= self.config.beacon_variance:
                signals["beaconing"] = {
                    "interval_variance": round(variance, 3), "mean_interval_seconds": round(mean, 3),
                    "intervals": len(gaps),
                }

        escalates = any(name in signals for name in ("nxdomain_ratio", "long_high_entropy_repetition", "beaconing"))
        escalates |= "entropy" in signals and "rarity" in signals
        if not escalates:
            return None
        return {
            "qname": qname, "client_ip": client_ip, "signals": signals,
            "timestamp": event.get("ts", event.get("timestamp")),
        }
