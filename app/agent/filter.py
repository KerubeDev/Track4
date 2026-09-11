"""Bounded, explainable DNS signals and escalation rules."""

from __future__ import annotations

import math
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Any

from app.emulator.attacks import CLIENT_VOCABULARY, edit_distance_at_most_one


def _entropy(value: str) -> float:
    counts = {char: value.count(char) for char in set(value)}
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values()) if length else 0.0


def _seconds(timestamp: Any) -> float:
    if isinstance(timestamp, (int, float)):
        return float(timestamp)
    value = str(timestamp).replace("Z", "+00:00")
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc if "+" not in value else None).timestamp()


@dataclass(frozen=True)
class FilterConfig:
    window_seconds: float = 60.0
    nxdomain_ratio: float = 0.6
    entropy: float = 3.5
    long_label: int = 40
    rarity: float = 0.2
    beacon_variance: float = 4.0

    @classmethod
    def from_env(cls) -> "FilterConfig":
        return cls(
            window_seconds=float(os.getenv("FILTER_WINDOW_SECONDS", "60")),
            nxdomain_ratio=float(os.getenv("FILTER_NXDOMAIN_RATIO", "0.6")),
            entropy=float(os.getenv("FILTER_ENTROPY", "3.5")),
            long_label=int(os.getenv("FILTER_LONG_LABEL", "40")),
            rarity=float(os.getenv("FILTER_RARITY", "0.2")),
            beacon_variance=float(os.getenv("FILTER_BEACON_VARIANCE", "4")),
        )


class DeterministicFilter:
    """Maintain only the current client windows and emit escalation evidence."""

    def __init__(self, config: FilterConfig | None = None, vocabulary=CLIENT_VOCABULARY):
        self.config = config or FilterConfig.from_env()
        self.vocabulary = tuple(vocabulary)
        self._windows: dict[str, deque[tuple[float, dict]]] = defaultdict(deque)

    def process(self, event: dict) -> dict | None:
        now = _seconds(event.get("ts", event.get("timestamp", 0)))
        key = str(event.get("client_ip", ""))
        window = self._windows[key]
        window.append((now, event))
        cutoff = now - self.config.window_seconds
        while window and window[0][0] < cutoff:
            window.popleft()
        for client, client_window in list(self._windows.items()):
            if client != key:
                while client_window and client_window[0][0] < cutoff:
                    client_window.popleft()
            if not client_window:
                del self._windows[client]
        events = [item for _, item in window]
        signals: dict[str, dict] = {}
        nx_ratio = sum(e.get("rcode") == "NXDOMAIN" for e in events) / len(events)
        if nx_ratio >= self.config.nxdomain_ratio:
            signals["nxdomain_ratio"] = {"ratio": round(nx_ratio, 3), "threshold": self.config.nxdomain_ratio}

        label = str(event.get("qname", "")).rstrip(".").split(".")[0]
        entropy = _entropy(label)
        if entropy >= self.config.entropy:
            signals["entropy"] = {"value": round(entropy, 3), "threshold": self.config.entropy}

        repeated = sum(e.get("qname") == event.get("qname") for e in events) > 1
        if len(label) > self.config.long_label and entropy > self.config.entropy and repeated:
            signals["long_high_entropy_repetition"] = {"label_length": len(label), "entropy": round(entropy, 3)}

        e2ld = ".".join(str(event.get("qname", "")).rstrip(".").split(".")[-2:])
        e2ld_count = sum(".".join(str(e.get("qname", "")).rstrip(".").split(".")[-2:]) == e2ld for e in events)
        rarity = 1 / e2ld_count
        typo = any(edit_distance_at_most_one(e2ld, vocabulary) and e2ld != vocabulary for vocabulary in self.vocabulary)
        # Long labels are judged by the composite signal, not singleton rarity.
        if (rarity >= self.config.rarity and len(label) <= self.config.long_label) or typo:
            signals["rarity"] = {"e2ld": e2ld, "rarity": round(rarity, 3), "typosquat": typo}

        timestamps = [stamp for stamp, e in window if e.get("qname") == event.get("qname")]
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:])]
        burst_gaps = [interval for interval in intervals if interval >= 5.0]
        variance = sum((x - sum(burst_gaps) / len(burst_gaps)) ** 2 for x in burst_gaps) / len(burst_gaps) if burst_gaps else float("inf")
        if len(burst_gaps) >= 2 and variance <= self.config.beacon_variance:
            signals["beaconing"] = {"interval_variance": round(variance, 3), "intervals": len(burst_gaps)}

        escalates = any(name in signals for name in ("nxdomain_ratio", "long_high_entropy_repetition", "beaconing"))
        escalates |= "entropy" in signals and "rarity" in signals
        if not escalates:
            return None
        return {"qname": event.get("qname", ""), "client_ip": key, "signals": signals, "timestamp": event.get("timestamp")}
