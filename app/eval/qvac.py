"""QVAC sources for offline evaluation.

A deterministic, signal-evidence-keyed stand-in for the demo QVAC stub
(same verdict families as ``app/qvac/server.py``) so the harness can run
end to end without the live model, plus a thin adapter-backed variant for
live runs against the local QVAC service.
"""

from __future__ import annotations

from app.agent.qvac_adapter import QVACAdapter, QVACVerdict

DEFAULT_MOCK_LATENCY_MS = 12.0


class MockQVAC:
    """Deterministic QVAC trained on structural filter evidence.

    Mirrors the demo stub's mappings: NXDOMAIN ratio -> dga,
    long/high-entropy repetition -> tunnel, periodicity -> beaconing,
    typosquat rarity -> typosquat, anything else -> benign.
    """

    def __init__(self, latency_ms: float = DEFAULT_MOCK_LATENCY_MS):
        self.latency_ms = float(latency_ms)

    def infer(self, qname: str, signal_evidence: dict, context: dict | None = None) -> QVACVerdict:
        evidence = signal_evidence or {}
        verdict, confidence, reasoning = "benign", 0.95, "No threat indicators found"
        if "nxdomain_ratio" in evidence:
            verdict, confidence, reasoning = "dga", 0.92, "High NXDOMAIN rate suggests DGA activity"
        elif "long_high_entropy_repetition" in evidence:
            verdict, confidence, reasoning = "tunnel", 0.88, "High entropy label indicates DNS tunneling"
        elif "beaconing" in evidence:
            verdict, confidence, reasoning = "beaconing", 0.85, "Periodic query pattern detected"
        elif evidence.get("rarity", {}).get("typosquat"):
            verdict, confidence, reasoning = "typosquat", 0.75, "Edit distance suggests typosquatting"
        return QVACVerdict(
            verdict=verdict,
            confidence=confidence,
            reasoning_short=reasoning,
            recommended_action="Block and investigate" if verdict != "benign" else "Allow",
            latency_ms=self.latency_ms,
            signal_evidence=signal_evidence,
        )


class AdapterQVAC:
    """Live evaluation against the local QVAC service via QVACAdapter."""

    def __init__(self, adapter: QVACAdapter | None = None):
        self.adapter = adapter or QVACAdapter()

    def infer(self, qname: str, signal_evidence: dict, context: dict | None = None) -> QVACVerdict:
        return self.adapter.infer(qname, signal_evidence, context)