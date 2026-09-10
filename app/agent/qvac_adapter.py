"""Local, bounded QVAC chat adapter with controlled degradation."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib import request

logger = logging.getLogger(__name__)

VERDICTS = {"dga", "tunnel", "beaconing", "typosquat", "benign"}
MODEL = "QWEN3_1_7B_INST_Q4"


@dataclass(frozen=True)
class QVACVerdict:
    verdict: str
    confidence: float
    reasoning_short: str
    recommended_action: str
    latency_ms: float = 0.0
    error: str | None = None
    signal_evidence: dict[str, Any] = field(default_factory=dict)


class QVACAdapter:
    """Call only the configured local QVAC endpoint and never raise on failure."""

    def __init__(self, base_url: str = "http://localhost:11434", *, timeout: float = 2.0,
                 retries: int = 1, transport: Callable[[str, bytes, float], bytes] | None = None):
        self.endpoint = base_url.rstrip("/") + "/api/chat"
        self.timeout = timeout
        self.retries = max(0, retries)
        self._transport = transport or self._http_transport

    @staticmethod
    def _http_transport(url: str, body: bytes, timeout: float) -> bytes:
        req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=timeout) as response:  # nosec B310: URL is operator-configured
            return response.read()

    def _unverified(self, started: float, error: str, evidence: dict[str, Any]) -> QVACVerdict:
        return QVACVerdict("unverified", 0.0, error, "Investigate", (time.monotonic() - started) * 1000, error, evidence)

    def infer(self, qname: str, signal_evidence: dict[str, Any], context: dict[str, Any] | None = None) -> QVACVerdict:
        started = time.monotonic()
        payload = {"model": MODEL, "stream": False, "messages": [{
            "role": "user", "content": json.dumps({"qname": qname, "signal_evidence": signal_evidence, "context": context or {}}, separators=(",", ":"))
        }]}
        body = json.dumps(payload, separators=(",", ":")).encode()
        last_error = "QVAC unavailable"
        for attempt in range(self.retries + 1):
            try:
                raw = self._transport(self.endpoint, body, self.timeout)
                response = json.loads(raw)
                content = response.get("message", {}).get("content", response)
                if isinstance(content, str):
                    content = json.loads(content)
                verdict = content["verdict"]
                confidence = content["confidence"]
                if verdict not in VERDICTS or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
                    raise ValueError("invalid verdict contract")
                if not isinstance(content.get("reasoning_short"), str) or not isinstance(content.get("recommended_action"), str):
                    raise ValueError("invalid verdict contract")
                return QVACVerdict(verdict, float(confidence), content["reasoning_short"], content["recommended_action"], (time.monotonic() - started) * 1000, signal_evidence=signal_evidence)
            except Exception as exc:  # transport and contract failures degrade identically
                last_error = str(exc)
                if attempt < self.retries:
                    continue
        logger.warning("QVAC request failed: %s", last_error)
        return self._unverified(started, last_error, signal_evidence)
