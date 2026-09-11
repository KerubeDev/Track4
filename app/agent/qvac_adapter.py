"""Local, bounded QVAC chat adapter with controlled degradation."""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib import parse, request

logger = logging.getLogger(__name__)

VERDICTS = {"dga", "tunnel", "beaconing", "typosquat", "benign"}
MODEL = os.environ.get("QVAC_MODEL", "QWEN3_1_7B_INST_Q4")


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

    def __init__(self, base_url: str = "http://localhost:11434", *, timeout: float | None = None,
                 retries: int = 1, transport: Callable[[str, bytes, float], bytes] | None = None):
        parsed = parse.urlparse(base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("QVAC must use a local HTTP endpoint")
        self.endpoint = base_url.rstrip("/") + "/v1/chat/completions"
        self.timeout = timeout if timeout is not None else float(os.environ.get("QVAC_TIMEOUT_SECONDS", "30"))
        self.retries = max(0, retries)
        self._transport = transport or self._http_transport

    @staticmethod
    def _http_transport(url: str, body: bytes, timeout: float) -> bytes:
        # Compose uses a private service name; it is still local to the demo
        # network. Never permit an arbitrary remote endpoint.
        allowed_hosts = {
            host.strip().lower()
            for host in os.environ.get("QVAC_ALLOWED_HOSTS", "localhost,127.0.0.1,::1,qvac,host.docker.internal").split(",")
            if host.strip()
        }
        host = parse.urlparse(url).hostname
        if not host or host.lower() not in allowed_hosts:
            raise ValueError(f"non-loopback QVAC endpoint refused: {host}")
        req = request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
        with request.urlopen(req, timeout=timeout) as response:  # nosec B310: refused non-loopback above
            return response.read()

    def _unverified(self, started: float, error: str, evidence: dict[str, Any]) -> QVACVerdict:
        return QVACVerdict("unverified", 0.0, error, "Investigate", (time.monotonic() - started) * 1000, error, evidence)

    def infer(self, qname: str, signal_evidence: dict[str, Any], context: dict[str, Any] | None = None) -> QVACVerdict:
        started = time.monotonic()
        payload = {
            "model": MODEL,
            "stream": False,
            "temperature": 0,
            "max_tokens": 128,
            "messages": [
                {"role": "system", "content": "Return only one valid JSON object with keys verdict, confidence, reasoning_short, recommended_action. verdict MUST be exactly one of benign, dga, tunnel, beaconing, typosquat. confidence MUST be a number from 0 to 1. No markdown. /no_think"},
                {"role": "user", "content": json.dumps({"qname": qname, "signal_evidence": signal_evidence, "context": context or {}}, separators=(",", ":"))},
            ],
        }
        body = json.dumps(payload, separators=(",", ":")).encode()
        last_error = "QVAC unavailable"
        for attempt in range(self.retries + 1):
            try:
                raw = self._transport(self.endpoint, body, self.timeout)
                response = json.loads(raw)
                choices = response.get("choices")
                content = choices[0].get("message", {}).get("content") if choices else response
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
