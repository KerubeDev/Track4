#!/usr/bin/env python3
"""
QVAC stub server — Sentinel-DNS Track4
Issue #15 (S2-T5) — Docker compose + idempotent provision

Minimal HTTP server that mimics the QVAC chat API for demo purposes.
Returns mock verdicts for escalated queries so the full pipeline can
run end-to-end without the real QVAC/QWEN3 model.

The real QVAC adapter will replace this in issue #9 (S1-T5).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

logger = logging.getLogger("sentinel.qvac")

QVAC_PORT: int = int(os.environ.get("QVAC_PORT", "11434"))
_running = True


def _handle_signal(signum: int, _frame: Any) -> None:
    global _running
    logger.info("Received signal %s — shutting down", signum)
    _running = False


class QVACHandler(BaseHTTPRequestHandler):
    """Handle /api/chat and /ping requests."""

    def do_GET(self) -> None:
        if self.path == "/ping":
            self._respond(200, {"status": "ok"})
        elif self.path == "/health":
            self._respond(200, {"status": "ok"})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/api/chat":
            self._handle_chat()
        else:
            self._respond(404, {"error": "not found"})

    def _handle_chat(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        try:
            request = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        # Extract query info from the prompt
        prompt = request.get("messages", [{}])[-1].get("content", "")

        # Return a mock verdict
        verdict = self._mock_verdict(prompt)
        self._respond(200, verdict)

    def _mock_verdict(self, prompt: str) -> dict:
        """Generate a mock verdict based on prompt content."""
        prompt_lower = prompt.lower()

        if "nxdomain" in prompt_lower or "dga" in prompt_lower:
            return {
                "verdict": "dga",
                "confidence": 0.92,
                "reasoning_short": "High NXDOMAIN rate suggests DGA activity",
                "recommended_action": "Block and investigate",
            }
        elif "tunnel" in prompt_lower or "entropy" in prompt_lower:
            return {
                "verdict": "tunnel",
                "confidence": 0.88,
                "reasoning_short": "High entropy label indicates DNS tunneling",
                "recommended_action": "Block tunnel endpoint",
            }
        elif "beacon" in prompt_lower:
            return {
                "verdict": "beaconing",
                "confidence": 0.85,
                "reasoning_short": "Periodic query pattern detected",
                "recommended_action": "Monitor and rate-limit",
            }
        elif "typo" in prompt_lower:
            return {
                "verdict": "typosquat",
                "confidence": 0.75,
                "reasoning_short": "Edit distance suggests typosquatting",
                "recommended_action": "Alert user",
            }
        else:
            return {
                "verdict": "benign",
                "confidence": 0.95,
                "reasoning_short": "No threat indicators found",
                "recommended_action": "Allow",
            }

    def _respond(self, code: int, data: dict) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        logger.info(format, *args)


def run() -> None:
    """Start the QVAC stub server."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    server = HTTPServer(("0.0.0.0", QVAC_PORT), QVACHandler)
    logger.info("QVAC stub listening on port %d", QVAC_PORT)

    server.timeout = 1
    while _running:
        server.handle_request()

    server.server_close()
    logger.info("QVAC stub stopped")


if __name__ == "__main__":
    run()
