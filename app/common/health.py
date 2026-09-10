#!/usr/bin/env python3
"""Minimal HTTP health endpoint shared by Sentinel-DNS services.

Serves ``GET /ping`` on the configured port so Docker Compose healthchecks
can gate service readiness without pulling in a web framework.
"""

from __future__ import annotations

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

logger = logging.getLogger("sentinel.common")


class _PingHandler(BaseHTTPRequestHandler):
    """Responds 200 to /ping, 404 everywhere else."""

    def do_GET(self) -> None:  # noqa: N802 (BaseHTTPRequestHandler API)
        if self.path.rstrip("/") == "/ping":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"pong")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, _format: str, *args) -> None:  # noqa: N802
        logger.debug("health probe: %s", args)


def start_health_server(port: int) -> ThreadingHTTPServer:
    """Start a daemon HTTP health server on ``port`` and return the server."""
    server = ThreadingHTTPServer(("0.0.0.0", port), _PingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info("Health server listening on 0.0.0.0:%d", port)
    return server