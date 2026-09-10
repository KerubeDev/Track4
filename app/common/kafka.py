#!/usr/bin/env python3
"""Kafka connectivity helpers shared by Sentinel-DNS services."""

from __future__ import annotations

import logging
import socket
import time

logger = logging.getLogger("sentinel.common")


def wait_for_kafka(bootstrap: str, timeout: int = 60) -> bool:
    """Wait for Kafka to become reachable.

    Returns True once the bootstrap endpoint accepts a TCP connection,
    False when the deadline expires.
    """
    host, port = bootstrap.split(":")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, int(port)), timeout=2):
                logger.info("Kafka is reachable at %s", bootstrap)
                return True
        except OSError:
            time.sleep(1)
    logger.error("Kafka not reachable at %s after %ds", bootstrap, timeout)
    return False