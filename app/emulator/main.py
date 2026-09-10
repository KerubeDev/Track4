#!/usr/bin/env python3
"""
Emulator stub — Sentinel-DNS Track4
Issue #15 (S2-T5) — Docker compose + idempotent provision

Replays DNS telemetry from the BIND9 dataset into the Kafka topic
``dns.telemetry.v1`` at configurable speed (REPLAY_RATE) with a fixed
random seed (DEMO_SEED) for reproducibility.

This is a minimal stub that satisfies the compose health gate.
The full dual-clock replay implementation lives in issue #5 (S1-T1).
"""

from __future__ import annotations

import json
import logging
import os
import random
import signal
import sys
import time
from typing import Any, Dict, List

logger = logging.getLogger("sentinel.emulator")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
REPLAY_RATE: float = float(os.environ.get("REPLAY_RATE", "20"))
DEMO_SEED: int = int(os.environ.get("DEMO_SEED", "42"))
KAFKA_BOOTSTRAP: str = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC: str = os.environ.get("KAFKA_TOPIC", "dns.telemetry.v1")
DATASET_PATH: str = os.environ.get("DATASET_PATH", "/data/queries")
HEALTH_PORT: int = int(os.environ.get("EMULATOR_HEALTH_PORT", "8080"))

_running = True


def _handle_signal(signum: int, _frame: Any) -> None:
    global _running
    logger.info("Received signal %s — shutting down", signum)
    _running = False


def _generate_synthetic_events(seed: int, count: int = 100) -> List[Dict[str, Any]]:
    """Generate synthetic DNS events for the demo when dataset is unavailable."""
    rng = random.Random(seed)

    zones = ["Z1", "Z2", "Z3", "Z4"]
    pops = [f"POP{i}" for i in range(1, 7)]
    qtypes = ["A", "AAAA", "TYPE65", "PTR", "MX"]
    rcodes = ["NOERROR"] * 90 + ["NXDOMAIN"] * 8 + ["SERVFAIL"] * 2

    events = []
    for i in range(count):
        zone = rng.choice(zones)
        pop = rng.choice(pops)
        client_ip = f"10.{rng.randint(0, 3)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        qname = f"host{i:04d}.example.com."
        events.append({
            "ts": f"2026-09-09T10:{(i // 60):02d}:{(i % 60):02d}.000",
            "client_ip": client_ip,
            "qname": qname,
            "qtype": rng.choice(qtypes),
            "rcode": rng.choice(rcodes),
            "latency_ms": round(rng.uniform(5.0, 200.0), 1),
            "zone_id": zone,
            "pop_id": pop,
        })
    return events


def _wait_for_kafka(bootstrap: str, timeout: int = 60) -> bool:
    """Wait for Kafka to become reachable."""
    import socket
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


def run() -> None:
    """Main emulator loop — publish events to Kafka at REPLAY_RATE speed."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    logger.info(
        "Emulator starting — REPLAY_RATE=x%.1f  DEMO_SEED=%d  KAFKA=%s",
        REPLAY_RATE, DEMO_SEED, KAFKA_BOOTSTRAP,
    )

    if not _wait_for_kafka(KAFKA_BOOTSTRAP):
        sys.exit(1)

    try:
        from kafka import KafkaProducer  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("kafka-python not installed — running in dry-run mode")
        _dry_run_mode()
        return

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=3,
    )

    events = _generate_synthetic_events(DEMO_SEED)
    logger.info("Generated %d synthetic events", len(events))

    interval = 1.0 / REPLAY_RATE
    published = 0

    for event in events:
        if not _running:
            break
        producer.send(KAFKA_TOPIC, value=event)
        published += 1
        time.sleep(interval)

    producer.flush(timeout=10)
    producer.close(timeout=5)
    logger.info("Emulator finished — published %d events", published)


def _dry_run_mode() -> None:
    """Run without Kafka to verify the compose health gate."""
    logger.info("Dry-run mode: waiting for shutdown signal")
    while _running:
        time.sleep(1)
    logger.info("Dry-run complete")


if __name__ == "__main__":
    run()
