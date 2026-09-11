#!/usr/bin/env python3
"""Container entry point for the real dataset replay."""
from __future__ import annotations

import logging
import os
import signal
import sys
from typing import Any

from app.common.health import start_health_server
from app.common.kafka import wait_for_kafka
from app.emulator.cli import run as run_cli

logger = logging.getLogger("sentinel.emulator")
REPLAY_RATE = float(os.environ.get("REPLAY_RATE", "20"))
DEMO_SEED = int(os.environ.get("DEMO_SEED", "42"))
KAFKA_BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
DATASET_PATH = os.environ.get("DATASET_PATH", "/data/queries")
HEALTH_PORT = int(os.environ.get("EMULATOR_HEALTH_PORT", "8080"))
_running = True


def _handle_signal(signum: int, _frame: Any) -> None:
    global _running
    logger.info("Received signal %s - shutting down", signum)
    _running = False


def run() -> None:
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    start_health_server(HEALTH_PORT)
    if not wait_for_kafka(KAFKA_BOOTSTRAP):
        sys.exit(1)
    if not os.path.isdir(DATASET_PATH):
        logger.error("Dataset directory does not exist: %s", DATASET_PATH)
        sys.exit(1)
    run_cli(["--dataset", DATASET_PATH, "--rate", str(REPLAY_RATE), "--seed", str(DEMO_SEED),
             "--emit", "kafka", "--bootstrap", KAFKA_BOOTSTRAP])


if __name__ == "__main__":
    run()
