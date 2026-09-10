#!/usr/bin/env python3
"""
Agent stub — Sentinel-DNS Track4
Issue #15 (S2-T5) — Docker compose + idempotent provision

Consumes DNS events from Kafka topic ``dns.telemetry.v1``, runs the
deterministic filter (5 signals), and escalates to QVAC when escalation
rules are met. Alerts are published to Wazuh via syslog.

This is a minimal stub that satisfies the compose health gate.
The full filter implementation lives in issue #8 (S1-T4).
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from typing import Any, Dict, Optional

from app.common.health import start_health_server
from app.common.kafka import wait_for_kafka
from app.agent.filter import DeterministicFilter
from app.agent.qvac_adapter import QVACAdapter

logger = logging.getLogger("sentinel.agent")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP: str = os.environ.get("KAFKA_BOOTSTRAP", "kafka:9092")
KAFKA_TOPIC: str = os.environ.get("KAFKA_TOPIC", "dns.telemetry.v1")
KAFKA_GROUP: str = os.environ.get("KAFKA_GROUP", "sentinel-agent")
CLICKHOUSE_HOST: str = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CLICKHOUSE_PORT: int = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
CLICKHOUSE_DB: str = os.environ.get("CLICKHOUSE_DB", "sentinel_dns")
QVAC_URL: str = os.environ.get("QVAC_URL", "http://qvac:11434")
WAZUH_HOST: str = os.environ.get("WAZUH_HOST", "wazuh")
WAZUH_PORT: int = int(os.environ.get("WAZUH_PORT", "1514"))
HEALTH_PORT: int = int(os.environ.get("AGENT_HEALTH_PORT", "8081"))

_running = True
_filter = DeterministicFilter()
_qvac = QVACAdapter(QVAC_URL)


def _handle_signal(signum: int, _frame: Any) -> None:
    global _running
    logger.info("Received signal %s — shutting down", signum)
    _running = False


def _process_event(event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Process a single DNS event: deterministic filter then QVAC verdict.

    Runs the 5-signal deterministic filter; if it produces a candidate,
    sends it through QVAC for a verdict and returns an alert dict with
    verdict, confidence, and metadata. Returns None when no escalation
    is triggered.
    """
    candidate = _filter.process(event)
    if candidate is None:
        return None
    verdict = _qvac.infer(candidate["qname"], candidate["signals"], {"client_ip": candidate["client_ip"]})
    return {
        **candidate,
        "verdict": verdict.verdict,
        "confidence": verdict.confidence,
        "reasoning_short": verdict.reasoning_short,
        "recommended_action": verdict.recommended_action,
        "signal_evidence": verdict.signal_evidence,
        "qvac_latency_ms": verdict.latency_ms,
    }


def run() -> None:
    """Main agent loop — consume from Kafka, filter, alert."""
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    start_health_server(HEALTH_PORT)

    logger.info(
        "Agent starting — KAFKA=%s  CLICKHOUSE=%s:%d  QVAC=%s  WAZUH=%s:%d",
        KAFKA_BOOTSTRAP, CLICKHOUSE_HOST, CLICKHOUSE_PORT,
        QVAC_URL, WAZUH_HOST, WAZUH_PORT,
    )

    if not wait_for_kafka(KAFKA_BOOTSTRAP):
        sys.exit(1)

    try:
        from kafka import KafkaConsumer  # type: ignore[import-untyped]
    except ImportError:
        logger.warning("kafka-python not installed — running in dry-run mode")
        _dry_run_mode()
        return

    from app.agent.alert_publisher import AlertPublisher, VerdictInfo

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=KAFKA_GROUP,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )

    publisher = AlertPublisher(wazuh_host=WAZUH_HOST, wazuh_port=WAZUH_PORT)
    consumed = 0
    alerts = 0

    try:
        for message in consumer:
            if not _running:
                break
            event = message.value
            consumed += 1

            alert = _process_event(event)
            if alert is not None:
                vi = VerdictInfo(
                    verdict=alert["verdict"],
                    confidence=alert["confidence"],
                    reasoning_short=alert.get("reasoning_short", ""),
                    recommended_action=alert.get("recommended_action", ""),
                    qname=alert.get("qname", ""),
                    client_ip=alert.get("client_ip", ""),
                )
                publisher.publish(vi)
                alerts += 1

            if consumed % 100 == 0:
                logger.info("Processed %d events, %d alerts", consumed, alerts)
    finally:
        consumer.close()
        logger.info("Agent finished — processed %d events, %d alerts", consumed, alerts)


def _dry_run_mode() -> None:
    """Run without Kafka to verify the compose health gate."""
    logger.info("Dry-run mode: waiting for shutdown signal")
    while _running:
        time.sleep(1)
    logger.info("Dry-run complete")


if __name__ == "__main__":
    run()
