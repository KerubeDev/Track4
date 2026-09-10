#!/usr/bin/env bash
# =============================================================================
# init-topics.sh — Idempotent Kafka topic provisioning (KRaft, single broker)
# Issue #7 (S1-T3) — Kafka topic and event schema (dns.telemetry.v1)
#
# Creates the single telemetry topic with an explicit, deterministic layout:
#   topic             : ${KAFKA_TOPIC} (default dns.telemetry.v1)
#   partitions        : ${KAFKA_TOPIC_PARTITIONS} (default 3)
#   replication factor: 1 (single-node cluster)
#   retention         : ${KAFKA_TOPIC_RETENTION_MS} (default 3600000 = ~1 h)
#   cleanup.policy    : delete
#
# Keying by client_ip hash is a producer responsibility (the emulator sends
# client_ip as the Kafka message key), not a topic property.
#
# Safe to run multiple times — topic creation is guarded with --if-not-exists.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-localhost:9092}"
KAFKA_TOPIC="${KAFKA_TOPIC:-dns.telemetry.v1}"
KAFKA_TOPIC_PARTITIONS="${KAFKA_TOPIC_PARTITIONS:-3}"
KAFKA_TOPIC_RETENTION_MS="${KAFKA_TOPIC_RETENTION_MS:-3600000}"

TOPICS_BIN="${KAFKA_TOPICS_BIN:-kafka-topics.sh}"

echo "============================================="
echo " Sentinel-DNS — Kafka topic provisioning"
echo "============================================="
echo "  bootstrap    : ${KAFKA_BOOTSTRAP}"
echo "  topic        : ${KAFKA_TOPIC}"
echo "  partitions   : ${KAFKA_TOPIC_PARTITIONS}"
echo "  retention(ms): ${KAFKA_TOPIC_RETENTION_MS}"
echo ""

if ! "${TOPICS_BIN}" --bootstrap-server "${KAFKA_BOOTSTRAP}" --list >/dev/null 2>&1; then
    echo "ERROR: Kafka not reachable at ${KAFKA_BOOTSTRAP}" >&2
    exit 1
fi

if "${TOPICS_BIN}" --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --topic "${KAFKA_TOPIC}" --describe >/dev/null 2>&1; then
    echo "OK: topic ${KAFKA_TOPIC} already exists — nothing to do."
    exit 0
fi

if "${TOPICS_BIN}" --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --create \
    --topic "${KAFKA_TOPIC}" \
    --partitions "${KAFKA_TOPIC_PARTITIONS}" \
    --replication-factor 1 \
    --config retention.ms="${KAFKA_TOPIC_RETENTION_MS}" \
    --config cleanup.policy=delete \
    --if-not-exists; then
    echo ""
    echo "OK: topic ${KAFKA_TOPIC} created with"
    echo "  partitions=${KAFKA_TOPIC_PARTITIONS} retention_ms=${KAFKA_TOPIC_RETENTION_MS} cleanup.policy=delete"
else
    echo "ERROR: topic creation failed for ${KAFKA_TOPIC}" >&2
    exit 1
fi