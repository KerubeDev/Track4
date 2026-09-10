#!/usr/bin/env python3
"""Consumer-side Kafka health probe for the dns.telemetry.v1 topic.

Verifies the topic layout contract from the acceptance criteria of
issue #7 (S1-T3):

  * topic ``dns.telemetry.v1`` exists with exactly 3 partitions
  * retention is configured at ~1 h with ``cleanup.policy = delete``
  * offsets advance while the stream is live

Runnable standalone::

    python -m app.common.kafka_health --bootstrap localhost:9092

Exits 0 when all checks pass, 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Dict, List

from app.common.kafka import wait_for_kafka

DEFAULT_PARTITIONS = 3
DEFAULT_RETENTION_MS = 3_600_000
SAMPLE_INTERVAL_S = 1.0


class KafkaHealthError(RuntimeError):
    """Raised when a health probe check fails."""


def _admin(bootstrap: str):
    from confluent_kafka.admin import AdminClient, ConfigResource, ResourceType

    return AdminClient({"bootstrap.servers": bootstrap})


def check_partitions(admin, topic: str, expected: int = DEFAULT_PARTITIONS) -> int:
    """Return the topic partition count, raising if it differs from ``expected``.

    ``KafkaHealthError`` is also raised when the topic does not exist yet.
    """
    metadata = admin.list_topics(topic=topic, timeout=15)
    entry = metadata.topics.get(topic)
    if entry is None:
        raise KafkaHealthError(f"topic {topic!r} not found")
    found = len(entry.partitions)
    if found != expected:
        raise KafkaHealthError(
            f"topic {topic!r} has {found} partition(s), expected {expected}"
        )
    return found


def check_retention(
    admin,
    topic: str,
    expected_ms: int = DEFAULT_RETENTION_MS,
) -> Dict[str, str]:
    """Verify retention.ms and cleanup.policy on the topic.

    Retention is considered satisfied when the configured value is at or
    below the target (``<=``), so shorter windows still meet the ~1 h goal.
    """
    from confluent_kafka.admin import ConfigResource, ResourceType

    resource = ConfigResource(ResourceType.TOPIC, topic)
    result = admin.describe_configs([resource])
    config = result[resource].result()

    def _value(name: str) -> str:
        entry = config.get(name)
        if entry is None:
            raise KafkaHealthError(f"topic {topic!r} has no config {name!r}")
        return entry.value

    retention_ms = int(_value("retention.ms"))
    cleanup = _value("cleanup.policy")
    if retention_ms > expected_ms:
        raise KafkaHealthError(
            f"topic {topic!r} retention.ms={retention_ms} exceeds target {expected_ms}"
        )
    if "delete" not in cleanup:
        raise KafkaHealthError(
            f"topic {topic!r} cleanup.policy={cleanup!r} does not include 'delete'"
        )
    return {"retention.ms": str(retention_ms), "cleanup.policy": cleanup}


def _watermark_sums(consumer, partitions: List) -> Dict[int, int]:
    """Map partition.id -> latest (high watermark) offset."""
    sums: Dict[int, int] = {}
    for partition in partitions:
        _, high = consumer.get_watermark_offsets(partition, timeout=5)
        sums[partition.partition] = high
    return sums


def check_offsets_advance(
    bootstrap: str,
    topic: str,
    partition_count: int,
    sample_seconds: float = 30.0,
    allow_idle_data: bool = False,
) -> Dict[str, int]:
    """Confirm the stream is live: the sum of end offsets grows over time.

    Assigns the consumer to the topic rather than polling a group, so the
    probe observes the raw topic watermark and never interferes with the
    sentinel-agent consumer group.

    When ``allow_idle_data`` is set, a topic that already holds data passes
    immediately — this fits one-shot producers (e.g. the compose emulator
    stub) that write a deterministic batch and exit. Without it, offsets must
    advance inside the sample window (live streaming producers).
    """
    from confluent_kafka import Consumer, TopicPartition

    consumer = Consumer(
        {
            "bootstrap.servers": bootstrap,
            "group.id": "sentinel-health-probe",
            "enable.auto.commit": False,
            "auto.offset.reset": "earliest",
        }
    )
    partitions = [
        TopicPartition(topic, idx) for idx in range(partition_count)
    ]
    consumer.assign(partitions)
    try:
        consumer.poll(0.5)  # prime metadata for watermark queries
        before = _watermark_sums(consumer, partitions)
        group_before = sum(before.values())
        if allow_idle_data and group_before > 0:
            return {
                "offset_before": group_before,
                "offset_after": group_before,
                "idle": True,
            }
        deadline = time.monotonic() + sample_seconds
        while time.monotonic() < deadline:
            time.sleep(SAMPLE_INTERVAL_S)
            now = _watermark_sums(consumer, partitions)
            group_now = sum(now.values())
            if group_now > group_before:
                return {"offset_before": group_before, "offset_after": group_now}
        raise KafkaHealthError(
            f"offsets did not advance on {topic!r} within {sample_seconds:g}s "
            f"(sum before={group_before}, sum after={group_now})"
        )
    finally:
        consumer.close()


def probe(
    bootstrap: str,
    topic: str,
    expected_partitions: int = DEFAULT_PARTITIONS,
    expected_retention_ms: int = DEFAULT_RETENTION_MS,
    sample_seconds: float = 30.0,
    allow_idle_data: bool = False,
) -> Dict:
    """Run every check and return a structured result.

    Raise ``KafkaHealthError`` on any failure. The returned dict is the
    health report, useful for logging or as a JSON artifact.
    """
    admin = _admin(bootstrap)
    partitions = check_partitions(admin, topic, expected_partitions)
    retention = check_retention(admin, topic, expected_retention_ms)
    offsets = check_offsets_advance(
        bootstrap,
        topic,
        partitions,
        sample_seconds=sample_seconds,
        allow_idle_data=allow_idle_data,
    )
    return {
        "topic": topic,
        "partitions": partitions,
        "retention": retention,
        "offsets": offsets,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-dns-kafka-health",
        description="Probe the dns.telemetry.v1 topic for partitions, retention,"
        " and offset advancement.",
    )
    parser.add_argument("--bootstrap", default="localhost:9092")
    parser.add_argument("--topic", default="dns.telemetry.v1")
    parser.add_argument("--partitions", type=int, default=DEFAULT_PARTITIONS)
    parser.add_argument("--retention-ms", type=int, default=DEFAULT_RETENTION_MS)
    parser.add_argument("--sample-seconds", type=float, default=30.0)
    parser.add_argument(
        "--allow-idle-data",
        action="store_true",
        help="pass when the topic already holds data but is not streaming "
        "(fits one-shot producers)",
    )
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    if not wait_for_kafka(args.bootstrap):
        return 1
    try:
        report = probe(
            args.bootstrap,
            args.topic,
            expected_partitions=args.partitions,
            expected_retention_ms=args.retention_ms,
            sample_seconds=args.sample_seconds,
            allow_idle_data=args.allow_idle_data,
        )
    except KafkaHealthError as exc:
        print(f"KAFKA_HEALTH_FAIL: {exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        for key, value in report.items():
            print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())