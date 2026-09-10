"""Tests for the consumer-side Kafka health probe (issue #7, S1-T3).

Uses fake confluent-kafka modules injected into ``sys.modules`` so the
checks run without a broker or the library installed.
"""

import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from app.common.kafka_health import (
    KafkaHealthError,
    check_offsets_advance,
    check_partitions,
    check_retention,
    probe,
)


# ---------------------------------------------------------------------------
# Fake confluent_kafka package
# ---------------------------------------------------------------------------

class FakeConfigEntry:
    def __init__(self, value):
        self.value = value


class FakeConfigResource:
    def __init__(self, resource_type, name):
        self.type = resource_type
        self.name = name


class FakeFuture:
    def __init__(self, config):
        self._config = {name: FakeConfigEntry(value) for name, value in config.items()}

    def result(self, timeout=None):
        return self._config


class FakeAdminClient:
    def __init__(self, partitions_by_topic, configs=None):
        self.partitions_by_topic = partitions_by_topic
        self.configs = configs or {}

    def list_topics(self, topic=None, timeout=None):
        topics = {
            name: SimpleNamespace(partitions={i: object() for i in range(count)})
            for name, count in self.partitions_by_topic.items()
        }
        return SimpleNamespace(topics=topics)

    def describe_configs(self, resources):
        return {r: FakeFuture(self.configs.get(r.name, {})) for r in resources}


class CountingConsumer:
    """Fake consumer whose watermark high offsets advance per call."""

    def __init__(self, samples):
        self.samples = samples
        self.calls = 0
        self.partitions = []
        self.closed = False

    def assign(self, partitions):
        self.partitions = partitions

    def poll(self, timeout):
        return None

    def get_watermark_offsets(self, partition, timeout=None):
        idx = min(self.calls, len(self.samples) - 1)
        self.calls += 1
        high = self.samples[idx].get(partition.partition, 0)
        return (0, high)

    def close(self):
        self.closed = True


def _install_fake_confluent():
    admin = SimpleNamespace(
        AdminClient=FakeAdminClient,
        ConfigResource=FakeConfigResource,
        ResourceType=SimpleNamespace(TOPIC="topic"),
    )
    package = SimpleNamespace(
        admin=admin,
        Consumer=CountingConsumer,
        TopicPartition=_TopicPartition,
    )
    sys.modules["confluent_kafka"] = package
    sys.modules["confluent_kafka.admin"] = admin
    return package


def _TopicPartition(topic, partition):
    return SimpleNamespace(topic=topic, partition=partition)


@mock.patch("app.common.kafka_health._admin")
class CheckPartitionsTest(unittest.TestCase):
    def setUp(self):
        _install_fake_confluent()

    def test_matching_count_returns(self, _admin):
        admin = FakeAdminClient({"dns.telemetry.v1": 3})
        self.assertEqual(check_partitions(admin, "dns.telemetry.v1"), 3)

    def test_wrong_count_raises(self, _admin):
        admin = FakeAdminClient({"dns.telemetry.v1": 2})
        with self.assertRaises(KafkaHealthError):
            check_partitions(admin, "dns.telemetry.v1")

    def test_missing_topic_raises(self, _admin):
        admin = FakeAdminClient({})
        with self.assertRaises(KafkaHealthError):
            check_partitions(admin, "dns.telemetry.v1")


class CheckRetentionTest(unittest.TestCase):
    def setUp(self):
        _install_fake_confluent()

    def test_retention_and_cleanup_ok(self):
        admin = FakeAdminClient(
            {"dns.telemetry.v1": 3},
            configs={
                "dns.telemetry.v1": {
                    "retention.ms": "3600000",
                    "cleanup.policy": "delete",
                }
            },
        )
        report = check_retention(admin, "dns.telemetry.v1")
        self.assertEqual(report["retention.ms"], "3600000")
        self.assertEqual(report["cleanup.policy"], "delete")

    def test_retention_too_long_raises(self):
        admin = FakeAdminClient(
            {"dns.telemetry.v1": 3},
            configs={
                "dns.telemetry.v1": {
                    "retention.ms": "9000000",
                    "cleanup.policy": "delete",
                }
            },
        )
        with self.assertRaises(KafkaHealthError):
            check_retention(admin, "dns.telemetry.v1")

    def test_cleanup_without_delete_raises(self):
        admin = FakeAdminClient(
            {"dns.telemetry.v1": 3},
            configs={
                "dns.telemetry.v1": {
                    "retention.ms": "3600000",
                    "cleanup.policy": "compact",
                }
            },
        )
        with self.assertRaises(KafkaHealthError):
            check_retention(admin, "dns.telemetry.v1")


@mock.patch("app.common.kafka_health.time.sleep", lambda _s: None)
class CheckOffsetsAdvanceTest(unittest.TestCase):
    def test_live_advance_detected(self):
        package = _install_fake_confluent()
        package.Consumer = lambda opts: CountingConsumer(
            [{0: 0, 1: 0, 2: 0}, {0: 5, 1: 0, 2: 0}]
        )
        report = check_offsets_advance(
            "localhost:9092", "dns.telemetry.v1", 3, sample_seconds=10.0
        )
        self.assertEqual(report["offset_before"], 0)
        self.assertEqual(report["offset_after"], 5)

    def test_no_advance_raises(self):
        package = _install_fake_confluent()
        package.Consumer = lambda opts: CountingConsumer([{0: 0, 1: 0, 2: 0}])
        with self.assertRaises(KafkaHealthError):
            check_offsets_advance(
                "localhost:9092", "dns.telemetry.v1", 3, sample_seconds=0.01
            )

    def test_idle_data_passes_with_flag(self):
        package = _install_fake_confluent()
        package.Consumer = lambda opts: CountingConsumer([{0: 3, 1: 2, 2: 4}])
        report = check_offsets_advance(
            "localhost:9092",
            "dns.telemetry.v1",
            3,
            sample_seconds=10.0,
            allow_idle_data=True,
        )
        self.assertEqual(report["offset_before"], 9)
        self.assertEqual(report["offset_after"], 9)
        self.assertTrue(report.get("idle"))

    def test_idle_data_still_requires_advance_without_flag(self):
        package = _install_fake_confluent()
        package.Consumer = lambda opts: CountingConsumer([{0: 3, 1: 2, 2: 4}])
        with self.assertRaises(KafkaHealthError):
            check_offsets_advance(
                "localhost:9092", "dns.telemetry.v1", 3, sample_seconds=0.01
            )


@mock.patch("app.common.kafka_health._admin")
class ProbeTest(unittest.TestCase):
    def test_full_probe_passes(self, _admin):
        package = _install_fake_confluent()
        _admin.return_value = FakeAdminClient(
            {"dns.telemetry.v1": 3},
            configs={
                "dns.telemetry.v1": {
                    "retention.ms": "3600000",
                    "cleanup.policy": "delete",
                }
            },
        )
        package.Consumer = lambda opts: CountingConsumer(
            [{0: 0, 1: 0, 2: 0}, {0: 1, 1: 0, 2: 0}]
        )
        with mock.patch("app.common.kafka_health.time.sleep", lambda _s: None):
            report = probe("localhost:9092", "dns.telemetry.v1", sample_seconds=1.0)
        self.assertEqual(report["partitions"], 3)
        self.assertEqual(report["retention"]["cleanup.policy"], "delete")
        self.assertEqual(report["offsets"]["offset_after"], 1)

    def test_partition_mismatch_fails_probe(self, _admin):
        _install_fake_confluent()
        _admin.return_value = FakeAdminClient(
            {"dns.telemetry.v1": 2},
            configs={"dns.telemetry.v1": {"retention.ms": "3600000", "cleanup.policy": "delete"}},
        )
        with self.assertRaises(KafkaHealthError):
            probe("localhost:9092", "dns.telemetry.v1", sample_seconds=1.0)


class ModuleSmokeTest(unittest.TestCase):
    def test_disable_fake_cleanup(self):
        for name in (
            "confluent_kafka",
            "confluent_kafka.admin",
        ):
            sys.modules.pop(name, None)


if __name__ == "__main__":
    unittest.main()