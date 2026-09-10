import io
import json
import sys
import unittest
from datetime import datetime

from app.emulator.emitter import (
    MAX_BUFFER_RETRIES,
    Emitter,
    JsonLinesEmitter,
    KafkaEmitter,
    KafkaPartitionError,
    NullEmitter,
)
from app.emulator.events import TOPIC
from app.emulator.parser import QueryRecord
from app.emulator.synthesizer import DnstapSynthesizer

_RECORD = QueryRecord(
    timestamp=datetime(2026, 9, 9, 8, 4, 59, 901000),
    client_ip="190.102.59.241",
    client_port=35082,
    qname="www.apple.com",
    qtype="A",
    resolver_ip="172.19.1.2",
    source_file="queries.0",
)


class NullEmitterTest(unittest.TestCase):
    def test_counts_events(self):
        emitter = NullEmitter()
        for _ in range(5):
            emitter.emit(_event())
        self.assertEqual(emitter.count, 5)


class JsonLinesEmitterTest(unittest.TestCase):
    def test_writes_one_line_per_event(self):
        handle = io.StringIO()
        emitter = JsonLinesEmitter(handle)
        for _ in range(3):
            emitter.emit(_event())
        emitter.flush()
        lines = handle.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0])["schema_version"], 1)

    def test_ground_truth_null_serialized(self):
        handle = io.StringIO()
        emitter = JsonLinesEmitter(handle)
        emitter.emit(_event())
        emitter.flush()
        self.assertIn('"ground_truth":null', handle.getvalue())

    def test_close_closes_handle(self):
        handle = io.StringIO()
        emitter = JsonLinesEmitter(handle)
        emitter.emit(_event())
        emitter.close()
        self.assertTrue(handle.closed)

    def test_close_keeps_stdout_open(self):
        emitter = JsonLinesEmitter(sys.stdout)
        emitter.close()
        self.assertFalse(sys.stdout.closed)


class KafkaEmitterTest(unittest.TestCase):
    def test_requires_confluent_kafka(self):
        import importlib.util

        if importlib.util.find_spec("confluent_kafka") is not None:
            self.skipTest("confluent-kafka installed")
        with self.assertRaises(ImportError):
            KafkaEmitter("localhost:9092")

    def test_topic_default(self):
        self.assertEqual(TOPIC, "dns.telemetry.v1")

    def test_emit_success(self):
        fake = _FakeProducer(None)
        emitter = _kafka(fake)
        emitter.emit(_event())
        self.assertEqual(emitter.count, 1)
        self.assertEqual(emitter.failed, 0)
        self.assertEqual(fake.produced, 1)

    def test_buffer_error_retry_is_bounded(self):
        fake = _FakeProducer(None)
        fake.fail = True
        emitter = _kafka(fake)
        emitter.emit(_event())
        self.assertEqual(emitter.count, 0)
        self.assertEqual(emitter.failed, 1)
        self.assertEqual(fake.produced, 0)
        self.assertEqual(fake.polls, MAX_BUFFER_RETRIES - 1)

    def test_partition_match_passes(self):
        _kafka(_FakeProducer(None), checker=lambda bootstrap, topic: 3)

    def test_partition_mismatch_raises(self):
        with self.assertRaises(KafkaPartitionError):
            _kafka(_FakeProducer(None), checker=lambda bootstrap, topic: 2)


class EmitterBaseTest(unittest.TestCase):
    def test_base_emitter_has_close(self):
        self.assertIsNone(Emitter().close())


def _kafka(fake, checker=lambda bootstrap, topic: 3):
    return KafkaEmitter(
        "localhost:9092",
        producer_factory=lambda options: fake,
        partition_checker=checker,
    )


class _FakeProducer:
    def __init__(self, options):
        self.options = options
        self.produced = 0
        self.polls = 0
        self.fail = False

    def produce(self, **kwargs):
        if self.fail:
            raise BufferError("queue full")
        self.produced += 1

    def poll(self, timeout):
        self.polls += 1

    def flush(self):
        pass


def _event():
    return DnstapSynthesizer().synthesize(_RECORD, _profile())


def _profile():
    from app.emulator.mapping import ZoneMapping

    return ZoneMapping.from_csv().resolve("190.102.59.241")


if __name__ == "__main__":
    unittest.main()
