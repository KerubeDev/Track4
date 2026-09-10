import sys

from app.emulator.events import TOPIC

MAX_BUFFER_RETRIES = 10


class KafkaPartitionError(RuntimeError):
    pass


def _topic_partition_count(bootstrap_servers, topic):
    from confluent_kafka.admin import AdminClient

    metadata = AdminClient({"bootstrap.servers": bootstrap_servers}).list_topics(
        topic, timeout=10
    )
    partitions = metadata.topics.get(topic)
    if partitions is None:
        raise KafkaPartitionError(f"topic {topic!r} not found")
    return len(partitions.partitions)


class Emitter:
    def emit(self, event):
        raise NotImplementedError

    def flush(self):
        pass

    def close(self):
        pass


class NullEmitter(Emitter):
    def __init__(self):
        self.count = 0

    def emit(self, event):
        self.count += 1


class JsonLinesEmitter(Emitter):
    def __init__(self, handle):
        self._handle = handle
        self.count = 0

    def emit(self, event):
        self._handle.write(event.to_json() + "\n")
        self.count += 1

    def flush(self):
        self._handle.flush()

    def close(self):
        if self._handle is not sys.stdout:
            self._handle.close()


class KafkaEmitter(Emitter):
    def __init__(
        self,
        bootstrap_servers,
        topic=TOPIC,
        partitions=3,
        producer_factory=None,
        partition_checker=None,
        strict_partitions=False,
        **producer_opts,
    ):
        if producer_factory is None:
            try:
                from confluent_kafka import Producer
            except ImportError as exc:
                raise ImportError(
                    "confluent-kafka is required for KafkaEmitter; "
                    "install with `pip install -r requirements-kafka.txt`"
                ) from exc
            producer_factory = Producer

        checker = partition_checker if partition_checker is not None else _topic_partition_count
        try:
            actual = checker(bootstrap_servers, topic)
        except KafkaPartitionError:
            if strict_partitions:
                raise
            print(
                f"WARN: topic {topic!r} partition check failed, continuing anyway",
                file=sys.stderr,
            )
            actual = partitions
        if actual != partitions:
            if strict_partitions:
                raise KafkaPartitionError(
                    f"topic {topic!r} has {actual} partition(s), expected {partitions}"
                )
            print(
                f"WARN: topic {topic!r} has {actual} partition(s), expected {partitions}",
                file=sys.stderr,
            )

        options = {
            "bootstrap.servers": bootstrap_servers,
            "partitioner": "consistent_random",
        }
        options.update(producer_opts)
        self._producer = producer_factory(options)
        self.topic = topic
        self.partitions = partitions
        self.count = 0
        self.failed = 0

    def emit(self, event):
        attempts = 0
        while True:
            try:
                self._producer.produce(
                    topic=self.topic,
                    key=event.client_ip.encode("utf-8"),
                    value=event.to_json().encode("utf-8"),
                )
                self.count += 1
                return
            except BufferError:
                attempts += 1
                if attempts >= MAX_BUFFER_RETRIES:
                    self.failed += 1
                    print(
                        f"WARN: dropped event after {MAX_BUFFER_RETRIES} retries",
                        file=sys.stderr,
                    )
                    return
                self._producer.poll(0.5)

    def flush(self):
        self._producer.flush()

    def close(self):
        self.flush()
