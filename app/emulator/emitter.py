from app.emulator.events import TOPIC


class Emitter:
    def emit(self, event):
        raise NotImplementedError

    def flush(self):
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


class KafkaEmitter(Emitter):
    def __init__(self, bootstrap_servers, topic=TOPIC, partitions=3, **producer_opts):
        try:
            from confluent_kafka import Producer
        except ImportError as exc:
            raise ImportError(
                "confluent-kafka is required for KafkaEmitter; "
                "install with `pip install -r requirements-kafka.txt`"
            ) from exc
        options = {
            "bootstrap.servers": bootstrap_servers,
            "partitioner": "consistent_random",
        }
        options.update(producer_opts)
        self._producer = Producer(options)
        self.topic = topic
        self.partitions = partitions
        self.count = 0
        self.failed = 0

    def emit(self, event):
        try:
            self._producer.produce(
                topic=self.topic,
                key=event.client_ip.encode("utf-8"),
                value=event.to_json().encode("utf-8"),
            )
            self.count += 1
        except BufferError:
            self._producer.poll(0.5)
            self.emit(event)

    def flush(self):
        self._producer.flush()