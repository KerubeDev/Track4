from datetime import datetime


def iso(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Sleeper:
    def __init__(self):
        self.total = 0.0

    def __call__(self, delay):
        self.total += delay


class Collector:
    def __init__(self):
        self.events = []

    def emit(self, event):
        self.events.append(event)

    def flush(self):
        pass

    def close(self):
        pass
