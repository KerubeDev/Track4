import glob
import heapq
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from app.emulator.parser import QueryRecord, iter_file

DEFAULT_RATE = 20.0
DEFAULT_SEED = 20260909


@dataclass(frozen=True)
class ReplayConfig:
    replay_rate: float = DEFAULT_RATE
    seed: int = DEFAULT_SEED


def find_dataset_files(directory):
    paths = glob.glob(f"{directory.rstrip('/')}/queries.*")
    return sorted(paths, key=_natural_key)


def _natural_key(path):
    stem = path.rsplit("/", 1)[-1].removeprefix("queries.")
    digits = "".join(ch for ch in stem if ch.isdigit())
    return int(digits) if digits else float("inf")


def merged_stream(paths):
    iterators = [iter_file(path) for path in paths]
    heap = []
    for idx, iterator in enumerate(iterators):
        record = next(iterator, None)
        if record is not None:
            heapq.heappush(heap, (record.timestamp, idx, record))
    while heap:
        _, idx, record = heapq.heappop(heap)
        yield record
        nxt = next(iterators[idx], None)
        if nxt is not None:
            heapq.heappush(heap, (nxt.timestamp, idx, nxt))


class Replayer:
    def __init__(self, config, sleeper=None):
        self.config = config
        self._sleep = sleeper if sleeper is not None else time.sleep

    def pace(self, previous, current):
        if self.config.replay_rate <= 0 or previous is None:
            return
        delay = (current - previous).total_seconds() / self.config.replay_rate
        if delay > 0:
            self._sleep(delay)


def parse_event_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)