import glob
import heapq
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from operator import attrgetter

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
    """Ordering key for query files; unnumbered stems sort last."""
    stem = os.path.basename(path).removeprefix("queries.")
    digits = "".join(ch for ch in stem if ch.isdigit())
    return int(digits) if digits else float("inf")


def heap_merge(iterables, key):
    """Merge sorted iterables by key(item), yielding items in key order."""
    heap = []
    counter = 0
    for idx, stream in enumerate(iterables):
        iterator = iter(stream)
        item = next(iterator, None)
        if item is not None:
            heap.append((key(item), idx, counter, item, iterator))
            counter += 1
    heapq.heapify(heap)
    while heap:
        _, idx, _, item, iterator = heapq.heappop(heap)
        yield item
        nxt = next(iterator, None)
        if nxt is not None:
            heapq.heappush(heap, (key(nxt), idx, counter, nxt, iterator))
            counter += 1


def merged_stream(paths):
    return heap_merge((iter_file(path) for path in paths), key=attrgetter("timestamp"))


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
