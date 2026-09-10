import heapq
from dataclasses import dataclass

from app.emulator.replay import Replayer, parse_event_timestamp


@dataclass(frozen=True)
class PlaybackStats:
    events: int
    attack_events: int


def synthesize_stream(records, mapping, synthesizer):
    for record in records:
        profile = mapping.resolve(record.client_ip)
        yield synthesizer.synthesize(record, profile)


def merge_event_streams(*streams):
    heap = []
    counter = 0
    for idx, stream in enumerate(streams):
        iterator = iter(stream)
        item = next(iterator, None)
        if item is not None:
            heap.append((item.timestamp, idx, counter, item, iterator))
            counter += 1
    heapq.heapify(heap)
    while heap:
        _, idx, _, item, iterator = heapq.heappop(heap)
        yield item
        nxt = next(iterator, None)
        if nxt is not None:
            heapq.heappush(heap, (nxt.timestamp, idx, counter, nxt, iterator))
            counter += 1


class Playback:
    def __init__(self, config, sleeper=None):
        self.config = config
        self.replayer = Replayer(config, sleeper=sleeper)

    def run(self, background_stream, emitter, attack_stream=None):
        streams = [background_stream]
        if attack_stream is not None:
            streams.append(attack_stream)
        merged = merge_event_streams(*streams) if attack_stream else background_stream

        previous = None
        background = 0
        attack = 0
        for event in merged:
            current = parse_event_timestamp(event.timestamp)
            self.replayer.pace(previous, current)
            if event.ground_truth is None:
                background += 1
            else:
                attack += 1
            emitter.emit(event)
            previous = current
        emitter.flush()
        return PlaybackStats(events=background + attack, attack_events=attack)