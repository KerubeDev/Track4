from dataclasses import dataclass
from operator import attrgetter

from app.emulator.replay import Replayer, heap_merge, parse_event_timestamp


@dataclass(frozen=True)
class PlaybackStats:
    events: int
    attack_events: int
    first_ts: str | None = None
    last_ts: str | None = None


def synthesize_stream(records, mapping, synthesizer):
    for record in records:
        profile = mapping.resolve(record.client_ip)
        yield synthesizer.synthesize(record, profile)


def merge_event_streams(*streams):
    return heap_merge(streams, key=attrgetter("ts"))


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
        first_ts = None
        last_ts = None
        for event in merged:
            current = parse_event_timestamp(event.ts)
            self.replayer.pace(previous, current)
            if first_ts is None:
                first_ts = event.ts
            last_ts = event.ts
            if event.ground_truth is None:
                background += 1
            else:
                attack += 1
            emitter.emit(event)
            previous = current
        emitter.flush()
        return PlaybackStats(
            events=background + attack,
            attack_events=attack,
            first_ts=first_ts,
            last_ts=last_ts,
        )
