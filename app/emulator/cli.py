import argparse
import os
import random
import sys

from app.emulator import parser
from app.emulator.emitter import JsonLinesEmitter, KafkaEmitter, NullEmitter
from app.emulator.mapping import ZoneMapping, DEFAULT_MAPPING_PATH
from app.emulator.playback import Playback, synthesize_stream
from app.emulator.replay import DEFAULT_RATE, DEFAULT_SEED, ReplayConfig, find_dataset_files, merged_stream
from app.emulator.synthesizer import DnstapSynthesizer

EMITTERS = ("null", "json", "kafka")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="sentinel-dns-emulator",
        description="Replay the BIND9 queries dataset with its original timestamps, "
        "synthesize the dnstap layer (ADR-0005), and publish to Kafka.",
    )
    parser.add_argument("--dataset", default=os.environ.get("EMULATOR_DATASET", ""),
                        help="directory with queries.N files")
    parser.add_argument("--mapping", default=os.environ.get("ZONE_MAPPING", DEFAULT_MAPPING_PATH),
                        help="path to zone_mapping.csv")
    parser.add_argument("--rate", type=float, default=_env_float("REPLAY_RATE", DEFAULT_RATE),
                        help="REPLAY_RATE: wall-clock compression factor (0 = no wait)")
    parser.add_argument("--seed", type=int, default=int(os.environ.get("EMULATOR_SEED", DEFAULT_SEED)),
                        help="RNG seed for the synthesized dnstap layer")
    parser.add_argument("--emit", choices=EMITTERS, default=os.environ.get("EMULATOR_EMIT", "null"),
                        help="destination for the JSON events")
    parser.add_argument("--out", default=None, help="JSON-lines output file (--emit json)")
    parser.add_argument("--bootstrap", default=os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092"),
                        help="Kafka bootstrap servers (--emit kafka)")
    parser.add_argument("--limit", type=int, default=0, help="stop after N events (0 = replay all)")
    parser.add_argument("--partitions", type=int, default=3, help="expected Kafka partitions")
    return parser.parse_args(argv)


def _env_float(name, default):
    value = os.environ.get(name)
    return float(value) if value is not None else default


def build_emitter(args):
    if args.emit == "json":
        handle = sys.stdout if args.out is None else open(args.out, "w", encoding="utf-8")
        return JsonLinesEmitter(handle)
    if args.emit == "kafka":
        return KafkaEmitter(args.bootstrap, partitions=args.partitions)
    return NullEmitter()


def run(argv=None):
    args = parse_args(argv)
    mapping = ZoneMapping.from_csv(args.mapping)
    synthesizer = DnstapSynthesizer(random.Random(args.seed))

    if args.dataset:
        records = merged_stream(find_dataset_files(args.dataset))
        background = synthesize_stream(records, mapping, synthesizer)
    else:
        background = iter(())

    emitter = build_emitter(args)
    playback = Playback(ReplayConfig(replay_rate=args.rate, seed=args.seed))
    stream = _limited(background, args.limit)
    stats = playback.run(stream, emitter)
    emitter.close()
    kafka_failed = ""
    if args.emit == "kafka" and hasattr(emitter, "failed"):
        kafka_failed = f" kafka_failed={emitter.failed}"
    print(
        f"replayed={stats.events} attack={stats.attack_events} "
        f"window=({stats.first_ts} .. {stats.last_ts}) "
        f"rate=x{_display_rate(args.rate)} seed={args.seed} emit={args.emit} "
        f"decode_errs={parser.bad_decodes}{kafka_failed}"
    )
    return stats


def _limited(stream, limit):
    if limit <= 0:
        return stream
    return _head(stream, limit)


def _head(stream, limit):
    for i, event in enumerate(stream):
        if i >= limit:
            return
        yield event


def _display_rate(rate):
    return rate if rate > 0 else "no-wait"


if __name__ == "__main__":
    run()
