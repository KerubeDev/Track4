#!/usr/bin/env python3
"""Create a deterministic, ordered presentation sample from the raw dataset."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

# Allow direct execution from the repository root without installing the app.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.emulator.parser import ParserStats, iter_file


def _files(root: Path) -> list[Path]:
    return sorted(root.glob("queries.*"), key=lambda path: int(path.name.rsplit(".", 1)[1]))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def curate(source: Path, output: Path, sample_size: int, seed: int) -> dict:
    files = _files(source)
    if not files:
        raise ValueError(f"no queries.N files found in {source}")

    rng = random.Random(seed)
    sample = []
    total = 0
    stats = ParserStats()
    qtypes = Counter()
    clients = Counter()
    for path in files:
        for record in iter_file(str(path), source_file=path.name, stats=stats):
            total += 1
            qtypes[record.qtype] += 1
            clients[record.client_ip] += 1
            item = {
                "timestamp": record.timestamp.isoformat(timespec="milliseconds"),
                "client_ip": record.client_ip,
                "client_port": record.client_port,
                "qname": record.qname,
                "qtype": record.qtype,
                "resolver_ip": record.resolver_ip,
                "source_file": record.source_file,
            }
            if len(sample) < sample_size:
                sample.append(item)
            else:
                index = rng.randrange(total)
                if index < sample_size:
                    sample[index] = item

    sample.sort(key=lambda item: (item["timestamp"], item["source_file"], item["qname"]))
    output.mkdir(parents=True, exist_ok=True)
    data_path = output / "benign-sample.jsonl"
    with data_path.open("w", encoding="utf-8") as handle:
        for item in sample:
            handle.write(json.dumps(item, separators=(",", ":")) + "\n")

    manifest = {
        "schema": "sentinel-dns.curated-dataset.v1",
        "source": str(source),
        "files": [{"name": path.name, "sha256": _sha256(path)} for path in files],
        "records_total": total,
        "sample_records": len(sample),
        "sample_method": "reservoir-sampling",
        "seed": seed,
        "ordered_by": ["timestamp", "source_file", "qname"],
        "timestamp_start": sample[0]["timestamp"] if sample else None,
        "timestamp_end": sample[-1]["timestamp"] if sample else None,
        "parse_decode_errors": stats.decode_errors,
        "qtype_counts": dict(qtypes),
        "unique_clients": len(clients),
        "sample_sha256": _sha256(data_path),
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="raw directory containing queries.N files")
    parser.add_argument("output", type=Path, help="directory for the curated artifacts")
    parser.add_argument("--sample-size", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if args.sample_size < 1:
        parser.error("--sample-size must be positive")
    manifest = curate(args.source, args.output, args.sample_size, args.seed)
    print(json.dumps({key: manifest[key] for key in ("records_total", "sample_records", "timestamp_start", "timestamp_end")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
