# Dataset Curation

`LogsDNSQueries/` is the raw challenge dataset and must not be edited. The
curated presentation artifacts are generated from it and are intentionally not
committed because they are derived and potentially large.

Generate a deterministic, timestamp-ordered benign sample and its manifest:

```bash
python3 scripts/curate-dataset.py \
  docs/data/LogsDNSQueries \
  docs/data/curated \
  --sample-size 100000 \
  --seed 42
```

The command writes:

- `curated/benign-sample.jsonl`: normalized records ordered by timestamp;
- `curated/manifest.json`: source file hashes, counts, time range, parser
  errors, query-type distribution, sampling seed, and output hash.

The sample uses deterministic reservoir sampling, so it does not load the full
dataset into memory and can be reproduced from the same source files and seed.
Attack episodes are added separately by the emulator and are never mixed into
the raw or benign curated dataset.
