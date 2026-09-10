# Issue #10 Implementation Note

## Changes

- Added `app/eval/harness.py` — the S1-T6 evaluation harness:
  - Unit = query; reads `ground_truth` from the recorded emulator run (JSON-lines of `TelemetryEvent` dicts) and scores it against the chain's verdicts.
  - Computes a multiclass confusion matrix (benign, dga, tunnel, beaconing, typosquat, unverified) and TP/FP/FN/TN per class.
  - Reports precision / recall / F1 per class plus macro averages over the four attack classes (and an all-class macro), and overall accuracy.
  - Reports filter **elimination rate**: share of queries (and specifically ground-truth-benign queries) that never reached QVAC — the `>= 80 % benign never costs a QVAC call` criterion.
  - Reports p50/p95 (nearest-rank) latency for the filter path (deterministic-filter wall time per query) and the QVAC path (filter + verdict latency for escalated queries).
  - Splits results by `zone_id` / `pop_id`.
- `app/eval/harness.evaluate(...)` is the seam: pluggable `DeterministicFilter`, QVAC source, and injected `clock` for deterministic latency measurement in tests.
- `app/eval/qvac.py` — deterministic `MockQVAC` keyed on filter signal evidence (mirrors the demo QVAC stub's verdict families), plus `AdapterQVAC` for live runs against the local QVAC service via `QVACAdapter`.
- `app/eval/__main__.py` — CLI (`python -m app.eval --run run.jsonl [--qvac mock|adapter] [--out report.json]`) emitting a single JSON report plus a human-readable summary.
- Ground-truth isolation is structural: `agent_view()` strips `ground_truth` before anything reaches the filter or QVAC; the scoring side keeps a separate label copy (`ground_truth_label`). Tested with spy filter/QVAC asserting the field never appears.
- Added `tests/test_eval_harness.py`:
  - Golden fixture (16 queries, deterministic per-client filter windows) with a hand-calculated matrix — asserts TP/FP/FN/TN, per-class precision/recall/F1, macro, accuracy, elimination, and p50/p95 latency match hand calculation.
  - Nearest-rank `percentile` unit checks.
  - Ground-truth isolation tests.
  - Cluster-splitting by zone/pop and JSON report serialization.
  - CLI end-to-end test writing/reading a JSON report.

## Verification

- `python3 -m pytest tests/test_eval_harness.py -q` → 11 passed.
- Regression seams: `pytest -q tests/test_filter.py tests/test_qvac_adapter.py tests/test_attacks.py` → 47 passed, 1 skipped.
- Full suite at completion: `pytest -q tests/` → 196 passed, 1 skipped, 3 failed, 1 collection error.
  - The 3 failures (`test_hour_replay.py` x2, `test_playback.py::test_find_dataset_files_natural_sort`) and the `test_wazuh.py` collection error are pre-existing on this Windows-host view of the WSL filesystem (CRLF line endings, backslash path separators, Unix-only `syslog` import) and are unrelated to this change; they pass in the WSL/Linux environment per prior validation records.
- End-to-end sanity on the real emulator (`--attack --seed 42` over `tests/fixtures`): harness scored 3366 queries; DGA recall 83.1 % / precision 88.8 %; benign elimination rate 66.7 % (only 6 benign fixtures exist in that tiny window). This fixture is not representative enough to verify the issue's `>= 80 %` benign-elimination acceptance threshold, so that end-to-end acceptance criterion remains **pending**. Tunnel/beaconing/typosquat episodes compress into a ~2 s replay window where the corresponding thresholded signals (repetition, >= 5 s intervals, entropy >= 3.5) cannot fire; the harness surfaces this as low recall, which is expected for this fixture scale.
