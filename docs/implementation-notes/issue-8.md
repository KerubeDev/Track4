# Issue #8 Implementation Note

## Changed

- Added `app.agent.filter.DeterministicFilter` with bounded 60-second client windows.
- Implemented configurable NXDOMAIN ratio, entropy, composite long-label repetition, e2ld rarity, and beacon interval-variance signals.
- Applied escalation rules so NXDOMAIN, composite long-label, and beaconing signals escalate alone; entropy requires rarity; rarity alone does not escalate.
- Typosquatting evidence uses edit distance against the client vocabulary.
- Replaced the agent's NXDOMAIN stub with the filter seam and included quantitative signal evidence in candidates.
- Added focused unit coverage in `tests/test_filter.py`.

## Verification

- `python3 -m pytest tests/test_filter.py tests/test_attacks.py` — 39 passed.
- Full-suite command: `python3 -m pytest` — run after this note is committed.

## Skipped

- Live Kafka/QVAC/Wazuh integration was not run because it requires the external compose services; the pure agent seam is covered with fabricated events.
