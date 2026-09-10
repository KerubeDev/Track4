# Issue #9 Implementation Note

## Changes

- Added `app.agent.qvac_adapter.QVACAdapter` for local OpenAI-compatible QVAC chat calls.
- Enforced the one-shot JSON verdict contract and model `QWEN3_1_7B_INST_Q4`.
- Added bounded retries, timeout propagation, latency measurement, and `unverified` degradation.
- Integrated verdict, evidence, and QVAC latency into agent alert output.

## Verification

- `pytest -q tests/test_qvac_adapter.py`
- Full `pytest -q` run at completion.
- Added opt-in live smoke test (`QVAC_LIVE_SMOKE=1`): known DGA qname with confidence >= 0.7 and benign vocabulary qname; skips when not enabled or when no local QVAC service is reachable.
- Added explicit no-egress assertion: verifies the injected fake transport never calls the real HTTP transport.
- Live QVAC smoke was not run because no local QVAC service/model is available in this environment; the skipped-validation note is retained.
