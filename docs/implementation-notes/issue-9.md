# Issue #9 Implementation Note

## Changes

- Added `app.agent.qvac_adapter.QVACAdapter` for local OpenAI-compatible QVAC chat calls.
- Enforced the one-shot JSON verdict contract and model `QWEN3_1_7B_INST_Q4`.
- Added bounded retries, timeout propagation, latency measurement, and `unverified` degradation.
- Integrated verdict, evidence, and QVAC latency into agent alert output.
- Enforced loopback-only egress: `_http_transport` refuses non-`localhost`/`127.0.0.1`/`::1` endpoints before any network call (ADR-0003 / issue #9 "no network egress").
- Wired `signal_evidence` through `VerdictInfo` into the Wazuh alert payload so S2 consumers receive the filter signals (issue #9 validation).

## Verification

- `pytest -q tests/test_qvac_adapter.py`
- Full `pytest -q` run at completion.
- Added opt-in live smoke test (`QVAC_LIVE_SMOKE=1`): known DGA qname with confidence >= 0.7, benign vocabulary qname, and full four-field contract (`reasoning_short`, `recommended_action` non-empty); skips when not enabled or when no local QVAC service is reachable.
- Added no-egress assertions at the stdlib level: injected fake transport never reaches `urllib.request.urlopen`, and a non-loopback endpoint is refused before any network call (`urlopen` never invoked).
- Live QVAC smoke was not run because no local QVAC service/model is available in this environment; the skipped-validation note is retained.
- `tests/test_wazuh.py` (which would validate the `signal_evidence` propagation into Wazuh alerts) cannot be collected on this Windows host (Unix-only `syslog` import); verified statically instead.
