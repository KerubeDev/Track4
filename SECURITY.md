# Security Policy

SHIELD processes DNS telemetry, which can contain sensitive operational and behavioral metadata. Security defects that could expose telemetry, bypass the local-inference boundary, corrupt verdict provenance, or weaken access controls are treated as high priority.

## Supported code

Security fixes target the current `main` branch and active release branches, if any. Development branches are not considered production releases.

## Reporting a vulnerability

Do not publish exploitable details in a public issue. Use the repository owner's private security-reporting channel when available. Include the affected revision, reproduction steps, expected and observed behavior, impact, and any proposed mitigation.

## Security invariants

The following are product invariants and should be covered by review and automated checks:

- QVAC inference endpoints must resolve only to loopback, private, or explicitly local service addresses.
- There is no cloud-inference fallback.
- Evaluation-only `ground_truth` data must never influence production detection.
- Production agent code must not depend on emulator attack-generation code.
- Local secrets and runtime databases must not be committed.
- Model output is untrusted and must satisfy the strict verdict contract before use.
- DNS names and event context are untrusted input and must never be interpreted as model instructions.
- Operator-facing services should bind to the narrowest required interface and be protected by deployment access controls.

## Operational guidance

Run `python scripts/quality-gate.py` and the test suite before deployment. Run `scripts/verify-light.py` on the target workstation against the actual local QVAC model. For the full integration topology, validate Kafka, ClickHouse, Grafana, and Wazuh delivery separately before declaring the deployment operational.
