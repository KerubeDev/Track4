# ADR-0003: QVAC is a local HTTP inference boundary

Status: accepted  
Date: 2026-09-09  
Updated: 2026-09-11

## Context

DNS telemetry is sensitive and the inference path must remain inside operator-controlled infrastructure. QVAC can be exposed as a local OpenAI-compatible HTTP service, which gives the agent a narrow and testable inference boundary while keeping model lifecycle concerns outside the application process.

The developer workstation already has the model installed, so the preferred topology is QVAC on the host and the remaining services in Docker.

## Decision

QVAC is the only AI inference dependency. The default model is `QWEN3_1_7B_INST_Q4` and the default host endpoint is `http://localhost:11434`; the containerized agent reaches it through `http://host.docker.internal:11434`.

`QVACAdapter` accepts only plain `http://` endpoints that are loopback, link-local or private, plus known local Docker service names. Public addresses fail closed. The endpoint cannot contain URL credentials, query strings or fragments.

Each escalation is one-shot and stateless. DNS fields are explicitly treated as untrusted data. The response must satisfy the strict verdict contract; timeout, transport failure or malformed output becomes an `unverified` finding.

An optional `container-qvac` Compose profile is retained for deployments that have a preloaded local image/model bundle. It is not required for the host-runtime path.

## Consequences

- The application has no cloud-inference fallback.
- The privacy boundary can be tested independently of classification quality.
- A local HTTP hop adds small latency but isolates the runtime cleanly.
- Model download/cache preparation is an installation concern, not a runtime dependency.
- Operators can disable outbound network access after images, plugins and model artifacts are present and still exercise the inference path.

## Verification

Run the local service, then execute:

```bash
curl -fsS http://localhost:11434/ping
QVAC_LIVE_SMOKE=1 python3 -m pytest -q tests/test_qvac_adapter.py
```

A public `QVAC_URL` must be rejected before any inference request is sent.
