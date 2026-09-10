# QVAC runs as a local HTTP service (OpenAI-compatible endpoint) with a preloaded model

Status: accepted
Date: 2026-09-09

## Context

The challenge forbids inference or data leaving the client's infrastructure. QVAC supports two modes:
an SDK embedded in-process or an HTTP server. The QVAC model registry is the authorized source of model
weights (distribution, not inference). The client's datacenter must not depend on external downloads or calls
in operation, and the demo must be able to prove the privacy guarantee.

## Decision

QVAC is deployed as a local OpenAI-compatible HTTP server (localhost:11434) and is the agent's only AI entry
point. The model is selected from the QVAC registry (base: `QWEN3_1_7B_INST_Q4`, ~1 GB) and preloaded
(downloaded and cached) before operation, so inference and the demo run without network egress.

## Consequences

- Positive: the local HTTP API isolates the AI engine from the agent code; the absence of network in operation is verifiable (demo with network cut); a model downloaded from the distributed registry exactly as specified does not require calls at runtime.
- Negative: latency of one extra HTTP hop (acceptable: it is localhost); first boot requires a model download (mitigated by preloading).
- Follow-up: verify that model precaching requires no credentials or external network in the final demo.