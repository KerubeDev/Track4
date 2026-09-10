# Sentinel-DNS is a read-only consumer of the DNS telemetry bus

Status: accepted
Date: 2026-09-09

## Context

Ovnicom's production pipeline generates the telemetry event (DNS resolution + dnstap) and already notifies
other consumers. The challenge requires "local intelligence over DNS telemetry" without assuming the ability
to modify that production pipeline. Modifying it would be costly to reverse, break other consumers, and risk
the client's service.

## Decision

Sentinel-DNS is an additional, read-only consumer of the telemetry event bus. It does not alter the production
pipeline. In the demo, the emulation stage builds the same event stream (BIND log + synthesized dnstap layer)
to faithfully reproduce that behavior without touching anything in production.

## Consequences

- Positive: the contract with the production pipeline stays intact; the agent is deployable without coordination with other teams; the demo is a 1:1 representation of production consumption.
- Negative: it depends on the format and content of the event emitted by the bus (we don't control what comes in); the normalization layer must tolerate missing fields in future drift.
- Follow-up: validate the event schema against a real dnstap fixture when integrating the demo with data in another format.