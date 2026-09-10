# Telemetry schema derived from the BIND9 log with a synthesized dnstap layer in the demo

Status: accepted
Date: 2026-09-09

## Context

The challenge's public dataset is BIND9 query logs (IPv4 A-type). It does not include rcode, resolution
latency, or Ovnicom's zone/PoP identity — fields that classification and QoE need. In production those fields
come from dnstap and Ovnicom's routing; they are not available in the dataset. Also, the real pipeline must not
be modified (ADR-0001).

## Decision

The normalized telemetry event is defined from the BIND9 log schema (timestamp, client_ip, client_port,
qname, qtype, resolver_ip) plus a dnstap layer synthesized by the emulator for the demo: rcode, latency_ms,
`pop_id`, and `zone_id` (derived by the emulator using a client IP-range mapping and each zone's latency
profile). The schema is versioned (`schema_version`).

## Consequences

- Positive: agents and aggregators consume a single contract without depending on the raw dataset; QoE and classification can be measured even though the dataset has no dnstap; the emulator is swappable for future production without touching the agent.
- Negative: the demo's dnstap layer is fictitious — the jury must see which fields are real and which are synthesized (provenance); if the provider changes the log format, the emulator must be updated.
- Follow-up: document in the README and the video that the dnstap layer is synthesized for evaluation purposes, and expose the zone-to-latency mapping as configuration.