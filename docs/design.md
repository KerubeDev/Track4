# Design — Sentinel-DNS

Local intelligence over DNS telemetry for Ovnicom's regulated clients. Real-time threat detection and
per-site QoE, with no query or inference leaving the client's datacenter.

## Reference decisions

- **Two-stage detection** (ADR-0002): fast, deterministic rules filter (math + counting with temporal memory:
  DGA, typosquatting, tunneling bursts, beaconing) → QVAC decides via LLM over the suspicious/ambiguous ones.
- **Local QVAC** (ADR-0003): OpenAI-compatible HTTP server on `localhost:11434`, model from the QVAC registry
  (`QWEN3_1_7B_INST_Q4`, ~1 GB), preloaded, 100% offline demo.
- **Read-only consumption** (ADR-0001): the agent never touches the production pipeline; in the demo, the
  emulator faithfully reproduces it.
- **Event schema** (ADR-0005): derived from the BIND9 log + synthesized dnstap layer (rcode, latency_ms,
  pop_id, zone_id). Versioned (`schema_version`).
- **Real Wazuh** (ADR-0004): JSON alert via remote syslog, local decoder/rules, severity by verdict.
- **Per-site QoE** (ADR-0006): 0–100 score per minute, culprit breakdown, human labels.

## Flow

```
BIND9 logs (dataset) ─┐
Attack script ────────┤
zone_mapping ─────────┘
        │  EMULATOR
        ▼
  JSON events (Kafka)
        │
        ▼
  │ Sentinel-DNS AGENT │
  │  rules filter → QVAC (verdict) │
        ├───── JSON alerts ──► Wazuh (remote syslog) ──► dashboard / incidents
        └───── events (raw + verdict) ──► ClickHouse
                                                     │
                                                     ▼
                                            Per-minute/site QoE aggregate ──► Grafana
```

## Components

| Component | Responsibility |
|---|---|
| **Emulator** | Replays the BIND9 dataset, injects the reproducible attack script (DGA, typosquat, tunnel, beaconing), adds the synthesized dnstap layer with `zone_id`/`pop_id`/`latency_ms` and `ground_truth` labels, and publishes to Kafka. |
| **Agent** | Consumes from Kafka, filters with fast rules, escalates suspicious domains to QVAC, emits verdict + confidence + evidence, publishes the alert to Wazuh and the event to ClickHouse. |
| **QVAC** | Local HTTP service that produces the deep verdict. No network egress. |
| **Wazuh** | SIEM: syslog ingestion, JSON decoder, local rules, severity by verdict, dashboard visibility. |
| **ClickHouse** | Storage: raw events + per-minute/site QoE aggregates. |
| **Grafana** | Dashboard: score per site, p50/p95 latency, NXDOMAIN, saturation, culprits. |

## Fictional geography (demo)

- 6 PoPs: `PAN-PAC-01`, `PAN-ATL-01`, `COL-BOG-01`, `COL-MED-01`, `GUA-GUA-01`, `SAL-SAL-01`.
- 4 clients: `BANCO-PA`, `BANCO-COL`, `GOB-PA`, `HOSP-PA`.
- Site = PoP × client zone (pair). The emulator assigns `zone_id`/`pop_id` by IP ranges
  (`zone_mapping.csv`) and models latency per zone profile.
- Full vocabulary: `docs/domain.md`.

## Evaluation

The injected dataset carries `ground_truth` to measure precision/recall of the full pipeline (filter + QVAC,
ADR-0002), and the attack script stress-tests the QoE (ADR-0006). Evaluation artifacts run with the repo alone.

## Deliverables

- Code and deployment (structure `app/` + `deploy/`).
- Clean dataset: small sample in repo + download script for the original source.
- README with the pre-existing bases declaration (mandated by the rules).
- Video ≤5 min in Spanish (`docs/video-script.md`).