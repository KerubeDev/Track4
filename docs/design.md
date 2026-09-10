# Design — Sentinel-DNS

Local intelligence over DNS telemetry for Ovnicom's regulated clients. Real-time threat detection and
per-site QoE, with no query or inference leaving the client's datacenter.

## Reference decisions

- **Two-stage detection** (ADR-0002): fast, deterministic rules filter (math + counting with temporal memory:
  DGA, typosquatting, tunneling bursts, beaconing) → QVAC decides via LLM over the suspicious/ambiguous ones.
- **Filter signals** (ADR-0002): five deterministic detectors over a sliding window, per `client_ip` and per
  e2ld, with configurable thresholds; escalation rules decide what reaches QVAC (see below).
- **Local QVAC** (ADR-0003): OpenAI-compatible HTTP server on `localhost:11434`, model from the QVAC registry
  (`QWEN3_1_7B_INST_Q4`, ~1 GB), preloaded, 100% offline demo. Verdict contract: strict one-shot JSON
  `{verdict, confidence, reasoning_short, recommended_action}`; malformed output → `unverified` alert.
- **Read-only consumption** (ADR-0001): the agent never touches the production pipeline; in the demo, the
  emulator faithfully reproduces it.
- **Event schema** (ADR-0005): derived from the BIND9 log + synthesized dnstap layer (rcode, latency_ms,
  pop_id, zone_id). Versioned (`schema_version`).
- **Real Wazuh** (ADR-0004): JSON alert via remote syslog, local decoder/rules, severity by verdict mapping
  (`local_rules.xml`, IDs 100101–100106).
- **Per-site QoE** (ADR-0006): 0–100 score per minute, culprit breakdown, human labels; weights and thresholds
  fixed (45/35/20; 85/70/50) and justification-guarded in `config/qoe.yaml`.

## Filter signals and escalation

| Id | Signal | Escalates alone? | Rule |
|---|---|---|---|
| 1 | NXDOMAIN ratio | Yes | ratio ≥ 0.6 in the window |
| 2 | Entropy (Shannon) | No | entropy ≥ 3.5 **and** rarity (signal 4) |
| 3 | Length | Yes | **composite**: single label > 40 chars **and** entropy > 3.5 **and** repeated in ≤ 60 s |
| 4 | Rarity | Never | e2ld below count `N` in the client's window; reinforces signal 2; typosquatting = edit-distance against the client's vocabulary, not rarity |
| 5 | Beaconing | Yes | periodicity confirmed in the window (inter-arrival variance / autocorrelation) |

Empirical basis (measured on the real dataset, `scripts/baseline-qname-dist.sh`): longest single label
mean 10.5, p90 17, p95 21, p99 36, max 63; 29.8 % of unique qnames appear once (rarity alone unusable);
top e2ld repeaters are microsoft.com/google.com/googleapis.com; QTYPE mix dominated by A + HTTPS/TYPE65.

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

Evaluation protocol (confirmed): unit = query; TP/FP/FN/TN matrix; precision, recall, and F1 (macro and per
class); filter elimination rate; p50/p95 latency (filter vs QVAC); splits by `zone_id`/`pop_id`.
`ground_truth` exists only inside the emulator — the agent never reads it.

Attack script (confirmed): 5 escalating episodes (E1 DGA ~2000 queries / 5–8 IPs, E2 typosquat ~300,
E3 tunnel ~1000 / 1 IP, E4+E5 beaconing ~60 s) interleaved with the real-dataset background, fixed seed.

Dual clock (confirmed): the emulator publishes with the original dataset timestamps; `REPLAY_RATE`
(default x20) compresses wall time only, never the logical timeline seen by the detectors.

## Deliverables

- Code and deployment (structure `app/` + `deploy/`).
- Clean dataset: small sample in repo + download script for the original source.
- README with the pre-existing bases declaration (mandated by the rules).
- Video ≤5 min in Spanish (`docs/video-script.md`).