# Context

This repository (Track4) hosts **Sentinel-DNS**, the solution for the **Ovnicom corporate challenge** at the **Decentralized AI Hackathon** (Tether, September 2026, Panama City). It also runs the quirk Skills workflow system: the canonical skills bundle is installed in `.agents/skills/` and pinned by `skills-lock.json`.

## The problem

Ovnicom operates a distributed DNS infrastructure. From a stream of DNS telemetry we must deliver, in real time:

1. **Threat detection** over the query stream — identify DGA, DNS tunneling, typosquatting, and periodic beaconing — while staying explainable.
2. **QoE per site** — a numeric, interpretable quality score per site / zone / PoP so the operator can spot degraded resolution before users complain.
3. **Wazuh integration** — every finding must land in Wazuh as a structured, processable alert for the SOC to act on.
4. **Fully local AI** — all inference runs on-device via **QVAC**, never on a cloud API.

The input is a BIND9-style dataset of synthetic corporate queries (`docs/data/LogsDNSQueries 2/LogsDNSQueries/queries.N`, excluded from git). Raw baseline (measured from the dataset): ~4.6 M queries, 36 files, A and HTTPS/TYPE65 dominate; p99 of the longest single label is 36 chars, max 63.

## What the rules require

| Rule | Implication |
|---|---|
| Inference must use **QVAC** (`qvac.tether.io`), on-device or P2P; cloud inference = instant disqualification | The LLM (QWEN3 1.7B) runs with QVAC locally, models precached, port `11434`, chat API compatible |
| Bases preexistentes must be declared in the README (Art. 11c); omission = disqualification | README lists QVAC and other origins; dataset is synthetic |
| Deliverables: **repo** accessible to jury + **video ≤ 5 min in Spanish**, before Sep 11, 08:00 (UTC−5) | Video narration stays in Spanish; all repo docs are in English |
| Evaluation: Technical 35%, Innovation 25%, Impact 20%, Design 10%, Completion 10% | The refined, decision-guided work plan below targets exactly those axes |

## What we built and decided (quirk Method)

### Architecture (already in the repo, docs updated to match)

```
BIND dataset ──► emulator (replay P5, attack episodes P4)
                  │  produces dns.telemetry.v1 (Kafka)
        ClickHouse (dns_events_raw P6) ──► Grafana dashboard (P16)
                  ▼
             agent/filter (5 deterministic signals P1+P1b)
         no signal            any escalation rule met
                  │              │  ──► QVAC (local, P2 verdict JSON)
        benign─────────────► alert: Wazuh via syslog/Localfile shim (P15)
                             rule IDs 100101–100106 mapped to severity (P3b)
```

### Decision ledger (session two of grilling; all confirmed)

| # | Decision |
|---|---|
| P1 | Workflow = 5 deterministic signals over a sliding window, per `client_ip` and per e2ld, configurable thresholds; only escalation-triggering queries reach QVAC |
| P1b | Signal 3 (length) is **composite**: single label > 40 chars **AND** entropy > 3.5 **AND** repetition in ≤ 60 s — avoids CDN false positives (measured: ~29.8 % of unique qnames occur once; long labels are mostly legitimate ntp/CDN/UUID) |
| P1‑escalation | Signals 1 (NXDOMAIN ≥ 0.6), 3, 5 (beaconing) escalate alone; signal 2 (entropy) escalates only together with 4 (rarity); signal 4 (**rarity**) never escalates alone — typosquatting is checked by **edit-distance against the client's vocabulary**, not rarity |
| P2 | QVAC verdict contract: strict one-shot JSON, no history; input = qname + signal evidence + context; output `{verdict, confidence, reasoning_short, recommended_action}`; malformed JSON → `unverified` alert (ADR-0002 degradation) |
| P2b | QoE weights fixed: latency 45 %, NXDOMAIN 35 %, saturation 20 %; labels ≥ 85 Excellent, 70–84 Good, 50–69 Fair, < 50 Poor; justification-guarded in `config/qoe.yaml` (resolves the loose ADR-0006) |
| P3 | Evaluation: unit = query, TP/FP/FN/TN matrix; precision/recall/F1 (macro and per class), filter elimination rate, p50/p95 latency (filter vs QVAC), split by zone_id/pop_id; `ground_truth` exists only in the emulator — the agent never reads it |
| P3b | Verdict → Wazuh severity mapping in `local_rules.xml`: dga ≥ 0.90 → 12, dga < 0.90 → 9, tunnel → 12, beaconing → 10, typosquat → 6, unverified → 5; benign emits no rule; decoder + rule propagate `sentinel.verdict`/`sentinel.confidence` into the event |
| P4 | Attack script: 5 escalating episodes (E1 DGA ~2000 queries / 5–8 IPs, E2 typosquat ~300, E3 tunnel ~1000/1 IP, E4+E5 beaconing ~60 s) over real-dataset background, fixed seed |
| P5 | Dual clock: emulator publishes with original dataset timestamps; `REPLAY_RATE` (default x20) compresses only wall time, never the logical timeline |
| P6 | Kafka: 1 topic `dns.telemetry.v1`, 3 partitions keyed by `client_ip`, ~1 h retention; ClickHouse: `dns_events_raw` (MergeTree by day, `ORDER BY (ts, client_ip)`) + `site_qoe_minute` (`ORDER BY (site, ts)`). Note: `client_port` and `resolver_ip` from ADR-0005 are excluded from the current schema per issue #11 scope. |
| P7 | Single `docker compose up`: qvac, kafka (KRaft), emulator, agent, wazuh, clickhouse, grafana + idempotent `provision`; `REPLAY_RATE` and seed via `.env`; full stack is always-on (no profile gate) |
| P11–P18 | Vocabulary Cliente / Zona de cliente / PoP / Sitio; 6 PoPs + 4 clientes + `zone_mapping.csv` + latency profiles; `ground_truth` style; model `QWEN3_1_7B_INST_Q4`; mono-repo `docs/ app/ deploy/ scripts/`; 5-min video script (see `docs/video-script.md`) |

### Empirical basis for the thresholds (measured from the real dataset, in `docs/design.md`)

- Longest single label: mean 10.5, p90 17, p95 21, p99 36, max 63 → threshold 40 + entropy + repetition is safe.
- Unique qnames once-only: 29.8 % → rarity alone is unusable (signal 4 rule above).
- Top e2ld repeaters: microsoft.com (10 179), google.com (8404), googleapis.com → whitelist-vocabulary candidates.
- QTYPE mix: A (84 k), TYPE65/HTTPS (29 k), AAAA (7 k), PTR (4.1 k) dominate → filter must not flag high-entropy label shapes seen in normal CDN/UUID traffic.

## Repo layout

```
docs/  design.md · domain.md · adr/0001-0006 · video-script.md · hackathon_rules/ · data/ (gitignored)
scripts/  probe-dataset.sh · baseline-query-dist.sh · baseline-qname-dist.sh
app/  (not yet created) — emulator · agent/filter · qvac adapter
deploy/  (not yet created) — docker-compose · kafka · clickhouse · grafana · wazuh local_rules.xml
```

## Validation

Run from the repository root:

```bash
node .agents/skills/platform/check-all.mjs
```

Note: this currently reports `warning` level pre-existing findings from the upstream bundle outside our scope (retired provenance terms, symlink parity); our work is greenfield.

## Vocabulary

| Term | Meaning |
|---|---|
| **QVAC** | The local AI inference runtime (Tether) running the precached QWEN3 1.7B model; the only place inference ever runs |
| **Sentinel-DNS agent** | The service that consumes `dns.telemetry.v1`, runs the deterministic filter, and escalates to QVAC |
| **Filter signal** | One of the 5 deterministic detectors (NXDOMAIN ratio, entropy, composite length, rarity, beaconing) |
| **QVAC verdict** | Strict one-shot JSON from the model: `{verdict, confidence, reasoning_short, recommended_action}` |
| **Escalation rule** | The AND/OR rule that decides when a signal earns a QVAC call (P1‑escalation) |
| **QoE score** | Weighted 0–100 per site/minute: latency 45 % + NXDOMAIN 35 % + saturation 20 % |
| **Site (QoE)** | Composite identifier `"{zone_id}-{pop_id}"` (e.g. `"Z1-POP3"`), used as the key in `site_qoe_minute` |
| **Dual clock** | Emulator writes original dataset timestamps; wall-time rate is decoupled via `REPLAY_RATE` |
| **Compatibility view** | The `.claude/skills/` symlink tree exposing canonical quirk skills |
| **Provenance** | Recorded origin/redesign status of a skill, name, or workflow (quirk) |