# SHIELD Engineering Context

SHIELD is a local-first DNS telemetry intelligence system for distributed infrastructure. It is designed for environments where DNS queries and derived telemetry must remain inside the operator-controlled network.

## Product requirements

The system must provide four outcomes from the same DNS telemetry stream:

1. **Threat detection** — identify DGA, DNS tunneling, typosquatting and periodic beaconing with evidence that an operator can inspect.
2. **Per-site QoE** — produce a numeric and interpretable DNS quality score per zone / PoP / site.
3. **SIEM integration** — deliver structured findings to Wazuh so the SOC can process them as normal alerts.
4. **Local AI** — all model inference runs through QVAC on the local machine or private network. There is no cloud-inference fallback.

The reference input is a BIND9-style DNS query corpus under `docs/data/LogsDNSQueries/` (ignored by Git). The source query log does not contain response-side dnstap fields, so the replay environment synthesizes `rcode`, latency and topology identity in a versioned, explicitly documented layer. Synthetic attack episodes carry `ground_truth` for evaluation only; production agent code must never use it.

## Architecture

```text
DNS corpus / dnstap
        |
        v
emulator + normalization
        |
        v
dns.telemetry.v1 (Kafka, keyed by client_ip)
        |
        +-----------------------> ClickHouse raw telemetry
        |
        v
SHIELD deterministic filter
        |
        +-- no escalation ------> QoE aggregation / persistence
        |
        +-- candidate ----------> QVAC local inference
                                      |
                                      v
                              strict verdict contract
                                      |
                                      v
                              Wazuh structured alert
```

Grafana reads ClickHouse for operational visualization. Wazuh is the security operations sink. QVAC is an inference dependency, not a general-purpose network service.

## Detection decisions

The deterministic stage maintains bounded per-client windows and computes five explainable signals: NXDOMAIN ratio, label entropy, long/high-entropy repetition, domain rarity/typosquat proximity and beacon periodicity. NXDOMAIN ratio requires a minimum sample count so an isolated failed lookup cannot trigger an immediate escalation.

Escalation policy:

- NXDOMAIN ratio, long/high-entropy repetition and beaconing can escalate independently.
- Entropy escalates only when combined with rarity/typosquat evidence.
- Rarity by itself never escalates.
- Typosquatting is evaluated against a versioned client-domain vocabulary.

The production filter depends only on `app/common/domain.py`; it must not import the attack generator or evaluation fixtures.

## QVAC contract and trust boundary

Default model: `QWEN3_1_7B_INST_Q4`.

Input is a one-shot JSON payload containing the qname, deterministic signal evidence and minimal context. Output must contain:

```json
{
  "verdict": "dga|tunnel|beaconing|typosquat|benign",
  "confidence": 0.0,
  "reasoning_short": "...",
  "recommended_action": "..."
}
```

Malformed output, timeout or local runtime failure degrades to `unverified`; it never becomes benign. `QVAC_URL` must resolve to loopback, link-local or private addressing. Public inference endpoints are rejected.

The recommended developer topology is QVAC on the host at `localhost:11434` and the Docker agent using `http://host.docker.internal:11434`.

## QoE

The score is a 0–100 minute aggregate per site:

- latency contribution: 45%
- DNS success / NXDOMAIN contribution: 35%
- saturation contribution: 20%

Labels: `Excellent >= 85`, `Good 70–84`, `Fair 50–69`, `Poor < 50`. The normalization constants and rationale live in `config/qoe.yaml` and ADR-0006.

## Data and evaluation

The reference corpus is replayed with its logical timestamps; `REPLAY_RATE` changes wall-clock speed only. Attack generation is deterministic for a fixed seed. Evaluation is query-level and reports precision, recall, F1, filter elimination rate and filter/QVAC latency. Results should also be segmented by zone and PoP when those fields are available.

Because response code, latency and topology are synthesized for the reference corpus, QoE results from the replay are simulation results, not claims about measured production network performance. A real dnstap source can populate the same normalized contract without changing downstream components.

## Repository layout

```text
app/       agent, common primitives, emulator, evaluation, QoE
deploy/    Docker Compose and service provisioning
config/    topology and scoring configuration
docs/      design, domain model, ADRs and operational notes
scripts/   data preparation, baselines and verification
tests/     deterministic unit and integration-contract tests
```

## External foundations

The repository records the origin of pre-existing components in the README. The engineering workflow bundle under `.agents/skills` is tooling, not runtime product code. Kafka, ClickHouse, Grafana and Wazuh are third-party infrastructure. QVAC is the local inference runtime. The DNS corpus is externally supplied and is not redistributed.

## Definition of operational

A target machine is operational only when all of the following are demonstrated together: local QVAC responds with the strict verdict contract; Kafka receives normalized telemetry; the agent consumes it; ClickHouse stores raw and QoE rows; Grafana reads the provisioned datasource/dashboard; and a triggered finding is decoded by Wazuh. Unit tests alone are not sufficient evidence of an operational deployment.
