# Track4

Local DNS telemetry intelligence agent **Sentinel-DNS** (Ovnicom · Decentralized AI Hackathon), together with
the quirk Skills workflow bundle installed from `https://github.com/quantumquirkxyz/skills-quirk`.

## Sentinel-DNS

Real-time DNS threat detection and a per-site quality-of-experience (QoE) score, all local: QVAC produces the
deep verdict as an HTTP service on `localhost`, alerts reach Wazuh over remote syslog, and QoE is aggregated
in ClickHouse and displayed in Grafana.

- Design and decisions: [`docs/design.md`](docs/design.md)
- Domain vocabulary: [`docs/domain.md`](docs/domain.md)
- ADRs: [`docs/adr/`](docs/adr/)
- Demo video script: [`docs/video-script.md`](docs/video-script.md)

### Pre-existing bases declaration (Art. 11 of the rules)

In compliance with the Terms and Conditions, the following pre-existing bases were used, with their origin:

| Base | Origin | Use |
|---|---|---|
| quirk Skills bundle | `https://github.com/quantumquirkxyz/skills-quirk` (`main` @ `7c4877f`, `0.1.0`) | Repository workflow; not part of the Sentinel-DNS product |
| DNS log dataset (BIND9) | Ovnicom — official problem link (challenge SharePoint) | Input dataset for the emulator; read-only, not modified |
| QVAC SDK and model registry | Tether — `qvac.tether.io`, `docs.qvac.tether.io`, `github.com/tetherto/qvac` | Local AI engine (HTTP server) and model selection `QWEN3_1_7B_INST_Q4` |
| Third-party kits/accelerators (as integrated) | Public images of Kafka, ClickHouse, Grafana, Wazuh | Demo deployment (`docker compose`) |
| Public DGA / typosquatting domain lists | Public sources cited in the emulator | Attack-script generation to evaluate the detector |

The zone-to-PoP mapping tables and latency profiles are fictional data generated for the demo (four clients,
six PoPs), and the dnstap layer (rcode, latency, zone identity) is **synthesized by the emulator** because the
challenge dataset is a BIND9 log without those fields. Provenance is preserved for the jury through the event
`schema_version`, the attack-episode `ground_truth` marker, and the versioned mapping configuration (ADR-0005).
All reasoning and the substantial product were built within the competition window.

## Workflow quirk

This repository also runs the quirk Skills workflow bundle, installed from the canonical upstream: `https://github.com/quantumquirkxyz/skills-quirk`.

## Reproducible Demo Preparation

The challenge dataset is not redistributed in this repository. Obtain it from
the official Ovnicom challenge link, then prepare the local ignored directory:

```bash
DATASET_SOURCE=/path/to/official/LogsDNSQueries.zip ./scripts/prepare-dataset.sh
```

The demo requires a locally installed QVAC runtime image with the precached
`QWEN3_1_7B_INST_Q4` model. Set `QVAC_IMAGE` in `.env` to that image. The
compose file intentionally has no mock or cloud inference fallback.

Before recording or submitting, run:

```bash
python3 -m pytest -q
docker compose --env-file .env -f deploy/docker-compose.yml config
./scripts/verify-delivery.sh
```

The final acceptance check must be performed with the real local QVAC image:
the QVAC health endpoint must respond, an inference request must return the
strict verdict contract, and the run must continue with network egress
disabled. The repository deliberately does not substitute a heuristic mock for
that check.

Fast demo path with QVAC running on the host:

```bash
qvac serve --openai --no-default --config deploy/qvac/qvac.config.json \
  --model QWEN3_1_7B_INST_Q4 --port 11434
docker compose --env-file .env -f deploy/docker-compose.yml up -d \
  kafka clickhouse grafana wazuh kafka-init emulator agent
```

## Quick start

- Validate the bundle from the repository root:

  ```bash
  node .agents/skills/platform/check-all.mjs
  ```

  Expected result: `status: "pass"`.

- Read `docs/agents/adoption-guide.md` to finish the tracker and domain setup for this repository.
- Check `CONTEXT.md` for this repository's local vocabulary.
- Start work through the `ask-to` skill or the standard work-item flow.

## Install or sync

To reinstall or sync the bundle from upstream:

```bash
git clone https://github.com/quantumquirkxyz/skills-quirk.git /tmp/skills-quirk
bash /tmp/skills-quirk/scripts/install-quirk-skills.sh /path/to/track4
```

The installer copies `.agents/skills/`, `.claude/skills/`, `docs/agents/`, `CONTEXT.md`, and `skills-lock.json`.
