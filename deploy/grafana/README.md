# Grafana Dashboard — Sentinel-DNS QoE

Issue #13 (S2-T3) — auto-provisioned Grafana dashboard for QoE monitoring.

## Quick Start

```bash
# Start ClickHouse + Grafana
docker compose up -d clickhouse grafana

# Apply schema + seed fixtures (if not already done)
docker compose run --rm provision
docker compose run --rm seed-fixtures --profile dev

# Open Grafana
open http://localhost:3000   # admin / sentinel
```

The dashboard is auto-provisioned under **Dashboards → Sentinel-DNS → Sentinel-DNS — QoE Dashboard**.

## Dashboard Panels

| # | Panel | Type | Description |
|---|---|---|---|
| P1 | **QoE Per Site** | Time series | Composite 0–100 score per site with label banding thresholds (Excellent ≥ 85, Good 70–84, Fair 50–69, Poor < 50). |
| P2 | **p50 / p95 Latency** | Time series | Resolution latency percentiles from `dns_events_raw`. p50 (dashed blue) and p95 (solid red). |
| P3 | **NXDOMAIN Rate** | Time series | Fraction of NXDOMAIN responses per site (0.0–1.0). Thresholds at 0.3 (yellow) and 0.6 (red, matches signal 1 escalation). |
| P4 | **Saturation (QPS)** | Time series | Queries per second per site from `site_qoe_minute`. Spikes above baseline indicate load pressure. |
| P5 | **Culprit Breakdown** | Time series | Three weighted component lines: Latency (45%, blue), NXDOMAIN (35%, orange), Saturation (20%, purple). The lowest bar dominates degradation. |

## Selectors

Two template variables at the top of the dashboard allow drill-down:

- **Zone** — filters by `zone_id` (BANCO-PA, BANCO-COL, GOB-PA, HOSP-PA). "All" shows all zones.
- **PoP** — filters by `pop_id` (PAN-PAC-01, PAN-ATL-01, COL-BOG-01, etc.). Cascades: selecting a zone narrows the PoP list. "All" shows all PoPs.

Both selectors cascade from `site_qoe_minute` and `dns_events_raw` data.

## Files

```
deploy/grafana/
├── provisioning/
│   ├── datasources/
│   │   └── clickhouse.yml        # ClickHouse datasource (auto-provisioned)
│   └── dashboards/
│       └── dashboards.yml         # Dashboard provider (reads JSON files)
├── dashboards/
│   └── sentinel-dns.json          # Dashboard with 5 panels
└── README.md                      # This file
```

## Data Sources

- **`site_qoe_minute`** — per-minute QoE aggregates (score, label, components, QPS, NXDOMAIN rate). Used by panels P1, P3, P4, P5.
- **`dns_events_raw`** — raw DNS events. Used by panel P2 (latency percentiles).

## Credentials

Default admin credentials are `admin` / `sentinel` (set in `docker-compose.yml`). These are demo-only defaults for the hackathon. For production, override via environment variables or a `docker-compose.override.yml` file.

## Datasource

The ClickHouse datasource is provisioned automatically via `provisioning/datasources/clickhouse.yml`:
- Plugin: `grafana-clickhouse-datasource` (installed via `GF_INSTALL_PLUGINS` env var)
- Host: `clickhouse:8123` (HTTP interface)
- Database: `sentinel_dns`
- UID: `sentinel-clickhouse`

## During E1–E5 Replay

During attack replay, at least one site visibly degrades to Fair or Poor. The culprit panel (P5) shows which component dominates:
- **E1 (DGA):** NXDOMAIN component drops (high NXDOMAIN rate → low nxdomain_component)
- **E2 (Typosquat):** Latency component may drop (elevated p95 latency)
- **E3 (Tunnel):** Latency component drops (high resolution latency for tunnel queries)
- **E4/E5 (Beaconing):** Saturation component may drop (elevated QPS from beacon traffic)
