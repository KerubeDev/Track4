# Quality-of-experience score (QoE) per site: composite 0–100 and interpretable

Status: accepted
Date: 2026-09-09

## Context

The challenge asks for a service experience score per site that an operator can read without being an analyst.
Raw metrics (latency, NXDOMAIN, saturation) are hard to compare across clients and do not aggregate into a
single judgment. An unexplained score breeds distrust and cannot be audited.

## Decision

QoE is a 0–100 value aggregated per minute and per site (client zone × PoP), composed of a weighted sum of
components normalized to 0–100: resolution latency, NXDOMAIN rate, and traffic saturation. It also publishes
the culprit breakdown (how many points each component subtracts) and a derived human label
(Excellent | Good | Fair | Poor). The aggregate lives in ClickHouse (per-minute table) and is visualized in Grafana.

## Consequences

- Positive: score comparable across sites and stable over time; auditable because the breakdown shows what subtracts points from each site; readable by operations.
- Negative: per-minute aggregation hides short spikes (accepted by design for stability); the component weights must be calibrated and documented.
- Follow-up: set weights and label thresholds in configuration, and validate them against the attack script in the evaluation.