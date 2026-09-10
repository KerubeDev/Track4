# Two-stage detection: fast rules + QVAC as the arbiter

Status: accepted
Date: 2026-09-09

## Context

The DNS flow is high-volume and inference must be local and explainable to an operator. A single neural
network pass per query would be slow and costly on local compute; rules alone would be easy to evade and would
produce false positives on legitimate names (CDNs, internal applications). Each option alone fails on either
throughput or accuracy.

## Decision

Two stages in the agent: (1) a fast, deterministic rules filter —math + counting with temporal memory for DGA,
typosquatting, tunneling bursts, and beaconing— that discards the majority of queries without AI; and (2) a
deep verdict by QVAC, a local LLM from the QVAC registry, deciding on the suspicious or ambiguous domains the
filter escalates. Only QVAC's output constitutes a final verdict.

The filter runs **five deterministic signals** over a sliding window, per `client_ip` and per e2ld, with
configurable thresholds:

| Id | Signal | Escalates alone? | Rule |
|---|---|---|---|
| 1 | NXDOMAIN ratio | Yes | ratio ≥ 0.6 in the window |
| 2 | Entropy (Shannon) | No | entropy ≥ 3.5 **and** rarity (signal 4) |
| 3 | Length (composite) | Yes | single label > 40 chars **and** entropy > 3.5 **and** repeated within ≤ 60 s (avoids CDN/UUID false positives) |
| 4 | Rarity | Never | e2ld count below `N` in the window for that client; reinforces signal 2 only; typosquatting is not rarity — it is edit-distance against the client's vocabulary |
| 5 | Beaconing | Yes | periodicity confirmed in the window (inter-arrival variance / autocorrelation) |

## Consequences

- Positive: high throughput because AI only sees the short queue of suspicious domains; interpretable verdict (model reasoning); bounded local compute latency.
- Negative: if QVAC is unavailable, suspicious domains go without a final verdict (controlled degradation — see ADR-0002 degradation and the `unverified` alert); the filter must be calibrated so it does not drown QVAC in traffic.
- Follow-up: measure precision/recall with the attack-script ground truth in the evaluation, including the filter's elimination rate (P4, P3).