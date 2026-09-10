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

## Consequences

- Positive: high throughput because AI only sees the short queue of suspicious domains; interpretable verdict (model reasoning); bounded local compute latency.
- Negative: if QVAC is unavailable, suspicious domains go without a final verdict (controlled degradation); the filter must be calibrated so it does not drown QVAC in traffic.
- Follow-up: measure precision/recall with the attack-script ground truth in the evaluation, including the filter's elimination rate (P13).