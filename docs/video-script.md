# SHIELD — 5-minute product walkthrough

## 0:00–0:35 — Problem

DNS telemetry is operationally valuable but sensitive. It can expose user and company behavior, so sending raw queries or derived evidence to a public AI API is unacceptable in regulated environments.

SHIELD adds intelligence to the existing DNS stream without changing the capture pipeline and keeps model inference on the operator-controlled machine.

## 0:35–1:15 — Architecture

Show the README architecture diagram.

The emulator/normalizer publishes `dns.telemetry.v1` to Kafka. SHIELD consumes that topic as an additional consumer. Every event is persisted to ClickHouse and contributes to the per-site QoE aggregate. Suspicious candidates pass through a deterministic evidence stage and only then reach QVAC. Findings are sent to Wazuh; Grafana reads operational QoE from ClickHouse.

Emphasize that QVAC is running locally on the host and that there is no cloud-inference fallback.

## 1:15–2:15 — Explainable security detection

Show agent logs while replay traffic is running.

Explain the five deterministic signals: NXDOMAIN ratio, entropy, long/high-entropy repetition, domain rarity/typosquat proximity and periodic beaconing. The filter reduces the volume that reaches the model and preserves the exact evidence responsible for each escalation.

Open one finding and show the strict QVAC result: verdict, confidence, short reasoning and recommended action. Then show the corresponding structured Wazuh event/rule match.

## 2:15–3:10 — Local inference boundary

Show the QVAC process listening on `localhost:11434` and the configured `QVAC_URL` used by the containerized agent.

Explain that the adapter rejects public inference endpoints. If the local model is unavailable or returns malformed output, SHIELD emits `unverified`; it never silently treats an inference failure as benign.

## 3:10–4:10 — DNS QoE

Open Grafana. Show the site score, latency, NXDOMAIN contribution and saturation component. Explain the 45/35/20 weighted model and the Excellent/Good/Fair/Poor labels.

Clarify that the reference BIND corpus contains queries but not response latency/rcode, so those response-side fields and topology are synthesized in the replay environment. In a real dnstap deployment the same normalized contract is populated from observed response telemetry.

## 4:10–4:45 — Reproducibility and evaluation

Show the deterministic replay seed and the evaluation command. Mention precision/recall/F1, filter elimination rate and latency percentiles. Point out that `ground_truth` belongs only to the emulator/evaluation path and is never read by the production detector.

## 4:45–5:00 — Close

SHIELD turns an existing DNS stream into two local operational outputs: actionable security intelligence in Wazuh and interpretable site-level DNS quality in Grafana, while keeping inference and telemetry under operator control.
