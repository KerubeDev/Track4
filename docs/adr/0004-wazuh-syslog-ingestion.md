# Real Wazuh in the demo: remote syslog ingestion + custom JSON decoder

Status: accepted
Date: 2026-09-09

## Context

The challenge requires the agent to send security alerts to a SIEM processable by the client's security
operations center. A mock of log concatenation does not demonstrate integration; Wazuh is the option with an
existing track record at Ovnicom. But Wazuh does not accept "alerts from external agents" arbitrarily: the real
path is log ingestion via syslog or a monitored file with a decoder.

## Decision

The agent publishes each alert as a one-line JSON event. Real Wazuh ingests that flow via remote syslog
(`remote connection=syslog` config with `allowed-ips`) and a default Wazuh decoder plus a rule family turns it
into an incident shown in the dashboard. The incident severity is set according to the verdict
(DGA, typosquat, tunnel, beaconing) via an explicit mapping in `local_rules.xml`:

| Verdict | Confidence | Rule ID | Severity | Level |
|---|---|---|---|---|
| dga | ≥ 0.90 | 100101 | 12 (high) | Incident |
| dga | < 0.90 | 100102 | 9 (high) | Notable event |
| tunnel | — | 100103 | 12 (high) | Incident |
| beaconing | — | 100104 | 10 (high) | Incident |
| typosquat | — | 100105 | 6 (medium) | Suspected |
| unverified (QVAC malformed/unavailable) | — | 100106 | 5 (medium) | Review |
| benign | — | — | no rule emitted | — |

`dga` modulates with the model's `confidence` (bounded to 9–12; severity 15 is reserved for confirmed harm).
The decoder and the rule propagate `sentinel.verdict` and `sentinel.confidence` into the Wazuh event so the
incident panel shows the reasoning the SOC needs.

## Consequences

- Positive: alert legitimated as a Wazuh event (decoder, rule, dashboard) without a Wazuh agent installed on the client; a flow processable exactly as the SOC would see it.
- Negative: real Wazuh configuration adds weight to the demo (container + decoders/rules); syslog is text and forces one JSON per line, with no internal newlines.
- Follow-up: alert fixtures to test decoder/rule before the demo; verify severity by verdict in the dashboard (mapping confirmed: 100101–100106).