# Domain — Sentinel-DNS

Sentinel-DNS is Ovnicom's local intelligence agent over DNS telemetry. It consumes the DNS query stream
from the event bus, detects malicious activity in real time, and computes a quality-of-experience score per
site. All inference runs inside the client's datacenter (local QVAC): no query or derived data leaves the
infrastructure.

## Language

### Service geography

**Client**
: The organization that contracts Ovnicom (banking, government, health). It owns the traffic.
_Use when_: referring to the contracting organization.
_Avoid_: account, end user, customer.

**Client zone**
: A network or network segment of a client that Ovnicom serves. It is the operational granularity of a client.
_Use when_: referring to the client's network segment where the service is measured.
_Avoid_: site, PoP, network.

**Point of presence (PoP)**
: The physical location (city / datacenter / edge) of Ovnicom's infrastructure where the resolver runs.
_Use when_: referring to the physical location of the service.
_Avoid_: zone, site, datacenter (when logical location is meant).

**Site**
: The combination PoP × client zone where real traffic is served. It is the unit where score and alerts are measured.
_Use when_: referring to the composite measurement unit (where a client is served).
_Avoid_: zone, PoP, client (separately).

### Telemetry

**DNS telemetry**
: The data stream that records DNS queries from the pipeline (BIND9 with dnstap), in real time.
_Use when_: referring to the input stream, not the analysis.
_Avoid_: BIND logs, queries, network events.

**Telemetry event**
: A normalized JSON message (by Vector) with one DNS query and its derived attributes (rcode, latency, zone, PoP).
_Use when_: referring to a query already normalized for the agent to consume.
_Avoid_: raw query, log line, query.

**Synthesized dnstap layer**
: In the demo, the fields that in production come from the dnstap response (rcode, latency) which the emulator
generates while replaying the query log, because the raw log does not contain them.
_Use when_: explaining why the emulator adds fields the log does not have.
_Avoid_: real dnstap, BIND response (in the demo context).

### Security

**DNS threat**
: Malicious behavior detected over the stream: DGA, typosquatting, DNS tunneling, or beaconing.
_Use when_: referring to the attack category, not the alert it produces.
_Avoid_: incident, alert, IOC.

**Verdict**
: The final decision on a suspicious domain, produced by the QVAC model (DGA / typosquat / tunnel / beaconing / benign).
_Use when_: referring to the QVAC stage output.
_Avoid_: score, label, rule label (a rule produces a signal; QVAC produces the verdict).

**Rule signal**
: An indicator computed by the rules filter (entropy, rarity, temporal pattern) that decides whether a domain is escalated to QVAC.
_Use when_: referring to the fast stage before QVAC.
_Avoid_: verdict, confidence score.

**Ground truth**
: A golden label in the injected dataset marking what is a real threat, used to measure detector performance.
_Use when_: evaluating agent behavior, not in production.
_Avoid_: label, domain label.

### Experience

**Quality-of-experience score (QoE)**
: A 0–100 value per site, aggregated per minute, summarizing resolution latency, NXDOMAIN rate, and saturation.
_Use when_: referring to the composite score an operator can read.
_Avoid_: latency, NXDOMAIN rate, metrics (those are components, not the score).

**Score component**
: Each metric normalized 0–100 (latency, NXDOMAIN, saturation) that feeds the composite score.
_Use when_: referring to a metric inside the score.
_Avoid_: score, KPI.

**Human score label**
: The `Excellent | Good | Fair | Poor` classification derived from the score for fast operator reading.
_Use when_: wanting the human-readable state.
_Avoid_: color, severity (severity goes with security).

### AI infrastructure

**QVAC**
: Tether's local AI platform. In Sentinel-DNS it runs as a local HTTP service (localhost:11434) and produces
the verdict. No inference leaves the machine.
_Use when_: referring to the AI engine.
_Avoid_: LLM, model, cloud API.

**QVAC model registry**
: The distributed model registry (where the model weights are downloaded from). Download is distribution, not inference.
_Use when_: referring to where the model is obtained.
_Avoid_: cloud AI provider.