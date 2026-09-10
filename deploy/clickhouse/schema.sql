-- =============================================================================
-- ClickHouse schema: dns_events_raw + site_qoe_minute
-- Issue #11 (S2-T1) — Sentinel-DNS Track4
-- Idempotent: all CREATE TABLE statements use IF NOT EXISTS.
-- =============================================================================

-- ---------------------------------------------------------------------------
-- dns_events_raw
-- Raw DNS telemetry event, one row per query.
-- Partitioned by day for efficient retention and time-range scans.
-- ORDER BY (ts, client_ip) matches P6 and the canonical query pattern:
--   "give me all events in a 1-minute window for a site (zone_id + pop_id)."
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dns_events_raw
(
    -- Time of the query (dual-clock: original dataset timestamp, not wall time).
    ts              DateTime64(3),

    -- Client IP address (IPv4 string).
    client_ip       String,

    -- Fully-qualified query name (e.g. "www.example.com.").
    qname           String,

    -- DNS query type (A, AAAA, TYPE65, PTR, MX, etc.).
    qtype           LowCardinality(String),

    -- DNS response code (NOERROR, NXDOMAIN, SERVFAIL, REFUSED, etc.).
    rcode           LowCardinality(String),

    -- Resolution latency in milliseconds (synthesized dnstap layer).
    latency_ms      Float32,

    -- Ovnicom zone identifier (synthesized dnstap layer).
    zone_id         LowCardinality(String),

    -- Ovnicom Point-of-Presence identifier (synthesized dnstap layer).
    pop_id          LowCardinality(String),

    -- Schema version for forward/backward compatibility tracking.
    schema_version  UInt16 DEFAULT 1,

    -- QVAC verdict: benign | dga | tunnel | beaconing | typosquat | unverified.
    -- NULL if the query was filtered (did not reach QVAC).
    verdict         LowCardinality(Nullable(String)),

    -- QVAC confidence score (0.0–1.0). NULL if verdict is NULL.
    confidence      Nullable(Float32),

    -- Which deterministic signal(s) triggered escalation (JSON array string).
    -- NULL if no signal triggered escalation.
    signal          Nullable(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (ts, client_ip)
SETTINGS index_granularity = 8192;


-- ---------------------------------------------------------------------------
-- site_qoe_minute
-- Per-minute, per-site QoE aggregate.
-- site = zone_id × pop_id (concatenated, e.g. "Z1-POP3").
-- ORDER BY (site, ts) matches the Grafana dashboard query pattern.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS site_qoe_minute
(
    -- Site identifier: "{zone_id}-{pop_id}".
    site                    String,

    -- Start of the aggregation minute (truncated to minute boundary).
    ts                      DateTime,

    -- Composite QoE score (0–100, higher = better).
    score                   UInt8,

    -- Human-readable label derived from score.
    -- Excellent (≥85) | Good (70–84) | Fair (50–69) | Poor (<50).
    label                   LowCardinality(String),

    -- Latency component (0–100, higher = better). Weight: 45%.
    latency_component       UInt8,

    -- NXDOMAIN component (0–100, higher = better). Weight: 35%.
    nxdomain_component      UInt8,

    -- Saturation component (0–100, higher = better). Weight: 20%.
    saturation_component    UInt8,

    -- Queries per second during this minute window.
    qps                     Float32,

    -- Total query count in this minute window.
    query_count             UInt32,

    -- Number of distinct client IPs observed in this minute window.
    distinct_clients        UInt32,

    -- Fraction of NXDOMAIN responses in this minute window (0.0–1.0).
    nxdomain_rate           Float32,

    -- p95 latency in milliseconds for this minute window.
    p95_latency_ms          Float32
)
ENGINE = MergeTree
PARTITION BY toYYYYMMDD(ts)
ORDER BY (site, ts)
SETTINGS index_granularity = 8192;
