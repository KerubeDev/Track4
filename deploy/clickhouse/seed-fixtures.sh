#!/usr/bin/env bash
# =============================================================================
# seed-fixtures.sh — Insert fixture rows for validation
# Issue #11 (S2-T1) — Sentinel-DNS Track4
#
# Inserts test data into dns_events_raw and site_qoe_minute, then runs
# validation queries to confirm partitioning, ordering, and query patterns.
# =============================================================================

set -euo pipefail

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_URL="http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"

CH() {
    curl -sf "${CLICKHOUSE_URL}/" --data-binary "$1" -H "Content-Type: text/plain"
}

echo "=== Seeding dns_events_raw ==="

CH "
INSERT INTO dns_events_raw
    (ts, client_ip, qname, qtype, rcode, latency_ms, zone_id, pop_id, schema_version, verdict, confidence, signal)
VALUES
    -- Day 1, Site Z1-POP1: normal traffic
    ('2026-09-09 10:00:01.000', '10.0.1.100', 'www.example.com.',      'A',      'NOERROR',  12.5,  'Z1', 'POP1', 1, 'benign',     0.95, NULL),
    ('2026-09-09 10:00:02.100', '10.0.1.101', 'api.google.com.',      'A',      'NOERROR',   8.3,  'Z1', 'POP1', 1, 'benign',     0.98, NULL),
    ('2026-09-09 10:00:03.200', '10.0.1.102', 'cdn.microsoft.com.',   'A',      'NOERROR',  15.0,  'Z1', 'POP1', 1, 'benign',     0.92, NULL),

    -- Day 1, Site Z2-POP3: suspicious traffic (DGA)
    ('2026-09-09 10:01:01.000', '10.0.2.50',  'xkjlqwmzpl.info.',     'A',      'NXDOMAIN', 45.2,  'Z2', 'POP3', 1, 'dga',        0.93, '[\"nxdomain_ratio\"]'),
    ('2026-09-09 10:01:02.000', '10.0.2.51',  'bmvxtkqhgz.net.',      'A',      'NXDOMAIN', 50.1,  'Z2', 'POP3', 1, 'dga',        0.87, '[\"nxdomain_ratio\"]'),
    ('2026-09-09 10:01:03.000', '10.0.2.52',  'rfwytpmjkn.org.',      'A',      'NXDOMAIN', 38.7,  'Z2', 'POP3', 1, 'unverified', NULL,  NULL),

    -- Day 1, Site Z3-POP2: tunneling
    ('2026-09-09 10:02:01.000', '10.0.3.10',  'aGVsbG8gd29ybGQ.dg.', 'A',      'NOERROR', 120.0,  'Z3', 'POP2', 1, 'tunnel',     0.91, '[\"entropy\"]'),

    -- Day 2: different day to test partitioning
    ('2026-09-10 08:00:01.000', '10.0.1.100', 'mail.example.com.',    'A',      'NOERROR',  10.0,  'Z1', 'POP1', 1, 'benign',     0.99, NULL),
    ('2026-09-10 08:00:02.000', '10.0.1.101', 'login.google.com.',    'AAAA',   'NOERROR',   5.0,  'Z1', 'POP1', 1, 'benign',     0.97, NULL);
"

echo "=== Seeding site_qoe_minute ==="

CH "
INSERT INTO site_qoe_minute
    (site, ts, score, label, latency_component, nxdomain_component, saturation_component, qps, query_count, distinct_clients, nxdomain_rate, p95_latency_ms)
VALUES
    ('Z1-POP1', '2026-09-09 10:00:00', 92, 'Excellent', 95,  98, 80, 3.0, 3, 3, 0.00, 15.0),
    ('Z2-POP3', '2026-09-09 10:01:00', 38, 'Poor',      60,  10, 50, 3.0, 3, 3, 0.67, 50.1),
    ('Z3-POP2', '2026-09-09 10:02:00', 55, 'Fair',      30,  90, 40, 1.0, 1, 1, 0.00, 120.0),
    ('Z1-POP1', '2026-09-10 08:00:00', 96, 'Excellent', 97,  99, 85, 2.0, 2, 2, 0.00, 10.0);
"

echo "=== Validation queries ==="

echo ""
echo "--- [V1] Raw events for Site Z1-POP1 in a 1-min window (2026-09-09 10:00) ---"
CH "
SELECT ts, client_ip, qname, verdict
FROM dns_events_raw
WHERE ts >= toDateTime64('2026-09-09 10:00:00', 3)
  AND ts <  toDateTime64('2026-09-09 10:01:00', 3)
  AND zone_id = 'Z1' AND pop_id = 'POP1'
ORDER BY ts
FORMAT PrettyCompact
"

echo ""
echo "--- [V2] Partition pruning: only Day 1 events for Z2-POP3 ---"
CH "
SELECT ts, client_ip, qname, verdict
FROM dns_events_raw
WHERE ts >= toDateTime64('2026-09-09 00:00:00', 3)
  AND ts <  toDateTime64('2026-09-10 00:00:00', 3)
  AND zone_id = 'Z2' AND pop_id = 'POP3'
ORDER BY ts
FORMAT PrettyCompact
"

echo ""
echo "--- [V3] QoE scores for Z2-POP3 ---"
CH "
SELECT site, ts, score, label, nxdomain_rate
FROM site_qoe_minute
WHERE site = 'Z2-POP3'
ORDER BY ts
FORMAT PrettyCompact
"

echo ""
echo "--- [V4] QoE scores across all sites ---"
CH "
SELECT site, ts, score, label
FROM site_qoe_minute
ORDER BY site, ts
FORMAT PrettyCompact
"

echo ""
echo "=== Fixture seeding and validation complete ==="
