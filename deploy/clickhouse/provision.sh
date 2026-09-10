#!/usr/bin/env bash
# =============================================================================
# provision.sh — Idempotent ClickHouse schema provisioning
# Issue #11 (S2-T1) — Sentinel-DNS Track4
#
# Usage:
#   ./deploy/clickhouse/provision.sh                    # default: localhost:8123
#   CLICKHOUSE_HOST=ch CLICKHOUSE_PORT=8123 ./deploy/clickhouse/provision.sh
#
# Safe to run multiple times — all CREATE TABLE statements use IF NOT EXISTS.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_URL="http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/schema.sql"

# ---------------------------------------------------------------------------
# Wait for ClickHouse to be ready (max 30 s)
# ---------------------------------------------------------------------------
echo "[provision] Waiting for ClickHouse at ${CLICKHOUSE_URL} ..."
for i in $(seq 1 30); do
    if curl -sf "${CLICKHOUSE_URL}/ping" >/dev/null 2>&1; then
        echo "[provision] ClickHouse is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "[provision] ERROR: ClickHouse not reachable after 30 s." >&2
        exit 1
    fi
    sleep 1
done

# ---------------------------------------------------------------------------
# Apply schema (idempotent)
# ---------------------------------------------------------------------------
echo "[provision] Applying schema from ${SCHEMA_FILE} ..."
curl -sf "${CLICKHOUSE_URL}/" \
    --data-binary "@${SCHEMA_FILE}" \
    -H "Content-Type: text/plain"

echo "[provision] Schema provisioned successfully."

# ---------------------------------------------------------------------------
# Verify tables exist
# ---------------------------------------------------------------------------
echo "[provision] Verifying tables ..."
TABLES=$(curl -sf "${CLICKHOUSE_URL}/" \
    --data "SELECT name FROM system.tables WHERE database = currentDatabase() AND name IN ('dns_events_raw', 'site_qoe_minute') ORDER BY name FORMAT TabSeparated" \
    -H "Content-Type: text/plain")

if echo "$TABLES" | grep -q "dns_events_raw"; then
    echo "[provision] ✓ dns_events_raw exists"
else
    echo "[provision] ✗ dns_events_raw MISSING" >&2
    exit 1
fi

if echo "$TABLES" | grep -q "site_qoe_minute"; then
    echo "[provision] ✓ site_qoe_minute exists"
else
    echo "[provision] ✗ site_qoe_minute MISSING" >&2
    exit 1
fi

echo "[provision] Provisioning complete."
