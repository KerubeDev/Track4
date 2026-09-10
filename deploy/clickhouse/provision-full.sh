#!/usr/bin/env bash
# =============================================================================
# provision.sh — Idempotent full-stack provisioning
# Issue #15 (S2-T5) — Docker compose + idempotent provision
#
# Provisions all infrastructure components:
#   1. ClickHouse: schema tables (dns_events_raw, site_qoe_minute)
#   2. Grafana: datasource + dashboard auto-provisioned via files
#   3. Wazuh: local_rules.xml + local_decoder.xml mounted as volumes
#
# Safe to run multiple times — all operations are idempotent.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration (overridable via environment)
# ---------------------------------------------------------------------------
CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_URL="http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
CLICKHOUSE_DB="${CLICKHOUSE_DB:-sentinel_dns}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/schema.sql"

GRAFANA_HOST="${GRAFANA_HOST:-localhost}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
GRAFANA_URL="http://${GRAFANA_HOST}:${GRAFANA_PORT}"

ERRORS=0

echo "============================================="
echo " Sentinel-DNS — Idempotent Provision"
echo "============================================="
echo ""

# ---------------------------------------------------------------------------
# 1. ClickHouse — schema provisioning
# ---------------------------------------------------------------------------
echo "[1/3] ClickHouse schema provisioning"
echo "  Waiting for ClickHouse at ${CLICKHOUSE_URL} ..."
for i in $(seq 1 30); do
    if curl -sf "${CLICKHOUSE_URL}/ping" >/dev/null 2>&1; then
        echo "  ClickHouse is ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "  ERROR: ClickHouse not reachable after 30 s." >&2
        ERRORS=$((ERRORS + 1))
    fi
    sleep 1
done

if [ "$ERRORS" -eq 0 ]; then
    echo "  Applying schema from ${SCHEMA_FILE} ..."
    curl -sf "${CLICKHOUSE_URL}/" \
        --data-binary "@${SCHEMA_FILE}" \
        -H "Content-Type: text/plain" \
        -H "X-ClickHouse-Database: ${CLICKHOUSE_DB}"

    echo "  Verifying tables ..."
    TABLES=$(curl -sf "${CLICKHOUSE_URL}/" \
        --data "SELECT name FROM system.tables WHERE database = '${CLICKHOUSE_DB}' AND name IN ('dns_events_raw', 'site_qoe_minute') ORDER BY name FORMAT TabSeparated" \
        -H "Content-Type: text/plain" \
        -H "X-ClickHouse-Database: ${CLICKHOUSE_DB}")

    if echo "$TABLES" | grep -q "dns_events_raw"; then
        echo "  OK: dns_events_raw exists"
    else
        echo "  FAIL: dns_events_raw MISSING" >&2
        ERRORS=$((ERRORS + 1))
    fi

    if echo "$TABLES" | grep -q "site_qoe_minute"; then
        echo "  OK: site_qoe_minute exists"
    else
        echo "  FAIL: site_qoe_minute MISSING" >&2
        ERRORS=$((ERRORS + 1))
    fi
else
    echo "  Skipping schema provisioning (ClickHouse unavailable)"
fi

echo ""

# ---------------------------------------------------------------------------
# 2. Grafana — verify datasource and dashboard provisioning files
# ---------------------------------------------------------------------------
echo "[2/3] Grafana provisioning verification"
echo "  Grafana datasource and dashboard are auto-provisioned on startup"
echo "  via /etc/grafana/provisioning/ and /var/lib/grafana/dashboards/."

# Verify the provisioning files are mounted correctly
if [ -f /etc/grafana/provisioning/datasources/clickhouse.yml ]; then
    echo "  OK: ClickHouse datasource provisioning file present"
else
    echo "  WARN: Datasource provisioning file not found (may not be mounted yet)"
fi

if [ -f /etc/grafana/provisioning/dashboards/dashboards.yml ]; then
    echo "  OK: Dashboard provisioning config present"
else
    echo "  WARN: Dashboard provisioning config not found (may not be mounted yet)"
fi

if [ -f /var/lib/grafana/dashboards/sentinel-dns.json ]; then
    echo "  OK: Dashboard JSON present"
else
    echo "  WARN: Dashboard JSON not found (may not be mounted yet)"
fi

# Verify Grafana is healthy (if running)
if curl -sf "${GRAFANA_URL}/api/health" >/dev/null 2>&1; then
    echo "  OK: Grafana is healthy"
else
    echo "  INFO: Grafana not reachable (may not be started yet)"
fi

echo ""

# ---------------------------------------------------------------------------
# 3. Wazuh — verify local rules and decoder files
# ---------------------------------------------------------------------------
echo "[3/3] Wazuh configuration verification"
echo "  Wazuh rules and decoder are mounted as read-only volumes."

WAZUH_RULES="/var/ossec/etc/rules/local_rules.xml"
WAZUH_DECODER="/var/ossec/etc/decoders/local_decoder.xml"

if [ -f "$WAZUH_RULES" ]; then
    echo "  OK: local_rules.xml present"
else
    echo "  INFO: local_rules.xml not found at $WAZUH_RULES (may not be mounted yet)"
fi

if [ -f "$WAZUH_DECODER" ]; then
    echo "  OK: local_decoder.xml present"
else
    echo "  INFO: local_decoder.xml not found at $WAZUH_DECODER (may not be mounted yet)"
fi

echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "============================================="
if [ "$ERRORS" -eq 0 ]; then
    echo " Provisioning complete (no errors)"
else
    echo " Provisioning completed with $ERRORS error(s)"
fi
echo "============================================="

exit "$ERRORS"
