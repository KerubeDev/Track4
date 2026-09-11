#!/bin/sh
# Idempotent SHIELD infrastructure verification/provisioning.
set -eu

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
CLICKHOUSE_DB="${CLICKHOUSE_DB:-sentinel_dns}"
CLICKHOUSE_URL="http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}"
GRAFANA_HOST="${GRAFANA_HOST:-localhost}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
GRAFANA_URL="http://${GRAFANA_HOST}:${GRAFANA_PORT}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
SCHEMA_FILE="${SCRIPT_DIR}/schema.sql"

printf '%s\n' "SHIELD infrastructure provision"

printf '%s\n' "[1/3] ClickHouse"
curl --fail --silent --show-error --data-binary @"${SCHEMA_FILE}" "${CLICKHOUSE_URL}/?multiquery=1"
curl --fail --silent --show-error "${CLICKHOUSE_URL}/?query=SELECT%201" >/dev/null
for table in dns_events_raw site_qoe_minute; do
  count="$(curl --fail --silent --show-error --get \
    --data-urlencode "query=SELECT count() FROM system.tables WHERE database='${CLICKHOUSE_DB}' AND name='${table}'" \
    "${CLICKHOUSE_URL}/")"
  [ "${count}" = "1" ] || { echo "missing ClickHouse table: ${table}" >&2; exit 1; }
done

printf '%s\n' "[2/3] Grafana"
curl --fail --silent --show-error "${GRAFANA_URL}/api/health" >/dev/null
# Datasource/dashboard files are mounted and provisioned by Grafana itself.

printf '%s\n' "[3/3] Wazuh"
# Wazuh decoder/rules are mounted read-only by Compose and its service health
# gate must pass before this one-shot provision service starts.
printf '%s\n' "Wazuh configuration mounted; manager health gate passed."

printf '%s\n' "Provision complete (idempotent; safe to run multiple times)."
