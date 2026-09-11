#!/usr/bin/env bash
set -euo pipefail
DB="${SHIELD_DB:-data/shield.db}"
DATASET="${DATASET_PATH:-docs/data/LogsDNSQueries}"
QVAC_URL="${QVAC_URL:-http://127.0.0.1:11434}"
LIMIT="${LIGHT_LIMIT:-50000}"
if [[ ! -d "$DATASET" ]]; then echo "Dataset directory not found: $DATASET" >&2; exit 2; fi
mkdir -p "$(dirname "$DB")" data
python -m app.light.web --db "$DB" --port "${LIGHT_UI_PORT:-8080}" &
UI_PID=$!
trap 'kill "$UI_PID" 2>/dev/null || true' EXIT INT TERM
echo "Dashboard: http://127.0.0.1:${LIGHT_UI_PORT:-8080}"
echo "Replaying dataset directly into the local runtime; QVAC=$QVAC_URL"
python -m app.emulator.cli --dataset "$DATASET" --rate 0 --seed "${DEMO_SEED:-42}" --attack --emit json --out data/light-input.jsonl --limit "$LIMIT"
python -m app.light.runtime --input data/light-input.jsonl --db "$DB" --qvac-url "$QVAC_URL"
echo "Local run complete. Dashboard remains available until Ctrl-C."
wait "$UI_PID"
