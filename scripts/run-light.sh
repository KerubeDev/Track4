#!/usr/bin/env bash
set -euo pipefail
DB="${SHIELD_DB:-data/shield.db}";DATASET="${DATASET_PATH:-docs/data/LogsDNSQueries}";QVAC_URL="${QVAC_URL:-http://127.0.0.1:11434}";LIMIT="${LIGHT_LIMIT:-50000}";PORT="${LIGHT_UI_PORT:-8080}"
[[ -d "$DATASET" ]] || { echo "Dataset directory not found: $DATASET" >&2; exit 2; }
mkdir -p "$(dirname "$DB")" data
rm -f "$DB" data/light-input.jsonl
python -m app.light.web --db "$DB" --port "$PORT" & UI_PID=$!;trap 'kill "$UI_PID" 2>/dev/null || true' EXIT INT TERM
echo "Dashboard: http://127.0.0.1:$PORT";echo "QVAC: $QVAC_URL";echo "Generating a bounded merged stream from the corpus + evaluation episodes..."
python -m app.emulator.cli --dataset "$DATASET" --rate 0 --seed "${DEMO_SEED:-42}" --attack --emit json --out data/light-input.jsonl --limit "$LIMIT"
python -m app.light.runtime --input data/light-input.jsonl --db "$DB" --qvac-url "$QVAC_URL"
echo "Run complete. Dashboard remains available until Ctrl-C.";wait "$UI_PID"
