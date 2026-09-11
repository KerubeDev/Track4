#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
errors=0

fail() { printf 'FAIL: %s\n' "$1" >&2; errors=$((errors + 1)); }
pass() { printf 'PASS: %s\n' "$1"; }

[[ -f "${root}/README.md" ]] && pass "README exists" || fail "README.md missing"
grep -q "Pre-existing bases declaration" "${root}/README.md" && pass "pre-existing bases declared" || fail "Art. 11 declaration missing"
grep -q "QVAC_IMAGE" "${root}/.env" && pass "QVAC image is explicit" || fail "QVAC_IMAGE missing"
grep -q "QWEN3_1_7B_INST_Q4" "${root}/.env" && pass "required model is configured" || fail "QVAC model missing"
[[ -x "${root}/scripts/prepare-dataset.sh" ]] && pass "dataset preparation script is executable" || fail "dataset script missing/not executable"

dataset="${root}/docs/data/LogsDNSQueries"
if [[ -d "${dataset}" ]] && compgen -G "${dataset}/queries.*" >/dev/null; then
  pass "challenge dataset is prepared"
else
  printf 'INFO: dataset is not present; run scripts/prepare-dataset.sh before the demo.\n'
fi

if command -v docker >/dev/null 2>&1; then
  docker compose --env-file "${root}/.env" -f "${root}/deploy/docker-compose.yml" config >/dev/null && pass "compose configuration is valid" || fail "compose configuration is invalid"
else
  printf 'INFO: Docker is unavailable; compose validation was not run.\n'
fi

if (( errors > 0 )); then
  exit 1
fi
printf 'Delivery checks passed. External checks still required: QVAC runtime smoke test and end-to-end Compose run.\n'
