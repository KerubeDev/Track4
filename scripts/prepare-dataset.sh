#!/usr/bin/env bash
set -euo pipefail

# The challenge dataset is obtained from Ovnicom and remains ignored by Git.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${repo_root}/docs/data/LogsDNSQueries"
source_path="${DATASET_SOURCE:-}"

if [[ -z "${source_path}" ]]; then
  printf '%s\n' "Set DATASET_SOURCE to the official archive or directory." >&2
  exit 2
fi

mkdir -p "${repo_root}/docs/data"
if [[ -d "${source_path}" ]]; then
  rm -rf "${target}"
  cp -a "${source_path}" "${target}"
elif [[ -f "${source_path}" ]]; then
  case "${source_path}" in
    *.zip) unzip -q "${source_path}" -d "${repo_root}/docs/data" ;;
    *.tar.gz|*.tgz) tar -xzf "${source_path}" -C "${repo_root}/docs/data" ;;
    *) printf '%s\n' "Unsupported dataset archive: ${source_path}" >&2; exit 2 ;;
  esac
else
  printf '%s\n' "Dataset source does not exist: ${source_path}" >&2
  exit 2
fi

if [[ ! -d "${target}" ]] || ! compgen -G "${target}/queries.*" >/dev/null; then
  printf '%s\n' "Expected queries.N files under ${target}" >&2
  exit 1
fi

printf '%s\n' "Dataset ready at ${target} (not tracked by Git)."
