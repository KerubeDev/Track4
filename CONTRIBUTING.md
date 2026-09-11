# Contributing to SHIELD

Changes should preserve the local-first privacy boundary, deterministic reproducibility, and separation between production detection and evaluation fixtures.

## Development setup

Use Python 3.11 or newer in an isolated environment and install `requirements-dev.txt`. The default test path does not require a live QVAC model. Live-model acceptance is a separate workstation check.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
python scripts/quality-gate.py
python -m ruff check app tests scripts
python -m pytest -q
```

## Change discipline

Keep commits atomic and describe the engineering intent in imperative English. Add or update tests when behavior changes. Update an ADR when changing an architectural invariant, data contract, privacy boundary, delivery guarantee, or scoring model. Update the README when an operator-facing command, prerequisite, environment variable, or validation path changes.

Do not commit `.env`, DNS corpora, SQLite databases, validation reports, credentials, model weights, generated telemetry, or other runtime artifacts.

## Definition of done

A change is ready for review when its deterministic tests pass, the repository quality gate passes, relevant documentation is synchronized, failure behavior is explicit, and no production path relies on evaluation-only data or a cloud inference fallback. Changes that affect QVAC behavior additionally require a real-model acceptance run on a machine with the intended model installed.

## Review priorities

Review in this order: privacy/security invariants, correctness and failure semantics, data-contract compatibility, test coverage, operational reproducibility, maintainability, then presentation. Avoid adding infrastructure or dependencies when the same requirement can be met by the existing lightweight path.
