.PHONY: install test lint quality verify light compose-check

install:
	python -m pip install -r requirements-dev.txt

test:
	python -m pytest -q

lint:
	python -m ruff check app tests scripts

quality:
	python scripts/quality-gate.py
	python -m ruff check app tests scripts
	python -m pytest -q

verify:
	python scripts/verify-light.py --dataset "$${DATASET_PATH:-docs/data/LogsDNSQueries}" --qvac-url "$${QVAC_URL:-http://127.0.0.1:11434}"

light:
	./scripts/run-light.sh

compose-check:
	docker compose --env-file .env.example -f deploy/docker-compose.yml config -q
