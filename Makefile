.PHONY: setup lint test evaluate evaluate-toolsafe baselines tune fetch-benchmarks opa-up opa-down serve

setup:
	python3 -m venv .venv
	.venv/bin/pip install -e '.[dev]'

lint:
	.venv/bin/ruff check src scripts tests

test:
	.venv/bin/pytest -q

evaluate:
	.venv/bin/agentgate evaluate --dataset benchmarks/agentgatebench/cases.jsonl --mode full --output artifacts/results/full.json

evaluate-toolsafe:
	.venv/bin/agentgate evaluate-toolsafe --source benchmarks/external/toolsafe/TS-Bench --output artifacts/results/toolsafe-full.json

baselines:
	.venv/bin/agentgate evaluate --dataset benchmarks/agentgatebench/cases.jsonl --mode static --output artifacts/results/static.json
	.venv/bin/agentgate evaluate --dataset benchmarks/agentgatebench/cases.jsonl --mode no_guard --output artifacts/results/no_guard.json

tune:
	.venv/bin/python scripts/tune.py --dataset benchmarks/agentgatebench/cases.jsonl --output artifacts/results/tuning.json

fetch-benchmarks:
	.venv/bin/python scripts/fetch_benchmarks.py

opa-up:
	docker compose up -d opa

opa-down:
	docker compose down

serve:
	.venv/bin/uvicorn agentgate.runtime.api:app --host 127.0.0.1 --port 8080
