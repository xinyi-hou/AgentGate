.PHONY: setup lint test policy-check serve

setup:
	python3 -m venv .venv
	.venv/bin/pip install -e '.[dev]'

lint:
	.venv/bin/ruff format --check src tests
	.venv/bin/ruff check --no-cache src tests

test:
	PYTHONDONTWRITEBYTECODE=1 .venv/bin/pytest -q -p no:cacheprovider

policy-check:
	PYTHONDONTWRITEBYTECODE=1 .venv/bin/agentgate policy-check

serve:
	PYTHONDONTWRITEBYTECODE=1 .venv/bin/agentgate serve --host 127.0.0.1 --port 8080
