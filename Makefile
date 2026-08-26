.PHONY: setup lint test policy-check serve

setup:
	python3 -m venv .venv
	.venv/bin/pip install -e '.[dev]'

lint:
	.venv/bin/ruff check src tests

test:
	.venv/bin/pytest -q

policy-check:
	.venv/bin/agentgate policy-check

serve:
	.venv/bin/agentgate serve --host 127.0.0.1 --port 8080
