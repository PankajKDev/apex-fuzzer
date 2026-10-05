# Apex-Fuzzer developer workflows. Every target mirrors a CI job.
# Uses plain `python` (CI) — locally, run inside .venv or prefix PATH.
PY := python

.PHONY: test lint typecheck security build ci lock clean

test:  ## full suite
	$(PY) -m pytest tests/ -q

test-cov:  ## suite with coverage report + floor gate
	$(PY) -m pytest tests/ -q --cov=main --cov-report=term-missing \
		--cov-fail-under=70

lint:  ## ruff bug-catching subset (see pyproject [tool.ruff])
	$(PY) -m ruff check --select F,E9 main tests

typecheck:  ## mypy on the gated scope (ratchets outward, see pyproject)
	$(PY) -m mypy main/safety main/verify \
		main/budgets.py main/ai

security:  ## dependency audit (gitleaks runs in CI + pre-commit)
	$(PY) -m pip_audit --desc

build:  ## wheel + sdist build check
	$(PY) -m build

lock:  ## regenerate requirements.lock from the dev venv
	$(PY) -m pip freeze > requirements.lock

ci: lint typecheck test-cov security build  ## everything CI runs

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
