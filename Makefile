


venv:
	python -m venv .venv
	.venv/bin/pip install --upgrade pip wheel
	.venv/bin/pip install -e . -e ".[testing]" -e ".[devtools]"

test:
	.venv/bin/pytest .

coverage:
	.venv/bin/coverage run -m pytest
	.venv/bin/coverage report

lint:
	.venv/bin/ruff format --check
	.venv/bin/ruff check

fix:
	.venv/bin/ruff format
	.venv/bin/ruff check --fix
