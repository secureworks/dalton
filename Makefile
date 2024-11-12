
VENV := $(or ${VENV},${VENV},$(CURDIR)/.venv)
PIP=$(VENV)/bin/pip
PYTHON=$(VENV)/bin/python
PYTEST=$(VENV)/bin/pytest
COVERAGE=$(VENV)/bin/coverage
RUFF=$(VENV)/bin/ruff
ACTIVATE=$(VENV)/bin/activate
BUMPVERSION=$(VENV)/bin/bump-my-version
BUMPPART ?= patch

venv $(VENV):
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip wheel
	$(PIP) install -e . -e ".[testing]" -e ".[devtools]"

test: $(VENV)
	. $(ACTIVATE) && $(PYTEST) tests

coverage: $(VENV)
	. $(ACTIVATE) && $(COVERAGE) run -m pytest tests
	$(COVERAGE) report

lint: $(VENV)
	$(RUFF) format --check
	$(RUFF) check

fix: $(VENV)
	$(RUFF) format
	$(RUFF) check --fix

hadolint: Dockerfile-dalton Dockerfile-nginx dalton-agent/Dockerfiles/Dockerfile_*
	docker run -t --rm -v `pwd`:/app -w /app hadolint/hadolint /bin/hadolint $^

bumpversion: $(VENV) pyproject.toml
	$(BUMPVERSION) bump $(BUMPPART)

bumpagent: $(VENV) pyproject.toml
	$(BUMPVERSION) bump --config-file dalton-agent/.bumpversion.toml $(BUMPPART)
