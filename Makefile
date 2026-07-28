VENV ?= .venv-test
PYTHON ?= python3

VENV_PYTHON := $(VENV)/bin/python
BLACK := $(VENV)/bin/black
COVERAGE := $(VENV)/bin/coverage
PYRIGHT := $(VENV)/bin/pyright

LANGUAGE_CHECKER ?= language-checker

PYTHON_FILES := sandy test_sandy.py

.PHONY: all check coverage format format-check inclusivity-check
.PHONY: install-test install-tools test type-check

all: check

$(VENV_PYTHON):
	$(PYTHON) -m venv $(VENV)

install-test: $(VENV_PYTHON)
	$(VENV_PYTHON) -m pip install -r requirements-test.txt

install-tools: install-test

format:
	$(BLACK) $(PYTHON_FILES)

format-check:
	$(BLACK) --check $(PYTHON_FILES)

type-check:
	$(PYRIGHT) --project pyrightconfig.json $(PYTHON_FILES)

test:
	$(VENV_PYTHON) -W error -m unittest -v test_sandy.py

coverage:
	$(COVERAGE) run -m unittest test_sandy.py
	$(COVERAGE) report

inclusivity-check:
	@if command -v "$(LANGUAGE_CHECKER)" >/dev/null; then \
		"$(LANGUAGE_CHECKER)" --exit-1-on-failure .; \
	else \
		echo "W: $(LANGUAGE_CHECKER) not found; install language-checker or set LANGUAGE_CHECKER"; \
	fi

check: format-check type-check test inclusivity-check
