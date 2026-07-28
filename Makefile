VENV ?= .venv-test
PYTHON ?= python3
INSTALL_DIR ?= /usr/local/lib/sandy
DESTDIR ?=

export DESTDIR INSTALL_DIR

VENV_PYTHON := $(VENV)/bin/python
BLACK := $(VENV)/bin/black
COVERAGE := $(VENV)/bin/coverage
PYRIGHT := $(VENV)/bin/pyright

LANGUAGE_CHECKER ?= language-checker

PYTHON_FILES := sandy $(wildcard tests/*.py) $(wildcard tests/e2e/*.py)
SHELL_FILES := debootstrap.sh oci.sh setup-container.sh \
	$(wildcard tests/e2e/*.sh)
UNIT_TEST_MODULES := tests.test_sandy tests.test_e2e_harness

.PHONY: all check coverage e2e e2e-full e2e-guard format format-check install
.PHONY: inclusivity-check install-test install-tools shell-check test type-check

all: check

install: sandy debootstrap.sh oci.sh setup-container.sh
	@set -eu; \
	normalized=$$(realpath -ms -- "$$INSTALL_DIR" 2>/dev/null || true); \
	if [ -z "$$INSTALL_DIR" ] || [ "$$INSTALL_DIR" = "/" ] || \
			[ "$$normalized" != "$$INSTALL_DIR" ]; then \
		echo "ERROR: INSTALL_DIR must be a normalized absolute path other than /" >&2; \
		exit 1; \
	fi; \
	case "$$DESTDIR" in \
		""|/*) ;; \
		*) echo "ERROR: DESTDIR must be an absolute path" >&2; exit 1 ;; \
	esac; \
	target_dir="$${DESTDIR%/}$$INSTALL_DIR"; \
	install -d -m 0755 -- "$$target_dir"; \
	install -m 0755 -- sandy debootstrap.sh oci.sh setup-container.sh \
		"$$target_dir/"; \
	echo "I: Installed sandy to $$target_dir"; \
	echo "I: sudoers was not changed"; \
	echo "I: If appropriate for this host, consider adding this with visudo(8):"; \
	printf '%s\n' "%sudo ALL=(root:root) $$INSTALL_DIR/sandy"

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
	$(VENV_PYTHON) -W error -m unittest -v $(UNIT_TEST_MODULES)

coverage:
	$(COVERAGE) run -m unittest $(UNIT_TEST_MODULES)
	$(COVERAGE) report

shell-check:
	shellcheck $(SHELL_FILES)

inclusivity-check:
	@if command -v "$(LANGUAGE_CHECKER)" >/dev/null; then \
		"$(LANGUAGE_CHECKER)" --exit-1-on-failure .; \
	else \
		echo "W: $(LANGUAGE_CHECKER) not found; install language-checker or set LANGUAGE_CHECKER"; \
	fi

e2e-guard:
	@if [ "$$SANDY_E2E" != "1" ]; then \
		echo "ERROR: e2e requires SANDY_E2E=1 (run only in a disposable VM)" >&2; \
		exit 1; \
	fi
	@if [ "$$(id -u)" != "0" ]; then \
		echo "ERROR: e2e must run as root" >&2; \
		exit 1; \
	fi

e2e: e2e-guard
	$(PYTHON) -m tests.e2e.runner

e2e-full: e2e-guard
	$(PYTHON) -m tests.e2e.runner --full

check: format-check type-check test inclusivity-check
