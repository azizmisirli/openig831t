# SPDX-License-Identifier: Apache-2.0
PYTHON ?= python3
export PYTHONPATH := $(CURDIR)/src
export PYTHONDONTWRITEBYTECODE := 1
.PHONY: setup lint test test-sanitizers audit docs bundle
setup:
	$(PYTHON) -m venv .venv
	.venv/bin/python -m pip install -e '.[dev]'
lint:
	$(PYTHON) scripts/check_static.py
test:
	$(PYTHON) scripts/validate_offline.py
test-sanitizers:
	$(PYTHON) -m unittest discover -s tests -p 'test_kernel*.py' -v
audit:
	$(PYTHON) scripts/publication_audit.py --git-objects
	$(PYTHON) scripts/scan_secrets.py
docs:
	$(PYTHON) scripts/validate_docs.py
bundle:
	$(PYTHON) scripts/build_bundle.py --output dist/source
