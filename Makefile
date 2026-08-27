.PHONY: help setup venv run clean test dist

VENV := scripts/venv
PY := $(VENV)/bin/python
SHELL := /bin/bash
OUTDIR ?= reports

help:
	@echo "Attack Surface Toolkit"
	@echo "  make setup           Create venv and install dependencies"
	@echo "  make run             Run full pipeline (set DOMAIN=example.com)"
	@echo "  make run-quick       Run fast subset (no cloud buckets, no username check, no wayback)"
	@echo "  make run-no-pdf      Run pipeline without PDF generation"
	@echo "  make test            Syntax-check all scripts"
	@echo "  make clean           Remove venv, cache, and artifacts"
	@echo "  make dist            Create compressed distribution archive (<25MB)"
	@echo ""
	@echo "Or use the single CLI entry point:"
	@echo "  ast --help"
	@echo "  ast run-pipeline example.com"
	@echo "  ast run-quick example.com"

setup:
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install --upgrade pip
	$(VENV)/bin/pip install -r scripts/requirements.txt

run:
	@test -n "$(DOMAIN)" || (echo "Usage: make run DOMAIN=example.com [OUTDIR=reports]"; exit 1)
	$(PY) scripts/run_pipeline.py "$(DOMAIN)" --out "$(OUTDIR)" $(EXTRA_ARGS)

run-quick:
	@test -n "$(DOMAIN)" || (echo "Usage: make run-quick DOMAIN=example.com [OUTDIR=reports]"; exit 1)
	$(PY) scripts/run_pipeline.py "$(DOMAIN)" --out "$(OUTDIR)" --skip cloud_bucket_enum.py username_presence_check.py wayback_urls.py $(EXTRA_ARGS)

run-no-pdf:
	@test -n "$(DOMAIN)" || (echo "Usage: make run-no-pdf DOMAIN=example.com [OUTDIR=reports]"; exit 1)
	$(PY) scripts/run_pipeline.py "$(DOMAIN)" --out "$(OUTDIR)" --no-pdf $(EXTRA_ARGS)

test:
	@echo "[*] Syntax-checking scripts..."
	@for f in scripts/*.py; do python3 -m py_compile "$$f" || exit 1; done
	@echo "[+] All scripts pass syntax check"

clean:
	rm -rf $(VENV)
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -f .coverage
	rm -rf htmlcov/
	rm -rf reports/

dist:
	@echo "[*] Creating distribution archive..."
	tar -czf /tmp/attack-surface-toolkit-dist.tar.gz \
		--exclude='scripts/venv' \
		--exclude='reports' \
		--exclude='__pycache__' \
		--exclude='.git' \
		.
	@echo "[+] Distribution archive created: /tmp/attack-surface-toolkit-dist.tar.gz"
	@ls -lh /tmp/attack-surface-toolkit-dist.tar.gz


