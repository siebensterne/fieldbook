# Repository task entry point.
#
# The Makefile is a thin, deterministic facade over `cargo xtask`, which owns
# the authoritative gate definitions. Style rules follow the Linux kernel
# coding guidelines and the Google Python, Shell, Markdown, JSON and Rust
# style guides; see docs/style-guide.md.
#
# Command surface (`make help` prints the same list):
#   check        full gate: style plus CI parity
#   check-static fmt, lint, docs and style; no tests
#   ci           full CI parity task
#   assure       full assurance superset
#   fmt          non-mutating rustfmt check
#   format-fix   apply the mutating Python and Markdown style fixes
#   lint         clippy with warnings denied
#   test         all-target and doc tests
#   docs         rustdoc with broken links denied
#   style        every non-Rust language and policy gate
#   e2e          curated end-to-end suites
#   verify       matrix, architecture and generated-path gates
#   tools        install the pinned Python tools
#
# Recipe lines use tabs (required by make). Every target is phony: there is no
# file produced by any target name, so `.PHONY` prevents stale-file skips.

.PHONY: all help check check-static ci assure style format-fix fmt lint test \
	docs e2e verify python-check ruff-check q-check standards-check \
	python-fmt shell-check json-check markdown-check makefile-check \
	rust-check tools

.DEFAULT_GOAL := check

SHELL := /bin/bash

all: check

help:
	@echo "check        full gate: style plus CI parity"
	@echo "check-static fmt, lint, docs and style; no tests"
	@echo "ci           full CI parity task"
	@echo "assure       full assurance superset"
	@echo "fmt          non-mutating rustfmt check"
	@echo "format-fix   apply mutating Python and Markdown style fixes"
	@echo "lint         clippy with warnings denied"
	@echo "test         all-target and doc tests"
	@echo "docs         rustdoc with broken links denied"
	@echo "style        every non-Rust language and policy gate"
	@echo "e2e          curated end-to-end suites"
	@echo "verify       matrix, architecture and generated-path gates"
	@echo "tools        install the pinned Python tools"

check: style ci

ci:
	cargo xtask ci

assure:
	cargo xtask assure

check-static:
	cargo xtask fmt
	cargo xtask lint
	cargo xtask docs
	cargo xtask style

fmt:
	cargo xtask fmt

format-fix:
	python3 scripts/check_style.py --fix

style: python-check ruff-check q-check standards-check shell-check \
	json-check markdown-check makefile-check

python-check:
	python3 scripts/check_style.py --python

ruff-check:
	python3 scripts/ruff_gate.py .

q-check:
	python3 scripts/check_q_style.py
	python3 scripts/check_q_style.py --self-test

standards-check:
	python3 scripts/check_prose_unified.py --self-test
	python3 scripts/check_prose_unified.py
	python3 scripts/check_quality_contract.py --self-test
	python3 scripts/check_quality_contract.py
	python3 scripts/check_license_provenance.py --self-test
	python3 scripts/check_license_provenance.py

python-fmt:
	python3 -m pyink --config pyproject.toml scripts

shell-check:
	python3 scripts/check_style.py --shell
	python3 scripts/check_shellcheck.py

json-check:
	python3 scripts/check_style.py --json

markdown-check:
	python3 scripts/check_style.py --markdown

makefile-check:
	python3 scripts/check_style.py --makefile

rust-check:
	cargo xtask fmt
	cargo xtask lint

lint:
	cargo xtask lint

test:
	cargo xtask test

docs:
	cargo xtask docs

e2e:
	cargo xtask e2e

verify:
	cargo xtask verify

tools:
	python3 -m pip install -r requirements-dev.txt
