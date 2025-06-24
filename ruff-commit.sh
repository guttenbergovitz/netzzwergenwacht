#!/bin/bash
# ruff-commit.sh: Automated lint-format-add-commit cycle for ruff

set -e

uv run ruff check --fix
uv run ruff format
git add .
git commit "$@"
