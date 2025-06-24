#!/bin/bash
# ruff-commit.sh: Automatyczny cykl lint-format-add-commit dla ruff

set -e

uv run ruff check --fix
uv run ruff format
git add .
git commit "$@"
