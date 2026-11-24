#!/bin/bash
# ruff-commit.sh: Automated lint-format-add-commit cycle for ruff

set -e

# Repeat lint/format/add until ruff check passes with no errors
while true; do
    uv run ruff check --fix
    uv run ruff format
    git reset  # unstages everything
    git add .
    # If ruff check passes, break the loop
    if uv run ruff check; then
        break
    fi
done

git commit "$@"
