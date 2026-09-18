#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../backend"
: "${DATABASE_URL:?Set DATABASE_URL to an isolated test PostgreSQL database}"
python_bin="${PYTHON:-python3}"
"$python_bin" -m alembic -c migrations/alembic.ini upgrade head
"$python_bin" -m pytest -q --ignore=tests/test_cli_report.py
