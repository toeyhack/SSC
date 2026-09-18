#!/usr/bin/env bash
# Full regression using a caller-supplied isolated test PostgreSQL database.
set -euo pipefail
root_dir="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root_dir"
: "${DATABASE_URL:?Set DATABASE_URL to an isolated test PostgreSQL database}"
python_bin="${PYTHON:-python3}"
mkdir -p reports
stamp="$(date +%Y%m%d-%H%M%S)"
run_logged() {
  local phase="$1"
  "./scripts/${phase}_validate.sh" 2>&1 | tee "reports/${phase}-validation-${stamp}.txt"
}
run_logged phase4b
run_logged phase5
run_logged phase6
cd backend
"$python_bin" -m alembic -c migrations/alembic.ini downgrade 0005_phase4_scan_engine
"$python_bin" -m alembic -c migrations/alembic.ini upgrade head
"$python_bin" -m alembic -c migrations/alembic.ini check
"$python_bin" -m pytest -q
"$python_bin" -m compileall -q app migrations
"$python_bin" -m pip check
