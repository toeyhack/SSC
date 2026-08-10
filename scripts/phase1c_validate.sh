#!/usr/bin/env sh
# scripts/phase1c_validate.sh
# Phase 1C runtime validation helper.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT" || exit 1

REPORT_DIR="$REPO_ROOT/reports"
mkdir -p "$REPORT_DIR"
TS=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORT_DIR/phase1c-validation-$TS.txt"

rprint() {
  printf "%s\n" "$1" | tee -a "$REPORT_FILE"
}

CRITICAL_FAIL=0

run_critical() {
  label="$1"
  shift
  rprint "=== CHECK: $label ==="
  rprint "Command: $*"

  tmpf=$(mktemp)
  if "$@" >"$tmpf" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  cat "$tmpf" >>"$REPORT_FILE"
  rm -f "$tmpf"

  if [ "$rc" -ne 0 ]; then
    rprint "RESULT: FAIL"
    rprint "ExitCode: $rc"
    CRITICAL_FAIL=$((CRITICAL_FAIL + 1))
  else
    rprint "RESULT: PASS"
  fi
  rprint ""
}

run_noncritical() {
  label="$1"
  shift
  rprint "=== DIAG: $label ==="
  rprint "Command: $*"

  tmpf=$(mktemp)
  if "$@" >"$tmpf" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  cat "$tmpf" >>"$REPORT_FILE"
  rm -f "$tmpf"

  if [ "$rc" -ne 0 ]; then
    rprint "DIAG RESULT: ERROR (non-critical)"
    rprint "ExitCode: $rc"
  else
    rprint "DIAG RESULT: OK"
  fi
  rprint ""
}

check_http_endpoint() {
  label="$1"
  url="$2"
  attempts=12
  sleep_sec=5
  ok=1
  rprint "Checking HTTP endpoint $label -> $url"

  for i in $(seq 1 "$attempts"); do
    rprint "HTTP attempt $i"
    rc=0
    out=$(curl -fsS -m 10 "$url" 2>&1) || rc=$?
    printf "%s\n" "$out" >>"$REPORT_FILE"

    if [ "$rc" -eq 0 ]; then
      rprint "$label HTTP OK"
      ok=0
      break
    fi

    rprint "$label HTTP not ready (rc=$rc). Retrying in $sleep_sec s"
    sleep "$sleep_sec"
  done

  if [ "$ok" -ne 0 ]; then
    run_critical "HTTP $label" false
  else
    run_critical "HTTP $label" echo "OK"
  fi
}

rprint "Phase 1C validation started at $(date -u)"
rprint "Repository root: $REPO_ROOT"
rprint "Report: $REPORT_FILE"
rprint ""

run_critical "Docker Compose up --build -d" docker compose up --build -d
run_noncritical "Docker Compose ps" docker compose ps

MAX_RETRIES=12
SLEEP_SEC=5
attempt=1
backend_ready=1
rprint "Waiting for backend container exec (retries: $MAX_RETRIES, sleep: $SLEEP_SEC)"
while [ "$attempt" -le "$MAX_RETRIES" ]; do
  if docker compose exec -T backend pwd >/dev/null 2>&1; then
    backend_ready=0
    rprint "backend exec OK on attempt $attempt"
    break
  fi
  rprint "backend exec not ready (attempt $attempt)"
  attempt=$((attempt + 1))
  sleep "$SLEEP_SEC"
done

if [ "$backend_ready" -ne 0 ]; then
  run_critical "Backend container running and exec-able" false
else
  run_critical "Backend container running and exec-able" docker compose exec -T backend pwd
fi

MIG_PATH="/app/migrations/alembic.ini"
run_critical "alembic --version inside backend" docker compose exec -T backend alembic --version
run_critical "Alembic upgrade head" docker compose exec -T backend alembic -c "$MIG_PATH" upgrade head
run_critical "Backend pytest" docker compose exec -T backend python -m pytest -q

BASELINE_FIXTURE="$REPO_ROOT/backend/tests/fixtures/phase1b_sample_baseline.json"
run_critical "Admin baseline preview endpoint" curl -fsS -m 10 -H "Content-Type: application/json" --data-binary "@$BASELINE_FIXTURE" "http://localhost:8000/api/v1/catalog/golden-baseline/preview"

check_http_endpoint "root" "http://localhost:8000/"
check_http_endpoint "health_ping" "http://localhost:8000/health/ping"
check_http_endpoint "catalog_factors" "http://localhost:8000/api/v1/catalog/factors"
check_http_endpoint "catalog_issues" "http://localhost:8000/api/v1/catalog/issues"
check_http_endpoint "catalog_snapshots" "http://localhost:8000/api/v1/catalog/snapshots"
check_http_endpoint "frontend" "http://localhost:3000"

run_critical "Frontend production build" docker compose exec -T frontend npm run build

run_noncritical "backend logs (last 500)" docker compose logs --tail=500 backend
run_noncritical "frontend logs (last 200)" docker compose logs --tail=200 frontend
run_noncritical "postgres logs (last 200)" docker compose logs --tail=200 postgres
run_noncritical "redis logs (last 200)" docker compose logs --tail=200 redis

rprint "================================"
rprint "PHASE 1C VALIDATION SUMMARY"
rprint "================================"
if [ "$CRITICAL_FAIL" -eq 0 ]; then
  rprint "Overall              PASS"
  exit_code=0
else
  rprint "Overall              FAIL"
  rprint "Critical checks failed: $CRITICAL_FAIL"
  exit_code=1
fi
rprint "Report: $REPORT_FILE"

exit "$exit_code"
