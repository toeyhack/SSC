#!/usr/bin/env sh
# scripts/phase4_validate.sh
# Phase 4 runtime validation helper.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT" || exit 1

REPORT_DIR="$REPO_ROOT/reports"
mkdir -p "$REPORT_DIR"
TS=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORT_DIR/phase4-validation-$TS.txt"

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

rprint "Phase 4 validation started at $(date -u)"
rprint "Repository root: $REPO_ROOT"
rprint "Report: $REPORT_FILE"
rprint ""

run_critical "Docker Compose up --build -d" docker compose up --build -d
run_noncritical "Docker Compose ps" docker compose ps
run_critical "Backend container running and exec-able" docker compose exec -T backend pwd
run_critical "Alembic upgrade head" docker compose exec -T backend alembic -c /app/migrations/alembic.ini upgrade head
run_critical "Backend pytest" docker compose exec -T backend python -m pytest -q
run_critical "Scanner worker once" docker compose exec -T backend python -m app.cli.scan_worker --once

check_http_endpoint "root" "http://localhost:8000/"
check_http_endpoint "health_ping" "http://localhost:8000/health/ping"
check_http_endpoint "scan_jobs" "http://localhost:8000/api/v1/scans/jobs"
check_http_endpoint "scan_runs" "http://localhost:8000/api/v1/scans/runs"
check_http_endpoint "rules" "http://localhost:8000/api/v1/rules"
check_http_endpoint "inventory_hosts" "http://localhost:8000/api/v1/inventory/hosts"
check_http_endpoint "frontend" "http://localhost:3000"

run_critical "Frontend production build" docker compose exec -T frontend npm run build

run_noncritical "backend logs (last 500)" docker compose logs --tail=500 backend
run_noncritical "frontend logs (last 200)" docker compose logs --tail=200 frontend
run_noncritical "postgres logs (last 200)" docker compose logs --tail=200 postgres
run_noncritical "redis logs (last 200)" docker compose logs --tail=200 redis

rprint "================================"
rprint "PHASE 4 VALIDATION SUMMARY"
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
