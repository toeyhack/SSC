#!/usr/bin/env sh
# scripts/phase1a_validate.sh
# Phase 1A runtime validation helper.

set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT" || exit 1

REPORT_DIR="$REPO_ROOT/reports"
mkdir -p "$REPORT_DIR"
TS=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORT_DIR/phase1a-validation-$TS.txt"

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

rprint "Phase 1A validation started at $(date -u)"
rprint "Repository root: $REPO_ROOT"
rprint "Report: $REPORT_FILE"
rprint ""

run_critical "Docker Compose up --build -d" docker compose up --build -d
run_noncritical "Docker Compose ps" docker compose ps

if SERVICES=$(docker compose config --services 2>>"$REPORT_FILE"); then
  rprint "Detected services from compose config:"
  printf "%s\n" "$SERVICES" >>"$REPORT_FILE"
  rprint ""
else
  SERVICES=""
  run_critical "Docker Compose config services" false
fi

if ! printf "%s\n" "$SERVICES" | grep -w backend >/dev/null 2>&1; then
  rprint "ERROR: backend service not found in docker compose config"
  run_critical "Backend service present in compose" false
fi

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

run_noncritical "Backend ls -la /app" docker compose exec -T backend ls -la /app
run_noncritical "Backend find alembic locations" docker compose exec -T backend sh -c 'find /app -maxdepth 3 -type f \( -name "alembic.ini" -o -name "env.py" \)'

MIG_PATH=""
if docker compose exec -T backend sh -c 'test -f /app/migrations/alembic.ini && echo yes' 2>/dev/null | grep -q yes; then
  MIG_PATH="/app/migrations/alembic.ini"
elif docker compose exec -T backend sh -c 'test -f migrations/alembic.ini && echo yes' 2>/dev/null | grep -q yes; then
  MIG_PATH="migrations/alembic.ini"
fi

if [ -z "$MIG_PATH" ]; then
  rprint "Could not detect alembic.ini inside backend container"
  run_critical "Alembic configuration detection" false
else
  rprint "Detected alembic config at: $MIG_PATH"
  run_critical "alembic --version inside backend" docker compose exec -T backend alembic --version

  attempt=1
  mig_success=1
  rprint "Running alembic upgrade head using $MIG_PATH"
  while [ "$attempt" -le "$MAX_RETRIES" ]; do
    rprint "alembic attempt $attempt"
    tmpf=$(mktemp)
    if docker compose exec -T backend alembic -c "$MIG_PATH" upgrade head >"$tmpf" 2>&1; then
      cat "$tmpf" >>"$REPORT_FILE"
      rm -f "$tmpf"
      mig_success=0
      rprint "Alembic upgrade succeeded on attempt $attempt"
      break
    fi
    cat "$tmpf" >>"$REPORT_FILE"
    rm -f "$tmpf"
    rprint "Alembic upgrade failed on attempt $attempt; retrying in $SLEEP_SEC s"
    attempt=$((attempt + 1))
    sleep "$SLEEP_SEC"
  done

  if [ "$mig_success" -ne 0 ]; then
    run_critical "Alembic upgrade head" false
  else
    run_critical "Alembic upgrade head" echo "alembic OK"
  fi
fi

run_critical "Backend pytest" docker compose exec -T backend python -m pytest -q

check_http_endpoint "root" "http://localhost:8000/"
check_http_endpoint "health_ping" "http://localhost:8000/health/ping"
check_http_endpoint "health_db" "http://localhost:8000/health/db"
check_http_endpoint "health_redis" "http://localhost:8000/health/redis"
check_http_endpoint "docs" "http://localhost:8000/docs"
check_http_endpoint "catalog_factors" "http://localhost:8000/api/v1/catalog/factors"
check_http_endpoint "catalog_issues" "http://localhost:8000/api/v1/catalog/issues"
check_http_endpoint "catalog_snapshots" "http://localhost:8000/api/v1/catalog/snapshots"

run_critical "Frontend HTTP HEAD" curl -fsSI -m 10 http://localhost:3000
run_critical "Frontend production build" docker compose exec -T frontend npm run build

run_noncritical "docker system df" docker system df
run_noncritical "project du -sh ." du -sh .
run_noncritical "host df -h" df -h
run_noncritical "docker images" docker images
run_noncritical "docker volume ls" docker volume ls

run_noncritical "backend logs (last 500)" docker compose logs --tail=500 backend
run_noncritical "postgres logs (last 200)" docker compose logs --tail=200 postgres
run_noncritical "redis logs (last 200)" docker compose logs --tail=200 redis
run_noncritical "frontend logs (last 200)" docker compose logs --tail=200 frontend

rprint "================================"
rprint "PHASE 1A VALIDATION SUMMARY"
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
