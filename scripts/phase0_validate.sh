#!/usr/bin/env sh
# scripts/phase0_validate.sh
# Phase 0 validation helper
# Produces a timestamped report in reports/

set -u

REPORT_DIR="reports"
mkdir -p "$REPORT_DIR"
TS=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="$REPORT_DIR/phase0-validation-$TS.txt"

# helper to write to report and stdout
rprint() {
  printf "%s\n" "$1" | tee -a "$REPORT_FILE"
}

rprint "Phase 0 validation started at $(date -u)"
rprint "Report: $REPORT_FILE"
rprint ""

# Track overall critical failures
CRITICAL_FAIL=0

# helper to run a critical command. It records output, status, and marks FAIL on non-zero
run_critical() {
  label="$1"
  shift
  rprint "=== CHECK: $label ==="
  rprint "Command: $*"

  tmpf=$(mktemp)
  if "$@" > "$tmpf" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  cat "$tmpf" >>"$REPORT_FILE"
  rm -f "$tmpf"

  if [ "$rc" -ne 0 ]; then
    rprint "RESULT: FAIL"
    rprint "ExitCode: $rc"
    CRITICAL_FAIL=$((CRITICAL_FAIL+1))
  else
    rprint "RESULT: PASS"
  fi
  rprint ""
}

# helper to run a non-critical command. Failures recorded but do not affect CRITICAL_FAIL
run_noncritical() {
  label="$1"
  shift
  rprint "=== DIAG: $label ==="
  rprint "Command: $*"

  tmpf=$(mktemp)
  if "$@" > "$tmpf" 2>&1; then
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

# 1) Start docker compose
run_critical "Docker Compose up --build -d" docker compose up --build -d

# 2) docker compose ps
run_noncritical "Docker Compose ps" docker compose ps

# Get list of services from compose config
SERVICES=$(docker compose config --services 2>/dev/null || true)
rprint "Detected services from compose config:"
printf "%s\n" "$SERVICES" >>"$REPORT_FILE"
rprint ""

# Check backend present
echo "$SERVICES" | grep -w backend >/dev/null 2>&1
if [ $? -ne 0 ]; then
  rprint "ERROR: 'backend' service not found in docker compose config. Detected services:"
  printf "%s\n" "$SERVICES" >>"$REPORT_FILE"
  run_critical "Backend service present in compose" false
fi

# 3) Ensure backend container is running (try a number of retries)
MAX_RETRIES=12
SLEEP_SEC=5
attempt=1
backend_ready=1
rprint "Waiting for backend container to accept exec (retries: $MAX_RETRIES, sleep: $SLEEP_SEC)"
while [ $attempt -le $MAX_RETRIES ]; do
  # Use docker compose exec -T to run pwd
  if docker compose exec -T backend pwd >/dev/null 2>&1; then
    backend_ready=0
    rprint "backend exec OK on attempt $attempt"
    break
  else
    rprint "backend exec not ready (attempt $attempt)"
    attempt=$((attempt+1))
    sleep $SLEEP_SEC
  fi
done
if [ $backend_ready -ne 0 ]; then
  run_critical "Backend container running and exec-able" false
else
  run_critical "Backend container running and exec-able" docker compose exec -T backend pwd
fi

# 4) Inspect backend working dir and find alembic.ini
run_noncritical "Backend ls -la /app" docker compose exec -T backend ls -la /app
run_noncritical "Backend find alembic locations" docker compose exec -T backend sh -c 'find /app -maxdepth 3 -type f \( -name "alembic.ini" -o -name "env.py" \)'

# Detect alembic path inside container
MIG_PATH=""
# Check common locations
if docker compose exec -T backend sh -c 'test -f /app/migrations/alembic.ini && echo yes' 2>/dev/null | grep -q yes; then
  MIG_PATH="/app/migrations/alembic.ini"
elif docker compose exec -T backend sh -c 'test -f /app/backend/migrations/alembic.ini && echo yes' 2>/dev/null | grep -q yes; then
  MIG_PATH="/app/backend/migrations/alembic.ini"
else
  # try relative paths (when WORKDIR = /app)
  if docker compose exec -T backend sh -c 'test -f migrations/alembic.ini && echo yes' 2>/dev/null | grep -q yes; then
    MIG_PATH="migrations/alembic.ini"
  elif docker compose exec -T backend sh -c 'test -f backend/migrations/alembic.ini && echo yes' 2>/dev/null | grep -q yes; then
    MIG_PATH="backend/migrations/alembic.ini"
  fi
fi

if [ -z "$MIG_PATH" ]; then
  rprint "Could not detect alembic.ini inside backend container. Attempting to list /app contents above."
  run_critical "Alembic configuration detection" false
else
  rprint "Detected alembic config at: $MIG_PATH"
  # Before running alembic, check alembic exists
  run_noncritical "alembic --version inside backend" docker compose exec -T backend alembic --version
  # Run alembic upgrade head (with retries waiting for DB readiness)
  attempt=1
  MIG_SUCCESS=1
  rprint "Running alembic upgrade head using $MIG_PATH (with retries for DB readiness)"
  while [ $attempt -le $MAX_RETRIES ]; do
    rprint "alembic attempt $attempt"
    if docker compose exec -T backend alembic -c "$MIG_PATH" upgrade head > /tmp/alembic_out 2>&1; then
      cat /tmp/alembic_out >>"$REPORT_FILE"
      MIG_SUCCESS=0
      rprint "Alembic upgrade succeeded on attempt $attempt"
      break
    else
      cat /tmp/alembic_out >>"$REPORT_FILE"
      rprint "Alembic upgrade failed on attempt $attempt, will retry after sleep"
      attempt=$((attempt+1))
      sleep $SLEEP_SEC
    fi
  done
  if [ $MIG_SUCCESS -ne 0 ]; then
    run_critical "Alembic upgrade head" false
  else
    run_critical "Alembic upgrade head" echo "alembic OK"
  fi
fi

# 5) Run backend pytest
run_critical "Backend pytest" docker compose exec -T backend pytest -q

# 6) Health endpoint checks (retrying)
check_http_endpoint() {
  label="$1"
  url="$2"
  attempts=12
  sleep_sec=5
  ok=1
  rprint "Checking HTTP endpoint $label -> $url"
  for i in $(seq 1 $attempts); do
    rprint "HTTP attempt $i"
    out=$(curl -sS -m 10 "$url" 2>&1) || rc=$?
    rc=${rc:-0}
    printf "%s\n" "$out" >>"$REPORT_FILE"
    if [ "$rc" -eq 0 ]; then
      rprint "$label HTTP OK"
      ok=0
      break
    else
      rprint "$label HTTP not ready (rc=$rc). Retrying in $sleep_sec s"
      sleep $sleep_sec
    fi
  done
  if [ $ok -ne 0 ]; then
    run_critical "HTTP $label" false
  else
    run_critical "HTTP $label" echo "OK"
  fi
}

# Use ports/paths per compose defaults — caller must ensure compose exposes correct ports
check_http_endpoint "root" "http://localhost:8000/"
check_http_endpoint "health_ping" "http://localhost:8000/health/ping"
check_http_endpoint "health_db" "http://localhost:8000/health/db"
check_http_endpoint "health_redis" "http://localhost:8000/health/redis"

# 7) Frontend checks: logs and HTTP header check
run_noncritical "Frontend logs (last 200 lines)" docker compose logs --tail=200 frontend
run_critical "Frontend HTTP HEAD" curl -sS -I -m 10 http://localhost:3000

# If package.json has build script, run build in frontend container
HAS_BUILD_SCRIPT=0
# detect build script inside package.json by reading file in host copy
if [ -f frontend/package.json ]; then
  if grep -q '"build"' frontend/package.json; then
    HAS_BUILD_SCRIPT=1
  fi
fi
if [ $HAS_BUILD_SCRIPT -eq 1 ]; then
  run_critical "Frontend production build (npm run build)" docker compose exec -T frontend npm run build
else
  rprint "No frontend build script detected in frontend/package.json; skipping production build step"
fi

# 8) Diagnostic non-critical storage commands
run_noncritical "docker system df" docker system df
run_noncritical "project du -sh ." du -sh .
run_noncritical "host df -h" df -h
run_noncritical "docker images" docker images
run_noncritical "docker volume ls" docker volume ls

# 9) Collect key container logs (non-critical)
run_noncritical "backend logs (last 500)" docker compose logs --tail=500 backend
run_noncritical "postgres logs (last 200)" docker compose logs --tail=200 postgres
run_noncritical "redis logs (last 200)" docker compose logs --tail=200 redis
run_noncritical "frontend logs (last 200)" docker compose logs --tail=200 frontend

# Final summary
rprint "================================"
rprint "PHASE 0 VALIDATION SUMMARY"
rprint "================================"
critical_checks="DockerCompose Backend PostgreSQL Redis Alembic BackendTests BackendHealth DBHealth RedisHealth Frontend FrontendBuild"
# We recorded passes/fails inline; now summarize based on CRITICAL_FAIL
if [ $CRITICAL_FAIL -eq 0 ]; then
  rprint "Overall              PASS"
  exit_code=0
else
  rprint "Overall              FAIL"
  rprint "Critical checks failed: $CRITICAL_FAIL"
  exit_code=1
fi
rprint "Report: $REPORT_FILE"
exit $exit_code
