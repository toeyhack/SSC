# CLI and REPORT

The CLI is the primary product interface. FastAPI, React and Redis are optional for scans. PostgreSQL and migrated inventory/catalog/rule tables are required.

## Setup from source

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ./backend
docker compose up -d postgres
export DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost:5432/ssc
cd backend
python -m alembic -c migrations/alembic.ini upgrade head
ssc rules load --input examples/internal-detectors.json
```

The starter bundle contains internal catalog definitions and versioned detectors, not captured SSC licensed data. It is loaded only by an explicit command. Reloading identical definitions is idempotent; changed definitions create versions, with old versions preserved. Existing factor metadata is reused and not overwritten. Selecting an existing bundle version can change the current-version pointer, so load only a reviewed bundle. The real Golden Baseline importer remains `python -m app.cli.import_golden_baseline`.

Register a target you are authorized to assess:

```bash
ssc targets add --organization "Authorized organization" --domain example.com \
  --hostname app.example.com --approve --approval-notes "Approved external assessment"
ssc scan --target app.example.com --output report --output-dir ../reports
```

Host/domain registration is manual, with no discovery. The scan command requires an already approved concrete target and rechecks its approval at execution time. Targets are never automatically approved by `ssc scan`. Private/loopback fixtures also require explicit `--allow-sensitive` during registration. Metadata/link-local/multicast/unspecified targets are always prohibited. For ambiguous targets, pass `--organization-id <uuid>`. URLs and unregistered arbitrary IP addresses are rejected.

A domain-only email-policy scan can use:

```bash
ssc targets add --organization "Authorized organization" --domain example.com --approve
ssc scan --target example.com --executors dns --output report
```

`--rule-key <stable-key>` selects one active applicable rule; repeat the option for several. Without it, the CLI selects active definitions matching the inventory target type. The supplied starter WEB/TLS rules apply to HOST targets and DNS rules to DOMAIN targets. No active applicable rule fails before scanning.

## Executor configuration

```json
{
  "executors": ["http", "tls", "dns", "tcp"],
  "http_ports": [80],
  "https_ports": [443],
  "tls_ports": [443],
  "tcp_ports": [443],
  "request_timeout_seconds": 5,
  "connect_timeout_seconds": 3,
  "dns_timeout_seconds": 3,
  "redirect_limit": 5,
  "response_size_limit_bytes": 65536,
  "per_target_interval_seconds": 0.05
}
```

Save as `scan.json` and pass `--scan-config scan.json`. HTTP, TLS and DNS are enabled by default. TCP is added only when explicit TCP ports are configured, or selected with `--executors tcp`; it never selects a default range. Maximum distinct lists: 4 HTTP ports, 4 HTTPS ports, 3 TLS ports and 10 TCP ports. Redirects must remain on the authorized hostname and configured scheme/port. HTTP records a representative reachable response (preferring HTTPS) and attempt/redirect summaries; it does not crawl an application. An explicit `dns_server_host`/`dns_server_port` overrides the system resolver; sensitive resolver addresses require the target's sensitive-network permission.

## Outputs and exits

REPORT writes a fresh `scan-<run-id>-<suffix>` directory containing:

- `report.html`: self-contained, escaped HTML with overall/factor scores, findings, factor/overall score impact, affected targets, evidence summaries, coverage and remediation.
- `result.json`: validated `ssc.result.v1`, including the full scoring definition and exact historical version references.

The same normalized result is saved in PostgreSQL. Reports can be regenerated without network probes:

```bash
ssc report --run-id <uuid> --output-dir ../reports
```

`--scoring-model model.json` creates a separate result snapshot when the scoring definition changes. Refer to `SCORING.md` for the policy and coverage semantics.

Exit codes: `0` = assessed result/report success; `1` = validation, inventory, execution, database or output error; `2` = argument error or deferred SYGNOS mode; `3` = report written with an incomplete/unassessed result. Findings alone do not make the command fail. An incomplete result never silently claims a perfect score.

The future command is `ssc scan --target <target> --output sygnos`. It currently exits before database/network activity. Future structured Sygnos events must reuse exactly `ssc.result.v1`; ingestion mapping and transport remain deferred.

## Docker CLI

```bash
docker compose up -d postgres
docker compose run --rm --build cli --help
docker compose run --rm cli rules load --input examples/internal-detectors.json
docker compose run --rm cli scan --target app.example.com --output report --output-dir /reports
```

Register/approve inventory first, using the same `targets add` command through the service. The CLI service is in the optional `cli` profile; `docker compose run cli` explicitly selects it. The existing Web/API services and worker are preserved.

## Validation

Use an isolated PostgreSQL test database; API integration tests write synthetic inventory/catalog/rules/jobs. Install the CLI first so the actual `ssc` console entry point is tested.

```bash
DATABASE_URL=<isolated-postgresql-test-url> PYTHON=<venv-python> ./scripts/phase4b_validate.sh
DATABASE_URL=<isolated-postgresql-test-url> PYTHON=<venv-python> ./scripts/phase5_validate.sh
DATABASE_URL=<isolated-postgresql-test-url> PYTHON=<venv-python> ./scripts/phase6_validate.sh
```

The scripts run migrations and tests and are intended only for test databases. They do not deploy to or validate production.
