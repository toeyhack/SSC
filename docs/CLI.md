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

The starter bundle contains internal catalog definitions and versioned detectors, not captured SSC licensed data. It is loaded only by an explicit command. Reloading identical definitions is idempotent; changed definitions create versions, with old versions preserved. Existing factor metadata is reused and not overwritten. Selecting an existing bundle version can change the current-version pointer, so load only a reviewed bundle. Preferred initial SSC baseline acquisition is `ssc baseline pull-ssc`; `python -m app.cli.import_golden_baseline` remains the supported licensed UI/manual canonical JSON fallback.

## SSC taxonomy baseline

After migrations, provision `SSC_TOKEN` in the process environment through your credential workflow. Never put it into source files or a CLI argument. Then run:

```bash
ssc baseline status
ssc baseline pull-ssc --dry-run
ssc baseline pull-ssc --dry-run --enrich-details
ssc baseline pull-ssc
ssc baseline pull-ssc --yes --expect-hash <reviewed-content-hash>
ssc baseline discover-details
ssc baseline activate-wave1 --yes
ssc baseline activate-wave2 --yes
```

Without enrichment, `pull-ssc` uses only `GET https://api.securityscorecard.io/metadata/factors` and `GET https://api.securityscorecard.io/metadata/issue-types`; this is a complete minimum baseline and can establish taxonomy alignment after approval. `--enrich-details` optionally requests `/metadata/issue-types/{type}` with at most four workers, a 20-second request timeout and at most three attempts for safe transient transport failures or HTTP 408, 425, 429, 500, 502, 503 and 504 responses. Numeric or HTTP-date `Retry-After` is honored up to 60 seconds; longer or invalid delays fail that lookup instead of retrying early. Permanent failures are not retried. An individual detail failure is reported but retains that issue's list metadata and does not discard the baseline.

`pull-ssc` displays source, counts, optional detail success/failure counts, capture time, content hash and existing match before import. The default prompts on a terminal; noninteractive imports require `--yes`. `--dry-run` never writes. `--expect-hash` prevents committing data that changed since review. Same content reuses the original baseline. Failed authentication/acquisition leaves the current catalog unchanged. Baseline commands return 0 on success and 1 on acquisition, validation, approval or database failure; invalid arguments return 2.

`discover-details` reads the three sample issue detail endpoints and reports returned field names/paths without changing the catalog. Live discovery on 2026-09-19 returned exactly `key`, `severity`, `factor`, `title`, `short_description`, `long_description` and `recommendation` for every tested issue. See `GOLDEN_BASELINE_IMPORTER.md` for the observed-field record and storage mapping.

`status` works offline. `INTERNAL_ONLY` means no real SSC baseline has been recorded; all existing runtime features remain available without claiming alignment. `SSC_ALIGNED` requires at least one real imported SSC baseline with provenance. It does not imply scoring calibration. For real licensed UI/manual canonical JSON, use `python -m app.cli.import_golden_baseline --input <capture.json> --attest-real-source --json` on its first import. Never attest synthetic fixtures. Previously unattested snapshots cannot be relabeled on reuse.

`activate-wave1 --yes` idempotently creates or selects the reviewed `HTTP_HEADERS`, `HTTP_REDIRECT`, and `TLS_CERTIFICATE` evaluator versions. `activate-wave2 --yes` does the same for the evidence-complete `TLS_HANDSHAKE` and `EMAIL_SECURITY` definitions. Activation succeeds only for exact current issue definitions contained in an attested real `SSC_API` snapshot. Each evaluator version stores a foreign key to that immutable issue version. Approved future SSC definition changes create a new linked rule version; they do not rewrite history. A newly approved `pull-ssc` import performs both reconciliations automatically.

Preferred initial SSC baseline: SSC API metadata endpoints. Fallback: licensed UI/manual canonical JSON. Future taxonomy updates: SSC API and/or reviewed public SSC methodology changes. Runtime: no SSC dependency. Neither scan nor report calls SSC. API `severity` stays separate from internal risk, breach risk, threat level, score impact and scoring relevance. API issues remain `breach_risk=UNKNOWN` and `threat_level=null` unless another authoritative source explicitly supplies those semantics.

## Authorized target registration

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
  "http_paths": ["/", "/login"],
  "tls_ports": [443],
  "trusted_self_signed_fingerprints": [],
  "tcp_ports": [443],
  "request_timeout_seconds": 5,
  "connect_timeout_seconds": 3,
  "dns_timeout_seconds": 3,
  "redirect_limit": 5,
  "response_size_limit_bytes": 65536,
  "per_target_interval_seconds": 0.05
}
```

Save as `scan.json` and pass `--scan-config scan.json`. HTTP, TLS and DNS are enabled by default. TCP is added only when explicit TCP ports are configured, or selected with `--executors tcp`; it never selects a default range. Maximum distinct lists: 4 HTTP ports, 4 HTTPS ports, 20 explicit same-target HTTP paths, 3 TLS ports and 10 TCP ports. Redirects must remain on the authorized hostname and configured scheme/port.

HTTP preserves every relevant header instance, redacted cookie attributes, CSP meta/header policies, a declared-path coverage manifest, and every normalized redirect hop/stop reason. It fetches only configured paths; it is not a general crawler. TLS preserves certificate evidence plus offered/negotiated TLS versions, actual accepted ciphers, alerts and policy/catalog versions. `trusted_self_signed_fingerprints` is an optional reviewed SHA-256 allowlist; it does not modify system trust. DNS preserves TXT response status, records, SPF/DMARC analysis and nonce wildcard queries. `email_subdomains` may contain at most 20 explicitly declared names strictly below the inventory domain; no subdomain discovery or organizational-domain inference is performed. An explicit `dns_server_host`/`dns_server_port` overrides the system resolver; sensitive resolver addresses require the target's sensitive-network permission.

Wave 1 and Wave 2 findings use tri-state evaluators: positive evidence creates a finding, a deterministic non-match creates none, and insufficient/malformed evidence is skipped as indeterminate. Reports show SSC issue key and SSC source severity separately from internal risk and scoring.

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
