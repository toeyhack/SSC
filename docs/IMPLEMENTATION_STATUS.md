# Implementation Status

CLI-FIRST MVP — COMPLETE / PASS

Current phase: Phase 6B - CLI-first REPORT Output

Direction correction: Phase 1B SSC API baseline acquisition extension; CLI-FIRST MVP behavior preserved.

Primary product interface: CLI (`ssc`). Web/API/frontend: OPTIONAL / PRESERVED.

Dashboard-centric work: PAUSED. Implementation sequence: Phase 4B PASS → Phase 5 PASS → Phase 6A CLI → Phase 6B REPORT. SYGNOS ingestion mapping and transport wait for its interface definition.

Phase 0–4 completion and historical validation below are preserved. Completed Phases 4B, 5, 6A and 6B form the CLI-first MVP milestone. This milestone closes the validated implementation; no production deployment or runtime data migration is performed. The preceding Phase 4 commit is `bb11f1b3557a190842eee33b31a1ab137771c026` (`Phase 4: implement scan engine`, 2026-08-10 15:29:45 +07:00). Use Git history for the exact MVP commit hash.

## Phase Status

Phase 0 - Foundation: COMPLETE / PASS

Phase 1A - Issue Catalog Data Model + Catalog API: COMPLETE / PASS

Phase 1B - Golden Baseline Importer: COMPLETE / PASS

Real SSC Golden Baseline: API availability verified by the operator; production import NOT PERFORMED in this implementation. Live read-only issue-detail discovery COMPLETE on 2026-09-19; no catalog or database write was performed.

Phase 1C - Catalog Administration / Review UI: COMPLETE / PASS

Phase 2 - Asset Inventory: COMPLETE / PASS

Phase 3 - Rule Engine: COMPLETE / PASS

Phase 4 - Scan Engine: COMPLETE / PASS

Phase 4B - Authorized HTTP/TLS/DNS/TCP Scan Executors: COMPLETE / PASS

Phase 5 - Scoring Engine: COMPLETE / PASS

Phase 6A - Primary CLI Interface: COMPLETE / PASS

Phase 6B - REPORT HTML/JSON Output: COMPLETE / PASS

Phase 6C - SYGNOS Structured Event Adapter: NOT STARTED / DEFERRED UNTIL INGESTION INTERFACE IS KNOWN

Phase 6D - Optional Web Dashboard: PAUSED / NOT STARTED

The former dashboard-first Phase 6 is superseded by 6A–6D. Existing Web administration through Phase 4 remains preserved.

Phase 7 - SSC Public Reference Sync: NOT STARTED

Phase 8 - Broader Optional SSC API Integration: NOT STARTED; initial metadata acquisition brought forward into Phase 1B

Phase 9 - SSC Comparison / Calibration: NOT STARTED

Phase 10 - Production Hardening: NOT STARTED

## Phase 0 Validation

Phase 0 runtime validation: COMPLETE / PASS

Last locally verified report:

```text
reports/phase0-validation-20260806-172053.txt
```

Validated Phase 0 checks included Docker Compose build/start, Alembic migration, backend tests, root and health endpoints, PostgreSQL health, Redis health, frontend HTTP, and frontend production build.

## Phase 1A Implemented Scope

Phase 1A adds:

- `catalog_factors`
- `catalog_issue_types`
- `catalog_issue_type_versions`
- `catalog_snapshots`
- `catalog_snapshot_items`
- Alembic revision `0002_phase1a_catalog`
- `/api/v1/catalog` backend API
- Pydantic v2 catalog schemas
- backend tests for catalog creation, duplicates, immutable versions, current-version behavior, informational and positive breach risks, snapshots, and duplicate snapshot items
- minimal frontend Issue Catalog page
- `scripts/phase1a_validate.sh`

Immutable history rule:

Issue definition changes create new `catalog_issue_type_versions` rows. Historical version rows and snapshot references are not overwritten.

## Phase 1A Validation

Phase 1A runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase1a-validation-20260806-183254.txt
```

Validated Phase 1A checks included Docker Compose build/start, backend container exec, Alembic version detection, Alembic upgrade to head, backend pytest, root and health endpoints, OpenAPI docs, catalog list endpoints, frontend HTTP, frontend production build, storage diagnostics, and container logs.

## Phase 1B Implemented Scope

Phase 1B adds:

- canonical JSON input schema `phase1b.ssc_licensed_ui.v1`
- validation for source type, factor codes, issue stable keys, breach risk, threat level, capture timestamp, duplicate issues, and source ordering
- `app.services.golden_baseline_importer` import service
- `python -m app.cli.import_golden_baseline` CLI with dry-run/preview mode
- SHA-256 content hashing over normalized canonical JSON
- exact-content idempotency by `SSC_LICENSED_UI` snapshot content hash
- factor creation/reuse by code without metadata overwrite
- issue type creation/reconciliation by explicit `stable_key`
- issue version creation only when definition fields change
- immutable `CatalogSnapshot` and `CatalogSnapshotItem` creation using Phase 1A tables
- preservation of factor and issue source ordering in snapshot item positions
- controlled rename/unknown handling that rejects ambiguous name collisions instead of merging by name
- synthetic validation fixture at `backend/tests/fixtures/phase1b_sample_baseline.json`
- importer documentation at `docs/GOLDEN_BASELINE_IMPORTER.md`
- backend tests for dry-run, idempotency, version changes, ordering, and ambiguous rename handling
- `scripts/phase1b_validate.sh`

The original Phase 1B milestone used licensed-UI JSON only and did not add SSC API integration, SSC public-web scraping, scanners, scoring, or asset inventory. The acquisition extension documented below adds the preferred API metadata source.

The repository does not contain a real captured SSC catalog. The real Golden Baseline can now be acquired through SSC API metadata; an external JSON file matching `docs/GOLDEN_BASELINE_IMPORTER.md` remains the fallback.

## Phase 1B Validation

### SSC API acquisition extension (2026-09-19)

Preferred initial SSC baseline: SSC API metadata endpoints. Fallback: licensed UI/manual canonical JSON. Future taxonomy updates: SSC API and/or reviewed public SSC methodology changes. Runtime: no SSC dependency.

The extension adds `ssc baseline pull-ssc`, optional `--enrich-details`, `status` and read-only `discover-details`; environment-only authentication; immutable raw API responses and normalized membership; API content hashing/idempotency; separate SSC severity metadata; migration `0008_ssc_api_baseline`; and mocked regression tests. A real baseline is required once for `SSC_ALIGNED`; otherwise the platform remains `INTERNAL_ONLY` with all existing CLI/scanner/rules/scoring/report functionality available. Manual real captures support explicit `--attest-real-source`; internal/synthetic/legacy unattested snapshots do not silently establish alignment.

The complete minimum baseline uses `GET https://api.securityscorecard.io/metadata/factors` and `GET https://api.securityscorecard.io/metadata/issue-types`. Optional enrichment uses `/metadata/issue-types/{type}` with four workers, a 20-second timeout, bounded safe-transient retries and per-issue failure isolation; it is not required for taxonomy alignment. Successful details preserve the exact response in versioned `ssc_metadata`; `short_description` also populates the existing issue-version description.

Live discovery verified HTTP 200 for `tls_weak_protocol`, `cookie_missing_http_only` and `csp_no_policy_v2`. Every response contained exactly `key`, `severity`, `factor`, `title`, `short_description`, `long_description` and `recommendation`, with no additional or nested fields. No returned field explicitly represented internal risk, Breach Risk, Threat Level, score impact or scoring relevance. SSC severity remains separate and unmapped; API issue versions remain `breach_risk=UNKNOWN` and `threat_level=null` unless another authoritative source explicitly provides them.

Validation: COMPLETE / PASS. `scripts/validate_cli_first.sh` passed against isolated PostgreSQL on Python 3.14: **111 tests passed** (71 existing + 40 SSC acquisition/enrichment cases), with the same two dependency deprecation warnings. Phase 4B and Phase 5 regression gates passed with 92 and 103 tests respectively. Downgrade to `0005_phase4_scan_engine`, re-upgrade, Alembic schema check (no new operations), compileall and pip check passed. Alembic reports the existing mutually dependent foreign-key sorting warning. Test HTTP responses are mocked; no live SSC access is required. Validation logs: `reports/phase4b-validation-20260919-224128.txt`, `reports/phase5-validation-20260919-224128.txt`, `reports/phase6-validation-20260919-224128.txt`.

New coverage includes normalization and unknown fields, factor/issue membership, provenance and raw immutability, hash/order/time idempotency, changed issue/factor metadata, alignment gating and real manual attestation, secret exclusion, authentication/partial-response failures, transaction rollback, redirects/pagination/size bounds, detail field discovery and CLI review/approval/hash checks. Historical validation below is preserved. No production migration, baseline import, push, company score comparison, calibration, public sync, dashboard, Sygnos transport or new scanner checks are part of this extension.

Final regression after optional enrichment passed 111 tests in 12.21s with two dependency warnings. The preserved frontend production build had already passed in an isolated temporary copy (Vite 5.4.21); no frontend source or dependency manifest changed. Installing that existing manifest reported two dependency advisories (one moderate, one high); dependency upgrades remain outside this change. `git diff --check` passed. Live detail discovery is complete. Production baseline acquisition remains pending by explicit instruction.

Phase 1B runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase1b-validation-20260810-092229.txt
```

Validated Phase 1B checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, importer dry-run, importer import, exact-content idempotency, root and health endpoints, catalog snapshot endpoint, and container log diagnostics.

## Phase 1C Implemented Scope

Phase 1C adds:

- catalog administration workspace in the React frontend
- issue catalog search and breach-risk filtering
- factor creation and active-state management
- issue identity creation and active-state management
- issue-version creation with current-version selection
- version-history review for selected issues
- catalog snapshot review
- Golden Baseline JSON preview/import UI backed by Phase 1B importer service
- backend preview/import endpoints:
  - `POST /api/v1/catalog/golden-baseline/preview`
  - `POST /api/v1/catalog/golden-baseline/import`
- backend tests for the admin preview/import endpoint behavior and idempotency
- `scripts/phase1c_validate.sh`

SecurityScorecard remains a reference source only. Phase 1C does not add SSC API integration, SSC public-web scraping, scanners, scoring, asset inventory, or public reference sync.

## Phase 1C Validation

Phase 1C runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase1c-validation-20260810-094850.txt
```

Validated Phase 1C checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, Golden Baseline preview endpoint, root and health endpoints, catalog list endpoints, frontend HTTP, frontend production build, and container log diagnostics.

## Phase 2 Implemented Scope

Phase 2 adds:

- formalized asset inventory metadata on the Phase 0 scaffold tables
- Alembic revision `0003_phase2_asset_inventory`
- inventory models for organizations, domains, hosts, host groups, and group members
- Pydantic inventory schemas
- REST API module at `/api/v1/inventory`
- uniqueness constraints for organization names, domain names per organization, hostnames per domain, host group names per organization, and host group membership
- same-organization validation for host group membership
- frontend Inventory tab for manual organization, domain, host, host group, and group member management
- backend tests for inventory lifecycle, duplicate handling, active-state updates, and membership validation
- `scripts/phase2_validate.sh`

Phase 2 is manual asset inventory only. It does not add scanning, discovery, findings, scoring, SSC API integration, or SSC public-web scraping.

## Phase 2 Validation

Phase 2 runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase2-validation-20260810-143424.txt
```

Validated Phase 2 checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, root and health endpoints, inventory list endpoints, frontend HTTP, frontend production build, and container log diagnostics.

## Phase 3 Implemented Scope

Phase 3 adds:

- versioned rule-engine definition tables
- Alembic revision `0004_phase3_rule_engine`
- `rule_engine_rules`
- `rule_engine_rule_versions`
- rule source types `MANUAL`, `INTERNAL`, and `SSC_REFERENCE`
- rule target types `DOMAIN`, `HOST`, `URL`, `CERTIFICATE`, `IP`, and `ORGANIZATION`
- optional linkage from rule identities to catalog issue types
- immutable rule-version creation with current-version selection
- REST API module at `/api/v1/rules`
- frontend Rules tab for rule identities, rule versions, JSON rule expressions, and version-history review
- backend tests for rule lifecycle, duplicate handling, catalog linkage, current-version validation, and expression validation
- `scripts/phase3_validate.sh`

Phase 3 stores rule definitions only. It does not add scan execution, scanner workers, findings, scoring, SSC API integration, SSC public-web scraping, or proprietary SSC logic.

## Phase 3 Validation

Phase 3 runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase3-validation-20260810-150157.txt
```

Validated Phase 3 checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, root and health endpoints, rule list endpoint, catalog and inventory list endpoints, frontend HTTP, frontend production build, and container log diagnostics.

## Phase 4 Implemented Scope

Phase 4 adds:

- scan job, scan target, scan run, and scan finding tables
- Alembic revision `0005_phase4_scan_engine`
- `scan_jobs`
- `scan_job_targets`
- `scan_runs`
- `scan_findings`
- deterministic JSON rule-expression evaluation for supplied evidence
- exact finding references to immutable rule versions
- exact finding references to linked catalog issue versions when available at scan time
- REST API module at `/api/v1/scans`
- synchronous scan run endpoint for explicit admin-triggered execution
- scanner worker CLI `python -m app.cli.scan_worker`
- optional Docker Compose `scanner_worker` service under the `workers` profile
- frontend Scans tab for queueing jobs, running jobs, and reviewing findings
- backend tests for scan job lifecycle, rule evaluation, findings, exact rule-version references, and validation errors
- `scripts/phase4_validate.sh`

Phase 4 does not add scoring, external network probing, automated asset discovery, SSC API integration, SSC public-web scraping, or proprietary SSC logic.

## Phase 4 Validation

Phase 4 runtime validation: COMPLETE / PASS

Validation report:

```text
reports/phase4-validation-20260810-152733.txt
```

Validated Phase 4 checks included Docker Compose build/start, backend container exec, Alembic upgrade to head, backend pytest, scanner worker once, root and health endpoints, scan/rule/inventory endpoints, frontend HTTP, frontend production build, and container log diagnostics.


## Phase 4B Implemented Scope

Phase 4B completes the pre-existing uncommitted executor draft after Phase 4:

- real HTTP/HTTPS, TLS, DNS TXT and explicit-port TCP executors in `app.services.scan_executors`
- manual inventory authorization (`approved_for_scan`, sensitive-network permission and approval notes)
- active inventory and concrete-target approval checks at queueing and execution; revocation blocks queued scans
- checked-IP connection pinning, HTTP Host and TLS SNI preservation, prohibited-address checks and constrained redirects
- bounded port lists, socket/resolver timeouts, redirect count and HTTP response reads
- redacted cookie attributes, security header/redirect observations, certificate metadata/trust/legacy TLS probes, SPF/DMARC TXT normalization and TCP connection observations
- evidence-source provenance and `scan_observations`, `scan_config`, finding source fields
- Alembic file `0006_phase4b_authorized_scan_executors.py`, with revision ID `0006_phase4b_executors` (within Alembic's default version-column length)
- observation API at `GET /api/v1/scans/runs/{scan_run_id}/observations`
- rule assessment/factor and target identity snapshots in new scan summaries
- deterministic evaluator extracted to `app.services.rule_evaluation`, with Phase 4 compatibility imports retained
- failed scan history preserved after transaction rollback
- existing optional frontend draft preserved; no new dashboard development
- `scripts/phase4b_validate.sh`

Unsuccessful collection is distinct from absent protection. Unavailable evidence skips applicable detection rules and does not silently produce missing-header/SPF/DMARC findings. Legacy TLS support is unknown when local capability or probe failure is inconclusive. DNS-only domains need no target A/AAAA record. No discovery, range scanning, SSC API calls or SSC scraping is added.

## Phase 4B Validation

Phase 4B local validation: COMPLETE / PASS.

First gate passed before scoring implementation: 45 backend tests and worker-once validation after migrations from empty PostgreSQL through `0006_phase4b_executors`.

Final Phase 4B/legacy subset: 51 tests passed. Validation report: `reports/phase4b-validation-20260918-160055.txt`.

Fixtures perform real authorized local HTTP/HTTPS/DNS/TCP operations. Checks include successful TLS certificate extraction and SNI, trust failure, legacy protocol rejection, configured ports, redaction, sensitive/prohibited addresses, address pinning, redirect boundaries, invalid configuration, timeouts, DNS collection failure semantics, DNS-only targets and approval revoked after queueing. No external target was scanned.

## Phase 5 Implemented Scope

- pure internal scoring engine `app.services.scoring_engine`
- documented `internal-exposure` v1.0 policy, default HIGH/MEDIUM/LOW penalties and factor weighting
- per-factor and overall scores, deduplicated/capped per-finding factor impact and weighted overall impact
- informational/positive/opt-out/resolved findings do not deduct points
- no assessed overall score when evidence/rule/catalog coverage is incomplete
- normalization using exact historical rule/catalog versions, captured factor identity, affected targets, evidence and remediation
- complete model definition, exact model name/version and canonical SHA-256 preserved in results
- append-only service snapshots in `score_results`, unique by run/model hash; changed model definitions create additional results
- Alembic revision `0007_phase5_score_results`
- shared Pydantic contract `ssc.result.v1` in `app.schemas.results`
- `docs/SCORING.md` and `scripts/phase5_validate.sh`

This is an explicitly defined internal model, not proprietary SSC scoring. Historical Phase 4 runs are preserved; absent new assessment metadata yields an unassessed result rather than an invented score.

## Phase 5 Validation

Phase 5 local validation: COMPLETE / PASS.

The scoring gate passed before CLI/REPORT implementation: 55 tests, including persisted score snapshots and historical-version retention after current rule/catalog/factor changes.

Final Phase 5/legacy subset: 62 tests passed. Validation report: `reports/phase5-validation-20260918-160055.txt`.

Checks include weighted scores, penalty allocation/deduplication/capping, risk exemptions, unknown/unlinked definitions, incomplete coverage, configuration validation, deterministic hashes, idempotent snapshots and separate snapshots on model changes.

## Phase 6A/6B Implemented Scope

- installable primary `ssc` console command, with `python -m app.cli.ssc` equivalent
- `ssc scan --target <target> --output report` using approved registered inventory and shared services directly
- CLI target registration/approval and versioned internal detector-bundle loading; idempotent definitions preserve old versions
- rule selection, executor configuration, scoring configuration and organization disambiguation
- report regeneration from saved scan results without network probes
- independent REPORT adapter producing escaped, self-contained `report.html` and `result.json` in a fresh output directory
- overall/factor scores, findings, score impact, affected target, evidence summary, coverage and remediation in outputs
- both outputs consume the same validated, saved `ssc.result.v1` model
- explicit incomplete-result exit code with report written and unassessed overall score
- `--output sygnos` reserved and rejected before database/network activity; no Sygnos event mapping or transport implemented
- optional Docker Compose `cli` service and registered CLI in the Python 3.12 backend image; existing API command/services retained
- `docs/CLI.md`, `docs/ROADMAP.md`, CLI-first architecture and `scripts/phase6_validate.sh`

## Phase 6A/6B and Overall Validation

Phase 6A/6B local validation: COMPLETE / PASS.

Full suite: 71 tests passed, with 2 dependency deprecation warnings, on Python 3.14 and Python 3.12.

Validation reports:

- `reports/phase6-validation-20260918-160055.txt`
- `reports/cli-first-validation-20260918.txt`
- `reports/cli-first-final-tests-20260918.txt`
- `reports/docker-cli-build-20260918.txt`
- `reports/docker-cli-tests-20260918.txt`

The full suite includes the installed `ssc` subprocess, real four-executor pipeline → evidence → findings → scoring → HTML/JSON, matching persisted normalized results, report regeneration, HTML escaping, retained artifacts, incomplete-report behavior, rejected unapproved targets and SYGNOS preflight rejection. The optional Compose configuration parses successfully. Final executor regression verifies that redirects from all HTTP attempts remain visible when HTTPS is selected for header assessment. Python 3.12 Docker build succeeds with the console command installed.

Migration downgrade to Phase 4 and re-upgrade to `0007` pass on the disposable database; the full suite passes again afterward. Alembic metadata check reports no new upgrade operations, with a warning about pre-existing cyclic catalog/rule foreign keys. Python compilation and dependency checks pass.

Validation uses a separate temporary PostgreSQL database and local fixtures. Existing SSC data and running services were not migrated or replaced. Existing Web/frontend Phase 0–4 runtime validation is historical; no new browser/dashboard validation is claimed. Production deployment and hardening remain incomplete.


## CLI-first MVP Milestone Closeout

CLI-FIRST MVP — COMPLETE / PASS

Closeout review confirms the authorized HTTP/TLS/DNS/TCP executors, deterministic rule evaluation, version-linked findings, versioned internal scoring, installed CLI scan command, self-contained HTML report and JSON normalized result remain intact. Completed Phase 0–4 work and the existing optional Web/API/frontend are preserved.

The implementation matches the validated source: 71 tests pass on Python 3.12 and Python 3.14, with two dependency deprecation warnings. Docker build, migration downgrade/upgrade, metadata, compilation, dependency and Compose checks passed. Closeout changes only mark the milestone and exclude local artifacts; no new product feature is added.

Commit contents are limited to source, migrations, synthetic detector definitions/tests, configuration, documentation and validation scripts. Generated reports, caches, build output, secrets and local runtime data are excluded. Validation report paths above reference local evidence intentionally ignored by Git.

Final CLI command: `ssc scan --target <approved-target> --output report`.

Deferred items remain: SYGNOS event mapping/transport pending its ingestion interface; optional dashboard development paused; real SSC Golden Baseline waiting for source data; Phases 7–10 (public reference sync, optional SSC integration, comparison/calibration and production hardening) not started.
