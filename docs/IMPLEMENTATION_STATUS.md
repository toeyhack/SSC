# Implementation Status

Current phase: Phase 2 - Asset Inventory

## Phase Status

Phase 0 - Foundation: COMPLETE / PASS

Phase 1A - Issue Catalog Data Model + Catalog API: COMPLETE / PASS

Phase 1B - Golden Baseline Importer: COMPLETE / PASS

Phase 1C - Catalog Administration / Review UI: COMPLETE / PASS

Phase 2 - Asset Inventory: COMPLETE / PASS

Phase 3 - Rule Engine: NOT STARTED

Phase 4 - Scan Engine: NOT STARTED

Phase 5 - Scoring Engine: NOT STARTED

Phase 6 - Dashboard / Usable Internal Platform: NOT STARTED

Phase 7 - SSC Public Reference Sync: NOT STARTED

Phase 8 - Optional SSC API Integration: NOT STARTED

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

SecurityScorecard remains a reference source only. Phase 1B does not add SSC API integration, SSC public-web scraping, scanners, scoring, or asset inventory.

The repository does not contain the real captured SecurityScorecard licensed-UI catalog. The real Golden Baseline import still requires an external JSON file matching `docs/GOLDEN_BASELINE_IMPORTER.md`.

## Phase 1B Validation

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
