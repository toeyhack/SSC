# Implementation Status

Current phase: Phase 1A - Issue Catalog Data Model + Catalog API

## Phase Status

Phase 0 - Foundation: COMPLETE / PASS

Phase 1A - Issue Catalog Data Model + Catalog API: COMPLETE / PASS

Phase 1B - Golden Baseline Importer: NOT STARTED

Phase 1C - Catalog Administration / Review UI: NOT STARTED

Phase 2 - Asset Inventory: NOT STARTED

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
