# Architecture

The platform is a modular monolith with separate scanner workers planned for later phases.

Current runtime:

```text
Browser
  -> React/Vite frontend
  -> FastAPI backend
  -> PostgreSQL
  -> Redis
```

SecurityScorecard is not a runtime dependency. It is treated only as a benchmark, taxonomy reference, optional comparison source, or optional future integration.

## Backend Modules

Phase 0 provides the FastAPI application, health endpoints, SQLAlchemy database session, Alembic migrations, PostgreSQL, Redis, and Docker Compose development runtime.

Phase 1A adds the issue catalog module:

- SQLAlchemy models in `app.models.catalog_models`
- Pydantic v2 schemas in `app.schemas.catalog`
- REST API routes in `app.api.catalog`
- Alembic revision `0002_phase1a_catalog`

Phase 1B adds the Golden Baseline importer:

- canonical SSC licensed-UI capture JSON schema
- import service in `app.services.golden_baseline_importer`
- CLI entry point `python -m app.cli.import_golden_baseline`
- synthetic importer validation fixture under `backend/tests/fixtures`

The importer writes only to the Phase 1A catalog tables. It does not integrate with SSC APIs, scrape public SSC pages, scan assets, or compute scores.

Phase 1C adds the catalog administration and review workspace:

- issue catalog table with search and breach-risk filtering
- factor creation and active-state management
- issue identity creation and active-state management
- immutable issue-version creation and version-history review
- snapshot review
- golden baseline JSON preview/import UI backed by the Phase 1B importer service

Phase 1C remains catalog-only. It does not add scanner execution, scoring, asset inventory, SSC API calls, or public-web synchronization.

The catalog API prefix is:

```text
/api/v1/catalog
```

## Catalog Versioning

`CatalogIssueType` represents a stable logical issue identity. `CatalogIssueTypeVersion` represents a specific definition of that issue at a point in time.

Definition changes create new version rows. Historical rows are never overwritten, which preserves:

- issue taxonomy history
- snapshot history
- future finding-to-rule history
- future score reproducibility

`CatalogSnapshot` and `CatalogSnapshotItem` preserve captured catalog states by referencing exact issue-version rows.

## Frontend

Phase 1A adds a minimal Issue Catalog page that reads from the backend API and displays:

- Factor
- Issue Name
- Breach Risk
- Threat Level
- Affects Score
- Version
- Active

No scoring UI, charts, scanner UI, asset inventory UI, or public reference review workflows are included through Phase 1C.
