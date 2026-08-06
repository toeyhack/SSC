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

No scoring UI, charts, baseline importer, or advanced administration workflows are included in Phase 1A.
