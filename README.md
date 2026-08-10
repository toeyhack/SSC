# README

Internal Security Rating Platform (SSC App)

This repository contains the initial foundation for the Internal Security Rating Platform.

See AGENTS.md for the permanent engineering rules and project objectives.

Phase 0 implements:
- repository skeleton
- docs
- Docker Compose (Postgres, Redis, backend, frontend)
- FastAPI backend skeleton with health endpoints
- SQLAlchemy models and Alembic scaffold
- React + Vite frontend skeleton
- basic tests

Phase 1A implements the versioned issue catalog data model, catalog API, backend tests, validation script, and minimal Issue Catalog frontend view.

Phase 1B implements the Golden Baseline importer for canonical SSC licensed-UI capture JSON. See `docs/GOLDEN_BASELINE_IMPORTER.md`.

Follow docs/IMPLEMENTATION_STATUS.md for progress and next steps.
