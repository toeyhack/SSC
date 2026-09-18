# README

Internal Security Rating Platform (SSC App)

The primary product interface is the `ssc` CLI. Completed Phase 0–4 work and the existing Web/API/frontend are preserved as optional interfaces. Dashboard-centric development is paused.

```bash
pip install -e ./backend
ssc scan --target <approved-inventory-target> --output report
```

REPORT writes human-readable HTML and machine-readable JSON from one versioned normalized result, including scores, findings, impact, targets, evidence and remediation. PostgreSQL and pre-approved inventory/rules are required; running the Web server or frontend is unnecessary. See [CLI setup and operation](docs/CLI.md), [roadmap](docs/ROADMAP.md) and [architecture](docs/ARCHITECTURE.md).

Phase 4B adds real authorized HTTP/TLS/DNS/TCP executors. Phase 5 adds internal versioned scoring and saved result snapshots. Phases 6A/6B add the CLI and REPORT adapter. SYGNOS structured event mapping and transport are deferred until the ingestion interface is known.

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

Phase 1C adds a catalog administration workspace for factors, issues, versions, snapshots, and baseline preview/import.

Phase 2 adds manual asset inventory for organizations, domains, hosts, and host groups.

Phase 3 adds versioned rule-engine definitions for later scanner use.

Phase 4 adds scan job orchestration, deterministic rule evaluation against supplied evidence, scan findings, and an optional worker process.

Follow docs/IMPLEMENTATION_STATUS.md for progress and next steps.
