# AGENTS.md

Internal Security Rating Platform - Permanent Engineering Rules

Project Objective
-----------------
Build an internal cybersecurity rating and continuous external exposure assessment platform inspired by SecurityScorecard (SSC).

SecurityScorecard is a benchmark/reference and optional integration. It is NOT a runtime dependency.

Do not implement or represent proprietary SecurityScorecard scoring algorithms as if they were known.

Permanent Rules
----------------
- Treat SecurityScorecard as a benchmark, public taxonomy/reference, and optional comparison source.
- The platform must continue to operate normally when no SSC account or API token exists.
- Public SSC information may be used to keep the catalog aligned but must not automatically overwrite production catalog.
- Public changes must enter a review/approval workflow.
- Build the application as a modular monolith with separate scanner workers.
- Preserve exact versions for issue taxonomy, detection rules, and scoring models in historical records.
- Follow the project implementation phases documented in docs/IMPLEMENTATION_STATUS.md.

See docs/PROJECT_PLAN.md and docs/IMPLEMENTATION_STATUS.md for further process and phase details.
