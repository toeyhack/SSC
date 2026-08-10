# Database Design

The application uses PostgreSQL with SQLAlchemy 2 and Alembic migrations.

## Phase 1A Issue Catalog

Phase 1A adds versioned issue-catalog tables under the `catalog_*` namespace. These tables are separate from the Phase 0 placeholder `factors`, `issue_types`, and `issue_type_versions` scaffold tables.

### `catalog_factors`

Stores issue factor groupings.

Key fields:
- `id`
- `code`
- `name`
- `description`
- `display_order`
- `is_active`
- `created_at`
- `updated_at`

Constraints:
- `code` is unique.

### `catalog_issue_types`

Stores stable logical issue identities. Mutable definition fields are intentionally not stored here.

Key fields:
- `id`
- `stable_key`
- `factor_id`
- `current_version_id`
- `is_active`
- `created_at`
- `updated_at`

Constraints and indexes:
- `stable_key` is unique.
- `factor_id` references `catalog_factors.id`.
- `current_version_id` references `catalog_issue_type_versions.id`.
- `ix_catalog_issue_types_factor_id` supports factor-scoped catalog browsing.

`current_version_id` must point to a version belonging to the same issue type. This same-parent rule is enforced in service/API logic because the schema has two foreign-key paths between issue identities and versions.

### `catalog_issue_type_versions`

Stores immutable issue definitions. A definition change creates a new row with the next `version_number`; old rows are not rewritten.

Key fields:
- `id`
- `issue_type_id`
- `version_number`
- `name`
- `description`
- `breach_risk`
- `threat_level`
- `affects_score`
- `source_type`
- `source_reference`
- `source_snapshot_hash`
- `effective_from`
- `effective_to`
- `created_at`

Supported `breach_risk` values:
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFORMATIONAL`
- `POSITIVE`
- `UNKNOWN`

`breach_risk` and `threat_level` are separate fields. Informational and positive catalog entries are preserved without forcing them into risk-reducing semantics.

Constraints and indexes:
- unique `(issue_type_id, version_number)`
- `issue_type_id` references `catalog_issue_types.id`
- `ix_catalog_issue_type_versions_issue_type_id`
- `ix_catalog_issue_type_versions_breach_risk`

### `catalog_snapshots`

Stores immutable catalog capture metadata.

Key fields:
- `id`
- `name`
- `source_type`
- `source_reference`
- `captured_at`
- `imported_at`
- `content_hash`
- `notes`
- `created_at`

Supported `source_type` values:
- `MANUAL`
- `SSC_LICENSED_UI`
- `SSC_PUBLIC_WEB`
- `SSC_API`

SecurityScorecard is stored only as a possible source/reference. The platform does not require an SSC account or token at runtime.

### `catalog_snapshot_items`

Connects snapshots to the exact issue-version rows captured in that snapshot.

Key fields:
- `id`
- `catalog_snapshot_id`
- `issue_type_version_id`
- `factor_position`
- `issue_position`

Constraints and indexes:
- unique `(catalog_snapshot_id, issue_type_version_id)`
- `catalog_snapshot_id` references `catalog_snapshots.id`
- `issue_type_version_id` references `catalog_issue_type_versions.id`
- `ix_catalog_snapshot_items_catalog_snapshot_id`

Historical snapshots continue to reference the original `catalog_issue_type_versions` rows even when an issue type later points to a newer current version.

## Phase 1B Golden Baseline Importer

Phase 1B does not add database tables. It imports canonical SSC licensed-UI baseline JSON into the Phase 1A `catalog_*` tables.

Importer behavior:

- `catalog_snapshots.source_type` is `SSC_LICENSED_UI`
- `catalog_snapshots.captured_at` comes from the baseline input
- `catalog_snapshots.imported_at` is set by the importer runtime
- `catalog_snapshots.content_hash` stores the SHA-256 hash of normalized canonical input JSON
- `catalog_snapshot_items.factor_position` and `catalog_snapshot_items.issue_position` preserve source ordering
- `catalog_issue_type_versions.source_snapshot_hash` stores the baseline content hash for versions created by the import

Exact-content idempotency is enforced in service logic by reusing an existing `SSC_LICENSED_UI` snapshot with the same content hash.

## Phase 2 Asset Inventory

Phase 2 formalizes the Phase 0 inventory scaffold for manually managed assets.

Tables:

- `organizations`
- `domains`
- `hosts`
- `host_groups`
- `host_group_members`

Phase 2 adds descriptions, active-state fields where missing, timestamps, uniqueness constraints, and lookup indexes.

Key constraints:

- organization names are unique
- domain names are unique per organization
- hostnames are unique per domain
- host group names are unique per organization
- host group membership is unique per host/group pair

Host group membership is validated in API logic so a host can only be added to a group in the same organization.

Phase 2 is manual asset inventory only. It does not add scanning, discovery, findings, or scoring.

## Phase 3 Rule Engine

Phase 3 adds versioned rule-definition storage. It does not execute rules.

Tables:

- `rule_engine_rules`
- `rule_engine_rule_versions`

`rule_engine_rules` stores stable rule identities. `rule_engine_rule_versions` stores immutable rule definitions.

Key fields:

- `stable_key`
- optional `catalog_issue_type_id`
- `current_version_id`
- `version_number`
- `target_type`
- `rule_expression`
- `evidence_schema`
- `remediation`
- `source_type`
- `effective_from`
- `effective_to`

Supported rule source types:

- `MANUAL`
- `INTERNAL`
- `SSC_REFERENCE`

Supported target types:

- `DOMAIN`
- `HOST`
- `URL`
- `CERTIFICATE`
- `IP`
- `ORGANIZATION`

Definition changes create new `rule_engine_rule_versions` rows. Historical versions are not overwritten.

Phase 3 does not add scan execution, scanner workers, findings, scoring, or proprietary SSC logic.

## Phase 4 Scan Engine

Phase 4 adds scan orchestration and deterministic rule evaluation records.

Tables:

- `scan_jobs`
- `scan_job_targets`
- `scan_runs`
- `scan_findings`

`scan_jobs` stores queued work. `scan_job_targets` stores explicit inventory targets and evidence supplied for a job. `scan_runs` stores each execution attempt. `scan_findings` stores rule matches observed during a run.

Findings preserve exact historical references:

- `rule_version_id` points to the immutable rule definition used during evaluation
- `catalog_issue_type_version_id` points to the linked catalog issue version that was current at scan time, when a linked issue exists

Supported scan statuses:

- `QUEUED`
- `RUNNING`
- `COMPLETED`
- `FAILED`
- `CANCELED`

Supported scan target types:

- `ORGANIZATION`
- `DOMAIN`
- `HOST`

Phase 4 does not add scoring, external network probing, automated asset discovery, SSC API integration, or SSC public-web scraping.
