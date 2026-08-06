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
