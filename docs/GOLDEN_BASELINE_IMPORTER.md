# Phase 1B Golden Baseline Importer

Phase 1B imports a captured SecurityScorecard licensed-UI issue catalog into the local versioned catalog as an immutable golden baseline snapshot.

SecurityScorecard remains a reference source only:

- no SSC API integration
- no SSC public-web scraping
- no scanner execution
- no scoring
- no asset inventory
- no proprietary SSC scoring logic

## Input File

The importer accepts canonical JSON only. The real licensed-UI capture is not stored in this repository; it must be supplied as a JSON file that matches this schema.

```json
{
  "schema_version": "phase1b.ssc_licensed_ui.v1",
  "name": "SSC Licensed UI Golden Baseline - YYYY-MM-DD",
  "source_type": "SSC_LICENSED_UI",
  "source_reference": "manual capture reference, ticket, or file id",
  "captured_at": "2026-08-06T18:30:00Z",
  "notes": "Optional capture notes",
  "factors": [
    {
      "code": "network_security",
      "name": "Network Security",
      "description": "Optional factor description",
      "position": 1,
      "issues": [
        {
          "stable_key": "network_security.tls_certificate_expired",
          "name": "TLS certificate expired",
          "description": "Issue definition captured from the licensed UI",
          "breach_risk": "HIGH",
          "threat_level": "HIGH",
          "affects_score": true,
          "source_reference": "Optional issue-level capture reference",
          "position": 1
        }
      ]
    }
  ]
}
```

Supported `breach_risk` values:

- `HIGH`
- `MEDIUM`
- `LOW`
- `INFORMATIONAL`
- `POSITIVE`
- `UNKNOWN`

Supported `threat_level` values:

- `HIGH`
- `MEDIUM`
- `LOW`
- `INFORMATIONAL`
- `POSITIVE`
- `UNKNOWN`
- `null`

`stable_key` and factor `code` must be explicit lowercase identifiers using letters, numbers, dots, hyphens, or underscores. The importer does not infer issue identity from a display name.

## Ordering

Source ordering is preserved in `catalog_snapshot_items.factor_position` and `catalog_snapshot_items.issue_position`.

Positions may be omitted. When omitted, list order is used. If any positions are supplied for a factor list or issue list, every item in that list must supply a position and the positions must be contiguous starting at `1`.

## Import Behavior

The importer:

- computes a SHA-256 content hash from normalized canonical JSON
- creates missing `CatalogFactor` rows
- reuses existing factors by `code` without overwriting factor metadata
- creates missing `CatalogIssueType` rows by `stable_key`
- rejects an existing `stable_key` assigned to a different factor
- creates a new `CatalogIssueTypeVersion` only when the issue definition differs from existing versions
- reuses an existing matching version when the definition is unchanged
- creates one immutable `CatalogSnapshot` with source type `SSC_LICENSED_UI`
- creates `CatalogSnapshotItem` rows that reference exact issue-version ids and preserve source order
- stores `captured_at` from input and `imported_at` from runtime

Issue definition comparison uses:

- `name`
- `description`
- `breach_risk`
- `threat_level`
- `affects_score`

Source references and snapshot hashes are provenance fields, not definition-change triggers.

## Idempotency

Importing the exact same baseline content again reuses the existing `CatalogSnapshot` with the same `SSC_LICENSED_UI` source type and content hash. No factor, issue, version, snapshot, or snapshot item rows are changed in that path.

## Rename And Unknown Handling

Renames are controlled by `stable_key`:

- same `stable_key` and changed display fields: create a new issue version
- new `stable_key` and unique name within the factor: create a new issue type
- new `stable_key` but a name matching an existing current issue in the same factor: reject as ambiguous
- missing `stable_key`: reject at schema validation

The importer never silently merges by name.

## CLI

Dry-run preview:

```sh
python -m app.cli.import_golden_baseline --input /path/to/baseline.json --dry-run --json
```

Import:

```sh
python -m app.cli.import_golden_baseline --input /path/to/baseline.json --json
```

The repository includes `backend/tests/fixtures/phase1b_sample_baseline.json` only as a synthetic validation fixture. It is not real SecurityScorecard content.
