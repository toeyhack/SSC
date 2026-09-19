# Golden Baseline Acquisition and Phase 1B Importer

A real SSC taxonomy baseline must be imported at least once before the platform may claim `SSC_ALIGNED`. The preferred initial source is now the licensed SSC API metadata endpoints. The existing Phase 1B licensed-UI/manual canonical JSON importer remains a supported fallback.

Preferred initial SSC baseline: **SSC API metadata endpoints**. Fallback: **licensed UI/manual canonical JSON**. Future taxonomy updates: **SSC API and/or reviewed public SSC methodology changes**. Runtime: **no SSC dependency**. Public changes require review/approval and never automatically overwrite the production catalog. No comparison, calibration, public sync, new scanner checks or proprietary scoring reconstruction is included.

## Preferred API path

```text
SSC API /metadata/factors + /metadata/issue-types
  -> raw immutable source in CatalogSnapshot
  -> normalization (ssc.api.metadata.v2)
  -> existing versioned Internal Catalog and exact snapshot membership
  -> Golden Baseline
```

Only these fixed-origin GET requests acquire the baseline:

- `https://api.securityscorecard.io/metadata/factors`
- `https://api.securityscorecard.io/metadata/issue-types`

Provision `SSC_TOKEN` through the process environment. The client reads no credential file and accepts no token argument. It sends `Authorization: Token <environment value>` over verified HTTPS. Tokens and request headers are never stored or printed; server errors and transport exceptions omit bodies/headers. Responses echoing the token are rejected. Redirects are disabled; each request has a 20-second timeout and an 8 MiB decoded-response limit. Both responses must succeed and validate before any catalog write. Detected pagination is rejected rather than importing an incomplete baseline.

```bash
ssc baseline pull-ssc --dry-run
ssc baseline pull-ssc --dry-run --enrich-details
ssc baseline pull-ssc
# Noninteractive approval, optionally bound to the reviewed content:
ssc baseline pull-ssc --yes --expect-hash <reviewed-content-hash>
ssc baseline status
```

`pull-ssc` displays Source, Factors, Issue Types, optional detail enrichment counts, Captured At, Content Hash, Existing Match and new issue-version count before committing. An interactive terminal prompts for approval; noninteractive imports require `--yes`. `--dry-run` writes nothing. The hash check rejects a changed capture after an earlier review. Successful unchanged imports reuse the original snapshot without changing current-version pointers. New API baselines are committed atomically through the existing importer.

The two list requests above remain the complete minimum baseline. `--enrich-details` is optional and is not required for import or `SSC_ALIGNED`. It requests one fixed-origin `/metadata/issue-types/{type}` route per list issue with at most four workers and the same 20-second request timeout. Safe transient transport failures and HTTP 408, 425, 429, 500, 502, 503 and 504 responses receive at most three total attempts. Numeric or HTTP-date `Retry-After` is honored up to 60 seconds; longer or invalid delays fail that lookup instead of retrying early. Other failures are not retried. Each failed or invalid detail response is reported for its issue, while that issue retains its list metadata and the rest of the baseline remains importable.

## API field mapping and unresolved semantics

Both documented list responses use an object containing `entries`. Unknown fields remain in the raw response and source metadata.

| SSC field | Local representation |
| --- | --- |
| Factor `key` | Factor code |
| Factor `name`, `description` | New factor display metadata; existing factors reused without overwrite |
| Factor `long_description` and other fields | Exact snapshot factor metadata; versioned by snapshot hash |
| Issue `key` | Issue stable key |
| Issue `factor` | Explicit factor membership; unknown factors rejected |
| Issue `title` | Issue-version name |
| Issue `severity` | `ssc_severity`, also preserved unchanged in `ssc_metadata` and raw source |
| Detail `short_description` | Issue-version `description`, and preserved unchanged in `ssc_metadata` and raw source |
| Detail `long_description` | Preserved unchanged in versioned `ssc_metadata` and raw source |
| Detail `recommendation` | Preserved unchanged in versioned `ssc_metadata` and raw source |

SSC `severity` is **not mapped to internal risk, Breach Risk, Threat Level, score impact or scoring relevance**. API versions use `breach_risk=UNKNOWN` and `threat_level=null` unless another authoritative source explicitly supplies them. The existing internal `affects_score=true` default is retained solely as a conservative review gate: UNKNOWN-risk findings prevent assessed scores under the unchanged internal scoring policy. It is not derived from `severity` and is not evidence that SSC deducts points for the issue. Internal risk assignment, SSC severity, SSC threat level and SSC scoring effects remain separate; no score calibration is performed.

API keys are authoritative identities, so distinct keys with the same title are allowed. An existing stable key assigned to a different factor remains a reconciliation error requiring review; the importer does not silently move existing identities. Removed issues remain in historical snapshots and the internal catalog, but are absent from the new baseline membership. API acquisition does not delete or disable internal rules.

## Provenance, immutability and versions

Migration `0008_ssc_api_baseline` adds nullable `ssc_severity` and `ssc_metadata` to issue versions; it adds `normalized_schema_version`, `normalized_payload`, `raw_source` and `is_real_baseline` to snapshots. Existing `SSC_API` source enumeration and snapshot-item tables are reused. No scanner, rule, scoring or report tables change.

For each required list endpoint and each successful optional detail endpoint, `raw_source` holds the original decoded UTF-8 JSON response body, its SHA-256 and capture timestamp, keyed by its full HTTPS endpoint. Failed detail responses are not treated as metadata. Response headers and credentials are excluded. The snapshot records overall capture/import times, source reference, canonical content hash and normalizer schema version. Its normalized payload preserves all factors (including zero-issue factors), factor descriptions, exact issue membership, enrichment status and any failed issue keys. Existing snapshot items reference exact immutable issue-version IDs. Factor definitions are preserved per snapshot rather than overwriting shared factor identities or introducing a new factor-version table.

Canonical API hashing sorts JSON object keys and top-level `entries` by SSC key, excludes capture times and ignores whitespace and list ordering. Successful detail responses participate in the hash; failed lookups do not replace or remove list metadata. Other fields, including unknown metadata, affect the hash. Thus repeated captures reuse one baseline; changed factor or successful detail metadata creates a new snapshot; changed issue metadata also creates a new issue version unless the same definition already exists. The first raw capture remains intact on reuse. API snapshot hashes have a database unique index for concurrent idempotency; PostgreSQL rejects updates/deletes of snapshots containing raw API provenance. Normalized membership is protected in that same row. Existing issue-version and snapshot-item creation remains append-only through the importer.

## Taxonomy status

`ssc baseline status` is an offline database query. `INTERNAL_ONLY` means no real baseline has been recorded; all existing scanner/rule/scoring/report operations remain available without an alignment claim. `SSC_ALIGNED` means at least one real imported SSC baseline has recorded provenance. It does not assert current coverage, latest taxonomy, proprietary score equivalence or calibrated scoring. Neither state needs SSC during scanning or reporting.

Successful approved API acquisition records a real baseline. Synthetic fixtures, internal detector bundles, arbitrary source labels and legacy unattested snapshots do not enable alignment. For a real manual capture, pass `--attest-real-source` at first import. This is an operator attestation, not cryptographic proof of provenance; do not apply it to fixtures. Existing snapshots cannot be relabeled as real on reuse: provide a new verified capture with its actual capture timestamp. Automated API tests simulate acquisition in isolated databases and cannot establish production alignment.

## Read-only issue detail discovery

Live read-only discovery completed on 2026-09-19 for `tls_weak_protocol`, `cookie_missing_http_only` and `csp_no_policy_v2`. Every HTTP 200 response contained exactly these seven top-level scalar fields and no additional or nested fields:

- `key`
- `severity`
- `factor`
- `title`
- `short_description`
- `long_description`
- `recommendation`

No returned field explicitly represented internal risk, Breach Risk, Threat Level, score impact or scoring relevance. No undocumented semantic equivalence is inferred.

```bash
ssc baseline discover-details
```

This read-only command requests the same three issue keys, reports every returned top-level field and nested field path plus endpoint, timestamp and response hash, and performs no catalog write. It remains separate from optional baseline enrichment; detail responses are merged only when the operator explicitly passes `pull-ssc --enrich-details`.

## Input File

The fallback importer accepts canonical JSON. The real licensed-UI capture is not stored in this repository; it must be supplied as a JSON file that matches this schema.

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

For the first import of verified real licensed data, append `--attest-real-source` to establish `SSC_ALIGNED`. Omit it for fixtures. The canonical schema, source ordering and existing manual content-hash algorithm are preserved.

The repository includes `backend/tests/fixtures/phase1b_sample_baseline.json` only as a synthetic validation fixture. It is not real SecurityScorecard content.
