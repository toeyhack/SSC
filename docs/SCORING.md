# Internal Scoring Model

The pure scoring engine uses the versioned `internal-exposure` model, version `1.0`. It is an internal policy and is not an implementation of proprietary SecurityScorecard scoring.

Each assessed factor starts at 100. Default penalties are HIGH = 15, MEDIUM = 7 and LOW = 2. Only OPEN findings with `affects_score=true` and a linked exact catalog issue version can deduct points. INFORMATIONAL and POSITIVE findings do not deduct or add points. UNKNOWN risk needs review and prevents a fully assessed factor score. Unlinked rules remain uncategorized and do not receive an invented risk/penalty.

Penalties deduplicate by exact catalog issue version and scan target within the run. Multiple rules detecting the same issue on the same target deduct once. Findings are sorted deterministically before penalty allocation. Total factor deductions cap at 100. Every finding records its allocated factor score impact and, for a fully assessed result, weighted overall impact.

The overall score is the weighted mean of assessed factor scores, rounded to two decimal places. Factors have equal weight unless explicitly configured. All configured factor weights must be positive finite numbers; explicitly configured factors with no evaluated rules are unassessed. Penalties must define exactly HIGH, MEDIUM and LOW, with finite values between 0 and 100. During an `ssc-v1` assessment, weights outside the four V1 factors are excluded and reported; V2 findings remain visible but have no V1 score impact.

No applicable rules, skipped rules, collection errors, unknown catalog risk or missing catalog linkage produces an unassessed overall score (`null` in JSON). Zero matched findings alone is not proof of a clean target. Coverage appears in every output. Scores describe only the configured detector scope; the starter bundle is intentionally limited. For an incomplete result, observed penalties are retained but no overall impact is claimed.

The V1 completeness correction implements versioned profile `ssc-v1` v1.0 against the immutable 202-issue baseline hash. Its V1 denominator is all 160 exact issue versions in `application_security`, `network_security`, `dns_health`, and `patching_cadence`; the other 42 issue versions are `OUT_OF_SCOPE`. Only a sufficient deterministic `MATCH` or `NO_MATCH` is `ASSESSED`. Every absent, unsupported, partial, unselected, skipped, errored, timed-out, malformed, or indeterminate issue is `NOT_ASSESSED`. A V1 factor has no score while any of its expected issues is `NOT_ASSESSED`, and the overall V1 score is `null` until all four factors are valid. The review is documented in [Version 1 Scope and Scoring Review](V1_SCOPE_AND_SCORING_REVIEW.md); penalty, deduplication, capping, weighting, and SSC-severity separation are unchanged.

When the exact attested V1 baseline is not installed, the platform continues to support its historical explicitly configured detector scope. Such a result has no `ssc-v1` profile identity and must not be presented as a complete V1 or SSC assessment.

Example configuration for `ssc scan --scoring-model model.json`:

```json
{
  "name": "internal-exposure",
  "version": "1.0",
  "penalties": {"HIGH": 15, "MEDIUM": 7, "LOW": 2},
  "factor_weights": {"WEB": 1, "TLS": 1, "DNS": 1}
}
```

Only include explicitly weighted factors intended for the scan scope. This example requires WEB, TLS and DNS coverage; a DNS-only scan using it remains incomplete.

The normalized result saves the full scoring definition plus a SHA-256 over canonical JSON. Persisted `score_results` are unique by scan run and definition hash. Results are append-only through the service: changed models generate new snapshots rather than mutate historical scores. API/database roles and database-level immutability enforcement remain Phase 10 work. Rule and catalog references always use versions captured by the finding, not the current definitions.
