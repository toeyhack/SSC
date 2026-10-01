# Internal Scoring Model

The pure scoring engine uses the versioned `internal-exposure` model, version `1.0`. It is an internal policy and is not an implementation of proprietary SecurityScorecard scoring.

Each rated factor starts at 100. Default penalties are HIGH = 15, MEDIUM = 7 and LOW = 2. In a V1 profile, only OPEN findings backed by an exact-version, deterministic `MATCH` assessment and `affects_score=true` can deduct points. `NO_MATCH` contributes no penalty. INFORMATIONAL, POSITIVE, and `affects_score=false` findings remain visible without a penalty. `NOT_ASSESSED` is never a pass and cannot contribute a penalty. UNKNOWN internal risk needs review: its penalty is not inferred from SSC severity, and the factor cannot be `COMPLETE` until that risk is resolved. Unlinked rules remain uncategorized and do not receive an invented risk/penalty.

Penalties deduplicate by exact catalog issue version and scan target within the run. Multiple rules detecting the same issue on the same target deduct once. Findings are sorted deterministically before penalty allocation. Total factor deductions cap at 100. Every finding records its allocated factor score impact and, when its factor is rated, its weighted overall impact.

The V1 overall score is the weighted mean of **rated** factor scores, rounded to two decimal places. `NOT_RATED` factors are excluded from both numerator and denominator; they are never counted as 100. Factors have equal weight unless explicitly configured. All configured factor weights must be positive finite numbers. Penalties must define exactly HIGH, MEDIUM and LOW, with finite values between 0 and 100. During an `ssc-v1` assessment, weights outside the four V1 factors are excluded and reported; V2 findings remain visible but have no V1 score impact.

For an `ssc-v1` assessment, a factor with zero assessed issues has `score: null` and `score_status: NOT_RATED`. Once at least one issue is assessed, its internal score is `100 - assessed MATCH penalties` (bounded to 0..100). It is `PROVISIONAL` while required issues remain `NOT_ASSESSED` or internal risk is unresolved; it is `COMPLETE` only when the existing completeness and scoring prerequisites are met. If no factor is rated, `overall_score` is `null` and `overall_score_status` is `NOT_RATED`. If at least one is rated but V1 is incomplete, the weighted overall score is `PROVISIONAL`. The existing `status: complete/incomplete` and `assessment_completeness.state: COMPLETE/INCOMPLETE` still describe full assessment completion, not the presence of a provisional number. The historical configured-detector scope remains separate and does not claim V1 coverage.

The V1 completeness correction introduced profile `ssc-v1` v1.0. Provisional scoring is versioned as `ssc-v1` v1.1 so append-only historical v1.0 snapshots remain distinct. Both versions use the same immutable 202-issue baseline and V1 denominator: 160 exact issue versions in `application_security`, `network_security`, `dns_health`, and `patching_cadence`; the other 42 are `OUT_OF_SCOPE`. Only a sufficient deterministic `MATCH` or `NO_MATCH` is `ASSESSED`. Every absent, unsupported, partial, unselected, skipped, errored, timed-out, malformed, or indeterminate issue remains `NOT_ASSESSED`. The [Version 1 Scope and Scoring Review](V1_SCOPE_AND_SCORING_REVIEW.md) records the earlier completeness correction. Penalty values, deduplication, capping, factor weights, and SSC-severity separation are unchanged.

**Score is not coverage.** A score represents observed risk among assessed checks. Coverage measures how much of the V1 profile was actually assessed. A provisional score must always be interpreted with coverage, including when it is 100. Normalized JSON exposes each factor's `total_v1_issues`, `assessed_count`, `not_assessed_count`, `coverage_percent`, `score`, and `score_status`, plus `overall_score`, `overall_score_status`, and `assessment_coverage`. HTML shows factor and overall score, status, coverage, findings and observed impact. `OUT_OF_SCOPE` issues are excluded from the 160-issue denominator.

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

The normalized result saves the full scoring definition plus a SHA-256 over canonical JSON. Persisted `score_results.result` JSONB already stores factor and overall scores, statuses, coverage, profile identity, exact issue assessments, target snapshots, and generated time; no migration is needed. Results are append-only through the service and keyed by scan run, scoring definition, and assessment-profile hash. The v1.1 profile hash prevents old v1.0 results from being silently reinterpreted. Future score deltas can compare snapshots for the same inventory target, scoring-model hash, and assessment-profile hash, ordered by scan-run time. A trend service still needs an explicit comparable-run selection policy and coverage-change handling; charts and frontend trend UI are not part of this milestone. API/database roles and database-level immutability enforcement remain Phase 10 work. Rule and catalog references always use versions captured by the finding, not the current definitions.
