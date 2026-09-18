# Internal Scoring Model

The pure scoring engine uses the versioned `internal-exposure` model, version `1.0`. It is an internal policy and is not an implementation of proprietary SecurityScorecard scoring.

Each assessed factor starts at 100. Default penalties are HIGH = 15, MEDIUM = 7 and LOW = 2. Only OPEN findings with `affects_score=true` and a linked exact catalog issue version can deduct points. INFORMATIONAL and POSITIVE findings do not deduct or add points. UNKNOWN risk needs review and prevents a fully assessed factor score. Unlinked rules remain uncategorized and do not receive an invented risk/penalty.

Penalties deduplicate by exact catalog issue version and scan target within the run. Multiple rules detecting the same issue on the same target deduct once. Findings are sorted deterministically before penalty allocation. Total factor deductions cap at 100. Every finding records its allocated factor score impact and, for a fully assessed result, weighted overall impact.

The overall score is the weighted mean of assessed factor scores, rounded to two decimal places. Factors have equal weight unless explicitly configured. All configured factor weights must be positive finite numbers; explicitly configured factors with no evaluated rules are unassessed. Penalties must define exactly HIGH, MEDIUM and LOW, with finite values between 0 and 100.

No applicable rules, skipped rules, collection errors, unknown catalog risk or missing catalog linkage produces an unassessed overall score (`null` in JSON). Zero matched findings alone is not proof of a clean target. Coverage appears in every output. Scores describe only the configured detector scope; the starter bundle is intentionally limited. For an incomplete result, observed penalties are retained but no overall impact is claimed.

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
