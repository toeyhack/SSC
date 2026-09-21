# Version 1 Scope and Scoring Review

Review date: 2026-09-21

Golden Baseline: immutable real `SSC_API` snapshot `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`

Implementation state reviewed: Waves 1–2, 21 active exact SSC evaluator mappings

This review changes product scope documentation only. It does not change the Golden Baseline, scanner behavior, rule activation, scoring arithmetic, factor weights, penalties, or report schema.

## Product scope decision

Version 1 covers exactly these SSC factors:

- `application_security` — Application Security
- `network_security` — Network Security
- `dns_health` — DNS Health
- `patching_cadence` — Patching Cadence

Version 2 is the complement of that set in the immutable 202-issue baseline. It currently contains `ip_reputation`, `cubit_score`, `hacker_chatter`, `leaked_information`, `social_engineering`, and `endpoint_security`. A future baseline factor not explicitly approved for Version 1 defaults to Version 2 review scope. Version 2 factors and issues remain in the Golden Baseline and catalog history; scope does not delete, deactivate, or rewrite taxonomy records.

`SUPPORTED`, `PARTIAL`, and `NOT_SUPPORTED` describe implementation coverage. They are not scan outcomes and do not mean pass, fail, safe, or risky.

## Current scoring and report behavior

The `internal-exposure` v1.0 scorer starts each materialized, assessed factor at 100 and applies only the documented internal HIGH/MEDIUM/LOW penalties. SSC severity remains separate. The scorer materializes a factor only when it appears in a rule assessment, finding, or explicit `factor_weights` entry.

| Condition | Current score behavior | Current report behavior |
|---|---|---|
| `NOT_SUPPORTED` issue | No active evaluator normally means no assessment row, no penalty, and no completeness effect. | The issue is absent; it is not shown as passed or not assessed. |
| `PARTIAL` issue | Coverage CSV state is not consumed at runtime. Without an active exact evaluator it behaves like `NOT_SUPPORTED`. | The issue is absent even if a collector captured a prerequisite observation. |
| Factor outside V1 | Runtime has no V1/V2 concept. An absent factor is omitted; an active/selected future rule could be scored unless a separate profile prevents it. | No `OUT_OF_SCOPE` row or label exists. |
| Active rule not selected, not applicable to the target type, or otherwise absent from the run | No assessment row and no completeness effect. | Not visible in factor coverage. |
| Selected applicable rule with insufficient/missing evidence | Assessment is `skipped`; its factor becomes `incomplete` and receives no factor score. | Factor is shown as incomplete, overall score is `Unassessed`, and rule skip count is shown. |
| Selected applicable rule with sufficient evidence and deterministic no-match | Assessment is evaluated. If every materialized factor is otherwise complete and all collected evidence succeeded, the factor starts at 100. | The factor may show 100 and the result may show a numeric overall score. |
| Finding with SSC catalog risk `UNKNOWN` | The factor becomes incomplete. No internal penalty is inferred from SSC severity. | Finding is shown, factor/overall score is unassessed, and SSC severity remains separate. |

The reports correctly render `null` scores as `Unassessed`, preserve observed findings and evidence, and warn that no findings alone do not prove a clean target. Coverage currently contains rule/evidence counts, not the expected V1 issue denominator.

## Correctness risk

There is an assessment-completeness defect relative to the newly declared V1 product scope. In `score_result`, the factor set is built only from assessment rows, findings, and configured factor weights. The `complete` decision then checks only those materialized factors. There is no versioned expected-issue manifest and no comparison to the 160 V1 issue versions.

Consequently, a successful no-match evaluation of one exact rule can produce factor score 100, overall score 100, and result status `complete`, while other `PARTIAL`, `NOT_SUPPORTED`, unselected, or V1-factor issues are absent. They are not explicitly recorded as passed, but their omission can have the same presentation effect. A V2 factor is likewise omitted rather than explicitly reported as out of scope. Supplying every factor in `factor_weights` can force missing factors to unassessed, but it still cannot detect missing issues within an otherwise materialized factor.

The penalty values, capping, deduplication, weighting, SSC-severity separation, and no-score handling for skipped/error evidence do not show a correctness problem. The defect is the completeness denominator and its report representation. No scoring change was made in this review.

## Required assessment states

Assessment state must be recorded per expected issue version and target, then aggregated without converting missing coverage into a pass:

| State | Exact meaning | Scoring effect | Report requirement |
|---|---|---|---|
| `ASSESSED` | The issue is in the declared assessment profile; an active evaluator pinned to that exact issue version ran with sufficient evidence and returned deterministic match or no-match. | Eligible for the internal model. A no-match contributes no penalty but is not inferred from absence of data. | Show evaluator/rule version, evidence status, match/no-match, target, and assessed count. |
| `NOT_ASSESSED` | The issue is in V1 but is unsupported, partial without a conclusive evaluator, not selected, inapplicable to the declared target coverage, skipped, timed out, errored, malformed, or indeterminate. | Never treated as pass, 100, or zero risk. It blocks a complete factor/overall score for any scoring profile that requires it; observed findings may still be reported without invented overall impact. | Show the issue and a reason code such as unsupported, not selected, insufficient evidence, error, or indeterminate. |
| `OUT_OF_SCOPE` | The issue belongs to a Version 2 factor for a V1 assessment. This is a product-scope decision, not an observation result. | Excluded from the V1 denominator and factor weights; it neither improves nor reduces a V1 score. | Show it separately or summarize exact baseline keys/counts as out of scope. Never label it passed or assessed. |

The proposed correction is a versioned assessment profile that pins the baseline hash, in-scope factor codes, expected issue-version IDs, required target coverage, and scoring-model version. Result generation should materialize all expected states and make completeness depend on the profile rather than on rows that happened to be produced. A deliberately narrower detector profile may retain its own internal score, but it must be labeled as that profile and must not be presented as a complete V1/SSC factor assessment. This correction changes assessment eligibility and reporting, not penalty methodology.

## Current V1 coverage

The denominator was verified from the 202 exact snapshot memberships in the attested database clone. Support states come from the reviewed coverage matrix and correspond to the 21 active exact evaluator mappings.

| V1 factor | Total | `SUPPORTED` | `PARTIAL` | `NOT_SUPPORTED` | Supported coverage |
|---|---:|---:|---:|---:|---:|
| `application_security` | 61 | 10 | 30 | 21 | 16.4% |
| `network_security` | 68 | 5 | 56 | 7 | 7.4% |
| `dns_health` | 10 | 6 | 4 | 0 | 60.0% |
| `patching_cadence` | 21 | 0 | 8 | 13 | 0.0% |
| **V1 total** | **160** | **21** | **98** | **41** | **13.1%** |

For reconciliation, Version 2 contains 42 issues: 0 `SUPPORTED`, 3 `PARTIAL`, and 39 `NOT_SUPPORTED`. The unchanged full-baseline totals remain 21 `SUPPORTED`, 101 `PARTIAL`, and 80 `NOT_SUPPORTED` across 202 issues.

The active V1 mappings are distributed as 10 Application Security, 6 DNS Health, 5 Network Security, and 0 Patching Cadence. Therefore current support coverage and current score completeness are separate facts; 21 active mappings do not make the four V1 factors fully assessed.

## Recommended next five primitives

This ordering favors deterministic support gained per engineering effort using current executors. Counts are V1-only ceilings from the reviewed matrix, not promises that an entire primitive becomes supported in one change.

| Rank | Primitive | V1 opportunity | Complexity and reliability | Reuse and recommendation |
|---:|---|---:|---|---|
| 1 | `SERVICE_PROTOCOL_IDENTIFICATION` | 31 partial issues; 29 are directly testable and 2 require enrichment | Medium–high; high reliability only with protocol-definitive positive transcripts | Extend the TCP executor with one bounded adapter framework, then ship small protocol families. Never infer a service from an open port. Highest supported-coverage ceiling. |
| 2 | `HTTP_CONTENT` | 9 issues: 1 partial and 8 not supported | Medium; high for declared-path parsing, with explicit crawl/negative boundaries | Reuses HTTP acquisition, limits, redirect scope, and raw observations. Implement link-scheme, server-error, SRI, and content-date rules in evidence-coherent batches. |
| 3 | `SSH_NEGOTIATION` | 3 partial, directly testable issues | Medium; high with an identification/KEX parser and versioned crypto policy | Reuses TCP safety, target authorization, timeout, and transcript patterns. No authentication is required. |
| 4 | `TCP_SERVICE_DISCOVERY` | 1 partial, directly testable issue | Low; high for a bounded positive connect observation | The TCP executor already provides the prerequisite. Add an exact scope manifest and evaluator so a closed/timeout result is not conflated with no exposed port. Best single-issue efficiency. |
| 5 | `EMAIL_SECURITY` completion | 1 directly testable SPF issue can advance; 3 DKIM issues remain selector-dependent | Medium; high for complete RFC 7208 malformed/permanent-error semantics | Reuses the DNS executor and normalized SPF evidence. Implement `spf_record_malformed`; keep DKIM partial until selectors or approved message provenance exist. |

These five have a defensible ceiling of 43 newly supported V1 issues (29 + 9 + 3 + 1 + 1), which would move V1 support from 21 to 64 of 160 (40.0%) if every direct boundary is satisfied. `TLS_HANDSHAKE` is not ranked because the remaining cipher and OCSP rows still need client capabilities that make negative results conclusive. `PRODUCT_FINGERPRINT` → `CVE_CORRELATION` → `LONGITUDINAL_PATCHING` is the critical follow-on path for Patching Cadence, but it is lower in immediate engineering efficiency and must not use ambiguous banners or unversioned vulnerability/lifecycle data.

## Recommended V1 exit criterion

The matrix contains 74 directly testable V1 issues: 25 Application Security, 42 Network Security, 7 DNS Health, and none in Patching Cadence. This provides a non-arbitrary base gate. V1 should exit only when all of the following are true:

1. All 74 directly testable V1 issues are truly `SUPPORTED`, unless a reviewed evidence-quality change formally reclassifies an issue.
2. One complete deterministic Patching Cadence primitive is supported end to end. The reviewed `LONGITUDINAL_PATCHING` primitive contains 11 issues, so this produces a concrete minimum of **85/160 supported (53.1%)** with factor floors of 25/61 Application Security, 42/68 Network Security, 7/10 DNS Health, and 11/21 Patching Cadence.
3. The assessment-profile correction is complete: every expected issue is `ASSESSED`, `NOT_ASSESSED`, or `OUT_OF_SCOPE`; a missing V1 issue cannot yield factor/overall 100; and V2 is explicitly excluded rather than silently omitted.
4. A representative authorized scan exercises observation → evaluator → finding/no-finding → internal scoring eligibility → HTML/JSON report for all four V1 factors, including timeout, malformed, insufficient-evidence, and no-match paths.
5. Every supported issue retains exact baseline/rule versions, positive and negative tests, false-positive boundaries, raw normalized evidence, authoritative references, remediation, and separate SSC severity. Full regression validation passes with scoring penalties/weights unchanged.

At that gate, up to 75 V1 issues may remain `PARTIAL` or `NOT_SUPPORTED`, but only because they require enrichment, external data, or are not reproducible under the reviewed matrix. Each must remain visibly `NOT_ASSESSED`; none may be counted as a pass or used to claim complete SSC-equivalent coverage.
