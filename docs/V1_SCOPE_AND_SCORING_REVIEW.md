# Version 1 Scope and Scoring Review

Review date: 2026-09-23

Golden Baseline: immutable real `SSC_API` snapshot `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`

Implementation state updated 2026-10-06: Waves 1–5A, 42 active exact SSC evaluator mappings; all 42 have separately approved internal-risk calibration

This review originally changed product scope documentation only. The V1 Assessment Completeness Fix implemented on 2026-09-23 applies the correction specified here without changing the Golden Baseline, scanner primitives, rule activation, penalty arithmetic, factor weights, or SSC severity.

## Provisional scoring update (2026-10-01)

The later `ssc-v1` v1.1 profile keeps the same 160 in-scope exact issue versions, 42 `OUT_OF_SCOPE` versions, and strict `ASSESSED`/`NOT_ASSESSED` semantics. It changes score availability: a factor with at least one assessed issue now has an internal `PROVISIONAL` score from assessed findings, while a zero-assessed factor remains `NOT_RATED` with a null score. The overall score weights only rated factors and stays `PROVISIONAL` until the existing complete-profile prerequisites hold. Neither a provisional 100 nor a `NO_MATCH` count implies that missing issues passed. The earlier v1.0 behavior described below is retained as historical context; [Internal Scoring Model](SCORING.md) documents current output fields and persistence.

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

## Implemented V1 completeness correction

The versioned `ssc-v1` assessment profile v1.0 pins Golden Baseline hash `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`, the four V1 factor codes, and `internal-exposure` v1.0. At result generation it resolves all 202 exact issue-version memberships from that immutable attested snapshot: 160 are in scope and 42 are explicitly `OUT_OF_SCOPE`.

Each in-scope exact issue version is now `ASSESSED` only when its pinned evaluator records a deterministic `MATCH` or `NO_MATCH` for sufficient evidence. Missing, unselected, unsupported, partial, skipped, errored, timed-out, malformed, indeterminate, and legacy assessments without deterministic outcome metadata remain `NOT_ASSESSED`. Factor totals and supported-capability counts come from the full profile rather than executed rows. A factor score is emitted only when every issue in that factor is assessed and the existing scoring prerequisites are satisfied; the overall score requires all 160 V1 issues.

V2 findings remain observable but are excluded from V1 penalties and weights. Normalized JSON and HTML expose the profile identity, overall counts, per-factor totals/counts/state, all exact issue states and target outcomes. Persisted results include the assessment-profile identity so the corrected append-only snapshot can coexist with historical configured-detector-scope results. No SSC score impact, breach risk, or threat level is inferred from SSC severity.

## Required assessment states

Assessment state must be recorded per expected issue version and target, then aggregated without converting missing coverage into a pass:

| State | Exact meaning | Scoring effect | Report requirement |
|---|---|---|---|
| `ASSESSED` | The issue is in the declared assessment profile; an active evaluator pinned to that exact issue version ran with sufficient evidence and returned deterministic match or no-match. | Eligible for the internal model. A no-match contributes no penalty but is not inferred from absence of data. | Show evaluator/rule version, evidence status, match/no-match, target, and assessed count. |
| `NOT_ASSESSED` | The issue is in V1 but is unsupported, partial without a conclusive evaluator, not selected, inapplicable to the declared target coverage, skipped, timed out, errored, malformed, or indeterminate. | Never treated as pass, 100, or zero risk. It blocks a complete factor/overall score for any scoring profile that requires it; observed findings may still be reported without invented overall impact. | Show the issue and a reason code such as unsupported, not selected, insufficient evidence, error, or indeterminate. |
| `OUT_OF_SCOPE` | The issue belongs to a Version 2 factor for a V1 assessment. This is a product-scope decision, not an observation result. | Excluded from the V1 denominator and factor weights; it neither improves nor reduces a V1 score. | Show it separately or summarize exact baseline keys/counts as out of scope. Never label it passed or assessed. |

The proposed correction is a versioned assessment profile that pins the baseline hash, in-scope factor codes, expected issue-version IDs, required target coverage, and scoring-model version. Result generation should materialize all expected states and make completeness depend on the profile rather than on rows that happened to be produced. A deliberately narrower detector profile may retain its own internal score, but it must be labeled as that profile and must not be presented as a complete V1/SSC factor assessment. This correction changes assessment eligibility and reporting, not penalty methodology.

## Current V1 coverage

The denominator was verified from the 202 exact snapshot memberships in the attested database clone. Support states come from the reviewed coverage matrix and correspond to the 42 active exact evaluator mappings after the bounded Wave 5A staged text-service batch.

| V1 factor | Total | `SUPPORTED` | `PARTIAL` | `NOT_SUPPORTED` | Supported coverage |
|---|---:|---:|---:|---:|---:|
| `application_security` | 61 | 16 | 29 | 16 | 26.2% |
| `network_security` | 68 | 18 | 43 | 7 | 26.5% |
| `dns_health` | 10 | 7 | 3 | 0 | 70.0% |
| `patching_cadence` | 21 | 0 | 8 | 13 | 0.0% |
| **V1 total** | **160** | **41** | **83** | **36** | **25.6%** |

For reconciliation, Version 2 contains 42 issues: 1 `SUPPORTED`, 2 `PARTIAL`, and 39 `NOT_SUPPORTED`. The full-baseline totals are now 42 `SUPPORTED`, 85 `PARTIAL`, and 75 `NOT_SUPPORTED` across 202 issues.

The active V1 mappings are distributed as 16 Application Security, 7 DNS Health, 18 Network Security, and 0 Patching Cadence. Therefore current support coverage and current score completeness are separate facts; 41 active V1 mappings do not make the four V1 factors fully assessed. The additional active `mail_server_unusual_port` mapping belongs to out-of-scope `ip_reputation` and is why full-baseline support is 42.

Wave 3A promoted `service_vnc`, `service_rsync`, `service_redis`, `service_socks_proxy`, `service_telnet`, and `service_smb`. The common adapter records bounded request/response metadata and transcript hashes. `MATCH` requires the protocol-specific exchange; `NO_MATCH` requires a complete recognized foreign-protocol response; timeouts, resets, arbitrary banners, malformed/truncated frames, unsupported transports, and incomplete exchanges remain `INDETERMINATE`. The other service-identification candidates remain `PARTIAL`; this batch does not claim the full primitive ceiling.

Wave 3B promoted `unsafe_sri_v2`, `insecure_ftp`, `contact_information_detected`, `local_file_path_exposed_via_url_scheme`, `server_error`, `links_to_insecure_website`, and `service_soap`. It uses only explicitly declared authorized paths, bounded bodies, two safe GETs per declared endpoint, nonrecursive same-origin SRI fetches, and compact redacted evidence. Missing, blocked, truncated, unsupported, malformed, out-of-scope, or budget-incomplete evidence remains `INDETERMINATE`. Calibration v1.1 assigns LOW/scoring to `unsafe_sri_v2`, `insecure_ftp`, `local_file_path_exposed_via_url_scheme`, and `links_to_insecure_website`; the other three remain UNKNOWN/non-scoring. Missing future calibration entries still fail closed to UNKNOWN/non-scoring.

Wave 4A promotes only `ssh_weak_protocol`, `ssh_weak_cipher`, and `ssh_weak_mac`. It uses one bounded pre-authentication SSH identification/KEXINIT exchange per explicitly declared port, exact-name policy matching, no credentials, and no application commands. Algorithm advertisement is evidence of support, not successful exploitation or downgrade. SSH-1.99 remains `INDETERMINATE` without safe compatibility proof. MAC evaluation uses both directional cipher and MAC lists: MAC-ignored OpenSSH/ChaCha20-Poly1305 AEAD directions need no standalone MAC, RFC 5647 AEAD names require exact paired MAC evidence, and a known non-AEAD cipher makes the standalone MAC list applicable; incomplete pairing or unclassified applicability fails closed. Calibration v1.2 assigns MEDIUM/scoring to `ssh_weak_protocol` and LOW/scoring to `ssh_weak_cipher` and `ssh_weak_mac`; the unchanged scoring engine derives deductions of 7, 2, and 2 factor points respectively. Missing future calibration entries still fail closed to UNKNOWN/non-scoring.

Wave 4B promotes only `spf_record_malformed`. It strictly selects records beginning with case-insensitive `v=spf1` followed by ASCII space or end-of-record, validates the complete selected policy before evaluation, and uses bounded path-sensitive include/redirect/A/AAAA/MX/exists traversal only to identify deterministic RFC permanent errors. It does not calculate or expose sender authorization. Reachable PTR and sender/IP/HELO-dependent macros, mixed safe/permanent-error paths, DNS uncertainty, and operational exhaustion remain `INDETERMINATE`. Calibration v1.3 assigns LOW/scoring to the deterministic authentication-control failure; the unchanged global LOW penalty derives a 2-point factor deduction for one qualifying OPEN MATCH.

Wave 5A promotes `service_ftp`, `service_imap`, `service_pop3`, and `mail_server_unusual_port`. Each explicitly declared endpoint receives one bounded plaintext TCP connection with a server greeting, one fixed non-authenticating command, and one completion read under a shared deadline and byte/line budgets. FTP requires NOOP/200, IMAP requires untagged CAPABILITY plus matching A001 OK, POP3 requires a dot-terminated CAPA result, and SMTP requires EHLO/250 before applying `smtp-standard-ports.v1` `{25,465,587}`. Greeting-only, malformed, truncated, timed-out, reset, TLS-only, or budget-exhausted evidence remains `INDETERMINATE`; verified SMTP on a standard policy port is the only new issue-specific `NO_MATCH`. Calibration v1.4 explicitly assigns all four keys UNKNOWN/non-scoring: deterministic service identity supports inventory, attack-surface visibility, and follow-up assessment, but does not establish a demonstrated vulnerability, unsafe authentication or transport, public exposure, unauthorized access, relay abuse, or compromise.

## Recommended next primitives

This ordering favors deterministic support gained per engineering effort using current executors. Counts are V1-only ceilings from the reviewed matrix, not promises that an entire primitive becomes supported in one change.

| Rank | Primitive | V1 opportunity | Complexity and reliability | Reuse and recommendation |
|---:|---|---:|---|---|
| 1 | `SERVICE_PROTOCOL_IDENTIFICATION` | After Wave 5A, 22 original-group V1 issues remain partial; 20 are directly testable and 2 require enrichment | Medium–high; high reliability only with protocol-definitive positive exchanges | Reuse the completed adapter framework for later separately approved batches. Never infer a service from an open port. Wave 3B separately completed declared-path `service_soap`; Wave 5A completed the three in-scope text mail/file services. |
| 2 | `TCP_SERVICE_DISCOVERY` | 1 partial, directly testable issue | Low; high for a bounded positive connect observation | The TCP executor already provides the prerequisite. Add an exact scope manifest and evaluator so a closed/timeout result is not conflated with no exposed port. Best single-issue efficiency. |
| 3 | `TLS_HANDSHAKE` completion | 2 partial directly testable issues remain | Medium–high; conclusive negatives require complete legacy-cipher offer capability and authenticated OCSP staple bytes | Keep cipher and OCSP rows partial until the runtime can collect their full negative evidence without proxy assumptions. |

Wave 3A moved V1 support from 21 to 27, Wave 3B moved it to 34, Wave 4A moved it to 37, Wave 4B moved it to 38, and Wave 5A moves it to 41 of 160. The remaining ranked work is a ceiling, not a commitment or a claim of assessment completeness. `PRODUCT_FINGERPRINT` → `CVE_CORRELATION` → `LONGITUDINAL_PATCHING` is the critical follow-on path for Patching Cadence, but it is lower in immediate engineering efficiency and must not use ambiguous banners or unversioned vulnerability/lifecycle data.

## Recommended V1 exit criterion

The matrix contains 74 directly testable V1 issues: 25 Application Security, 42 Network Security, 7 DNS Health, and none in Patching Cadence. This provides a non-arbitrary base gate. V1 should exit only when all of the following are true:

1. All 74 directly testable V1 issues are truly `SUPPORTED`, unless a reviewed evidence-quality change formally reclassifies an issue.
2. One complete deterministic Patching Cadence primitive is supported end to end. The reviewed `LONGITUDINAL_PATCHING` primitive contains 11 issues, so this produces a concrete minimum of **85/160 supported (53.1%)** with factor floors of 25/61 Application Security, 42/68 Network Security, 7/10 DNS Health, and 11/21 Patching Cadence.
3. The assessment-profile correction is complete: every expected issue is `ASSESSED`, `NOT_ASSESSED`, or `OUT_OF_SCOPE`; a missing V1 issue cannot yield factor/overall 100; and V2 is explicitly excluded rather than silently omitted.
4. A representative authorized scan exercises observation → evaluator → finding/no-finding → internal scoring eligibility → HTML/JSON report for all four V1 factors, including timeout, malformed, insufficient-evidence, and no-match paths.
5. Every supported issue retains exact baseline/rule versions, positive and negative tests, false-positive boundaries, raw normalized evidence, authoritative references, remediation, and separate SSC severity. Full regression validation passes with scoring penalties/weights unchanged.

At that gate, up to 75 V1 issues may remain `PARTIAL` or `NOT_SUPPORTED`, but only because they require enrichment, external data, or are not reproducible under the reviewed matrix. Each must remain visibly `NOT_ASSESSED`; none may be counted as a pass or used to claim complete SSC-equivalent coverage.
