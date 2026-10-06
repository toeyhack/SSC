# Wave 4B internal risk calibration approval record

**Status:** approved and implemented in internal calibration v1.3 on 2026-10-06. **Scope:** only `spf_record_malformed`. Calibration v1.3 preserves all 37 v1.2 decisions unchanged and adds this one Wave 4B decision. SSC severity remains vendor metadata and is not an input to internal risk or score relevance.

The calibration uses the existing internal model without modification: `HIGH = 15`, `MEDIUM = 7`, and `LOW = 2`. Those values remain owned by the scoring engine; the calibration registry stores only `breach_risk` and `affects_score`. Missing registry entries continue to fail closed to `UNKNOWN`, `affects_score=false`, and zero score impact.

## Approved decision

| Exact SSC issue key | Factor | SSC severity | Pre-v1.3 internal risk | Pre-v1.3 `affects_score` | Approved internal risk | Approved `affects_score` | Derived one-MATCH factor deduction |
|---|---|---|---|---:|---|---:|---:|
| `spf_record_malformed` | `dns_health` | medium | UNKNOWN | false | LOW | true | 2 |

The deduction assumes an OPEN finding backed by an exact-version deterministic MATCH, no prior same-issue-version/target deduction in the run, and room under the factor's 100-point cap. It is an internal factor deduction, not an SSC score or issue-specific penalty.

## What MATCH proves

A MATCH proves a deterministic RFC 7208 permanent-error condition under the bounded Wave 4B analyzer. This includes unconditional record-selection or complete-record grammar errors, or complete path analysis in which every feasible path ends in `permerror`.

## What MATCH does not prove

A MATCH does not prove:

- successful sender spoofing;
- successful phishing;
- DMARC bypass;
- domain, DNS, or account compromise;
- mail acceptance by a receiver; or
- absence of aligned DKIM.

## Risk rationale

A deterministic SPF `permerror` means SPF cannot provide a usable authorization result for the affected evaluation. This is a real authentication-control failure, but its practical security impact depends on whether the domain sends mail, aligned DKIM, effective DMARC, receiver disposition, and whether the underlying fault is short-lived or controlled by a third-party SPF dependency.

LOW/scoring is therefore proportionate. MEDIUM or HIGH would overstate the evidence because MATCH does not prove acceptance of spoofed mail or compromise. UNKNOWN/non-scoring would be inconsistent with the existing LOW/scoring calibration of `spf_record_missing`, `spf_record_softfail`, `dmarc_record_missing`, `dmarc_contains_none`, and `subdomain_dmarc_contains_none`, which likewise represent authentication-control failures whose practical impact depends on mail use and compensating controls.

The implemented MATCH causes differ in remediation, ownership, persistence, and possible delivery impact, but all share the same minimum security consequence: SPF cannot produce a usable authorization decision under the observed deterministic condition. A fixed LOW rating represents that common control failure; stronger context-sensitive ratings would require separate evidence and are not inferred here.

Calibration changes only finding metadata and existing score eligibility. It does not change SPF parsing or analysis, DNS collection, Wave 4B outcomes or rule definitions, activation, taxonomy, assessment profiles, coverage, schema, migrations, scoring arithmetic, factor weights, or global penalties. The existing real absence and controlled valid fixtures remain NO_MATCH with no finding. The existing controlled malformed MATCH will be rerun manually after merge to confirm report integration; manual E2E is not an automated calibration gate.
