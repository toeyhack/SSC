# Internal risk calibration V1 — review proposal

**Status:** proposed for review; no catalog, rule, scanner, or scoring behavior has changed. **Scope:** the 27 `SUPPORTED` keys in [SSC issue coverage](SSC_ISSUE_COVERAGE.md) for the attested SSC API baseline `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`. The companion [CSV](INTERNAL_RISK_CALIBRATION_V1.csv) is the row-level decision record, including rationale and conditions for every key. SSC severity remains vendor metadata; these are independent internal judgments and make no claim about SSC's scoring method.

## Decision basis

A deterministic `MATCH` proves only the exact observation described by its versioned evaluator. It does not prove an exploit, weak authentication, sensitive data, or a vulnerable product version unless that condition is part of the evaluator. LOW denotes a credible but generally indirect security exposure or hardening gap; MEDIUM denotes a direct transport or authentication weakness with plausible confidentiality or integrity impact; HIGH would require stronger evidence of serious compromise than any of these 27 MATCH conditions supplies. UNKNOWN is retained when the observation alone does not justify a stable penalty. A proposed `affects_score=false` keeps the finding visible without an invented risk penalty.

The current-state columns in the CSV reflect the `SSC_API` import path: it creates issue versions with `breach_risk=UNKNOWN` and `affects_score=true` independently of SSC severity. This is also consistent with the reported `csp_unsafe_policy_v2` E2E result. A live catalog was not modified or queried for per-version overrides; any locally reviewed versions should be reconciled by exact version ID before implementation. The proposal uses the documented 27 supported keys and their current SSC factor/severity values, not new taxonomy keys.

## Calibration summary

| Proposed internal risk | Count | One scored MATCH: factor deduction |
|---|---:|---:|
| HIGH | 0 | 15 |
| MEDIUM | 6 | 7 |
| LOW | 17 | 2 |
| UNKNOWN | 4 | 0 |
| **Total** | **27** | — |

**Proposed score relevance:** `affects_score=true` for 23; `false` for 4. A scored occurrence assumes an OPEN finding backed by an exact-version deterministic MATCH for an in-scope V1 issue, with no prior deduplication of the same issue version and target and room under the factor's 100-point cap. `NO_MATCH` and `NOT_ASSESSED` deduct zero. A factor starts at 100 once rated; a single LOW or MEDIUM MATCH would yield 98 or 93 for that factor. The weighted overall effect depends on which factors are rated and their configured weights. No penalty values, formula, factor weights, or scoring profile are proposed to change.

### All 27 supported keys

| Factor | Exact SSC issue key | SSC severity | Proposed risk | Score? | One MATCH |
|---|---|---|---|---|---:|
| application_security | `csp_no_policy_v2` | low | LOW | yes | 2 |
| application_security | `csp_too_broad_v2` | low | LOW | yes | 2 |
| application_security | `csp_unsafe_policy_v2` | low | LOW | yes | 2 |
| application_security | `domain_missing_https_v2` | low | MEDIUM | yes | 7 |
| application_security | `hsts_incorrect_v2` | low | LOW | yes | 2 |
| application_security | `insecure_https_redirect_pattern_v2` | low | MEDIUM | yes | 7 |
| application_security | `insecure_server_certificate_key_size` | low | MEDIUM | yes | 7 |
| application_security | `redirect_chain_contains_http_v2` | medium | MEDIUM | yes | 7 |
| application_security | `x_content_type_options_incorrect_v2` | low | LOW | yes | 2 |
| application_security | `x_frame_options_incorrect_v2` | low | LOW | yes | 2 |
| dns_health | `dmarc_contains_none` | info | LOW | yes | 2 |
| dns_health | `dmarc_record_missing` | info | LOW | yes | 2 |
| dns_health | `spf_record_missing` | low | LOW | yes | 2 |
| dns_health | `spf_record_softfail` | info | LOW | yes | 2 |
| dns_health | `spf_record_wildcard` | medium | UNKNOWN | no | 0 |
| dns_health | `subdomain_dmarc_contains_none` | info | LOW | yes | 2 |
| network_security | `service_redis` | medium | LOW | yes | 2 |
| network_security | `service_rsync` | medium | UNKNOWN | no | 0 |
| network_security | `service_smb` | medium | LOW | yes | 2 |
| network_security | `service_socks_proxy` | low | UNKNOWN | no | 0 |
| network_security | `service_telnet` | medium | LOW | yes | 2 |
| network_security | `service_vnc` | medium | LOW | yes | 2 |
| network_security | `tls_weak_protocol` | high | MEDIUM | yes | 7 |
| network_security | `tlscert_expired` | low | LOW | yes | 2 |
| network_security | `tlscert_no_revocation` | low | UNKNOWN | no | 0 |
| network_security | `tlscert_self_signed` | low | LOW | yes | 2 |
| network_security | `tlscert_weak_signature` | low | MEDIUM | yes | 7 |

### Differences from SSC severity

The following **17** keys have a proposed internal risk label different from the SSC severity label: `domain_missing_https_v2`, `insecure_https_redirect_pattern_v2`, `insecure_server_certificate_key_size`, `dmarc_contains_none`, `dmarc_record_missing`, `spf_record_softfail`, `spf_record_wildcard`, `subdomain_dmarc_contains_none`, `service_redis`, `service_rsync`, `service_smb`, `service_socks_proxy`, `service_telnet`, `service_vnc`, `tls_weak_protocol`, `tlscert_no_revocation`, and `tlscert_weak_signature`. This comparison includes SSC `info` and internal `UNKNOWN`, which are not numeric severity levels. The agreement on the other ten labels is an independent judgment, not a severity mapping.

### UNKNOWN and unscored

The same **four** keys should remain `UNKNOWN` and `affects_score=false`:

| Key | Why the MATCH is insufficient | Needed context |
|---|---|---|
| `spf_record_wildcard` | Wildcard SPF synthesis does not prove permissive authorization. | Effective policy and intended subdomain mail use. |
| `service_rsync` | A daemon greeting does not show accessible modules or file contents. | Module exposure and access controls. |
| `service_socks_proxy` | Method selection does not show that relay succeeds or can be abused. | Selected authentication method and authorized relay test or configuration. |
| `tlscert_no_revocation` | Missing OCSP/CRL URI does not establish compromise or the issuer's complete status strategy. | Issuer strategy, lifetime, and client validation behavior. |

The current scoring engine only treats `UNKNOWN` as an unresolved scoring risk when `affects_score=true`. With these proposals, the four observations would remain assessed findings but have no penalty. Their unscored status is a deliberate review decision; it must not be represented as proof that the services or configurations are safe.

### `csp_unsafe_policy_v2`

Recommend `LOW`, `affects_score=true`, **2 factor points for one qualifying MATCH**. The evaluator's MATCH means the effective active-content policy permits `unsafe-eval` or permits `unsafe-inline` without nonce/hash control. This weakens a browser defense against script injection; it does not establish an actual injection path or compromise. Its observed SSC severity is `low` metadata and is not the basis for the internal rating. A sensitive session plus a demonstrated injection path would justify a separate impact review based on additional evidence, not an automatic upgrade of this issue type. Until an approved catalog version carries LOW, the current `UNKNOWN` yields zero deduction even when a real MATCH occurs; a provisional 100 therefore must be read with coverage and the unresolved-risk warning.

## Where an approved decision would live

The intended configuration point is each exact [catalog issue version](../backend/app/models/catalog_models.py): `CatalogIssueTypeVersion.breach_risk` and `CatalogIssueTypeVersion.affects_score`, alongside separate `ssc_severity`. The [SSC API baseline importer](../backend/app/services/ssc_api_baseline.py) currently supplies `UNKNOWN` and `true`; the [finding loader](../backend/app/services/finding_results.py) reads the version pinned to the finding, and the [scoring engine](../backend/app/services/scoring_engine.py) applies that version's internal risk and relevance. An approved implementation should create reviewed immutable issue versions or use the existing catalog version review path, preserve exact rule and snapshot links for historical results, and avoid silently reinterpreting old scans. This document makes no database or code change.

## Supporting security references

The ratings are judgment calls constrained by the exact MATCH conditions in [SSC issue coverage](SSC_ISSUE_COVERAGE.md). Primary references for the underlying mechanisms are [OWASP CSP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [OWASP HTTP header guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [RFC 8996 on TLS 1.0/1.1](https://www.rfc-editor.org/rfc/rfc8996.html), [RFC 9989 on DMARC policy](https://www.rfc-editor.org/rfc/rfc9989.html), [RFC 7208 on SPF](https://www.rfc-editor.org/rfc/rfc7208.html), [RFC 5280 on certificates and revocation](https://www.rfc-editor.org/rfc/rfc5280.html), and [Redis security guidance](https://redis.io/docs/latest/operate/oss_and_stack/management/security/). These sources describe security mechanisms; none supplies or implies SSC proprietary score penalties.
