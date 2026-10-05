# Internal risk calibration V1

**Status:** approved and implemented through 2026-10-05. **Scope:** calibration v1.2 contains 37 `SUPPORTED` keys from the attested SSC API baseline `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`. It preserves all 34 v1.1 decisions unchanged and adds the three separately reviewed Wave 4A decisions. The companion [CSV](INTERNAL_RISK_CALIBRATION_V1.csv) is the row-level decision record. SSC severity remains vendor metadata; these are independent internal judgments and make no claim about SSC's scoring method.

## Decision basis

A deterministic `MATCH` proves only the exact observation described by its versioned evaluator. It does not prove an exploit, weak authentication, sensitive data, or a vulnerable product version unless that condition is part of the evaluator. LOW denotes a credible but generally indirect security exposure or hardening gap; MEDIUM denotes a direct transport or authentication weakness with plausible confidentiality or integrity impact; HIGH would require stronger evidence of serious compromise than any of these 37 MATCH conditions supplies. UNKNOWN is retained when the observation alone does not justify a stable penalty. An approved `affects_score=false` keeps the finding visible without an invented risk penalty.

For the original 27 rows, the current-state columns in the CSV preserve the pre-v1.0 `SSC_API` import state: issue versions had `breach_risk=UNKNOWN` and `affects_score=true` independently of SSC severity. The Wave 3B and Wave 4A rows preserve their pre-calibration fail-closed runtime state of `UNKNOWN` and `affects_score=false`. The approved columns contain the internal decisions now resolved by the registry. Imported taxonomy rows remain unchanged; internal calibration is applied separately by exact SSC issue key.

## Calibration summary

| Internal risk | Count | One scored MATCH: factor deduction |
|---|---:|---:|
| HIGH | 0 | 15 |
| MEDIUM | 7 | 7 |
| LOW | 23 | 2 |
| UNKNOWN | 7 | 0 |
| **Total** | **37** | — |

**Approved score relevance:** `affects_score=true` for 30; `false` for 7. A scored occurrence assumes an OPEN finding backed by an exact-version deterministic MATCH for an in-scope V1 issue, with no prior deduplication of the same issue version and target and room under the factor's 100-point cap. `NO_MATCH` and `NOT_ASSESSED` deduct zero. A factor starts at 100 once rated; a single LOW or MEDIUM MATCH yields 98 or 93 for that factor. The weighted overall effect depends on which factors are rated and their configured weights. No penalty values, formula, factor weights, or scoring profile changed.

### Original 27 calibrated keys (unchanged)

| Factor | Exact SSC issue key | SSC severity | Internal risk | Score? | One MATCH |
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

### Wave 3B extension

| Factor | Exact SSC issue key | SSC severity | Internal risk | Score? | One MATCH |
|---|---|---|---|---|---:|
| application_security | `unsafe_sri_v2` | high | LOW | yes | 2 |
| application_security | `insecure_ftp` | medium | LOW | yes | 2 |
| application_security | `contact_information_detected` | low | UNKNOWN | no | 0 |
| application_security | `local_file_path_exposed_via_url_scheme` | low | LOW | yes | 2 |
| application_security | `server_error` | low | UNKNOWN | no | 0 |
| application_security | `links_to_insecure_website` | low | LOW | yes | 2 |
| network_security | `service_soap` | medium | UNKNOWN | no | 0 |

### Wave 4A extension

| Factor | Exact SSC issue key | SSC severity | Internal risk | Score? | One MATCH |
|---|---|---|---|---|---:|
| network_security | `ssh_weak_protocol` | medium | MEDIUM | yes | 7 |
| network_security | `ssh_weak_cipher` | medium | LOW | yes | 2 |
| network_security | `ssh_weak_mac` | medium | LOW | yes | 2 |

### Differences from SSC severity

The following **24** keys have an internal risk label different from the SSC severity label: `domain_missing_https_v2`, `insecure_https_redirect_pattern_v2`, `insecure_server_certificate_key_size`, `dmarc_contains_none`, `dmarc_record_missing`, `spf_record_softfail`, `spf_record_wildcard`, `subdomain_dmarc_contains_none`, `service_redis`, `service_rsync`, `service_smb`, `service_socks_proxy`, `service_telnet`, `service_vnc`, `tls_weak_protocol`, `tlscert_no_revocation`, `tlscert_weak_signature`, `unsafe_sri_v2`, `insecure_ftp`, `contact_information_detected`, `server_error`, `service_soap`, `ssh_weak_cipher`, and `ssh_weak_mac`. This comparison includes SSC `info` and internal `UNKNOWN`, which are not numeric severity levels. Agreement on the other labels, including `ssh_weak_protocol`, is an independent judgment, not a severity mapping.

### UNKNOWN and unscored

The following **seven** keys are `UNKNOWN` and `affects_score=false`:

| Key | Why the MATCH is insufficient | Needed context |
|---|---|---|
| `spf_record_wildcard` | Wildcard SPF synthesis does not prove permissive authorization. | Effective policy and intended subdomain mail use. |
| `service_rsync` | A daemon greeting does not show accessible modules or file contents. | Module exposure and access controls. |
| `service_socks_proxy` | Method selection does not show that relay succeeds or can be abused. | Selected authentication method and authorized relay test or configuration. |
| `tlscert_no_revocation` | Missing OCSP/CRL URI does not establish compromise or the issuer's complete status strategy. | Issuer strategy, lifetime, and client validation behavior. |
| `contact_information_detected` | A contact URI can be intentional public functionality and does not establish sensitive-data exposure. | Sensitivity, publication intent, and a concrete abuse scenario. |
| `server_error` | Two HTTP 5xx responses establish failure, not a security-relevant cause or consequence. | Sensitive error leakage, attacker-controlled trigger, exhaustion, or an exploitable defect. |
| `service_soap` | SOAP/WSDL semantics establish a service surface, not weak authorization or vulnerable operations. | Callable operations, access controls, data sensitivity, and implementation vulnerabilities. |

The current scoring engine only treats `UNKNOWN` as an unresolved scoring risk when `affects_score=true`. With the implemented decisions, the seven observations remain assessed findings but have no penalty. Their unscored status is a deliberate review decision; it must not be represented as proof that the services or configurations are safe.

### `csp_unsafe_policy_v2`

Implemented as `LOW`, `affects_score=true`, **2 factor points for one qualifying MATCH**. The evaluator's MATCH means the effective active-content policy permits `unsafe-eval` or permits `unsafe-inline` without nonce/hash control. This weakens a browser defense against script injection; it does not establish an actual injection path or compromise. Its observed SSC severity is `low` metadata and is not the basis for the internal rating. A sensitive session plus a demonstrated injection path would justify a separate impact review based on additional evidence, not an automatic upgrade of this issue type.

### `unsafe_sri_v2`

Implemented as `LOW`, `affects_score=true`, **2 factor points for one qualifying MATCH**. Missing, invalid, disallowed, or mismatching integrity metadata establishes an SRI control weakness or inconsistency, not actual third-party compromise or successful malicious resource substitution. Its SSC severity is `high` metadata and is not the basis for the internal rating. A higher risk requires separate evidence of unauthorized resource modification and security-relevant delivery or execution.

## Implementation

The versioned v1.2 internal registry is [internal_risk_calibration.py](../backend/app/services/internal_risk_calibration.py). The [finding loader](../backend/app/services/finding_results.py) applies it only to findings pinned to imported `SSC_API` issue versions. Imported taxonomy rows keep their original SSC metadata and are not rewritten with internal risk. Missing SSC calibration entries fail closed to `UNKNOWN` and `affects_score=false`; SSC severity is never used as a fallback. Manual and other non-SSC catalog versions continue to use their explicit catalog risk metadata. Persisted normalized score results retain the internal risk, score relevance, exact catalog issue version, SSC severity, and allocated score impact used for that result. No schema migration is required.

## Supporting security references

The ratings are judgment calls constrained by the exact MATCH conditions in [SSC issue coverage](SSC_ISSUE_COVERAGE.md). Primary references for the underlying mechanisms are [OWASP CSP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [OWASP HTTP header guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html), [RFC 8996 on TLS 1.0/1.1](https://www.rfc-editor.org/rfc/rfc8996.html), [RFC 9989 on DMARC policy](https://www.rfc-editor.org/rfc/rfc9989.html), [RFC 7208 on SPF](https://www.rfc-editor.org/rfc/rfc7208.html), [RFC 5280 on certificates and revocation](https://www.rfc-editor.org/rfc/rfc5280.html), [RFC 4253 on SSH transport and negotiation](https://www.rfc-editor.org/rfc/rfc4253.html), [RFC 8758 on Arcfour deprecation](https://www.rfc-editor.org/rfc/rfc8758.html), [RFC 6151 on HMAC-MD5 considerations](https://www.rfc-editor.org/rfc/rfc6151.html), and [Redis security guidance](https://redis.io/docs/latest/operate/oss_and_stack/management/security/). These sources describe security mechanisms; none supplies or implies SSC proprietary score penalties.
