# SSC DIRECT 63 Audit

Audit date: 2026-10-01; implementation status updated 2026-10-08. Baseline: immutable `SSC_API` Golden Baseline content hash `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8` as captured in the repository. The 63 dashboard labels form a separate input set and do not replace or reduce the 202 issue baseline.

The [row-level CSV](SSC_DIRECT_63_AUDIT.csv) is the audit ledger. Each row includes the exact catalog key, factor, captured SSC severity, mapping status, current capability and implementation, proposed primitive, required evidence, deterministic MATCH/NO_MATCH/INDETERMINATE boundaries, classification, and rationale. `EXACT` means the dashboard label matches the captured catalog title character for character; no key was inferred from the label. `mapping_candidates` is reserved for ambiguous rows and is empty here.

## Source and decision rules

- Keys, titles, factors, SSC severity, feasibility, evidence proposals, and current support were read from [SSC_ISSUE_COVERAGE.csv](SSC_ISSUE_COVERAGE.csv) and checked against [SSC_ISSUE_COVERAGE.md](SSC_ISSUE_COVERAGE.md). The source CSV contains 202 distinct keys. No live SSC API was called.
- Feasibility and downgrades were cross-checked with [SSC_COVERAGE_QUALITY_REVIEW.md](SSC_COVERAGE_QUALITY_REVIEW.md), [SSC_SCANNER_PRIMITIVES.md](SSC_SCANNER_PRIMITIVES.md), and [SSC_TEST_METHOD_CATALOG.md](SSC_TEST_METHOD_CATALOG.md).
- Current implementation was checked against the Wave 1/2/3A/3B/4A/4B/5A/5B.1 rule registries, `scan_executors.py`, `http_content.py`, `service_probes.py`, `service_probe_database.py`, `ssh_negotiation.py`, focused Wave tests, and [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md). `SUPPORTED` retains the existing exact-version active-evaluator gate; proposed probes do not imply support.
- `VERIFIED_DIRECT` means the condition is deterministically observable on an authorized target within a declared URL/port/flow manifest. It does not assert full Internet-wide absence, SSC collection equivalence, or that an evaluator is already implemented. A complete scoped negative is required for `NO_MATCH`; missing, failed, ambiguous, or out-of-scope evidence is `INDETERMINATE`/`NOT_ASSESSED`. A port number or open socket never identifies a service.
- `MOVE_TO_ENRICHMENT` means the title requires authorized flow context, a reviewed catalog/policy, external terminal-destination proof, authoritative revocation data, or inventory/canary evidence in addition to a simple target probe. Such rows are excluded from the direct implementation backlog. No candidate remained `UNRESOLVED`.

## Exact counts

| Measure | Count |
|---|---:|
| Total reviewed | 63 |
| `VERIFIED_DIRECT` | 53 |
| `MOVE_TO_ENRICHMENT` | 10 |
| `UNRESOLVED` | 0 |
| `EXACT` mappings | 63 |
| `NAME_VARIANT` mappings | 0 |
| `AMBIGUOUS` mappings | 0 |
| `NOT_FOUND` mappings | 0 |
| Current `SUPPORTED` | 39 |
| Current `PARTIAL` | 23 |
| Current `NOT_SUPPORTED` | 1 |
| Direct backlog: verified and not supported | 14 |

The 63 include **39 of the platform’s 43 closed supported capabilities**. The other four supported issues are `spf_record_softfail`, `dmarc_record_missing`, `dmarc_contains_none`, and `subdomain_dmarc_contains_none`; they are in the 202 issue catalog but outside this dashboard list. All 39 supported rows here remain `VERIFIED_DIRECT`. Wave 5B.1 moves closed direct support from **38/53 to 39/53** through `service_ldap`. Wave 5C implements Minecraft, PPTP, and RDP protocol observations but keeps them inactive because no authoritative public-target plus approved external-vantage context exists; PPTP also lacks real interoperability. Including pending Oracle, the implementation ceiling is **43/53** while CLOSED remains **39/53**.

## By SSC factor

| Factor | Reviewed | Verified direct | Move to enrichment | Unresolved | Supported | Partial | Not supported |
|---|---:|---:|---:|---:|---:|---:|---:|
| `application_security` | 22 | 16 | 6 | 0 | 16 | 5 | 1 |
| `network_security` | 37 | 33 | 4 | 0 | 19 | 18 | 0 |
| `dns_health` | 3 | 3 | 0 | 0 | 3 | 0 | 0 |
| `ip_reputation` | 1 | 1 | 0 | 0 | 1 | 0 | 0 |
| **Total** | **63** | **53** | **10** | **0** | **39** | **23** | **1** |

## By proposed scanner primitive

The primary implementation backlog groups direct rows by reusable primitive. Composite primitives below show the extra dependency needed by reclassified rows. `SERVICE_PROTOCOL` means a protocol-specific bounded adapter on the existing framework, including DNS over the service endpoint; `DNS` means authoritative TXT/SPF policy evidence.

| Primitive | Reviewed | Verified direct | Move to enrichment | Supported | Direct backlog |
|---|---:|---:|---:|---:|---:|
| `SERVICE_PROTOCOL` | 24 | 24 | 0 | 11 | 13 |
| `HTTP_CONTENT` | 7 | 7 | 0 | 7 | 0 |
| `HTTP_HEADERS` | 6 | 6 | 0 | 6 | 0 |
| `TLS_CERTIFICATE` | 5 | 5 | 0 | 5 | 0 |
| `HTTP_REDIRECT` | 3 | 3 | 0 | 3 | 0 |
| `SSH_NEGOTIATION` | 3 | 3 | 0 | 3 | 0 |
| `DNS` | 3 | 3 | 0 | 3 | 0 |
| `HTTP_HEADERS+AUTH_FLOW` | 2 | 0 | 2 | 0 | 0 |
| `TLS_NEGOTIATION` | 2 | 2 | 0 | 1 | 1 |
| `BROWSER_RUNTIME+PRODUCT_FINGERPRINT` | 1 | 0 | 1 | 0 | 0 |
| `HTTP_REDIRECT+EXTERNAL_EVIDENCE` | 1 | 0 | 1 | 0 | 0 |
| `HTTP_CONTENT+PRODUCT_FINGERPRINT` | 1 | 0 | 1 | 0 | 0 |
| `BROWSER_RUNTIME+TLS_CERTIFICATE` | 1 | 0 | 1 | 0 | 0 |
| `TLS_REVOCATION` | 1 | 0 | 1 | 0 | 0 |
| `PROXY_VALIDATION` | 1 | 0 | 1 | 0 | 0 |
| `SERVICE_PROTOCOL+PRODUCT_FINGERPRINT` | 1 | 0 | 1 | 0 | 0 |
| `TLS_CERTIFICATE+POLICY` | 1 | 0 | 1 | 0 | 0 |
| **Total** | **63** | **53** | **10** | **39** | **14** |

## Prioritized direct implementation backlog

Only the 14 `VERIFIED_DIRECT` rows still lacking `SUPPORTED` status appear below. Priority favors shared collectors and parsers that unlock several exact catalog issues. Each later implementation batch still needs exact-version rule linkage, positive and negative tests, false-positive/unknown-boundary tests, and any required real interoperability before its coverage can become `SUPPORTED`. The order is a planning recommendation, not implementation authorization.

| Priority | Primitive | Count | Exact SSC keys and batch scope |
|---:|---|---:|---|
| 1 | `SERVICE_PROTOCOL` | 13 | Extend the bounded adapter framework only in separately reviewed protocol-specific groups. Wave 5B.1 closed LDAP; Oracle Net is implemented pending real interoperability. Wave 5C implements `minecraft_server`, `service_pptp`, and `service_rdp`, but all remain inactive pending authoritative exposure/vantage context and PPTP additionally awaits real interoperability.<br>`service_cassandra`, `service_couchdb`, `service_dns`, `service_elasticsearch`, `service_microsoft_sql`, `minecraft_server`, `service_mongodb`, `service_mysql`, `service_oracle_db`, `service_pptp`, `service_postgresql`, `service_rdp`, `upnp_accessible` |
| 2 | `TLS_NEGOTIATION` | 1 | Use a client capable of offering every prohibited suite in the pinned policy and retain successful modern controls before making a negative claim.<br>`tls_weak_cipher` |

Wave 4A completed SSH; Wave 5A completed FTP, IMAP, POP3, and unusual-port SMTP; Wave 5B.1 closes LDAP while Oracle remains pending. Wave 5C's complete framed Minecraft status, PPTP SCCRP, and RDP negotiation evidence proves protocol identity only. It does not prove the baseline's public-exposure condition, so those entries remain in the 13-row backlog until authoritative target exposure and external-vantage evidence exists; PPTP also needs real interoperability. Algorithm or protocol evidence does not prove exploitation, authentication weakness, product version, or Internet exposure.

## Candidates that do not survive DIRECT review

| # | Exact SSC key | Why moved |
|---:|---|---|
| 1 | `cookie_missing_http_only` | Session purpose needs a reviewed cookie inventory and authorized synthetic authentication flow. |
| 2 | `cookie_missing_secure_attribute` | Session purpose needs a reviewed cookie inventory and authorized synthetic authentication flow. |
| 4 | `payment_provider` | Provider identity needs a reviewed provider/SDK catalog; a contacted origin alone is insufficient. |
| 12 | `redirect_to_insecure_website` | An external Location is only a next hop; terminal scheme needs authorized or passive external redirect evidence. |
| 13 | `references_object_storage_v2` | Provider identity needs reviewed multi-signal storage fingerprints and a versioned catalog. |
| 17 | `communication_server_with_expired_cert` | A contacted third-party origin may be outside probe scope; expiry needs authorized TLS or fresh passive certificate evidence. |
| 23 | `tlscert_revoked` | Revocation requires fresh signed issuer OCSP/CRL evidence beyond the target certificate and TLS handshake. |
| 30 | `service_http_proxy` | Conclusive proxy semantics need a separately authorized organization-owned canary destination; an HTTP banner or 407 alone is insufficient. |
| 37 | `service_open_vpn` | OpenVPN may be silent unauthenticated; a unique product fingerprint or authoritative inventory is needed. |
| 56 | `tlscert_excessive_expiration` | Applicable maximum needs historical CA/B policy and certificate applicability at issuance. |

Nine of these ten already carry `TESTABLE_WITH_ENRICHMENT` in the current coverage matrix. `service_http_proxy` is the new downgrade in this audit: a generic HTTP response, proxy-looking error, or open port does not prove proxy forwarding; an organization-owned canary would need separate authorization and evidence. `service_open_vpn` may remain silent without authentication. A certificate with an OCSP URI is not proof of current non-revocation.

## Mapping and coverage observations

- All 63 titles match exactly one captured catalog title. There are no ambiguous or missing keys. `SPF Record Found Ineffective` is exactly `spf_record_wildcard` in this catalog; it is specifically about wildcard-synthesized SPF, not every weak SPF policy.
- `Server error detected` is `SUPPORTED`: the executor makes exactly two bounded safe GET attempts for each explicitly declared URL; one 5xx or an incomplete pair is `INDETERMINATE`.
- `TLS Service Supports Weak Cipher Suite` is `PARTIAL`: current constrained handshakes can prove some positive acceptance, but the client cannot offer every prohibited suite needed for a conclusive negative.
- `Malformed SPF Record` is `SUPPORTED` by Wave 4B's bounded permanent-error analyzer. Runtime-context-dependent or mixed paths remain `INDETERMINATE`; this is not sender-authorization scoring.
- `SOAP Server Accessible` is supported only for explicitly declared authorized HTTP endpoints. Unknown paths cannot produce a host-wide `NO_MATCH`.
- The active Wave 3A adapters cover six service labels in this set. The other service rows retain `PARTIAL` until a protocol-specific response is validated; a port number or arbitrary banner is never sufficient.

## Validation boundary

The original audit was docs-only. The implementation status through 2026-10-05 is backed by focused Wave tests and exact-version activation against isolated migrated test databases. No live SSC request, production database mutation, scoring change, catalog-baseline change, commit, or push was performed. The audit inherits the repository snapshot’s baseline attestation; it does not independently query a production database.
