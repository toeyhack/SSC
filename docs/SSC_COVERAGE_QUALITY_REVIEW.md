# SSC Coverage Quality Gate

Baseline content hash: `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`  
Review date: 2026-09-20  
Scope: analysis/design only; no scanner, rule, score, or Golden Baseline change.

## Wave 1 implementation update (2026-09-21)

The quality gate below remains the authority for issue selection. Wave 1 implemented only `HTTP_HEADERS`, `HTTP_REDIRECT`, and `TLS_CERTIFICATE`. Activation was verified against an isolated clone of the attested real SSC API baseline with the hash above: **14** exact issue definitions received active deterministic evaluators and immutable rule-version-to-issue-version links.

| Coverage | Before Wave 1 | After Wave 1 |
|---|---:|---:|
| `SUPPORTED` | 0 | 14 |
| `PARTIAL` | 119 | 105 |
| `NOT_SUPPORTED` | 83 | 83 |

Newly supported: `csp_no_policy_v2`, `csp_too_broad_v2`, `csp_unsafe_policy_v2`, `domain_missing_https_v2`, `hsts_incorrect_v2`, `insecure_https_redirect_pattern_v2`, `insecure_server_certificate_key_size`, `redirect_chain_contains_http_v2`, `tlscert_expired`, `tlscert_no_revocation`, `tlscert_self_signed`, `tlscert_weak_signature`, `x_content_type_options_incorrect_v2`, and `x_frame_options_incorrect_v2`.

The eight reviewed Wave 1 candidates requiring authentication/policy enrichment, external redirect evidence, CA attribution/lifetime data, or authoritative revocation status remain `PARTIAL`. SSC severity remains separate from internal risk and scoring. No score-impact inference was added.

## Wave 2 implementation update (2026-09-21)

Wave 2 implemented only `TLS_HANDSHAKE` and `EMAIL_SECURITY`. Exact activation against an isolated clone of the same attested real SSC API baseline added **7** mappings: `tls_weak_protocol`, `spf_record_missing`, `spf_record_softfail`, `spf_record_wildcard`, `dmarc_record_missing`, `dmarc_contains_none`, and `subdomain_dmarc_contains_none`.

| Coverage | Before Wave 2 | After Wave 2 |
|---|---:|---:|
| `SUPPORTED` | 14 | 21 |
| `PARTIAL` | 105 | 101 |
| `NOT_SUPPORTED` | 83 | 80 |
| **Total** | **202** | **202** |

`tls_weak_cipher`, `tls_ocsp_stapling`, `spf_record_malformed`, and the three DKIM issues remain `PARTIAL`: the current client cannot prove rejection of every prohibited legacy suite, the socket API does not expose a cryptographically verifiable staple, full RFC 7208 permanent-error evaluation is incomplete, and no authorized DKIM selector/message evidence exists. No service identification, external intelligence, Golden Baseline, or scoring-methodology changes are included.

## Pre-Wave 1 outcome

The original 87 `DIRECTLY_TESTABLE` rows were re-reviewed against the imported issue descriptions, current executor evidence, authorization boundaries, and public standards. Twelve were over-optimistic and have been downgraded to `TESTABLE_WITH_ENRICHMENT`. No issue was upgraded.

The key gate is semantic proof: observing a header, field name, port, banner, redirect, or browser event is not enough when that observation is only a proxy for session purpose, sensitive-data meaning, product identity, external destination state, CA attribution, certificate revocation, or time-varying policy.

### Revised feasibility

| Category | Count | Percentage |
|---|---:|---:|
| `DIRECTLY_TESTABLE` | 75 | 37.1% |
| `TESTABLE_WITH_ENRICHMENT` | 81 | 40.1% |
| `EXTERNAL_DATA_REQUIRED` | 42 | 20.8% |
| `NOT_REPRODUCIBLE` | 4 | 2.0% |
| **Total** | **202** | **100.0%** |

### Revised current coverage

| Coverage | Count | Percentage |
|---|---:|---:|
| `SUPPORTED` | 0 | 0.0% |
| `PARTIAL` | 119 | 58.9% |
| `NOT_SUPPORTED` | 83 | 41.1% |
| **Total** | **202** | **100.0%** |

`SUPPORTED` means both sufficient evidence collection **and** an implemented evaluator for that specific SSC-aligned condition. A read-only database check found zero active rule versions linked to an issue whose current source is `SSC_API`. The four previously labeled supported rows (`redirect_chain_contains_http_v2`, `spf_record_missing`, `open_port`, and `tlscert_expired`) collect useful or sufficient raw evidence, but no linked SSC-aligned evaluator exists; they are therefore `PARTIAL`.

### Factor coverage after review

| Factor | Total | Direct | Enrichment | External | Not reproducible | Supported | Partial | Not supported |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `application_security` | 61 | 25 | 35 | 0 | 1 | 0 | 40 | 21 |
| `cubit_score` | 3 | 0 | 1 | 0 | 2 | 0 | 1 | 2 |
| `dns_health` | 10 | 7 | 3 | 0 | 0 | 0 | 7 | 3 |
| `endpoint_security` | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 2 |
| `hacker_chatter` | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 2 |
| `ip_reputation` | 26 | 1 | 1 | 24 | 0 | 0 | 2 | 24 |
| `leaked_information` | 8 | 0 | 0 | 8 | 0 | 0 | 0 | 8 |
| `network_security` | 68 | 42 | 20 | 5 | 1 | 0 | 61 | 7 |
| `patching_cadence` | 21 | 0 | 21 | 0 | 0 | 0 | 8 | 13 |
| `social_engineering` | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 1 |

No factor has a currently supported SSC-aligned evaluator. The structurally weakest factors are `endpoint_security`, `hacker_chatter`, `leaked_information`, and `social_engineering` (all rows require external data), followed by `ip_reputation` (24 of 26 require external data). `patching_cadence` is addressable but needs product/version/CVE history rather than a point-in-time perimeter probe.

## Classification changes

| Issue | Previous | Revised | Quality-gate reason |
|---|---|---|---|
| `communication_server_with_expired_cert` | Direct | Enrichment | Browser dependency discovery is direct, but proving expiry can require a TLS probe of a third-party origin outside authorization or fresh passive certificate evidence. |
| `cookie_missing_http_only` | Direct | Enrichment | The attribute is observable; whether a cookie is a session/authentication cookie requires a reviewed cookie inventory and usually an approved synthetic authentication flow. |
| `cookie_missing_secure_attribute` | Direct | Enrichment | Same semantic gap as `cookie_missing_http_only`; cookie names are not reliable purpose evidence. |
| `redirect_to_insecure_website` | Direct | Enrichment | An external `Location` proves only the next hop. Establishing the terminal insecure destination may require out-of-scope probing or an approved passive redirect source. |
| `sensitive_data_exposure_through_insecure_channel` | Direct | Enrichment | Field names/input types are proxy signals. Sensitivity requires application schema/data-classification context and synthetic/test-authenticated flow evidence. |
| `websocket_requests_contain_sensitive_fields` | Direct | Enrichment | Browser frames are observable, but PII/sensitivity cannot be established from suggestive field names alone. |
| `x_xss_protection_incorrect_v2` | Direct | Enrichment | Imported guidance recommends a legacy value, while major modern browsers removed the feature. A versioned browser-estate policy is required to define correctness. |
| `service_open_vpn` | Direct | Enrichment | OpenVPN can intentionally remain silent to unauthenticated probes; TCP/UDP reachability is not product identity. Use reviewed fingerprints or authoritative inventory. |
| `service_oracle_registry` | Direct | Enrichment | No unique public wire-level handshake was identified. Generic SOAP/UDDI or banner evidence is only a proxy without product fingerprints/inventory. |
| `tlscert_excessive_expiration` | Direct | Enrichment | The certificate dates are direct, but the CA/B Forum maximum depends on issuance date and certificate applicability and changes over time. |
| `tlscert_revoked` | Direct | Enrichment | Revocation normally requires fresh, signed CA OCSP/CRL data; it is not established by the leaf certificate or ordinary TLS handshake. |
| `uses_go_daddy_infrastructure` | Direct | Enrichment | Issuer text is spoofable and CA hierarchies change. Attribution requires a versioned GoDaddy CA/SPKI identifier registry. |

Downgrades: **12**. Upgrades: **0**.

## Re-review of all 87 original direct rows

Legend: `Y` = yes; `N` = no; `C` = conditional on declared scan scope/flow; `S` = sufficient only for the bounded positive observation. “Extra data” asks whether external intelligence or application/product/policy enrichment is needed, not whether a static RFC is referenced. A retained direct result never treats absence outside the declared target/URL/port/flow set as a pass.

| Original direct issue | Externally observable | Semantics established | Auth | Browser | Product/version fingerprint | Extra data | Proxy risk | Gate result / constraint |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| `browser_logs_contain_debug_message` | Y | S | C | Y | N | N | C | **Direct retained** — repeatable console event matching a versioned message policy; coverage is limited to rendered URLs. |
| `communication_server_with_expired_cert` | C | N | N | Y | N | Y | Y | **Downgrade** — dependency discovery does not itself prove expiry, and third-party probing may be out of scope. |
| `contact_information_detected` | Y | Y | N | N | N | N | N | **Direct retained** — DOM URI scheme plus redacted contact token directly establishes displayed contact information. |
| `cookie_missing_http_only` | Y | N | Y | C | N | Y | Y | **Downgrade** — missing attribute is direct; session purpose is not. |
| `cookie_missing_secure_attribute` | Y | N | Y | C | N | Y | Y | **Downgrade** — missing attribute is direct; session purpose is not. |
| `csp_no_policy_v2` | Y | S | N | N | N | N | C | **Direct retained** — collect every CSP header/meta policy on declared HTML URLs; root-only absence is insufficient. |
| `csp_too_broad_v2` | Y | S | N | N | N | N | C | **Direct retained** — parse effective policy and apply a versioned broad-source rule set. |
| `csp_unsafe_policy_v2` | Y | S | N | N | N | N | C | **Direct retained** — effective `unsafe-inline`/`unsafe-eval` semantics are deterministically parseable. |
| `domain_missing_https_v2` | Y | S | N | N | N | N | C | **Direct retained** — HTTPS reachability, trust, and HTTP upgrade behavior for declared canonical endpoints. |
| `fail_to_load_page_components` | Y | S | C | Y | N | N | C | **Direct retained** — repeated failed browser subresource events; transient/client-blocked errors remain unknown. |
| `hsts_incorrect_v2` | Y | S | N | N | N | N | C | **Direct retained** — valid STS parsing on declared HTTPS hosts; HTTP-delivered STS is ignored. |
| `insecure_ftp` | Y | Y | N | N | N | N | N | **Direct retained** — an `ftp:` link is the issue observation; no FTP connection is needed. |
| `insecure_https_redirect_pattern_v2` | Y | S | N | N | N | N | C | **Direct retained** — normalized HTTPS-to-HTTP downgrade or oscillation in a bounded authorized chain. |
| `insecure_server_certificate_key_size` | Y | Y | N | N | N | N | N | **Direct retained** — key algorithm/size or curve from the served certificate against versioned crypto policy. |
| `insecure_telnet` | Y | Y | N | N | N | N | N | **Direct retained** — a `telnet:` link directly establishes the non-standard link condition. |
| `links_to_insecure_website` | Y | Y | N | N | N | N | N | **Direct retained** — an HTTP hyperlink is direct link evidence; it does not assert target compromise. |
| `local_file_path_exposed_via_url_scheme` | Y | Y | N | N | N | N | N | **Direct retained** — a `file:`/local-path URI in delivered content is direct evidence. |
| `redirect_chain_contains_http_v2` | Y | Y | N | N | N | N | N | **Direct retained** — any observed hop or emitted `Location` resolving to `http:` is sufficient. |
| `redirect_to_insecure_website` | C | N | N | N | N | Y | Y | **Downgrade** — an unprobed external redirect is not proof of the terminal destination. |
| `sensitive_data_exposure_through_insecure_channel` | C | N | Y | Y | N | Y | Y | **Downgrade** — sensitivity requires schema/policy or synthetic-marker provenance. |
| `server_error` | Y | S | N | N | N | N | C | **Direct retained** — 5xx or a reviewed server-error disclosure signature; generic error wording alone is not enough. |
| `site_emits_browser_log` | Y | S | C | Y | N | N | C | **Direct retained** — visible console event in a declared flow; no site-wide absence claim. |
| `site_requests_data_over_insecure_channel` | Y | S | C | Y | N | N | C | **Direct retained** — browser network event using `http:`/`ws:` from an HTTPS page. |
| `unsafe_sri_v2` | Y | S | N | N | N | N | C | **Direct retained** — cross-origin script/style element plus missing/invalid integrity/crossorigin semantics. |
| `website_copyright_expired` | Y | S | N | N | N | N | C | **Direct retained** — parsed footer year/range ends before scan year; this says nothing about compromise. |
| `website_copyright_up_to_date` | Y | S | N | N | N | N | C | **Direct retained** — parsed footer year/range includes scan year on a declared page set. |
| `websocket_receives_data` | Y | S | C | Y | N | N | C | **Direct retained** — bounded inbound frame observed; no traffic implies only not observed. |
| `websocket_requests_contain_sensitive_fields` | C | N | Y | Y | N | Y | Y | **Downgrade** — field names alone do not establish PII/sensitivity. |
| `websocket_sends_data` | Y | S | C | Y | N | N | C | **Direct retained** — bounded outbound frame observed; payload values need not be retained. |
| `x_content_type_options_incorrect_v2` | Y | Y | N | N | N | N | N | **Direct retained** — exact normalized `nosniff` value on declared responses. |
| `x_frame_options_incorrect_v2` | Y | S | N | N | N | N | C | **Direct retained** — evaluate effective CSP `frame-ancestors` and valid XFO fallback/precedence. |
| `x_xss_protection_incorrect_v2` | Y | N | N | N | N | Y | Y | **Downgrade** — observable header, but “best practice” depends on legacy browser estate and conflicts with modern guidance. |
| `dmarc_contains_none` | Y | Y | N | N | N | N | N | **Direct retained** — parse the applicable DMARC record and effective `p`/`sp` policy. |
| `dmarc_record_missing` | Y | S | N | N | N | N | C | **Direct retained** — authoritative NODATA/NXDOMAIN on a declared organizational domain; resolver failure is unknown. |
| `spf_record_malformed` | Y | Y | N | N | N | N | N | **Direct retained** — RFC 7208 parse/evaluation error, including multiple records and lookup-limit violations. |
| `spf_record_missing` | Y | S | N | N | N | N | C | **Direct retained** — no `v=spf1` TXT on the declared domain; DNS failure is unknown. |
| `spf_record_softfail` | Y | Y | N | N | N | N | N | **Direct retained** — terminal `~all` plus absent/non-enforcing effective DMARC, both from DNS evidence. |
| `spf_record_wildcard` | Y | Y | N | N | N | N | N | **Direct retained** — nonce subdomain TXT queries prove wildcard synthesis; `+all` is separately an ineffective-policy condition. |
| `subdomain_dmarc_contains_none` | Y | S | N | N | N | N | C | **Direct retained** — effective policy for each declared subdomain; no claim about undiscovered subdomains. |
| `mail_server_unusual_port` | Y | Y | N | N | N | N | N | **Direct retained** — protocol-valid SMTP greeting/command response on a port outside versioned policy. |
| `bitcoin_server` | Y | Y | N | N | N | N | N | **Direct retained** — valid Bitcoin network message exchange; TCP-open/banner alone is insufficient. |
| `exposed_mobile_printing_service` | Y | Y | N | N | N | N | N | **Direct retained** — protocol-valid IPP/AirPrint response; no print job is submitted. |
| `java_debugger` | Y | Y | N | N | N | N | N | **Direct retained** — exact JDWP handshake echo; stop immediately afterward. |
| `minecraft_server` | Y | Y | N | N | N | N | N | **Direct retained** — valid server-list status response; no login. |
| `open_port` | Y | Y | N | N | N | N | N | **Direct retained** — completed TCP handshake on an approved port is exactly the exposure fact. |
| `service_cassandra` | Y | S | N | N | N | N | C | **Direct retained** — valid Cassandra-native protocol response establishes the service family, not an exact vendor binary. |
| `service_couchdb` | Y | S | N | N | N | N | C | **Direct retained** — stable CouchDB API product marker; ambiguous compatible responses remain unknown. |
| `service_dns` | Y | Y | N | N | N | N | N | **Direct retained** — syntactically valid DNS response to a harmless query over UDP and, where applicable, TCP. |
| `service_elasticsearch` | Y | S | N | N | N | N | C | **Direct retained** — multiple stable Elasticsearch response markers; generic JSON/port evidence is insufficient. |
| `service_ftp` | Y | Y | N | N | N | N | N | **Direct retained** — valid FTP greeting/`SYST` behavior; no authentication. |
| `service_http_proxy` | Y | Y | N | N | N | N | N | **Direct retained** — proxy successfully reaches only an organization-owned canary via absolute-form/CONNECT. |
| `service_imap` | Y | Y | N | N | N | N | N | **Direct retained** — valid IMAP greeting and `CAPABILITY`; no authentication. |
| `service_ldap` | Y | Y | N | N | N | N | N | **Direct retained** — valid LDAP bind/root-DSE protocol response. |
| `service_ldap_anonymous` | Y | Y | N | N | N | N | N | **Direct retained** — anonymous bind succeeds and bounded root-DSE read is permitted. |
| `service_microsoft_sql` | Y | S | N | N | N | N | C | **Direct retained** — protocol-valid TDS pre-login identity; exact edition/version needs separate enrichment. |
| `service_mongodb` | Y | S | N | N | N | N | C | **Direct retained** — protocol-valid MongoDB hello/error identity; compatible services must be reported as family only. |
| `service_mysql` | Y | S | N | N | N | N | C | **Direct retained** — MySQL-family initial handshake; do not assert Oracle MySQL vs MariaDB without enrichment. |
| `service_neo4j` | Y | S | N | N | N | N | C | **Direct retained** — valid Bolt negotiation establishes a Neo4j/Bolt service family. |
| `service_open_vpn` | C | N | N | N | Y | Y | Y | **Downgrade** — silence/open port is not identity and unauthenticated response is not universal. |
| `service_oracle_db` | Y | S | N | N | N | N | C | **Direct retained** — protocol-valid TNS response establishes Oracle-compatible DB service, not patch level. |
| `service_oracle_registry` | C | N | N | N | Y | Y | Y | **Downgrade** — generic UDDI/SOAP evidence is only a proxy for the Oracle product. |
| `service_pop3` | Y | Y | N | N | N | N | N | **Direct retained** — valid POP3 greeting/`CAPA`; no authentication. |
| `service_postgresql` | Y | S | N | N | N | N | C | **Direct retained** — valid PostgreSQL wire response; compatible services are reported as family. |
| `service_pptp` | Y | Y | N | N | N | N | N | **Direct retained** — valid PPTP control response; no tunnel setup beyond negotiation. |
| `service_rdp` | Y | Y | N | N | N | N | N | **Direct retained** — valid X.224/RDP negotiation response; no authentication. |
| `service_redis` | Y | S | N | N | N | N | C | **Direct retained** — RESP-compatible response to a harmless command; do not assert vendor/version. |
| `service_rsync` | Y | Y | N | N | N | N | N | **Direct retained** — valid rsync daemon greeting; do not enumerate modules. |
| `service_smb` | Y | Y | N | N | N | N | N | **Direct retained** — valid SMB negotiate response; no session setup/share enumeration. |
| `service_soap` | Y | S | N | N | N | N | C | **Direct retained** — valid SOAP fault/envelope or WSDL at a declared endpoint; generic XML is insufficient. |
| `service_socks_proxy` | Y | Y | N | N | N | N | N | **Direct retained** — SOCKS negotiation plus connection only to an organization-owned canary. |
| `service_telnet` | Y | Y | N | N | N | N | N | **Direct retained** — valid Telnet IAC negotiation; banner text/TCP-open alone is insufficient. |
| `service_vnc` | Y | Y | N | N | N | N | N | **Direct retained** — valid RFB version/security-type exchange; stop before authentication. |
| `ssh_weak_cipher` | Y | Y | N | N | N | N | N | **Direct retained** — server KEXINIT offers a policy-prohibited encryption algorithm. |
| `ssh_weak_mac` | Y | Y | N | N | N | N | N | **Direct retained** — server KEXINIT offers a policy-prohibited MAC. |
| `ssh_weak_protocol` | Y | Y | N | N | N | N | N | **Direct retained** — SSH-1 identification or prohibited negotiation behavior. |
| `telephony` | Y | S | N | N | N | N | C | **Direct retained** — valid SIP response establishes an accessible VoIP signaling service, not a hardware brand. |
| `tls_ocsp_stapling` | Y | Y | N | N | N | N | N | **Direct retained** — cryptographically parseable staple in a status-request handshake. |
| `tls_weak_cipher` | Y | Y | N | N | N | N | N | **Direct retained** — at least one policy-prohibited cipher suite completes a bounded handshake. |
| `tls_weak_protocol` | Y | Y | N | N | N | N | N | **Direct retained** — at least one policy-prohibited protocol version completes a bounded handshake. |
| `tlscert_excessive_expiration` | Y | N | N | N | N | Y | Y | **Downgrade** — direct dates need issuance-date CA/B policy history and applicability. |
| `tlscert_expired` | Y | Y | N | N | N | N | N | **Direct retained** — `notAfter < observation_time` is deterministic. |
| `tlscert_no_revocation` | Y | Y | N | N | N | N | N | **Direct retained** — no usable AIA OCSP or CRL distribution point in the served certificate. |
| `tlscert_revoked` | C | N | N | N | N | Y | Y | **Downgrade** — requires fresh authoritative signed OCSP/CRL status. |
| `tlscert_self_signed` | Y | Y | N | N | N | N | N | **Direct retained** — subject/issuer plus self-signature verification; trust failure alone is insufficient. |
| `tlscert_weak_signature` | Y | Y | N | N | N | N | N | **Direct retained** — weak signature algorithm on leaf/intermediate in the served validated path. |
| `upnp_accessible` | Y | S | N | N | N | N | C | **Direct retained** — protocol-valid SSDP/UPnP response; absence is indeterminate because multicast may not traverse routing. |
| `uses_go_daddy_infrastructure` | Y | N | N | N | Y | Y | Y | **Downgrade** — chain is direct, but CA attribution needs maintained SPKI/certificate identifiers. |

The 75 retained rows are reliable only as bounded positive observations with explicit scope. “Not observed” must not silently become “secure” when crawl coverage, browser flow, UDP reachability, or protocol response is incomplete.

## Detailed review of the original Top 20

In this section, **fail** means the SSC-aligned condition was positively observed, **pass** means it was not present across the declared test scope, and **unknown** means the probe or required context was incomplete. These are finding outcomes, not score outcomes. The original Top 20 is retained as the review cohort; three rows are now enrichment-dependent and should not enter a no-enrichment implementation sprint.

| # | Issue | Exact request / probe | Exact evidence | Deterministic pass/fail condition | False-positive / false-negative controls | Authoritative reference | Current executor has all evidence? |
|---:|---|---|---|---|---|---|---|
| 1 | `cookie_missing_http_only` | Run the configured synthetic login/session-establishment HTTP/browser sequence once over HTTPS; capture every `Set-Cookie` without values and join hashed names to the approved session-cookie inventory. | URL, status, time, flow step, hashed cookie name, purpose-map version, `HttpOnly` boolean, parse error. | **Fail:** a cookie proven to carry a session/auth function lacks `HttpOnly`. **Pass:** every classified session cookie set in the complete flow has it. **Unknown:** no approved flow/purpose mapping, parse error, or incomplete flow. | FP: never classify by name alone. FN: include login, refresh, privilege change, and logout/session rotation steps; declare coverage. | [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html), [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | **No.** Attributes are captured, but there is no authenticated flow or cookie-purpose evidence. |
| 2 | `cookie_missing_secure_attribute` | Same approved session-establishment sequence; capture every redacted `Set-Cookie` from HTTP and HTTPS responses. | Same as #1, with `Secure` boolean and originating scheme. | **Fail:** a proven session/auth cookie lacks `Secure`. **Pass:** all classified session cookies have it. **Unknown:** purpose/flow incomplete. | FP: do not treat preferences/analytics as session cookies. FN: exercise every session-creation/rotation response, including alternate hosts. | [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265.html), [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) | **No.** It captures attributes but not session semantics or the complete flow. |
| 3 | `csp_no_policy_v2` | `GET` every declared HTML URL with a fixed user agent; retain all `Content-Security-Policy` and `Content-Security-Policy-Report-Only` instances and parse CSP `<meta http-equiv>` elements from the bounded body. | Final URL/status/content type, every policy instance in order, delivery channel, parsed directives, body hash, truncation flag. | **Fail:** an HTML document has no valid enforced CSP header or permitted CSP meta policy; report-only alone does not pass. **Pass:** at least one valid enforced policy applies. **Unknown:** body/header truncation, blocked/auth-only page, or fetch error. | FP: distinguish report-only; honor meta placement/unsupported directives. FN: crawl declared templates/routes, not only `/`; preserve duplicate headers. | [W3C CSP3](https://www.w3.org/TR/CSP3/), [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | **No.** Only one selected response/header value is retained; body/meta and multi-URL coverage are absent. |
| 4 | `csp_unsafe_policy_v2` | Use the same response set as #3 and compute the effective enforced CSP for each document. | Parsed effective directives, source expressions, nonce/hash presence, policy text hashes, parser diagnostics. | **Fail:** the versioned policy identifies an operative prohibited token such as `unsafe-eval` or an unmitigated `unsafe-inline` in a protected directive. **Pass:** no prohibited operative token. **Unknown:** invalid/truncated/ambiguous policy. | FP: account for CSP3 nonce/hash behavior and directive fallback. FN: collect all simultaneous policies and meta policies across declared routes. | [W3C CSP3](https://www.w3.org/TR/CSP3/), [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | **No.** A header value is available only for one selected response; no effective-policy parser exists. |
| 5 | `csp_too_broad_v2` | Use #3 evidence; compare each operative source list with a versioned rule set (for example wildcard or broad scheme sources in high-impact directives). | Effective directive, exact source expression, fallback source, rule/policy version, document URL. | **Fail:** an operative directive matches an explicitly prohibited broad-source rule. **Pass:** none match. **Unknown:** policy cannot be parsed or coverage incomplete. | FP: do not flag syntactically broad but non-operative tokens; state the local threshold. FN: include `default-src` fallback and all policy instances. | [W3C CSP3](https://www.w3.org/TR/CSP3/), [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) | **No.** No complete policy collection or evaluator. |
| 6 | `domain_missing_https_v2` | For each declared canonical host/port, perform SNI TLS handshake plus `GET /` over HTTPS, then `GET /` over HTTP and follow at most five inventory-scoped redirects. | IP/host/port/SNI, TLS availability/trust/name result, every HTTP status/location/hop, final scheme, stop reason. | **Fail:** HTTPS is unavailable for the declared endpoint or HTTP serves content/terminates without upgrading to the declared HTTPS endpoint. **Pass:** HTTPS is available and every tested HTTP entry upgrades without a downgrade. **Unknown:** timeout, scope boundary, or nonrepresentative/auth-only endpoint. | FP: separate TLS trust/name defects into certificate findings and use declared canonical hosts. FN: include alternate configured ports/hostnames and declared entry paths. | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), [OWASP TLS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | **No, not for the full method.** Root/port attempts and same-host redirects exist, but declared site coverage and a linked evaluator do not. |
| 7 | `hsts_incorrect_v2` | `GET` each declared HTTPS host/representative response; collect every `Strict-Transport-Security` instance only from authenticated HTTPS transport and parse directives. | Host/URL/status, transport validity, all STS values, parsed `max-age`, `includeSubDomains`, `preload`, policy version. | **Fail:** missing/invalid STS or `max-age`/subdomain behavior violates the explicit internal threshold. **Pass:** parsed effective value satisfies it. **Unknown:** HTTPS/coverage failure. | FP: ignore STS received over HTTP and do not universally require `preload`. FN: test each canonical hostname and preserve duplicate/conflicting values. | [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797.html), [OWASP HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | **No.** Presence/value on one selected response exists, but complete host/multi-value semantics and an evaluator do not. |
| 8 | `redirect_chain_contains_http_v2` | `GET` the declared HTTPS entry URL and follow at most five same-inventory redirects; normalize every relative `Location`. Do not fetch an external target. | Per hop: requested URL, status, raw/normalized `Location`, scheme/host/port, elapsed time, stop reason. | **Fail:** any observed hop after the start uses `http:` or any HTTPS hop emits a `Location` resolving to `http:`. **Pass:** complete bounded chain contains no HTTP hop/location. **Unknown:** loop, limit, transport error, or unresolved location. | FP: resolve relative/network-path references correctly. FN: declare entry URLs; external `http:` Location is already sufficient without fetching it. | [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html), [WHATWG URL](https://url.spec.whatwg.org/) | **Yes for evidence, no for support.** The current executor records hops and `location_scheme`, but no SSC-linked evaluator exists. |
| 9 | `x_content_type_options_incorrect_v2` | `GET` each declared HTML/script/style response and retain all `X-Content-Type-Options` instances. | URL/status/content type, every normalized header value, duplicate/conflict state. | **Fail:** header is absent, conflicting, or its normalized value is not exactly `nosniff` where policy requires it. **Pass:** valid `nosniff`. **Unknown:** response unavailable or outside coverage. | FP: define which resource classes require it. FN: do not test only `/`; preserve duplicate values. | [Fetch standard](https://fetch.spec.whatwg.org/), [OWASP HTTP Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) | **No.** One selected value/presence bit is captured, not all values/routes or a specific evaluator. |
| 10 | `x_frame_options_incorrect_v2` | `GET` declared HTML responses; collect all XFO and CSP policies, parse effective `frame-ancestors`, and apply CSP/XFO precedence. | URL, all XFO values, effective CSP `frame-ancestors`, parser result, policy version. | **Fail:** no effective anti-framing control, invalid/conflicting XFO, or effective allowlist violates policy. **Pass:** effective CSP or valid XFO meets policy. **Unknown:** incomplete policy/body/header evidence. | FP: CSP `frame-ancestors` can supersede XFO; `ALLOW-FROM` is obsolete. FN: collect all policies and representative routes. | [CSP3](https://www.w3.org/TR/CSP3/), [RFC 7034](https://www.rfc-editor.org/rfc/rfc7034.html), [OWASP Clickjacking Defense](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html) | **No.** Presence booleans exist, but complete effective-policy evaluation does not. |
| 11 | `tls_weak_protocol` | On each approved TLS endpoint, send bounded version-specific handshakes for every prohibited version (SSLv2/3 where the client supports safe detection, TLS 1.0, TLS 1.1) plus a modern control. | Host/IP/port/SNI, offered version, outcome, negotiated version/cipher, TLS alert/error, policy version. | **Fail:** any prohibited version completes negotiation. **Pass:** every prohibited attempt is definitively rejected and the control succeeds. **Unknown:** network/client limitation or ambiguous failure. | FP: require completed negotiation, not banner/port. FN: cover all approved TLS ports and all policy-prohibited versions. | [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996.html), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html) | **No.** TLS 1.0/1.1 probes exist, but the prohibited-version set and evaluator are incomplete. |
| 12 | `tls_weak_cipher` | For each supported protocol on an approved endpoint, offer constrained cipher groups/individual prohibited suites in bounded handshakes; include a modern control. | Offered suite set, accepted suite/version, SNI/port, handshake outcome/alert, crypto-policy version. | **Fail:** a policy-prohibited suite completes negotiation. **Pass:** all prohibited offers are rejected and a control succeeds. **Unknown:** client lacks the suite/version or transport is ambiguous. | FP: require server acceptance, not advertised client capability. FN: TLS 1.3 suites and legacy protocols need separate enumeration strategies. | [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html), [NIST SP 800-52r2](https://csrc.nist.gov/pubs/sp/800/52/r2/final) | **No.** The current TLS executor does not enumerate accepted cipher suites. |
| 13 | `tlscert_expired` | Perform a normal SNI TLS handshake while disabling only local trust rejection for collection; parse leaf DER and compare `notAfter` to UTC observation time. | Leaf SHA-256 fingerprint, `notBefore`, `notAfter`, observation time, port/SNI, parse status. | **Fail:** `notAfter < observation_time`. **Pass:** within validity window. **Unknown:** no/invalid certificate or handshake failure. | FP: use UTC and parsed ASN.1 time. FN: probe all declared TLS ports/SNI names. | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | **Yes for evidence, no for support.** Leaf expiry evidence exists; no SSC-linked evaluator exists. |
| 14 | `insecure_server_certificate_key_size` | Capture the served leaf certificate (and chain where available), identify key algorithm/parameters, and compare to the versioned crypto policy. | Fingerprint, key algorithm, RSA/DSA bits or EC curve, chain position, policy version. | **Fail:** any evaluated certificate key violates its algorithm-specific minimum. **Pass:** all evaluated keys meet policy. **Unknown:** algorithm/curve unavailable or chain incomplete. | FP: never compare unlike algorithms by bit count alone. FN: capture intermediates if the issue scope includes them. | [NIST SP 800-57 Part 1 Rev. 5](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | **No.** Leaf bit count exists, but algorithm/curve and full-chain evidence are incomplete. |
| 15 | `tlscert_weak_signature` | Capture the served chain, build the validated path, and inspect each leaf/intermediate signature algorithm against crypto policy. | Per certificate: fingerprint, chain position, signature OID/hash, path result, policy version. | **Fail:** evaluated path contains a prohibited signature algorithm/hash. **Pass:** none do. **Unknown:** path/algorithm incomplete. | FP: do not treat a locally supplied trust anchor as a served weak certificate. FN: leaf-only inspection misses intermediates. | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html) | **No.** Only the leaf signature and a SHA-1/MD5 boolean are collected. |
| 16 | `tlscert_revoked` | Build the certificate path; retrieve the issuing CA's AIA OCSP response and/or CRL, validate signer/signature, freshness, serial/issuer match, and status. | Certificate/issuer fingerprints, responder/CRL URI, response hash, signer result, `thisUpdate`/`nextUpdate`, status and reason. | **Fail:** a fresh, valid authoritative response says `revoked`. **Pass:** a fresh valid response says `good` under policy. **Unknown:** `unknown`, stale, invalid, missing, or retrieval failure. | FP: validate responder authorization and serial/issuer binding. FN: implement approved CRL fallback and cache freshness; stapling alone may be absent. | [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960.html), [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html), [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325.html) | **No.** No full chain, OCSP/CRL retrieval, validation, or status evidence. |
| 17 | `spf_record_malformed` | Query authoritative/recursive DNS for all TXT at the declared domain; select `v=spf1`, parse RFC 7208, and evaluate mechanisms with a hard ten-lookup budget. | DNS response status, complete TXT strings/hashes, parse tree/error, record count, lookup trace/count, terminal result. | **Fail:** multiple SPF records, syntax error, prohibited lookup overflow/loop, or deterministic `permerror`. **Pass:** one valid record evaluates without permanent error. **Unknown:** timeout/SERVFAIL/truncation. | FP: join multi-string TXT chunks correctly and distinguish TXT records. FN: follow include/redirect/MX/A lookups within the limit. | [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html) | **No.** Root TXT is collected, but no complete parser/evaluation trace exists. |
| 18 | `dmarc_contains_none` | Query TXT at `_dmarc.<declared-domain>` and, for subdomains, resolve organizational-domain fallback; parse the single applicable record. | DNS status, record hash/text, parsed tags, target/org-domain relation, effective `p`/`sp`, parser error. | **Fail:** effective policy is `none`. **Pass:** effective policy is `quarantine` or `reject`. **Unknown:** invalid/multiple record, DNS failure, or organizational-domain ambiguity. | FP: honor `sp` and inheritance. FN: use declared organizational-domain/PSL handling and evaluate every declared subdomain separately. | [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html) | **No.** `_dmarc` TXT exists as raw evidence, but effective-policy/inheritance parsing and evaluator do not. |
| 19 | `service_telnet` | TCP-connect each approved candidate port, read the bounded greeting, send only a minimal Telnet IAC negotiation/`AYT`, and stop after a protocol-valid response. | IP/port, bytes/time limits, sent negotiation type, response IAC sequence/greeting hash, stop/error reason. | **Fail:** protocol-valid Telnet negotiation/response. **No finding:** deterministic non-Telnet response/refusal on all declared ports. **Unknown:** silence/timeout/ambiguous banner. | FP: TCP-open or text banner alone is insufficient. FN: include nonstandard approved ports and tolerate servers that negotiate before greeting. | [RFC 854](https://www.rfc-editor.org/rfc/rfc854.html) | **No.** TCP-open only; no Telnet transcript. |
| 20 | `ssh_weak_cipher` | TCP-connect, read/send SSH identification, exchange KEXINIT without authentication, parse the server encryption lists, then disconnect. | IP/port, identification hash, server-to-client/client-to-server cipher lists, parse result, policy version. | **Fail:** server offers any policy-prohibited cipher in either direction. **Pass:** complete lists contain none. **Unknown:** no KEXINIT/parse error. | FP: match exact SSH algorithm names and a versioned policy. FN: probe every approved SSH endpoint; middleboxes may terminate negotiation. | [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253.html), [RFC 9142](https://www.rfc-editor.org/rfc/rfc9142.html) | **No.** There is no SSH negotiation executor. |

### Top 20 gate result

- Still directly testable: **17**.
- Downgraded to enrichment: **3** (`cookie_missing_http_only`, `cookie_missing_secure_attribute`, `tlscert_revoked`).
- Current executor already records all required raw evidence for the bounded method: **2** (`redirect_chain_contains_http_v2`, `tlscert_expired`). Neither is currently `SUPPORTED` because the SSC-linked evaluator is absent.
- The remaining 18 require more evidence collection, coverage context, or enrichment before a defensible pass/fail result.

## External and proprietary dependency boundary

The quality gate did not change the 42 `EXTERNAL_DATA_REQUIRED` or four `NOT_REPRODUCIBLE` rows.

### `EXTERNAL_DATA_REQUIRED` (42)

- `endpoint_security` (2): `outdated_browser`, `outdated_os`
- `hacker_chatter` (2): `ransomware_victim`, `targeted_by_threat_actor_group`
- `ip_reputation` (24): `active_cve_exploitation_attempted`, `adware_installation`, `adware_installation_trail`, `attack_detected`, `cobalt_strike_c2_detected`, `compromised_by_information_stealer`, `dos_attack_attempt_detected`, `general_scan_detected`, `infected_by_targeted_attack`, `ip_black_list_due_malicious_activity`, `known_compromised_or_hostile_host`, `malicious_botnet_c_and_c_server_detected`, `malicious_scan_detected`, `malicious_tor_exit_node_detected`, `malicious_tor_relay_router_node_detected`, `malicious_user_agent_detected`, `malware_detected`, `malware_infection`, `malware_infection_trail`, `mirai_botnet_traffic_detected`, `pva_installation`, `pva_installation_trail`, `ransomware_infection`, `ransomware_infection_trail`
- `leaked_information` (8): `alleged_first_party_breach`, `alleged_third_party_breach`, `attempted_information_leak`, `compromised_credentials_found`, `confirmed_first_party_breach`, `confirmed_third_party_breach`, `exploit_attempt_detected`, `historical_compromised_credentials_found`
- `network_security` (5): `cobalt_strike_c2_service`, `service_netbus_remote_access`, `sql_payload_using_tor_proxy_detected`, `tor_server`, `tor_traffic_detected`
- `social_engineering` (1): `typosquat`

These conditions fundamentally depend on reputation, telemetry, malware/botnet/sinkhole data, credential/breach intelligence, threat reporting, Tor consensus/flow context, domain intelligence, endpoint inventory, or similar external/internal sources. An external perimeter scanner cannot independently establish them from an isolated HTTP/TLS/DNS/TCP observation.

### `NOT_REPRODUCIBLE` (4)

- `application_security`: `potentially_vulnerable`
- `cubit_score`: `synth_high_risk_appsec_vulnerabilities`, `synth_possible_initial_access`
- `network_security`: `service_networking`

No falsifiable public/internal semantics were identified for these labels. They remain excluded from implementation until a credible, documented evidence source defines the condition. No SSC proprietary sensor or aggregation behavior is inferred.

## Recommended primitive order

The smallest useful set is detailed in `SSC_SCANNER_PRIMITIVES.md`. The top five are:

1. `HTTP_HEADERS` — six direct findings plus three enrichment-dependent findings; current evidence is close but loses coverage/multi-value semantics.
2. `EMAIL_SECURITY` — seven direct SPF/DMARC findings with strong RFC semantics; DKIM follows only with selector/message provenance.
3. `TLS_CERTIFICATE` — five direct certificate findings, then four explicitly separated enrichment paths.
4. `HTTP_REDIRECT` — three direct findings using evidence the current executor nearly provides; external destinations remain scope-safe and indeterminate.
5. `SERVICE_PROTOCOL_IDENTIFICATION` — a reusable safe-adapter framework can support 30 direct findings, but rollout should be protocol-by-protocol with positive transcript evidence.

This order intentionally does not lead with the 33 CVE-correlation rows. CVE coverage is valuable, but without defensible product/version identity it creates high-impact false positives. `TLS_HANDSHAKE` and `SSH_NEGOTIATION` are the next small, high-confidence additions after the five above.

## Required implementation gate for any future scanner work

Before an issue can change to `SUPPORTED`, its implementation must demonstrate:

1. a versioned executor evidence schema containing the exact observation listed in the CSV;
2. a versioned evaluator linked to that specific SSC_API catalog issue;
3. explicit `PASS`/`FAIL`/`UNKNOWN` semantics with errors and incomplete coverage mapped to `UNKNOWN`;
4. unit tests for positive, negative, ambiguous, timeout, malformed, and scope-boundary cases;
5. no authentication, browser flow, external lookup, product attribution, or data classification unless its required dependency is explicitly approved and provenance-bearing;
6. no mapping from `ssc_severity` to breach risk, threat level, internal severity, or score impact.

## Authoritative-source notes

- Modern OWASP guidance states that `X-XSS-Protection` has been removed from major browsers; a universal “missing header” finding would not be defensible. The row now requires an explicit legacy-browser policy.
- CA/B Forum certificate validity limits are issuance-date dependent and changed again in 2026; a fixed 398-day rule is no longer sufficient for newly issued public certificates.
- RFC 6960 distinguishes `good`, `revoked`, and `unknown`; network failure or `unknown` must never be converted to not revoked.
- RFC/standards references establish protocol semantics. They do not establish SSC scoring, SSC collection coverage, or proprietary aggregation.

## Files and data integrity

- `docs/SSC_ISSUE_COVERAGE.csv` was updated only for the 12 classification/method corrections and four support corrections described above.
- `docs/SSC_COVERAGE_QUALITY_REVIEW.md` is this gate record.
- `docs/SSC_SCANNER_PRIMITIVES.md` contains the complete 156-issue primary-primitive grouping and coverage summary.
- No database write, baseline import/change, scanner/rule/scoring code change, commit, or push was performed.
