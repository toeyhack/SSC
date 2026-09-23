# SSC Scanner Primitive Review

Baseline content hash: `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`  
Review date: 2026-09-23
Scope: the 156 issues classified `DIRECTLY_TESTABLE` or `TESTABLE_WITH_ENRICHMENT` after the quality gate.

This is a design and implementation-status catalog. A primitive supports a finding only when it records the exact observation, preserves scope and provenance, distinguishes negative results from errors/unknowns, and has a versioned evaluator linked to the SSC-aligned issue. It does not reproduce SSC collection methods or scoring.

## Current implementation boundary

The platform has HTTP, TLS, DNS, and TCP collectors. Wave 1 added declared-path HTTP and certificate evidence. Wave 2 added version-pinned TLS negotiation and deterministic email-security evidence. Wave 3A adds one bounded service-probe adapter framework and six non-authenticating protocol adapters: VNC/RFB, rsync daemon, Redis RESP, SOCKS5, Telnet option negotiation, and SMB2 negotiate. It still does not have a general body crawler, browser runtime, WebSocket capture, later service-protocol adapters, SSH negotiation, complete legacy-cipher client coverage, stapled-OCSP capture, complete RFC 7208 evaluation, DKIM selector provenance, revocation client, product fingerprint engine, CVE/lifecycle feeds, or longitudinal patching model. Therefore:

- fully `SUPPORTED` today: **27**;
- `PARTIAL` among the 156 primitive-addressable issues: **95**;
- `NOT_SUPPORTED` among the 156: **34**;
- every supported issue has an active evaluator pinned to an exact attested `SSC_API` issue version; other primitives still require issue-specific evidence and evaluators.

## Primitive coverage summary

`D/E` means directly testable / testable with enrichment. “Partial evidence” is not support; it means only that a current collector provides at least one useful prerequisite.

| Primitive | Issues | D/E | Fully supported today | Partial evidence today | Evidence absent today | Complexity | Principal dependencies |
|---|---:|---:|---:|---:|---:|---|---|
| `BROWSER_RUNTIME` | 6 | 4/2 | 0 | 1 | 5 | HIGH | sandboxed browser, bounded URL/flow manifest, network/console events, safe redaction |
| `CONFIGURATION_AUDIT` | 1 | 0/1 | 0 | 0 | 1 | HIGH | explicit authorization, synthetic test account/configuration assertion; no password guessing |
| `CONTENT_BASELINE` | 1 | 0/1 | 0 | 0 | 1 | HIGH | approved clean snapshots, signed history, similarity model, analyst review |
| `CVE_CORRELATION` | 33 | 0/33 | 0 | 31 | 2 | HIGH | product/version or SBOM evidence, CPE/package normalization, NVD/vendor advisories, optional KEV |
| `DOMAIN_PUBLIC_DATA` | 1 | 0/1 | 0 | 1 | 0 | LOW | versioned browser HSTS preload dataset |
| `EMAIL_SECURITY` | 10 | 7/3 | 6 | 4 | 0 | MEDIUM | complete RFC 7208 permanent-error evaluation and approved mail samples/selectors for DKIM |
| `EOL_EOS_CORRELATION` | 2 | 0/2 | 0 | 0 | 2 | HIGH | verified product/version and versioned vendor lifecycle records |
| `HTTP_CONTENT` | 9 | 9/0 | 0 | 1 | 8 | MEDIUM | bounded same-origin crawler, HTML/DOM parser, body-size limits, redaction |
| `HTTP_HEADERS` | 9 | 6/3 | 6 | 3 | 0 | MEDIUM | optional synthetic auth flow and versioned legacy-browser policy for the remaining rows |
| `HTTP_REDIRECT` | 4 | 3/1 | 3 | 1 | 0 | LOW | approved passive/authorized evidence for an external terminal destination |
| `LONGITUDINAL_PATCHING` | 11 | 0/11 | 0 | 0 | 11 | HIGH | stable asset/product identity, CVE state history, observation windows, missing-data semantics |
| `PRODUCT_FINGERPRINT` | 16 | 0/16 | 0 | 15 | 1 | HIGH | versioned multi-signal fingerprints, provenance, ambiguity/confidence model, inventory corroboration |
| `PROXY_VALIDATION` | 2 | 2/0 | 1 | 1 | 0 | MEDIUM | SOCKS5 identification is supported without relaying traffic; HTTP proxy validation still needs an organization-owned canary and strict egress target |
| `SERVICE_PROTOCOL_IDENTIFICATION` | 32 | 30/2 | 5 | 27 | 0 | MEDIUM–HIGH | common bounded adapter is active for five original-group issues; later adapters, UDP where needed, and per-protocol strict boundaries remain |
| `SSH_NEGOTIATION` | 3 | 3/0 | 0 | 3 | 0 | MEDIUM | SSH identification/KEX parser, versioned cryptographic policy, no authentication |
| `TCP_SERVICE_DISCOVERY` | 1 | 1/0 | 0 | 1 | 0 | LOW | approved port manifest and TCP connect evidence |
| `TLS_CERTIFICATE` | 9 | 5/4 | 5 | 4 | 0 | MEDIUM–HIGH | CA policy history, authoritative revocation, jurisdiction, and CA registry enrichment |
| `TLS_HANDSHAKE` | 3 | 3/0 | 1 | 1 | 1 | MEDIUM | complete prohibited-suite client coverage and OCSP-staple capture/validation |
| `WEBSOCKET_RUNTIME` | 3 | 2/1 | 0 | 0 | 3 | HIGH | browser runtime, bounded frame metadata, synthetic markers, application data schema |
| **Total** | **156** | **75/81** | **27** | **95** | **34** |  |  |

## Issue grouping

Each issue has exactly one primary primitive below. Secondary dependencies are represented in the summary and in `SSC_ISSUE_COVERAGE.csv`.

### `BROWSER_RUNTIME` (6)

`browser_logs_contain_debug_message`, `communication_server_with_expired_cert`, `fail_to_load_page_components`, `sensitive_data_exposure_through_insecure_channel`, `site_emits_browser_log`, `site_requests_data_over_insecure_channel`

### `CONFIGURATION_AUDIT` (1)

`mysql_server_empty_password`

This must use an explicitly approved synthetic connection/assertion. It must never attempt password lists or brute force.

### `CONTENT_BASELINE` (1)

`website_defacement`

### `CVE_CORRELATION` (33)

`openssl_critical_vulnerability`, `potentially_vulnerable_cve_2023_33246`, `potentially_vulnerable_cve_2023_34362`, `potentially_vulnerable_cve_2023_3519`, `potentially_vulnerable_cve_2023_37582`, `potentially_vulnerable_cve_2023_37979`, `potentially_vulnerable_cve_2023_38035`, `potentially_vulnerable_cve_2023_46747`, `potentially_vulnerable_cve_2024_21887`, `potentially_vulnerable_cve_2024_46805`, `product_exploited_by_ransomware_actors`, `web_vuln_host_high`, `web_vuln_host_low`, `web_vuln_host_medium`, `web_vuln_host_v3_critical`, `web_vuln_host_v3_high`, `web_vuln_host_v3_low`, `web_vuln_host_v3_medium`, `webapp_vulnerable_to_spring4shell`, `ransomware_association`, `exploited_product`, `microsoft_exchange_0_day_vulnerability`, `microsoft_exchange_http_api_vulnerability`, `potentially_vulnerable_cisco_rv_320_325`, `product_uses_vulnerable_log4j`, `service_vuln_host_high`, `service_vuln_host_info`, `service_vuln_host_low`, `service_vuln_host_medium`, `service_vuln_host_v3_critical`, `service_vuln_host_v3_high`, `service_vuln_host_v3_low`, `service_vuln_host_v3_medium`

A match requires a defensible product/version range or authoritative SBOM/package fact. Port presence, a product family, or an ambiguous banner is insufficient. No exploit validation is proposed.

### `DOMAIN_PUBLIC_DATA` (1)

`domain_uses_hsts_preloading`

### `EMAIL_SECURITY` (10)

`dkim_insufficient_key_length`, `dkim_record_detected`, `dkim_weak_signature`, `dmarc_contains_none`, `dmarc_record_missing`, `spf_record_malformed`, `spf_record_missing`, `spf_record_softfail`, `spf_record_wildcard`, `subdomain_dmarc_contains_none`

Six SPF/DMARC rows now have exact active Wave 2 evaluators. `spf_record_malformed` remains partial because complete RFC 7208 macro, void-lookup, and nested A/MX permanent-error evaluation is not yet implemented. DKIM rows require an approved message sample or selector inventory; blind selector guessing is not a reliable negative test.

### `EOL_EOS_CORRELATION` (2)

`service_end_of_life`, `service_end_of_service`

### `HTTP_CONTENT` (9)

`contact_information_detected`, `insecure_ftp`, `insecure_telnet`, `links_to_insecure_website`, `local_file_path_exposed_via_url_scheme`, `server_error`, `unsafe_sri_v2`, `website_copyright_expired`, `website_copyright_up_to_date`

### `HTTP_HEADERS` (9)

`cookie_missing_http_only`, `cookie_missing_secure_attribute`, `csp_no_policy_v2`, `csp_too_broad_v2`, `csp_unsafe_policy_v2`, `hsts_incorrect_v2`, `x_content_type_options_incorrect_v2`, `x_frame_options_incorrect_v2`, `x_xss_protection_incorrect_v2`

The three enrichment rows are the two session-cookie findings and `x_xss_protection_incorrect_v2`. Cookie purpose requires a reviewed cookie inventory/test flow. The legacy XSS header requires a versioned browser-estate policy because major modern browsers removed the feature.

### `HTTP_REDIRECT` (4)

`domain_missing_https_v2`, `insecure_https_redirect_pattern_v2`, `redirect_chain_contains_http_v2`, `redirect_to_insecure_website`

### `LONGITUDINAL_PATCHING` (11)

`patching_analysis_high`, `patching_analysis_low`, `patching_analysis_medium`, `patching_cadence_high`, `patching_cadence_info`, `patching_cadence_low`, `patching_cadence_medium`, `patching_cadence_v3_critical`, `patching_cadence_v3_high`, `patching_cadence_v3_low`, `patching_cadence_v3_medium`

### `PRODUCT_FINGERPRINT` (16)

`exposed_cisco_web_ui`, `hosted_on_object_storage_v2`, `payment_provider`, `references_object_storage_v2`, `uses_go_daddy_managed_wordpress`, `waf_detected_v2`, `cdn_hosting`, `exposed_embedded_iot_web_server`, `exposed_mac_airport_device`, `exposed_network_attached_storage_device`, `exposed_printer`, `industrial_control_device`, `iot_camera`, `remote_access`, `service_cloud_provider`, `service_pulse_vpn`

### `PROXY_VALIDATION` (2)

`service_http_proxy`, `service_socks_proxy`

`service_socks_proxy` is supported by the Wave 3A SOCKS5 method-selection adapter. It stops after the server selects or rejects the offered no-authentication method and never issues a proxy connect request. `service_http_proxy` remains partial because safe positive relay validation requires an organization-owned canary destination.

### `SERVICE_PROTOCOL_IDENTIFICATION` (32)

`mail_server_unusual_port`, `bitcoin_server`, `exposed_mobile_printing_service`, `java_debugger`, `minecraft_server`, `service_cassandra`, `service_couchdb`, `service_dns`, `service_elasticsearch`, `service_ftp`, `service_imap`, `service_ldap`, `service_ldap_anonymous`, `service_microsoft_sql`, `service_mongodb`, `service_mysql`, `service_neo4j`, `service_open_vpn`, `service_oracle_db`, `service_oracle_registry`, `service_pop3`, `service_postgresql`, `service_pptp`, `service_rdp`, `service_redis`, `service_rsync`, `service_smb`, `service_soap`, `service_telnet`, `service_vnc`, `telephony`, `upnp_accessible`

Thirty issues have a deterministic protocol-level positive observation. `service_open_vpn` and `service_oracle_registry` require product-fingerprint/inventory enrichment: OpenVPN may remain silent to unauthenticated probes, and no unique public Oracle Service Registry wire handshake was identified. TCP-open alone never establishes any service-specific issue.

Wave 3A supports `service_vnc`, `service_rsync`, `service_redis`, `service_telnet`, and `service_smb` from this group. The shared adapter also supports `service_socks_proxy` from `PROXY_VALIDATION`. Every other issue in this group remains partial until its own acquisition, parser, conclusive-negative, ambiguity, failure, and exact-version linkage gates pass.

### `SSH_NEGOTIATION` (3)

`ssh_weak_cipher`, `ssh_weak_mac`, `ssh_weak_protocol`

### `TCP_SERVICE_DISCOVERY` (1)

`open_port`

### `TLS_CERTIFICATE` (9)

`communication_with_server_certificate_issued_by_blacklisted_country`, `insecure_server_certificate_key_size`, `tlscert_excessive_expiration`, `tlscert_expired`, `tlscert_no_revocation`, `tlscert_revoked`, `tlscert_self_signed`, `tlscert_weak_signature`, `uses_go_daddy_infrastructure`

The direct rows are key size, expiry, revocation-control extension presence, self-signature, and weak signature. Jurisdiction, issuance-date CA/B policy, live revocation status, and GoDaddy CA identity require versioned enrichment.

### `TLS_HANDSHAKE` (3)

`tls_ocsp_stapling`, `tls_weak_cipher`, `tls_weak_protocol`

`tls_weak_protocol` is supported by completed version-pinned handshakes for TLS 1.0/1.1 and modern controls for TLS 1.2/1.3. `tls_weak_cipher` remains partial: accepted suites are positively observable, but the packaged client cannot offer every prohibited legacy family, so a negative is not yet conclusive. `tls_ocsp_stapling` remains partial because the current TLS socket API does not expose staple bytes for cryptographic validation.

### `WEBSOCKET_RUNTIME` (3)

`websocket_receives_data`, `websocket_requests_contain_sensitive_fields`, `websocket_sends_data`

Only the sensitive-fields row requires application schema/test-flow enrichment. The other two can make bounded positive observations, but absence is only “not observed in the declared flow.”

## Smallest high-value implementation set

The recommended order values defensibility and security usefulness over raw row count:

1. **`HTTP_HEADERS` — Wave 1 complete for six direct rows.** Multi-value header preservation, CSP/HSTS/clickjacking parsers, declared-path coverage manifests, and version-pinned evaluators are active. Three enrichment rows remain partial.
2. **`EMAIL_SECURITY` — Wave 2 complete for six direct rows.** Exact DNS response states, SPF/DMARC policy observations, nonce wildcard checks and declared-subdomain inheritance are active. Complete SPF permanent-error evaluation and DKIM selector/message provenance remain partial.
3. **`TLS_CERTIFICATE` — Wave 1 complete for five direct rows.** Served-chain/extensions and the five direct evaluators are active; CA/B policy, OCSP/CRL, jurisdiction, and CA registry feeds remain separate.
4. **`HTTP_REDIRECT` — Wave 1 complete for three direct rows.** Every normalized hop and stop reason is retained. External redirect targets remain indeterminate unless separately authorized or passively evidenced.
5. **`SERVICE_PROTOCOL_IDENTIFICATION` — Wave 3A first batch complete.** The common safe adapter framework and six protocol-specific mappings are active. Later protocol-definitive adapters must ship only in separately approved small batches and earn support independently.

Wave 2 also completes `tls_weak_protocol` under `TLS_HANDSHAKE`; cipher and OCSP-stapling boundaries remain partial. Wave 3A does not claim the full `SERVICE_PROTOCOL_IDENTIFICATION` ceiling. Any next batch requires separate approval.

## Safety and confidence rules

- Use allowlisted targets, fixed time/byte/request budgets, and positive protocol evidence.
- Never authenticate unless an approved synthetic flow/configuration explicitly supplies a test identity.
- Never brute force, exploit, mutate state, enumerate customer data, or use a discovered proxy against third parties.
- Treat timeout, access denial, TLS failure, unsupported browser flow, and enrichment-feed failure as `UNKNOWN`, not a pass.
- A product/CVE finding requires source version, retrieval time, identifier mapping, confidence, and the exact vulnerable range used.
- `ssc_severity` remains source metadata. No breach risk, threat level, internal severity, or score effect is inferred.
