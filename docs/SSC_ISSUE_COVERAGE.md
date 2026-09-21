# SSC 202-Issue Coverage Mapping

Snapshot content hash: `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`
Source: immutable real `SSC_API` Golden Baseline
Implementation state: Wave 1 (`HTTP_HEADERS`, `HTTP_REDIRECT`, `TLS_CERTIFICATE`) plus Wave 2 (`TLS_HANDSHAKE`, `EMAIL_SECURITY`)
Total mapped issues: **202**

> This is an independent implementation mapped to SSC taxonomy. It does not reproduce or claim knowledge of SSC collection, aggregation, severity, scoring, or proprietary detection logic. `ssc_severity` remains source metadata and is not mapped to internal risk or score impact.

## Support gate

`SUPPORTED` requires collected sufficient evidence, an active deterministic evaluator, an immutable link to the exact `SSC_API` issue version, positive and negative tests, and false-positive boundary tests. Acquisition or parsing failure is `INDETERMINATE`, not a non-finding.

## Coverage summary

| Coverage | Before Wave 2 | After Wave 2 | Percentage after |
|---|---:|---:|---:|
| `SUPPORTED` | 14 | 21 | 10.4% |
| `PARTIAL` | 105 | 101 | 50.0% |
| `NOT_SUPPORTED` | 83 | 80 | 39.6% |
| **Total** | **202** | **202** | **100.0%** |

### Feasibility (unchanged)

| Category | Count | Percentage |
|---|---:|---:|
| `DIRECTLY_TESTABLE` | 75 | 37.1% |
| `TESTABLE_WITH_ENRICHMENT` | 81 | 40.1% |
| `EXTERNAL_DATA_REQUIRED` | 42 | 20.8% |
| `NOT_REPRODUCIBLE` | 4 | 2.0% |

### Coverage by SSC factor

| Factor | Total | Direct | Enrichment | External | Not reproducible | Supported | Partial | Not supported |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `application_security` | 61 | 25 | 35 | 0 | 1 | 10 | 30 | 21 |
| `cubit_score` | 3 | 0 | 1 | 0 | 2 | 0 | 1 | 2 |
| `dns_health` | 10 | 7 | 3 | 0 | 0 | 6 | 4 | 0 |
| `endpoint_security` | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 2 |
| `hacker_chatter` | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 2 |
| `ip_reputation` | 26 | 1 | 1 | 24 | 0 | 0 | 2 | 24 |
| `leaked_information` | 8 | 0 | 0 | 8 | 0 | 0 | 0 | 8 |
| `network_security` | 68 | 42 | 20 | 5 | 1 | 5 | 56 | 7 |
| `patching_cadence` | 21 | 0 | 21 | 0 | 0 | 0 | 8 | 13 |
| `social_engineering` | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 1 |

## Active Wave 1 evaluator mappings

Every listed rule uses stable key `ssc.wave1.<issue-key>`, method schema `ssc-wave1-observation.v1`, policy `ssc-wave1-security-policy.v1`, source type `SSC_REFERENCE`, and a rule-version foreign key to the exact current issue definition from an attested real `SSC_API` snapshot.

| SSC issue key | Primitive | Exact positive condition | Authoritative reference |
|---|---|---|---|
| `csp_no_policy_v2` | `HTTP_HEADERS` | MATCH when a successfully fetched HTML response has neither a valid enforced CSP header nor a valid CSP meta policy; acquisition or parse failure is INDETERMINATE. | https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-web-security-testing-guide/ |
| `csp_unsafe_policy_v2` | `HTTP_HEADERS` | MATCH when the effective active-content policy permits unsafe-eval or permits unsafe-inline without a nonce/hash control; malformed policy evidence is INDETERMINATE. | https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-web-security-testing-guide/ |
| `csp_too_broad_v2` | `HTTP_HEADERS` | MATCH when the effective script/object policy permits a wildcard, an unscoped network scheme, or data: active content under the versioned Wave 1 policy; malformed evidence is INDETERMINATE. | https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-web-security-testing-guide/ |
| `hsts_incorrect_v2` | `HTTP_HEADERS` | MATCH when HSTS is absent, duplicated, malformed, has max-age below 31536000, or omits includeSubDomains on a covered HTTPS response; HTTP-delivered HSTS is ignored. | https://www.rfc-editor.org/rfc/rfc6797.html |
| `x_content_type_options_incorrect_v2` | `HTTP_HEADERS` | MATCH when the header is absent, duplicated, or its sole normalized value is not exactly nosniff; acquisition failure is INDETERMINATE. | https://owasp.org/www-project-secure-headers/ |
| `x_frame_options_incorrect_v2` | `HTTP_HEADERS` | MATCH when neither a restrictive valid CSP frame-ancestors directive nor exactly one valid X-Frame-Options DENY/SAMEORIGIN value protects the response; malformed evidence is INDETERMINATE. | https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-secure-headers/ |
| `domain_missing_https_v2` | `HTTP_REDIRECT` | MATCH when HTTP serves terminal content without a permanent same-target upgrade to a reachable trusted HTTPS endpoint, or no trusted HTTPS endpoint is available; incomplete attempts are INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc9110.html; https://www.rfc-editor.org/rfc/rfc6797.html |
| `insecure_https_redirect_pattern_v2` | `HTTP_REDIRECT` | MATCH when an HTTPS hop downgrades to HTTP, a chain oscillates from HTTPS back to HTTP, or an HTTP request reaches terminal content before an HTTPS upgrade. | https://www.rfc-editor.org/rfc/rfc9110.html |
| `redirect_chain_contains_http_v2` | `HTTP_REDIRECT` | MATCH when a hop after an HTTPS request uses HTTP or an HTTPS hop emits a Location resolving to HTTP; an ordinary HTTP-only chain does not match. | https://www.rfc-editor.org/rfc/rfc9110.html |
| `tlscert_expired` | `TLS_CERTIFICATE` | MATCH when leaf notAfter is strictly earlier than observation_time; parse or handshake failure is INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc5280.html; https://csrc.nist.gov/pubs/sp/800/52/r2/final |
| `tlscert_self_signed` | `TLS_CERTIFICATE` | MATCH only when subject equals issuer, the leaf signature verifies with its own public key, and the fingerprint is not explicitly trusted by the versioned local policy. | https://www.rfc-editor.org/rfc/rfc5280.html; https://csrc.nist.gov/pubs/sp/800/52/r2/final |
| `tlscert_weak_signature` | `TLS_CERTIFICATE` | MATCH when any parsed served leaf/intermediate uses MD5 or SHA-1; unknown algorithms or incomplete parsing are INDETERMINATE. | https://csrc.nist.gov/pubs/sp/800/52/r2/final; https://www.rfc-editor.org/rfc/rfc5280.html |
| `insecure_server_certificate_key_size` | `TLS_CERTIFICATE` | MATCH for RSA/DSA keys below 2048 bits or EC keys below 224 bits; supported stronger keys do not match and unknown key types are INDETERMINATE. | https://csrc.nist.gov/pubs/sp/800/52/r2/final; https://www.rfc-editor.org/rfc/rfc5280.html |
| `tlscert_no_revocation` | `TLS_CERTIFICATE` | MATCH for a non-self-signed certificate valid longer than seven days when neither an OCSP URI nor CRL distribution URI is present; malformed extensions are INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc5280.html; https://www.rfc-editor.org/rfc/rfc6960.html |

## Attempted Wave 1 issues remaining `PARTIAL`

| SSC issue key | Reason |
|---|---|
| `cookie_missing_http_only` | Session/authentication purpose requires an approved synthetic authentication flow and reviewed cookie-purpose inventory. |
| `cookie_missing_secure_attribute` | Session/authentication purpose requires an approved synthetic authentication flow and reviewed cookie-purpose inventory. |
| `x_xss_protection_incorrect_v2` | Correctness depends on an approved, versioned legacy-browser estate policy. |
| `redirect_to_insecure_website` | An out-of-scope Location does not prove the terminal destination without authorized or passive redirect evidence. |
| `communication_with_server_certificate_issued_by_blacklisted_country` | Issuer jurisdiction requires a reviewed CA registry and internal denylist. |
| `tlscert_excessive_expiration` | The applicable lifetime maximum requires issuance-date CA/B policy history and certificate applicability data. |
| `tlscert_revoked` | Reliable status requires fresh, signed authoritative OCSP/CRL evidence, which this architecture does not acquire. |
| `uses_go_daddy_infrastructure` | CA attribution requires a versioned reviewed CA/SPKI registry; issuer text is not sufficient. |

## Active Wave 2 evaluator mappings

Every listed rule uses stable key `ssc.wave2.<issue-key>`, method schema `ssc-wave2-observation.v1`, source type `SSC_REFERENCE`, and a rule-version foreign key to the exact current issue definition from an attested real `SSC_API` snapshot. TLS and email policy versions are retained independently in the rule evidence schema.

| SSC issue key | Primitive | Exact positive condition | Authoritative reference |
|---|---|---|---|
| `tls_weak_protocol` | `TLS_HANDSHAKE` | MATCH only when TLS 1.0 or TLS 1.1 completes negotiation; NO_MATCH requires definitive rejection of both weak versions and a successful TLS 1.2 or TLS 1.3 control; otherwise INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc8996.html; https://www.rfc-editor.org/rfc/rfc9325.html; https://csrc.nist.gov/pubs/sp/800/52/r2/final |
| `spf_record_missing` | `EMAIL_SECURITY` | MATCH when a definitive response contains no record beginning v=spf1; resolver timeout, SERVFAIL or other acquisition error is INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc7208.html |
| `spf_record_softfail` | `EMAIL_SECURITY` | MATCH when the terminal mechanism is ~all and DMARC is definitively absent or valid with effective p=none; malformed or unavailable SPF/DMARC evidence is INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc7208.html; https://www.rfc-editor.org/rfc/rfc9989.html |
| `spf_record_wildcard` | `EMAIL_SECURITY` | MATCH only when both nonce names return equivalent SPF policies, proving wildcard synthesis; two definitive negative answers are NO_MATCH and mixed/error evidence is INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc7208.html; https://www.rfc-editor.org/rfc/rfc4592.html |
| `dmarc_record_missing` | `EMAIL_SECURITY` | MATCH when the exact declared organizational domain has no applicable DMARC record; DNS errors are INDETERMINATE and a present malformed record is not classified as missing. | https://www.rfc-editor.org/rfc/rfc9989.html |
| `dmarc_contains_none` | `EMAIL_SECURITY` | MATCH when the valid applicable policy has p=none; quarantine/reject is NO_MATCH and invalid, multiple or unavailable evidence is INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc9989.html |
| `subdomain_dmarc_contains_none` | `EMAIL_SECURITY` | MATCH when any declared subdomain has effective policy none; NO_MATCH requires every declared subdomain to resolve deterministically to quarantine/reject; absent scope or ambiguity is INDETERMINATE. | https://www.rfc-editor.org/rfc/rfc9989.html |

## Attempted Wave 2 issues remaining `PARTIAL`

| SSC issue key | Reason |
|---|---|
| `tls_ocsp_stapling` | Python's current TLS socket interface does not expose the server's stapled OCSP bytes for cryptographic parsing and freshness/signature validation. |
| `tls_weak_cipher` | The runtime can positively prove acceptance from constrained handshakes, but its OpenSSL provider cannot offer every prohibited legacy suite; a conclusive negative would be a weak proxy. |
| `spf_record_malformed` | The collector parses syntax, multiple records, include/redirect loops and lookup overflow, but does not yet implement every RFC 7208 macro, void-lookup and nested A/MX permanent-error path. |
| `dkim_record_detected` | Selector discovery requires an approved selector inventory or authorized message sample; selectors are not safely enumerable from DNS. |
| `dkim_weak_signature` | The platform has no authorized message/selector evidence from which to verify the signature algorithm and selected key. |
| `dkim_insufficient_key_length` | The platform has no approved selector inventory or authorized message sample, so an exhaustive key-size observation cannot be made. |

## Per-issue index

The CSV remains normative for exact evidence requirements, proposed logic, dependencies, references, and notes.

| SSC issue key | Title | Factor | SSC severity | Feasibility | Executor | Current support |
|---|---|---|---|---|---|---|
| `browser_logs_contain_debug_message` | Browser logs contain debug messages | `application_security` | `low` | `DIRECTLY_TESTABLE` | `BROWSER` | `NOT_SUPPORTED` |
| `communication_server_with_expired_cert` | Server with Expired Certificate Contacted | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `BROWSER+TLS+CERT_ENRICHMENT` | `PARTIAL` |
| `communication_with_server_certificate_issued_by_blacklisted_country` | Server certificate issued by country on denylist | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `TLS+POLICY_ENRICHMENT` | `PARTIAL` |
| `contact_information_detected` | Non-standard links detected: Contact information displayed | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `cookie_missing_http_only` | Session Cookie Missing 'HttpOnly' Attribute | `application_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `HTTP+AUTH_FLOW` | `PARTIAL` |
| `cookie_missing_secure_attribute` | Session Cookie Missing 'Secure' Attribute | `application_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `HTTP+AUTH_FLOW` | `PARTIAL` |
| `csp_no_policy_v2` | Content Security Policy (CSP) Missing | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_HEADERS` | `SUPPORTED` |
| `csp_too_broad_v2` | Content Security Policy Contains Broad Directives | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_HEADERS` | `SUPPORTED` |
| `csp_unsafe_policy_v2` | Content Security Policy Contains 'unsafe-*' Directive | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_HEADERS` | `SUPPORTED` |
| `domain_missing_https_v2` | Site does not enforce HTTPS | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_REDIRECT` | `SUPPORTED` |
| `domain_uses_hsts_preloading` | Domain Uses HSTS Preloading | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP+PUBLIC_DATA` | `PARTIAL` |
| `exposed_cisco_web_ui` | Potentially Exposed Cisco Web UI | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+CVE` | `PARTIAL` |
| `fail_to_load_page_components` | Site fails to load page components | `application_security` | `low` | `DIRECTLY_TESTABLE` | `BROWSER` | `NOT_SUPPORTED` |
| `hosted_on_object_storage_v2` | Website Hosted on Object Storage | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `DNS+HTTP+TLS+FINGERPRINT` | `PARTIAL` |
| `hsts_incorrect_v2` | Website Does Not Implement HSTS Best Practices | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_HEADERS` | `SUPPORTED` |
| `insecure_ftp` | Non-standard links detected: Unsafe File Transfer Protocol | `application_security` | `medium` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `insecure_https_redirect_pattern_v2` | Insecure HTTPS Redirect Pattern | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_REDIRECT` | `SUPPORTED` |
| `insecure_server_certificate_key_size` | Certificate key is smaller than recommended size | `application_security` | `low` | `DIRECTLY_TESTABLE` | `TLS_CERTIFICATE` | `SUPPORTED` |
| `insecure_telnet` | Non-standard links detected: Unsafe Telnet protocol | `application_security` | `info` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `links_to_insecure_website` | Site links to insecure websites | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `local_file_path_exposed_via_url_scheme` | Non-standard links detected: Local file path exposed | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `openssl_critical_vulnerability` | November 2022 OpenSSL 3.X vulnerability detected | `application_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `payment_provider` | Website communicates with payment provider | `application_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `BROWSER+FINGERPRINT` | `NOT_SUPPORTED` |
| `potentially_vulnerable` | Potential vulnerability detected | `application_security` | `info` | `NOT_REPRODUCIBLE` | `None` | `NOT_SUPPORTED` |
| `potentially_vulnerable_cve_2023_33246` | Potentially Vulnerable RocketMQ (CVE-2023-33246) | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2023_34362` | MOVEit Service in Use (CVE-2023-34362) | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2023_3519` | Potentially Vulnerable Citrix NetScaler Service Detected | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2023_37582` | Potentially Vulnerable RocketMQ (CVE-2023-37582) | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2023_37979` | Potential Ninja Forms Vulnerability Detected | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2023_38035` | Potentially Vulnerable Ivanti Sentry Device Detected | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2023_46747` | Potentially vulnerable to BIG-IP Configuration utility vulnerability (CVE-2023-46747) | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2024_21887` | Potentially Vulnerable Ivanti Connect Secure or Ivanti Policy Secure (CVE-2024-21887) | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `potentially_vulnerable_cve_2024_46805` | Potentially Vulnerable Ivanti Connect Secure and Ivanti Policy Secure Gateways (CVE-2023-46805) | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP/TCP_FINGERPRINT+CVE` | `PARTIAL` |
| `product_exploited_by_ransomware_actors` | Vulnerable VMWare ESXi Server Detected | `application_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE+KEV` | `PARTIAL` |
| `redirect_chain_contains_http_v2` | Redirect Chain Contains HTTP | `application_security` | `medium` | `DIRECTLY_TESTABLE` | `HTTP_REDIRECT` | `SUPPORTED` |
| `redirect_to_insecure_website` | Link redirects to insecure website | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_CRAWLER+REDIRECT_ENRICHMENT` | `PARTIAL` |
| `references_object_storage_v2` | Website References Object Storage | `application_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `DNS+HTTP+TLS+FINGERPRINT` | `PARTIAL` |
| `sensitive_data_exposure_through_insecure_channel` | Insecure channel exposes sensitive information | `application_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `BROWSER+AUTH_FLOW+DATA_POLICY` | `NOT_SUPPORTED` |
| `server_error` | Server error detected | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `PARTIAL` |
| `site_emits_browser_log` | Site emits visible browser logs | `application_security` | `low` | `DIRECTLY_TESTABLE` | `BROWSER` | `NOT_SUPPORTED` |
| `site_requests_data_over_insecure_channel` | Site requests data over insecure channel | `application_security` | `low` | `DIRECTLY_TESTABLE` | `BROWSER` | `NOT_SUPPORTED` |
| `unsafe_sri_v2` | Unsafe Implementation Of Subresource Integrity | `application_security` | `high` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `uses_go_daddy_managed_wordpress` | Website Hosted by GoDaddy’s Wordpress | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `DNS+HTTP+TLS+FINGERPRINT` | `PARTIAL` |
| `waf_detected_v2` | Web Application Firewall (WAF) Detected | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP+DNS+TLS_FINGERPRINT` | `PARTIAL` |
| `web_vuln_host_high` | High Severity Content Management System vulnerabilities identified | `application_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `web_vuln_host_low` | Low Severity Content Management System vulnerabilities identified | `application_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `web_vuln_host_medium` | Medium Severity Content Management System vulnerabilities identified | `application_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `web_vuln_host_v3_critical` | Critical-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `web_vuln_host_v3_high` | High-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `web_vuln_host_v3_low` | Low-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `web_vuln_host_v3_medium` | Medium-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `webapp_vulnerable_to_spring4shell` | Web application potentially vulnerable to Spring4Shell | `application_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `SBOM+FINGERPRINT+CVE` | `NOT_SUPPORTED` |
| `website_copyright_expired` | Website Copyright is Not Current | `application_security` | `info` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `website_copyright_up_to_date` | Website copyright is current | `application_security` | `info` | `DIRECTLY_TESTABLE` | `HTTP_CRAWLER` | `NOT_SUPPORTED` |
| `website_defacement` | Website defaced | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_CRAWLER+BASELINE_DIFF` | `NOT_SUPPORTED` |
| `websocket_receives_data` | Site receives data over Websockets | `application_security` | `low` | `DIRECTLY_TESTABLE` | `BROWSER_WEBSOCKET` | `NOT_SUPPORTED` |
| `websocket_requests_contain_sensitive_fields` | Websocket requests contain sensitive fields or PII | `application_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `BROWSER_WEBSOCKET+AUTH_FLOW+DATA_POLICY` | `NOT_SUPPORTED` |
| `websocket_sends_data` | Site may use WebSockets to send user data | `application_security` | `low` | `DIRECTLY_TESTABLE` | `BROWSER_WEBSOCKET` | `NOT_SUPPORTED` |
| `x_content_type_options_incorrect_v2` | Website does not implement X-Content-Type-Options Best Practices | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_HEADERS` | `SUPPORTED` |
| `x_frame_options_incorrect_v2` | Site Does Not Use Best Practices Against Embedding of Malicious Content | `application_security` | `low` | `DIRECTLY_TESTABLE` | `HTTP_HEADERS` | `SUPPORTED` |
| `x_xss_protection_incorrect_v2` | Website does not implement X-XSS-Protection Best Practices | `application_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP_HEADERS+POLICY_ENRICHMENT` | `PARTIAL` |
| `ransomware_association` | Ransomware-Susceptible Remote Access Services Exposed | `cubit_score` | `high` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+CVE+KEV` | `PARTIAL` |
| `synth_high_risk_appsec_vulnerabilities` | High-Risk Application Security Vulnerabilities | `cubit_score` | `info` | `NOT_REPRODUCIBLE` | `None` | `NOT_SUPPORTED` |
| `synth_possible_initial_access` | Possible Initial Access by Threat Actor | `cubit_score` | `info` | `NOT_REPRODUCIBLE` | `None` | `NOT_SUPPORTED` |
| `dkim_insufficient_key_length` | Insufficient DKIM Key Length | `dns_health` | `info` | `TESTABLE_WITH_ENRICHMENT` | `MAIL_SAMPLE+DNS` | `PARTIAL` |
| `dkim_record_detected` | DKIM Record Present | `dns_health` | `info` | `TESTABLE_WITH_ENRICHMENT` | `MAIL_SAMPLE+DNS` | `PARTIAL` |
| `dkim_weak_signature` | DKIM Record Using Non-Secure Public Key Algorithm | `dns_health` | `info` | `TESTABLE_WITH_ENRICHMENT` | `MAIL_SAMPLE+DNS` | `PARTIAL` |
| `dmarc_contains_none` | DMARC Record Contains None Policy | `dns_health` | `info` | `DIRECTLY_TESTABLE` | `EMAIL_SECURITY` | `SUPPORTED` |
| `dmarc_record_missing` | DMARC Record Missing | `dns_health` | `info` | `DIRECTLY_TESTABLE` | `EMAIL_SECURITY` | `SUPPORTED` |
| `spf_record_malformed` | Malformed SPF Record | `dns_health` | `medium` | `DIRECTLY_TESTABLE` | `DNS` | `PARTIAL` |
| `spf_record_missing` | SPF Record Missing | `dns_health` | `low` | `DIRECTLY_TESTABLE` | `EMAIL_SECURITY` | `SUPPORTED` |
| `spf_record_softfail` | SPF Record Contains a Softfail without DMARC | `dns_health` | `info` | `DIRECTLY_TESTABLE` | `EMAIL_SECURITY` | `SUPPORTED` |
| `spf_record_wildcard` | SPF Record Found Ineffective | `dns_health` | `medium` | `DIRECTLY_TESTABLE` | `EMAIL_SECURITY` | `SUPPORTED` |
| `subdomain_dmarc_contains_none` | Subdomain DMARC Record Contains None Policy | `dns_health` | `info` | `DIRECTLY_TESTABLE` | `EMAIL_SECURITY` | `SUPPORTED` |
| `outdated_browser` | Outdated Web Browser Observed | `endpoint_security` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `outdated_os` | Outdated Operating System Observed | `endpoint_security` | `medium` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `ransomware_victim` | Domain Advertised as Ransomware Victim | `hacker_chatter` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `targeted_by_threat_actor_group` | Domain Targeted By Threat Actor Group | `hacker_chatter` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `active_cve_exploitation_attempted` | Active CVE Exploitation Attempted | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `adware_installation` | Adware Installation | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `adware_installation_trail` | Adware Installation Trail | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `attack_detected` | Attack Detected | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `cobalt_strike_c2_detected` | Cobalt Strike C2 Detected | `ip_reputation` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `compromised_by_information_stealer` | Information Stealer Detected | `ip_reputation` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `dos_attack_attempt_detected` | DOS Attack Attempt Detected | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `exploited_product` | Products Susceptible To Ransomware Exploits Exposed | `ip_reputation` | `low` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE+KEV` | `PARTIAL` |
| `general_scan_detected` | General Scan Detected | `ip_reputation` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `infected_by_targeted_attack` | Infected by Targeted Attack | `ip_reputation` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `ip_black_list_due_malicious_activity` | IP on blacklist due to malicious activity | `ip_reputation` | `medium` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `known_compromised_or_hostile_host` | Known compromised or Hostile Host | `ip_reputation` | `medium` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `mail_server_unusual_port` | SMTP Server on Unusual Port | `ip_reputation` | `medium` | `DIRECTLY_TESTABLE` | `TCP_SMTP` | `PARTIAL` |
| `malicious_botnet_c_and_c_server_detected` | Malicious botnet C2 server detected | `ip_reputation` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `malicious_scan_detected` | Malicious Scan Detected | `ip_reputation` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `malicious_tor_exit_node_detected` | Malicious TOR Exit Node Detected | `ip_reputation` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `malicious_tor_relay_router_node_detected` | Malicious TOR Relay/Router Node Detected | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `malicious_user_agent_detected` | Malicious User Agent Detected | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `malware_detected` | Malware Detected | `ip_reputation` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `malware_infection` | Malware Infection | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `malware_infection_trail` | Malware Infection Trail | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `mirai_botnet_traffic_detected` | Mirai Botnet Traffic Detected | `ip_reputation` | `medium` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `pva_installation` | Potentially Vulnerable Application (PVA) Installation | `ip_reputation` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `pva_installation_trail` | Potentially Vulnerable Application Installation (PVA) Trail | `ip_reputation` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `ransomware_infection` | Ransomware Infection Detected | `ip_reputation` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `ransomware_infection_trail` | Ransomware Infection Trail Detected | `ip_reputation` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `alleged_first_party_breach` | Alleged Breach Originator | `leaked_information` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `alleged_third_party_breach` | Alleged Breach Impacted | `leaked_information` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `attempted_information_leak` | Attempted Information Leak | `leaked_information` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `compromised_credentials_found` | Credentials at Risk for Up to 120 days | `leaked_information` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `confirmed_first_party_breach` | Confirmed Breach Originator | `leaked_information` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `confirmed_third_party_breach` | Confirmed Breach Impacted | `leaked_information` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `exploit_attempt_detected` | Exploit Attempt Detected | `leaked_information` | `medium` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `historical_compromised_credentials_found` | Credentials at Risk For Up to Two Years | `leaked_information` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `bitcoin_server` | Bitcoin Server Exposed | `network_security` | `info` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE` | `PARTIAL` |
| `cdn_hosting` | CDN Used | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `cobalt_strike_c2_service` | Cobalt Strike C2 server detected | `network_security` | `medium` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `exposed_embedded_iot_web_server` | Embedded IOT Web Server Exposed | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `exposed_mac_airport_device` | Apple AirPort Device Detected | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `exposed_mobile_printing_service` | Mobile Printing Service Detected | `network_security` | `low` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE` | `PARTIAL` |
| `exposed_network_attached_storage_device` | Network Attached Storage Device Exposed | `network_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `exposed_printer` | Printer Detected | `network_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `industrial_control_device` | Industrial Control System Device Accessible | `network_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `iot_camera` | IP Camera Accessible | `network_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `java_debugger` | Java Debugger Detected | `network_security` | `info` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE` | `PARTIAL` |
| `microsoft_exchange_0_day_vulnerability` | Product Potentially Impacted by CVE-2022-41040 & CVE-2022-41082 | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `microsoft_exchange_http_api_vulnerability` | Product Potentially Impacted by PowerShell Remoting RCE | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `minecraft_server` | Minecraft Server Accessible | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE` | `PARTIAL` |
| `mysql_server_empty_password` | MySQL Server Running with Empty Password | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `CONFIG_AUDIT` | `NOT_SUPPORTED` |
| `open_port` | Open Port Discovered | `network_security` | `info` | `DIRECTLY_TESTABLE` | `TCP` | `PARTIAL` |
| `potentially_vulnerable_cisco_rv_320_325` | Potentially Vulnerable Cisco RV320/RV325 Router | `network_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `product_uses_vulnerable_log4j` | Product Running Vulnerable Log4j Version | `network_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `remote_access` | Remote Access Service Observed | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `service_cassandra` | Apache Cassandra Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_cloud_provider` | Cloud Provider Service Used | `network_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `service_couchdb` | Apache CouchDB Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_dns` | DNS Server Accessible | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_elasticsearch` | Elasticsearch Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_ftp` | FTP Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_http_proxy` | HTTP Proxy Service Detected | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_imap` | IMAP Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_ldap` | LDAP Server Accessible | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_ldap_anonymous` | LDAP Server Allows Anonymous Binding | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_microsoft_sql` | Microsoft SQL Server Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_mongodb` | MongoDB Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_mysql` | MySQL Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_neo4j` | Neo4j Database Accessible | `network_security` | `info` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_netbus_remote_access` | NetBus Remote Access Service Detected | `network_security` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `service_networking` | Networking Service Observed | `network_security` | `medium` | `NOT_REPRODUCIBLE` | `None` | `NOT_SUPPORTED` |
| `service_open_vpn` | OpenVPN Device Accessible | `network_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_PROBE+PRODUCT_FINGERPRINT` | `PARTIAL` |
| `service_oracle_db` | Oracle Database Server Accessible | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_oracle_registry` | Oracle Service Registry Detected | `network_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `HTTP+PRODUCT_FINGERPRINT` | `PARTIAL` |
| `service_pop3` | POP3 Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_postgresql` | PostgreSQL Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_pptp` | PPTP Service Accessible | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_pulse_vpn` | Pulse Connect Secure VPN Product Observed | `network_security` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `TCP+HTTP+TLS+DNS_FINGERPRINT` | `PARTIAL` |
| `service_rdp` | RDP Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_redis` | Redis Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_rsync` | rsync Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_smb` | SMB Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_soap` | SOAP Server Accessible | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_socks_proxy` | SOCKS Proxy Service Detected | `network_security` | `low` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_telnet` | Telnet Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `service_vnc` | VNC Service Observed | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE+TCP` | `PARTIAL` |
| `sql_payload_using_tor_proxy_detected` | SQL Payload Using Tor proxy Detected | `network_security` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `ssh_weak_cipher` | SSH Supports Weak Cipher | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `SSH` | `PARTIAL` |
| `ssh_weak_mac` | SSH Supports Weak MAC | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `SSH` | `PARTIAL` |
| `ssh_weak_protocol` | SSH Software Supports Vulnerable Protocol | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `SSH` | `PARTIAL` |
| `telephony` | Telephony/VoIP Device Accessible | `network_security` | `info` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE` | `PARTIAL` |
| `tls_ocsp_stapling` | TLS Certificate Status Request ("OCSP Stapling") Detected | `network_security` | `info` | `DIRECTLY_TESTABLE` | `TLS` | `PARTIAL` |
| `tls_weak_cipher` | TLS Service Supports Weak Cipher Suite | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `TLS` | `PARTIAL` |
| `tls_weak_protocol` | SSL/TLS Service Supports Weak Protocol | `network_security` | `high` | `DIRECTLY_TESTABLE` | `TLS_HANDSHAKE` | `SUPPORTED` |
| `tlscert_excessive_expiration` | Certificate Lifetime Is Longer Than Best Practices | `network_security` | `low` | `TESTABLE_WITH_ENRICHMENT` | `TLS_CERTIFICATE+POLICY_ENRICHMENT` | `PARTIAL` |
| `tlscert_expired` | Certificate Is Expired | `network_security` | `low` | `DIRECTLY_TESTABLE` | `TLS_CERTIFICATE` | `SUPPORTED` |
| `tlscert_no_revocation` | Certificate Without Revocation Control | `network_security` | `low` | `DIRECTLY_TESTABLE` | `TLS_CERTIFICATE` | `SUPPORTED` |
| `tlscert_revoked` | Certificate Is Revoked | `network_security` | `high` | `TESTABLE_WITH_ENRICHMENT` | `TLS_CERTIFICATE+REVOCATION_ENRICHMENT` | `PARTIAL` |
| `tlscert_self_signed` | Certificate Is Self-Signed | `network_security` | `low` | `DIRECTLY_TESTABLE` | `TLS_CERTIFICATE` | `SUPPORTED` |
| `tlscert_weak_signature` | Certificate Signed With Weak Algorithm | `network_security` | `low` | `DIRECTLY_TESTABLE` | `TLS_CERTIFICATE` | `SUPPORTED` |
| `tor_server` | TOR Server Detected | `network_security` | `high` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `tor_traffic_detected` | Tor Traffic Detected | `network_security` | `low` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
| `upnp_accessible` | UPnP Accessible | `network_security` | `medium` | `DIRECTLY_TESTABLE` | `PROTOCOL_PROBE` | `PARTIAL` |
| `uses_go_daddy_infrastructure` | Website Uses GoDaddy TLS Certificates | `network_security` | `info` | `TESTABLE_WITH_ENRICHMENT` | `TLS_CERTIFICATE+CA_REGISTRY_ENRICHMENT` | `PARTIAL` |
| `patching_analysis_high` | High-severity CVE patching analyzed | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE_ANALYTICS` | `NOT_SUPPORTED` |
| `patching_analysis_low` | Low-severity CVE patching analyzed | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE_ANALYTICS` | `NOT_SUPPORTED` |
| `patching_analysis_medium` | Medium-severity CVE patching analyzed | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+CVE_ANALYTICS` | `NOT_SUPPORTED` |
| `patching_cadence_high` | High Severity CVEs Patching Cadence | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `patching_cadence_info` | Vulnerabilities observed | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `patching_cadence_low` | Low Severity CVEs Patching Cadence | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `patching_cadence_medium` | Medium Severity CVEs Patching Cadence | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `patching_cadence_v3_critical` | Critical-Severity CVSS v3.0 Vulnerability Patching Cadence | `patching_cadence` | `low` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `patching_cadence_v3_high` | High-Severity CVSS v3.0 Vulnerability Patching Cadence | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `patching_cadence_v3_low` | Low-Severity CVSS v3.0 Vulnerability Patching Cadence | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `patching_cadence_v3_medium` | Medium-Severity CVSS v3.0 Vulnerability Patching Cadence | `patching_cadence` | `info` | `TESTABLE_WITH_ENRICHMENT` | `LONGITUDINAL_FINGERPRINT+SBOM+CVE` | `NOT_SUPPORTED` |
| `service_end_of_life` | End-of-Life Product | `patching_cadence` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+LIFECYCLE` | `NOT_SUPPORTED` |
| `service_end_of_service` | End-of-Service Product | `patching_cadence` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `FINGERPRINT+SBOM+LIFECYCLE` | `NOT_SUPPORTED` |
| `service_vuln_host_high` | High-Severity Vulnerability in Last Observation | `patching_cadence` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `service_vuln_host_info` | Vulnerability observed in most recent scan | `patching_cadence` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `service_vuln_host_low` | Low-Severity Vulnerability in Last Observation | `patching_cadence` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `service_vuln_host_medium` | Medium-Severity Vulnerability in Last Observation | `patching_cadence` | `medium` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `service_vuln_host_v3_critical` | Critical-Severity CVSS v3.0 Service Vulnerability in Last Observation | `patching_cadence` | `low` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `service_vuln_host_v3_high` | High-Severity CVSS v3.0 Service Vulnerability in Last Observation | `patching_cadence` | `low` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `service_vuln_host_v3_low` | Low-Severity CVSS v3.0 Service Vulnerability in Last Observation | `patching_cadence` | `low` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `service_vuln_host_v3_medium` | Medium-Severity CVSS v3.0 Service Vulnerability in Last Observation | `patching_cadence` | `low` | `TESTABLE_WITH_ENRICHMENT` | `PROTOCOL_FINGERPRINT+SBOM+CVE` | `PARTIAL` |
| `typosquat` | Possible Typosquat Domains Detected | `social_engineering` | `info` | `EXTERNAL_DATA_REQUIRED` | `EXTERNAL_INTEL_INGEST` | `NOT_SUPPORTED` |
