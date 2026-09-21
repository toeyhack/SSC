# SSC 202-Issue Coverage Mapping

Snapshot content hash: `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`  
Source: immutable real `SSC_API` Golden Baseline  
Total mapped issues: **202**

> This is an independent feasibility and test-design analysis. It does not reproduce or claim knowledge of SSC collection, aggregation, severity, scoring, or proprietary detection logic. `ssc_severity` is retained only as source metadata and is not mapped to breach risk, threat level, internal severity, or score impact.

## Classification rubric

- `DIRECTLY_TESTABLE`: deterministic authorized observation using a protocol/browser/configuration check without third-party intelligence.
- `TESTABLE_WITH_ENRICHMENT`: deterministic observation plus local/public product, version, CVE, lifecycle, baseline, or policy data.
- `EXTERNAL_DATA_REQUIRED`: the fact itself depends on external intelligence or internal telemetry unavailable to a perimeter scanner.
- `NOT_REPRODUCIBLE`: no credible public/internal falsifiable method was identified; implementation would guess proprietary semantics.

Current support is deliberately strict: `SUPPORTED` means current executors record sufficient evidence for the complete method, `PARTIAL` means a useful prerequisite exists but the method is incomplete, and `NOT_SUPPORTED` means the required evidence is absent.

## Summary

### Feasibility

| Category | Count | Percentage |
|---|---:|---:|
| DIRECTLY_TESTABLE | 87 | 43.1% |
| TESTABLE_WITH_ENRICHMENT | 69 | 34.2% |
| EXTERNAL_DATA_REQUIRED | 42 | 20.8% |
| NOT_REPRODUCIBLE | 4 | 2.0% |

### Current platform coverage

| Coverage | Count | Percentage |
|---|---:|---:|
| SUPPORTED | 4 | 2.0% |
| PARTIAL | 115 | 56.9% |
| NOT_SUPPORTED | 83 | 41.1% |

### Coverage by SSC factor

| Factor | Total | Direct | Enrichment | External data | Not reproducible | Supported | Partial | Not supported |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| application_security | 61 | 32 | 28 | 0 | 1 | 1 | 39 | 21 |
| cubit_score | 3 | 0 | 1 | 0 | 2 | 0 | 1 | 2 |
| dns_health | 10 | 7 | 3 | 0 | 0 | 1 | 6 | 3 |
| endpoint_security | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 2 |
| hacker_chatter | 2 | 0 | 0 | 2 | 0 | 0 | 0 | 2 |
| ip_reputation | 26 | 1 | 1 | 24 | 0 | 0 | 2 | 24 |
| leaked_information | 8 | 0 | 0 | 8 | 0 | 0 | 0 | 8 |
| network_security | 68 | 47 | 15 | 5 | 1 | 2 | 59 | 7 |
| patching_cadence | 21 | 0 | 21 | 0 | 0 | 0 | 8 | 13 |
| social_engineering | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 1 |

## Recommended implementation priorities

### Priority 1 — deterministic checks fitting current HTTP/TLS/DNS/TCP architecture

1. `cookie_missing_http_only` — Session Cookie Missing 'HttpOnly' Attribute: Collect Set-Cookie headers over an approved unauthenticated flow and, where authorized test authentication exists, identify session cookies by configured names/purpose; never retain values.
2. `cookie_missing_secure_attribute` — Session Cookie Missing 'Secure' Attribute: Collect Set-Cookie headers over an approved unauthenticated flow and, where authorized test authentication exists, identify session cookies by configured names/purpose; never retain values.
3. `csp_no_policy_v2` — Content Security Policy (CSP) Missing: Fetch approved HTML pages, collect all CSP headers/meta policies, parse directives according to CSP3, and evaluate the effective policy.
4. `csp_unsafe_policy_v2` — Content Security Policy Contains 'unsafe-*' Directive: Fetch approved HTML pages, collect all CSP headers/meta policies, parse directives according to CSP3, and evaluate the effective policy.
5. `csp_too_broad_v2` — Content Security Policy Contains Broad Directives: Fetch approved HTML pages, collect all CSP headers/meta policies, parse directives according to CSP3, and evaluate the effective policy.
6. `domain_missing_https_v2` — Site does not enforce HTTPS: Probe approved HTTP and HTTPS endpoints and follow only bounded same-target redirects.
7. `hsts_incorrect_v2` — Website Does Not Implement HSTS Best Practices: Fetch HTTPS responses and parse Strict-Transport-Security according to RFC 6797 across approved canonical hosts.
8. `redirect_chain_contains_http_v2` — Redirect Chain Contains HTTP: Issue bounded HEAD/GET requests and resolve Location fields per HTTP semantics while enforcing inventory scope.
9. `x_content_type_options_incorrect_v2` — Website does not implement X-Content-Type-Options Best Practices: Fetch approved pages, collect relevant response headers and effective CSP, normalize tokens, and compare to versioned secure-header policy.
10. `x_frame_options_incorrect_v2` — Site Does Not Use Best Practices Against Embedding of Malicious Content: Fetch approved pages, collect relevant response headers and effective CSP, normalize tokens, and compare to versioned secure-header policy.
11. `tls_weak_protocol` — SSL/TLS Service Supports Weak Protocol: Attempt bounded handshakes for SSLv2/SSLv3/TLS 1.0/TLS 1.1 and approved modern controls.
12. `tls_weak_cipher` — TLS Service Supports Weak Cipher Suite: Enumerate accepted TLS cipher suites with bounded handshakes and compare to NIST/internal policy.
13. `tlscert_expired` — Certificate Is Expired: Parse certificate notAfter during a TLS handshake.
14. `insecure_server_certificate_key_size` — Certificate key is smaller than recommended size: Perform a TLS handshake, parse the leaf public key algorithm and size/curve, and compare with versioned internal cryptographic policy.
15. `tlscert_weak_signature` — Certificate Signed With Weak Algorithm: Parse every served chain certificate signature algorithm and compare to cryptographic policy.
16. `tlscert_revoked` — Certificate Is Revoked: Validate the chain and query/cache OCSP or CRL according to policy with freshness/signature checks.
17. `spf_record_malformed` — Malformed SPF Record: Query domain TXT records, select v=spf1 records, parse/evaluate mechanisms with bounded DNS lookups, and retain the normalized policy.
18. `dmarc_contains_none` — DMARC Record Contains None Policy: Query TXT at _dmarc.<domain>, parse the single applicable DMARC record and determine inherited/effective policy per RFC 9989.
19. `service_telnet` — Telnet Service Observed: Connect only to approved ports and perform a minimal, non-authenticating Telnet option negotiation exchange; do not enumerate data or change state.
20. `ssh_weak_cipher` — SSH Supports Weak Cipher: Perform SSH version exchange and algorithm negotiation enumeration without authentication, then compare offers with a versioned internal cryptographic policy.

Other Priority 1 candidates are the remaining direct TLS/PKI, DNS-policy, HTTP redirect/header, SSH negotiation, and safe protocol-identification rows in the CSV.

### Priority 2 — fingerprint, CVE, lifecycle, or longitudinal enrichment

Implement a versioned fingerprint evidence model, authenticated inventory/SBOM ingestion, CPE/package normalization, NVD/vendor advisory snapshots, CISA KEV ingestion, vendor lifecycle records, and longitudinal observation semantics. Never infer a vulnerability from a port or product family alone, and never validate by exploitation.

### Priority 3 — external intelligence integrations

Add only approved, provenance-bearing feeds for IP reputation, malware/botnet activity, breach/credential exposure, ransomware/hacker chatter, Tor consensus data, passive DNS/CT/RDAP, and internal IDS/EDR/NetFlow. Define retention, licensing, privacy, freshness, confidence, and analyst-review controls before ingestion.

`NOT_REPRODUCIBLE` items are excluded from the roadmap until a credible falsifiable evidence source is approved.

## Per-issue index

The CSV is normative for the complete 16-field mapping. This index keeps the Markdown reviewable while retaining one row per imported issue.

| SSC issue key | Title | Factor | Source severity | Feasibility | Executor | Complexity | Confidence | Current support |
|---|---|---|---|---|---|---|---|---|
| `browser_logs_contain_debug_message` | Browser logs contain debug messages | application_security | low | DIRECTLY_TESTABLE | BROWSER | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `communication_server_with_expired_cert` | Server with Expired Certificate Contacted | application_security | low | DIRECTLY_TESTABLE | BROWSER+TLS | HIGH | HIGH | PARTIAL |
| `communication_with_server_certificate_issued_by_blacklisted_country` | Server certificate issued by country on denylist | application_security | low | TESTABLE_WITH_ENRICHMENT | TLS+POLICY_ENRICHMENT | HIGH | MEDIUM | PARTIAL |
| `contact_information_detected` | Non-standard links detected: Contact information displayed | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | NOT_SUPPORTED |
| `cookie_missing_http_only` | Session Cookie Missing 'HttpOnly' Attribute | application_security | high | DIRECTLY_TESTABLE | HTTP | LOW | HIGH | PARTIAL |
| `cookie_missing_secure_attribute` | Session Cookie Missing 'Secure' Attribute | application_security | high | DIRECTLY_TESTABLE | HTTP | LOW | HIGH | PARTIAL |
| `csp_no_policy_v2` | Content Security Policy (CSP) Missing | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | PARTIAL |
| `csp_too_broad_v2` | Content Security Policy Contains Broad Directives | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | PARTIAL |
| `csp_unsafe_policy_v2` | Content Security Policy Contains 'unsafe-*' Directive | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | PARTIAL |
| `domain_missing_https_v2` | Site does not enforce HTTPS | application_security | low | DIRECTLY_TESTABLE | HTTP+TLS | LOW | HIGH | PARTIAL |
| `domain_uses_hsts_preloading` | Domain Uses HSTS Preloading | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP+PUBLIC_DATA | MEDIUM | HIGH | PARTIAL |
| `exposed_cisco_web_ui` | Potentially Exposed Cisco Web UI | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `fail_to_load_page_components` | Site fails to load page components | application_security | low | DIRECTLY_TESTABLE | BROWSER | HIGH | MEDIUM | NOT_SUPPORTED |
| `hosted_on_object_storage_v2` | Website Hosted on Object Storage | application_security | low | TESTABLE_WITH_ENRICHMENT | DNS+HTTP+TLS+FINGERPRINT | MEDIUM | MEDIUM | PARTIAL |
| `hsts_incorrect_v2` | Website Does Not Implement HSTS Best Practices | application_security | low | DIRECTLY_TESTABLE | HTTP | LOW | HIGH | PARTIAL |
| `insecure_ftp` | Non-standard links detected: Unsafe File Transfer Protocol | application_security | medium | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | NOT_SUPPORTED |
| `insecure_https_redirect_pattern_v2` | Insecure HTTPS Redirect Pattern | application_security | low | DIRECTLY_TESTABLE | HTTP | LOW | HIGH | PARTIAL |
| `insecure_server_certificate_key_size` | Certificate key is smaller than recommended size | application_security | low | DIRECTLY_TESTABLE | TLS | LOW | HIGH | PARTIAL |
| `insecure_telnet` | Non-standard links detected: Unsafe Telnet protocol | application_security | info | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | NOT_SUPPORTED |
| `links_to_insecure_website` | Site links to insecure websites | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | NOT_SUPPORTED |
| `local_file_path_exposed_via_url_scheme` | Non-standard links detected: Local file path exposed | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | MEDIUM | HIGH | NOT_SUPPORTED |
| `openssl_critical_vulnerability` | November 2022 OpenSSL 3.X vulnerability detected | application_security | high | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE | HIGH | HIGH | NOT_SUPPORTED |
| `payment_provider` | Website communicates with payment provider | application_security | high | TESTABLE_WITH_ENRICHMENT | BROWSER+FINGERPRINT | HIGH | MEDIUM | NOT_SUPPORTED |
| `potentially_vulnerable` | Potential vulnerability detected | application_security | info | NOT_REPRODUCIBLE | None | HIGH | LOW | NOT_SUPPORTED |
| `potentially_vulnerable_cve_2023_33246` | Potentially Vulnerable RocketMQ (CVE-2023-33246) | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2023_34362` | MOVEit Service in Use (CVE-2023-34362) | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2023_3519` | Potentially Vulnerable Citrix NetScaler Service Detected | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2023_37582` | Potentially Vulnerable RocketMQ (CVE-2023-37582) | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2023_37979` | Potential Ninja Forms Vulnerability Detected | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2023_38035` | Potentially Vulnerable Ivanti Sentry Device Detected | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2023_46747` | Potentially vulnerable to BIG-IP Configuration utility vulnerability (CVE-2023-46747) | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2024_21887` | Potentially Vulnerable Ivanti Connect Secure or Ivanti Policy Secure (CVE-2024-21887) | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `potentially_vulnerable_cve_2024_46805` | Potentially Vulnerable Ivanti Connect Secure and Ivanti Policy Secure Gateways (CVE-2023-46805) | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP/TCP_FINGERPRINT+CVE | HIGH | HIGH | PARTIAL |
| `product_exploited_by_ransomware_actors` | Vulnerable VMWare ESXi Server Detected | application_security | high | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE+KEV | HIGH | MEDIUM | PARTIAL |
| `redirect_chain_contains_http_v2` | Redirect Chain Contains HTTP | application_security | medium | DIRECTLY_TESTABLE | HTTP | LOW | HIGH | SUPPORTED |
| `redirect_to_insecure_website` | Link redirects to insecure website | application_security | low | DIRECTLY_TESTABLE | HTTP | LOW | HIGH | PARTIAL |
| `references_object_storage_v2` | Website References Object Storage | application_security | medium | TESTABLE_WITH_ENRICHMENT | DNS+HTTP+TLS+FINGERPRINT | MEDIUM | MEDIUM | PARTIAL |
| `sensitive_data_exposure_through_insecure_channel` | Insecure channel exposes sensitive information | application_security | medium | DIRECTLY_TESTABLE | BROWSER | HIGH | MEDIUM | NOT_SUPPORTED |
| `server_error` | Server error detected | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | LOW | HIGH | PARTIAL |
| `site_emits_browser_log` | Site emits visible browser logs | application_security | low | DIRECTLY_TESTABLE | BROWSER | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `site_requests_data_over_insecure_channel` | Site requests data over insecure channel | application_security | low | DIRECTLY_TESTABLE | BROWSER | MEDIUM | HIGH | NOT_SUPPORTED |
| `unsafe_sri_v2` | Unsafe Implementation Of Subresource Integrity | application_security | high | DIRECTLY_TESTABLE | HTTP_CRAWLER | HIGH | HIGH | NOT_SUPPORTED |
| `uses_go_daddy_managed_wordpress` | Website Hosted by GoDaddy’s Wordpress | application_security | info | TESTABLE_WITH_ENRICHMENT | DNS+HTTP+TLS+FINGERPRINT | MEDIUM | MEDIUM | PARTIAL |
| `waf_detected_v2` | Web Application Firewall (WAF) Detected | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP+DNS+TLS_FINGERPRINT | MEDIUM | MEDIUM | PARTIAL |
| `web_vuln_host_high` | High Severity Content Management System vulnerabilities identified | application_security | medium | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `web_vuln_host_low` | Low Severity Content Management System vulnerabilities identified | application_security | medium | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `web_vuln_host_medium` | Medium Severity Content Management System vulnerabilities identified | application_security | medium | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `web_vuln_host_v3_critical` | Critical-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | application_security | low | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `web_vuln_host_v3_high` | High-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | application_security | low | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `web_vuln_host_v3_low` | Low-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | application_security | low | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `web_vuln_host_v3_medium` | Medium-Severity CVSS v3.0 Content Management System Vulnerability in Last Observation | application_security | low | TESTABLE_WITH_ENRICHMENT | HTTP_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `webapp_vulnerable_to_spring4shell` | Web application potentially vulnerable to Spring4Shell | application_security | low | TESTABLE_WITH_ENRICHMENT | SBOM+FINGERPRINT+CVE | HIGH | HIGH | NOT_SUPPORTED |
| `website_copyright_expired` | Website Copyright is Not Current | application_security | info | DIRECTLY_TESTABLE | HTTP_CRAWLER | LOW | MEDIUM | NOT_SUPPORTED |
| `website_copyright_up_to_date` | Website copyright is current | application_security | info | DIRECTLY_TESTABLE | HTTP_CRAWLER | LOW | MEDIUM | NOT_SUPPORTED |
| `website_defacement` | Website defaced | application_security | info | TESTABLE_WITH_ENRICHMENT | HTTP_CRAWLER+BASELINE_DIFF | HIGH | MEDIUM | NOT_SUPPORTED |
| `websocket_receives_data` | Site receives data over Websockets | application_security | low | DIRECTLY_TESTABLE | BROWSER_WEBSOCKET | HIGH | MEDIUM | NOT_SUPPORTED |
| `websocket_requests_contain_sensitive_fields` | Websocket requests contain sensitive fields or PII | application_security | high | DIRECTLY_TESTABLE | BROWSER_WEBSOCKET | HIGH | MEDIUM | NOT_SUPPORTED |
| `websocket_sends_data` | Site may use WebSockets to send user data | application_security | low | DIRECTLY_TESTABLE | BROWSER_WEBSOCKET | HIGH | MEDIUM | NOT_SUPPORTED |
| `x_content_type_options_incorrect_v2` | Website does not implement X-Content-Type-Options Best Practices | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | LOW | HIGH | PARTIAL |
| `x_frame_options_incorrect_v2` | Site Does Not Use Best Practices Against Embedding of Malicious Content | application_security | low | DIRECTLY_TESTABLE | HTTP_CRAWLER | LOW | HIGH | PARTIAL |
| `x_xss_protection_incorrect_v2` | Website does not implement X-XSS-Protection Best Practices | application_security | info | DIRECTLY_TESTABLE | HTTP_CRAWLER | LOW | MEDIUM | PARTIAL |
| `ransomware_association` | Ransomware-Susceptible Remote Access Services Exposed | cubit_score | high | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+CVE+KEV | HIGH | MEDIUM | PARTIAL |
| `synth_high_risk_appsec_vulnerabilities` | High-Risk Application Security Vulnerabilities | cubit_score | info | NOT_REPRODUCIBLE | None | HIGH | LOW | NOT_SUPPORTED |
| `synth_possible_initial_access` | Possible Initial Access by Threat Actor | cubit_score | info | NOT_REPRODUCIBLE | None | HIGH | LOW | NOT_SUPPORTED |
| `dkim_insufficient_key_length` | Insufficient DKIM Key Length | dns_health | info | TESTABLE_WITH_ENRICHMENT | MAIL_SAMPLE+DNS | MEDIUM | HIGH | NOT_SUPPORTED |
| `dkim_record_detected` | DKIM Record Present | dns_health | info | TESTABLE_WITH_ENRICHMENT | MAIL_SAMPLE+DNS | MEDIUM | HIGH | NOT_SUPPORTED |
| `dkim_weak_signature` | DKIM Record Using Non-Secure Public Key Algorithm | dns_health | info | TESTABLE_WITH_ENRICHMENT | MAIL_SAMPLE+DNS | MEDIUM | HIGH | NOT_SUPPORTED |
| `dmarc_contains_none` | DMARC Record Contains None Policy | dns_health | info | DIRECTLY_TESTABLE | DNS | LOW | HIGH | PARTIAL |
| `dmarc_record_missing` | DMARC Record Missing | dns_health | info | DIRECTLY_TESTABLE | DNS | LOW | HIGH | PARTIAL |
| `spf_record_malformed` | Malformed SPF Record | dns_health | medium | DIRECTLY_TESTABLE | DNS | MEDIUM | HIGH | PARTIAL |
| `spf_record_missing` | SPF Record Missing | dns_health | low | DIRECTLY_TESTABLE | DNS | LOW | HIGH | SUPPORTED |
| `spf_record_softfail` | SPF Record Contains a Softfail without DMARC | dns_health | info | DIRECTLY_TESTABLE | DNS | MEDIUM | HIGH | PARTIAL |
| `spf_record_wildcard` | SPF Record Found Ineffective | dns_health | medium | DIRECTLY_TESTABLE | DNS | MEDIUM | HIGH | PARTIAL |
| `subdomain_dmarc_contains_none` | Subdomain DMARC Record Contains None Policy | dns_health | info | DIRECTLY_TESTABLE | DNS | LOW | HIGH | PARTIAL |
| `outdated_browser` | Outdated Web Browser Observed | endpoint_security | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | HIGH | NOT_SUPPORTED |
| `outdated_os` | Outdated Operating System Observed | endpoint_security | medium | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | HIGH | NOT_SUPPORTED |
| `ransomware_victim` | Domain Advertised as Ransomware Victim | hacker_chatter | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `targeted_by_threat_actor_group` | Domain Targeted By Threat Actor Group | hacker_chatter | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `active_cve_exploitation_attempted` | Active CVE Exploitation Attempted | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `adware_installation` | Adware Installation | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `adware_installation_trail` | Adware Installation Trail | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `attack_detected` | Attack Detected | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `cobalt_strike_c2_detected` | Cobalt Strike C2 Detected | ip_reputation | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `compromised_by_information_stealer` | Information Stealer Detected | ip_reputation | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `dos_attack_attempt_detected` | DOS Attack Attempt Detected | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `exploited_product` | Products Susceptible To Ransomware Exploits Exposed | ip_reputation | low | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE+KEV | HIGH | MEDIUM | PARTIAL |
| `general_scan_detected` | General Scan Detected | ip_reputation | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `infected_by_targeted_attack` | Infected by Targeted Attack | ip_reputation | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `ip_black_list_due_malicious_activity` | IP on blacklist due to malicious activity | ip_reputation | medium | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `known_compromised_or_hostile_host` | Known compromised or Hostile Host | ip_reputation | medium | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `mail_server_unusual_port` | SMTP Server on Unusual Port | ip_reputation | medium | DIRECTLY_TESTABLE | TCP_SMTP | LOW | HIGH | PARTIAL |
| `malicious_botnet_c_and_c_server_detected` | Malicious botnet C2 server detected | ip_reputation | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `malicious_scan_detected` | Malicious Scan Detected | ip_reputation | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `malicious_tor_exit_node_detected` | Malicious TOR Exit Node Detected | ip_reputation | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `malicious_tor_relay_router_node_detected` | Malicious TOR Relay/Router Node Detected | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `malicious_user_agent_detected` | Malicious User Agent Detected | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `malware_detected` | Malware Detected | ip_reputation | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `malware_infection` | Malware Infection | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `malware_infection_trail` | Malware Infection Trail | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `mirai_botnet_traffic_detected` | Mirai Botnet Traffic Detected | ip_reputation | medium | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `pva_installation` | Potentially Vulnerable Application (PVA) Installation | ip_reputation | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `pva_installation_trail` | Potentially Vulnerable Application Installation (PVA) Trail | ip_reputation | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `ransomware_infection` | Ransomware Infection Detected | ip_reputation | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `ransomware_infection_trail` | Ransomware Infection Trail Detected | ip_reputation | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `alleged_first_party_breach` | Alleged Breach Originator | leaked_information | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `alleged_third_party_breach` | Alleged Breach Impacted | leaked_information | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `attempted_information_leak` | Attempted Information Leak | leaked_information | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `compromised_credentials_found` | Credentials at Risk for Up to 120 days | leaked_information | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `confirmed_first_party_breach` | Confirmed Breach Originator | leaked_information | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `confirmed_third_party_breach` | Confirmed Breach Impacted | leaked_information | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `exploit_attempt_detected` | Exploit Attempt Detected | leaked_information | medium | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `historical_compromised_credentials_found` | Credentials at Risk For Up to Two Years | leaked_information | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |
| `bitcoin_server` | Bitcoin Server Exposed | network_security | info | DIRECTLY_TESTABLE | PROTOCOL_PROBE | MEDIUM | HIGH | PARTIAL |
| `cdn_hosting` | CDN Used | network_security | low | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `cobalt_strike_c2_service` | Cobalt Strike C2 server detected | network_security | medium | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `exposed_embedded_iot_web_server` | Embedded IOT Web Server Exposed | network_security | low | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `exposed_mac_airport_device` | Apple AirPort Device Detected | network_security | low | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `exposed_mobile_printing_service` | Mobile Printing Service Detected | network_security | low | DIRECTLY_TESTABLE | PROTOCOL_PROBE | MEDIUM | HIGH | PARTIAL |
| `exposed_network_attached_storage_device` | Network Attached Storage Device Exposed | network_security | high | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `exposed_printer` | Printer Detected | network_security | medium | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `industrial_control_device` | Industrial Control System Device Accessible | network_security | medium | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `iot_camera` | IP Camera Accessible | network_security | medium | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `java_debugger` | Java Debugger Detected | network_security | info | DIRECTLY_TESTABLE | PROTOCOL_PROBE | MEDIUM | HIGH | PARTIAL |
| `microsoft_exchange_0_day_vulnerability` | Product Potentially Impacted by CVE-2022-41040 & CVE-2022-41082 | network_security | low | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `microsoft_exchange_http_api_vulnerability` | Product Potentially Impacted by PowerShell Remoting RCE | network_security | low | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `minecraft_server` | Minecraft Server Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE | MEDIUM | HIGH | PARTIAL |
| `mysql_server_empty_password` | MySQL Server Running with Empty Password | network_security | low | TESTABLE_WITH_ENRICHMENT | CONFIG_AUDIT | MEDIUM | HIGH | NOT_SUPPORTED |
| `open_port` | Open Port Discovered | network_security | info | DIRECTLY_TESTABLE | TCP | LOW | HIGH | SUPPORTED |
| `potentially_vulnerable_cisco_rv_320_325` | Potentially Vulnerable Cisco RV320/RV325 Router | network_security | info | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `product_uses_vulnerable_log4j` | Product Running Vulnerable Log4j Version | network_security | high | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `remote_access` | Remote Access Service Observed | network_security | low | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `service_cassandra` | Apache Cassandra Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_cloud_provider` | Cloud Provider Service Used | network_security | info | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `service_couchdb` | Apache CouchDB Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_dns` | DNS Server Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_elasticsearch` | Elasticsearch Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_ftp` | FTP Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_http_proxy` | HTTP Proxy Service Detected | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_imap` | IMAP Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_ldap` | LDAP Server Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_ldap_anonymous` | LDAP Server Allows Anonymous Binding | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_microsoft_sql` | Microsoft SQL Server Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_mongodb` | MongoDB Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_mysql` | MySQL Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_neo4j` | Neo4j Database Accessible | network_security | info | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_netbus_remote_access` | NetBus Remote Access Service Detected | network_security | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `service_networking` | Networking Service Observed | network_security | medium | NOT_REPRODUCIBLE | None | HIGH | LOW | NOT_SUPPORTED |
| `service_open_vpn` | OpenVPN Device Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_oracle_db` | Oracle Database Server Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_oracle_registry` | Oracle Service Registry Detected | network_security | info | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_pop3` | POP3 Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_postgresql` | PostgreSQL Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_pptp` | PPTP Service Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_pulse_vpn` | Pulse Connect Secure VPN Product Observed | network_security | medium | TESTABLE_WITH_ENRICHMENT | TCP+HTTP+TLS+DNS_FINGERPRINT | HIGH | MEDIUM | PARTIAL |
| `service_rdp` | RDP Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_redis` | Redis Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_rsync` | rsync Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_smb` | SMB Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_soap` | SOAP Server Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_socks_proxy` | SOCKS Proxy Service Detected | network_security | low | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_telnet` | Telnet Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `service_vnc` | VNC Service Observed | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE+TCP | MEDIUM | HIGH | PARTIAL |
| `sql_payload_using_tor_proxy_detected` | SQL Payload Using Tor proxy Detected | network_security | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `ssh_weak_cipher` | SSH Supports Weak Cipher | network_security | medium | DIRECTLY_TESTABLE | SSH | MEDIUM | HIGH | PARTIAL |
| `ssh_weak_mac` | SSH Supports Weak MAC | network_security | medium | DIRECTLY_TESTABLE | SSH | MEDIUM | HIGH | PARTIAL |
| `ssh_weak_protocol` | SSH Software Supports Vulnerable Protocol | network_security | medium | DIRECTLY_TESTABLE | SSH | MEDIUM | HIGH | PARTIAL |
| `telephony` | Telephony/VoIP Device Accessible | network_security | info | DIRECTLY_TESTABLE | PROTOCOL_PROBE | MEDIUM | HIGH | PARTIAL |
| `tls_ocsp_stapling` | TLS Certificate Status Request ("OCSP Stapling") Detected | network_security | info | DIRECTLY_TESTABLE | TLS | MEDIUM | HIGH | PARTIAL |
| `tls_weak_cipher` | TLS Service Supports Weak Cipher Suite | network_security | medium | DIRECTLY_TESTABLE | TLS | MEDIUM | HIGH | PARTIAL |
| `tls_weak_protocol` | SSL/TLS Service Supports Weak Protocol | network_security | high | DIRECTLY_TESTABLE | TLS | MEDIUM | HIGH | PARTIAL |
| `tlscert_excessive_expiration` | Certificate Lifetime Is Longer Than Best Practices | network_security | low | DIRECTLY_TESTABLE | TLS | MEDIUM | HIGH | PARTIAL |
| `tlscert_expired` | Certificate Is Expired | network_security | low | DIRECTLY_TESTABLE | TLS | LOW | HIGH | SUPPORTED |
| `tlscert_no_revocation` | Certificate Without Revocation Control | network_security | low | DIRECTLY_TESTABLE | TLS | MEDIUM | HIGH | PARTIAL |
| `tlscert_revoked` | Certificate Is Revoked | network_security | high | DIRECTLY_TESTABLE | TLS | MEDIUM | HIGH | PARTIAL |
| `tlscert_self_signed` | Certificate Is Self-Signed | network_security | low | DIRECTLY_TESTABLE | TLS | MEDIUM | HIGH | PARTIAL |
| `tlscert_weak_signature` | Certificate Signed With Weak Algorithm | network_security | low | DIRECTLY_TESTABLE | TLS | LOW | HIGH | PARTIAL |
| `tor_server` | TOR Server Detected | network_security | high | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `tor_traffic_detected` | Tor Traffic Detected | network_security | low | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | MEDIUM | MEDIUM | NOT_SUPPORTED |
| `upnp_accessible` | UPnP Accessible | network_security | medium | DIRECTLY_TESTABLE | PROTOCOL_PROBE | MEDIUM | HIGH | PARTIAL |
| `uses_go_daddy_infrastructure` | Website Uses GoDaddy TLS Certificates | network_security | info | DIRECTLY_TESTABLE | TLS | LOW | HIGH | PARTIAL |
| `patching_analysis_high` | High-severity CVE patching analyzed | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE_ANALYTICS | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_analysis_low` | Low-severity CVE patching analyzed | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE_ANALYTICS | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_analysis_medium` | Medium-severity CVE patching analyzed | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+CVE_ANALYTICS | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_high` | High Severity CVEs Patching Cadence | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_info` | Vulnerabilities observed | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_low` | Low Severity CVEs Patching Cadence | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_medium` | Medium Severity CVEs Patching Cadence | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_v3_critical` | Critical-Severity CVSS v3.0 Vulnerability Patching Cadence | patching_cadence | low | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_v3_high` | High-Severity CVSS v3.0 Vulnerability Patching Cadence | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_v3_low` | Low-Severity CVSS v3.0 Vulnerability Patching Cadence | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `patching_cadence_v3_medium` | Medium-Severity CVSS v3.0 Vulnerability Patching Cadence | patching_cadence | info | TESTABLE_WITH_ENRICHMENT | LONGITUDINAL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | NOT_SUPPORTED |
| `service_end_of_life` | End-of-Life Product | patching_cadence | medium | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+LIFECYCLE | HIGH | HIGH | NOT_SUPPORTED |
| `service_end_of_service` | End-of-Service Product | patching_cadence | medium | TESTABLE_WITH_ENRICHMENT | FINGERPRINT+SBOM+LIFECYCLE | HIGH | HIGH | NOT_SUPPORTED |
| `service_vuln_host_high` | High-Severity Vulnerability in Last Observation | patching_cadence | medium | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `service_vuln_host_info` | Vulnerability observed in most recent scan | patching_cadence | medium | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `service_vuln_host_low` | Low-Severity Vulnerability in Last Observation | patching_cadence | medium | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `service_vuln_host_medium` | Medium-Severity Vulnerability in Last Observation | patching_cadence | medium | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `service_vuln_host_v3_critical` | Critical-Severity CVSS v3.0 Service Vulnerability in Last Observation | patching_cadence | low | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `service_vuln_host_v3_high` | High-Severity CVSS v3.0 Service Vulnerability in Last Observation | patching_cadence | low | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `service_vuln_host_v3_low` | Low-Severity CVSS v3.0 Service Vulnerability in Last Observation | patching_cadence | low | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `service_vuln_host_v3_medium` | Medium-Severity CVSS v3.0 Service Vulnerability in Last Observation | patching_cadence | low | TESTABLE_WITH_ENRICHMENT | PROTOCOL_FINGERPRINT+SBOM+CVE | HIGH | MEDIUM | PARTIAL |
| `typosquat` | Possible Typosquat Domains Detected | social_engineering | info | EXTERNAL_DATA_REQUIRED | EXTERNAL_INTEL_INGEST | HIGH | MEDIUM | NOT_SUPPORTED |

## Artifact contract

- `SSC_ISSUE_COVERAGE.csv` contains every required field and is the row-level source of truth.
- `SSC_TEST_METHOD_CATALOG.md` defines shared testing primitives, evidence requirements, safety rules, and authoritative references.
- Re-run mapping review whenever the immutable baseline hash changes; never silently carry mappings to a new taxonomy version.
