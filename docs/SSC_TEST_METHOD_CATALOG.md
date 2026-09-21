# SSC Independent Test Method Catalog

## Scope and non-equivalence

This catalog supports the 202 mappings tied to Golden Baseline `0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8`. SSC supplies the issue taxonomy—the **what**. The methods below are independent designs based on public standards, vendor documentation, approved intelligence, and internal policy—the **how**. They neither reconstruct SSC sensors nor claim equivalent coverage, confidence, aggregation, severity, or scoring.

All checks require explicit asset authorization. Prohibited techniques include exploitation, brute force, credential guessing, destructive validation, relay testing, unsolicited message submission, and collection of real secrets. Product vulnerabilities are determined by version/configuration evidence against authoritative affected ranges, never by exploit payload.

## Evidence contract

Every observation should include target identity, executor and version, method/rule version, started/completed time, bounded scope, raw-evidence hash, normalized fields, success/error/indeterminate state, and provenance. External/enrichment datasets also require provider, retrieval time, source revision/hash, license/retention class, and freshness. Absence may become a finding only after distinguishing authoritative negative answers from timeout, refusal, blocked scope, or parser failure.

## Shared method families

### HTTP headers, cookies, and redirects

Use bounded same-target HTTP(S) requests and standards-based redirect resolution. Preserve status, selected headers, parsed cookie attributes, every hop, and indeterminate errors. Cookie values and sensitive URL parameters are discarded. Primary references: [HTTP semantics](https://www.rfc-editor.org/rfc/rfc9110.html), [cookies](https://www.rfc-editor.org/rfc/rfc6265.html), [HSTS](https://www.rfc-editor.org/rfc/rfc6797.html), [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/), and [CSP3](https://www.w3.org/TR/CSP3/).

### Bounded crawl and instrumented browser

Static HTML parsing is sufficient for literal links and headers; JavaScript-created resources, browser console, mixed content, component failures, and WebSockets require a sandboxed headless browser. Declare seed URLs, same-origin rules, depth/page/time limits, browser version, and blocked side effects. Never submit forms unless a separately approved synthetic flow requires it. References: [OWASP client-side testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/), [WebSocket testing](https://wstg.owasp.org/latest/4-Web_Application_Security_Testing/11-Client-side/10-WebSockets/), [RFC 6455](https://www.rfc-editor.org/rfc/rfc6455.html), and [SRI](https://www.w3.org/TR/SRI/).

### TLS and PKI

Perform bounded handshakes per approved port, retaining protocol/cipher acceptance and certificate-chain metadata. Validate time, hostname/path, signatures, key strength, revocation evidence, and OCSP freshness independently. References: [NIST SP 800-52r2](https://csrc.nist.gov/pubs/sp/800/52/r2/final), [TLS 1.0/1.1 deprecation](https://www.rfc-editor.org/rfc/rfc8996.html), [PKIX](https://www.rfc-editor.org/rfc/rfc5280.html), and [OCSP](https://www.rfc-editor.org/rfc/rfc6960.html).

### DNS and email authentication

Preserve queried name/type, resolver, DNS response class, record hash, parser result, lookup limits, and organizational-domain basis. DKIM requires a selector from an approved message or managed inventory; selectors must not be guessed exhaustively. References: [SPF](https://www.rfc-editor.org/rfc/rfc7208.html), [DMARC](https://www.rfc-editor.org/rfc/rfc9989.html), [DKIM](https://www.rfc-editor.org/rfc/rfc6376.html), and [DKIM cryptographic update](https://www.rfc-editor.org/rfc/rfc8301.html).

### Safe service identification

An open TCP port is exposure evidence, not service identity. Send only the protocol's minimal greeting/capability/negotiation exchange, stop after identification, and record response magic/version/code. Use protocol/vendor specifications and the [IANA service registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml); do not authenticate, enumerate application data, test relaying, or change state.

### Product, CVE, KEV, and lifecycle enrichment

Prefer authenticated inventory/SBOM/package records. Passive fingerprints need multiple independent indicators and a versioned signature catalog. Normalize exact product/version to CPE or package identity, then evaluate vendor/NVD affected ranges and configuration preconditions. Pin all dataset versions. References: [NVD](https://nvd.nist.gov/), [CPE naming](https://csrc.nist.gov/pubs/ir/7695/final), and [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). A hidden or ambiguous version is **indeterminate**, never presumed vulnerable.

### Longitudinal patching analysis

Record first confirmed vulnerable observation, authoritative fix publication, observation gaps, and first confirmed remediated observation. Right-censored/unknown intervals remain explicit. Any cadence metric is internal and versioned; it must not be represented as SSC-equivalent and CVSS bands remain source metadata rather than internal severity.

### External intelligence and internal telemetry

Reputation, C2/malware, attack traffic, breach/credential exposure, ransomware chatter, endpoint versions, and Tor use depend on third-party sensors or internal telemetry. Require provenance, event time, ownership overlap, confidence, expiry, and analyst disposition. Candidate sources include [Tor signed consensus](https://spec.torproject.org/dir-spec/publishing-consensus.html), [abuse.ch](https://abuse.ch/), [Spamhaus](https://www.spamhaus.org/blocklists/), [MISP](https://www.misp-project.org/), [MITRE ATT&CK](https://attack.mitre.org/), and approved internal IDS/EDR/NetFlow. A feed assertion is evidence from that source, not universal truth.

### Typosquat/domain intelligence

Generate deterministic brand variants locally, but existence/activity requires external registration and certificate data. Use [RDAP](https://www.rfc-editor.org/rfc/rfc9082.html), [Certificate Transparency](https://www.rfc-editor.org/rfc/rfc9162.html), DNS, and passive DNS; require brand context and human review. Do not visit, register, or interact with candidate domains.

## Rule-design requirements

1. Use three-valued outcomes: pass/observed, finding, and indeterminate. Never collapse acquisition failure into absence.
2. Bind every rule to an immutable method version, evidence schema version, policy version, and enrichment dataset revision.
3. State asset/path/port/page coverage explicitly; do not claim whole-organization coverage from a sample.
4. Separate observations (for example, service present) from vulnerability assertions (confirmed affected version/configuration).
5. Preserve SSC source severity separately. Do not derive breach risk, threat level, internal severity, scoring relevance, or score impact from it.
6. Redact secrets, cookie values, credential material, contact values, request bodies, and WebSocket payloads; prefer hashes and field classifications.
7. Require human review for defacement, typosquat, hacker-chatter, allegations, and low-confidence fingerprints.
8. Exclude `NOT_REPRODUCIBLE` rows until a credible public/internal evidence contract exists.

## Architecture gaps exposed by the mapping

- HTTP currently captures one representative response and selected headers; it lacks bounded crawl/body analysis and complete header-policy parsing.
- TLS captures certificate time/key/signature basics and TLS 1.0/1.1 probes; it lacks cipher enumeration, full-chain/revocation/OCSP and lifetime policy evidence.
- DNS captures root SPF and DMARC TXT; it lacks full standards parsers, public-suffix processing, DKIM selector input and subdomain policy inventory.
- TCP records only connect success; it lacks protocol-specific safe handshakes and fingerprint confidence.
- No browser/WebSocket, SBOM/inventory, CPE/CVE/KEV, lifecycle, longitudinal analytics, or external-intelligence ingestion contracts exist yet.

## Mapping totals

- Directly testable: 87
- Testable with enrichment: 69
- External data required: 42
- Not reproducible: 4
- Current supported / partial / unsupported: 4 / 115 / 83

The row-level proposed method, exact evidence, rule logic, executor, external data, references, complexity, confidence, notes, and support status are in `SSC_ISSUE_COVERAGE.csv`.
