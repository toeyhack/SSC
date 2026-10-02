# Wave 3B internal risk calibration approval record

**Status:** approved and implemented in internal calibration v1.1 on 2026-10-02. **Scope:** only the seven Wave 3B `SUPPORTED` HTTP-content issue keys listed below. The original 27-key v1.0 calibration in [Internal risk calibration V1](INTERNAL_RISK_CALIBRATION_V1.md) remains unchanged. The registry and companion V1 CSV are the implementation sources of truth; this document preserves the Wave 3B decision rationale.

This calibration uses the existing internal model without modification: `HIGH = 15`, `MEDIUM = 7`, `LOW = 2`, and `UNKNOWN = 0`. SSC severity is retained as vendor metadata and is not an input to the internal decision. Issues absent from the explicit registry continue to resolve to `UNKNOWN`, `affects_score=false`, and zero score impact through the existing fail-closed behavior.

The decision unit is the exact deterministic `MATCH` currently documented for each issue. A `MATCH` does not inherit facts that the evaluator does not establish. In particular, it does not by itself prove compromise, malicious modification, sensitive data, weak authentication, successful protocol use, or a vulnerable SOAP operation. `LOW` is used only where the MATCH itself establishes a credible but indirect exposure or hardening weakness. `UNKNOWN` is retained where the observed condition can be ordinary or intentional and additional evidence is required before a stable breach-risk penalty is justified.

## A. Approved decisions

| Exact SSC issue key | SSC title | Factor | SSC severity | Pre-v1.1 internal risk | Pre-v1.1 `affects_score` | Approved internal risk | Approved `affects_score` | Expected penalty for one qualifying MATCH |
|---|---|---|---|---|---:|---|---:|---:|
| `unsafe_sri_v2` | Unsafe Implementation Of Subresource Integrity | `application_security` | high | UNKNOWN | false | LOW | true | 2 factor points |
| `insecure_ftp` | Non-standard links detected: Unsafe File Transfer Protocol | `application_security` | medium | UNKNOWN | false | LOW | true | 2 factor points |
| `contact_information_detected` | Non-standard links detected: Contact information displayed | `application_security` | low | UNKNOWN | false | UNKNOWN | false | 0 |
| `local_file_path_exposed_via_url_scheme` | Non-standard links detected: Local file path exposed | `application_security` | low | UNKNOWN | false | LOW | true | 2 factor points |
| `server_error` | Server error detected | `application_security` | low | UNKNOWN | false | UNKNOWN | false | 0 |
| `links_to_insecure_website` | Site links to insecure websites | `application_security` | low | UNKNOWN | false | LOW | true | 2 factor points |
| `service_soap` | SOAP Server Accessible | `network_security` | medium | UNKNOWN | false | UNKNOWN | false | 0 |

The expected penalty is the finding's factor deduction under the unchanged model. It assumes an OPEN finding backed by the exact-version deterministic MATCH, `affects_score=true`, no prior same-issue-version/target deduction in the run, and room below the factor's 100-point deduction cap. It is not an SSC penalty and does not state an overall-score change.

### `unsafe_sri_v2`

- **Practical security impact:** Missing, invalid, disallowed, or mismatching integrity metadata removes or defeats a browser control intended to reject unexpected script or stylesheet bytes. If a referenced resource is maliciously substituted, script can execute in the page's origin context and stylesheet changes can manipulate presentation. A digest mismatch can also result from benign deployment drift rather than attack.
- **Preconditions for meaningful exploitation:** The resource must be modified or substituted, the altered resource must be delivered and applied by a client, and the change must have security-relevant behavior. Third-party supply-chain compromise is one possible precondition, but a MATCH does not establish that the resource is third-party or compromised; the current evaluator also covers same-origin referenced scripts and stylesheets.
- **Does MATCH alone prove a security weakness?** Yes, but only a defense-in-depth hardening weakness: the expected integrity control is absent, unusable, or inconsistent. It does not prove malicious content, an exploitable injection path, supply-chain compromise, or successful script substitution.
- **Primary character:** hardening.
- **Rationale:** `LOW`, scoring, is proportionate to a real integrity-control gap whose breach impact remains conditional. `HIGH` would overstate the evidence because SSC's high severity is metadata and the MATCH does not prove compromise. A single qualifying MATCH should deduct 2 factor points.

### `insecure_ftp`

- **Practical security impact:** Public HTML references an `ftp:` destination. Classic FTP does not provide transport confidentiality or authenticated content integrity, so credentials or transferred content could be observed or modified when a compatible client actually uses the reference. The scanner never follows the destination.
- **Preconditions for meaningful exploitation:** A user or client must support and follow the FTP reference; a relevant transfer must occur; and an attacker must be able to observe or alter the network path or control the destination. Material impact further depends on credentials, sensitive files, or trusted executable content being transferred.
- **Does MATCH alone prove a security weakness?** Yes, at the reference/hardening level: externally served content directs a client toward an insecure transfer scheme. It does not prove that the link works, is followed, carries sensitive data, or has been intercepted.
- **Primary character:** hardening.
- **Rationale:** `LOW`, scoring, reflects a concrete but indirect insecure-protocol reference. The exact observation is weaker than a demonstrated cleartext credential or file transfer, so `MEDIUM` is not justified. A single qualifying MATCH should deduct 2 factor points.

### `contact_information_detected`

- **Practical security impact:** A declared HTML page contains an `href` using `mailto:`, `tel:`, `sms:`, `whatsapp:`, or `viber:`. This can make an address or contact route easier to harvest for spam, phishing, or social engineering, but it is also normal and intentional on many public sites.
- **Preconditions for meaningful exploitation:** The contact value must identify a person or privileged business function, be unintended or sensitive, and be used in a successful abuse scenario. A contact link alone supplies neither a secret nor a compromise path.
- **Does MATCH alone prove a security weakness?** No. It proves only the configured contact URI scheme on a declared page, with the contact value retained only as a hash in evidence.
- **Primary character:** exposure.
- **Rationale:** `UNKNOWN`, non-scoring, avoids penalizing ordinary public contact functionality without context about sensitivity, intent, or abuse. A qualifying MATCH should remain visible and deduct 0 points.

### `local_file_path_exposed_via_url_scheme`

- **Practical security impact:** Public HTML contains a `file:` URL. This may disclose local naming or path structure and indicates an inappropriate or broken resource reference. In a separate vulnerable client or application context, the reference could help target local resources, but the scanner does not follow it and does not demonstrate file access.
- **Preconditions for meaningful exploitation:** The exposed path must contain useful environmental information or identify a valuable local resource, and meaningful file access requires a client or application that permits the relevant local-file interaction or an additional file-read/path-handling weakness.
- **Does MATCH alone prove a security weakness?** Yes, at the low-level exposure/misconfiguration boundary: an externally served document contains a local-file reference. It does not prove that the path is sensitive, exists on a client, can be read, or enables code execution.
- **Primary character:** exposure.
- **Rationale:** `LOW`, scoring, reflects concrete disclosure of a local-resource reference while recognizing that practical exploitation requires additional conditions. A single qualifying MATCH should deduct 2 factor points.

### `server_error`

- **Practical security impact:** The same declared URL returned an HTTP 5xx status on both bounded attempts. This establishes a repeatable server-side failure and possible availability or quality concern. The observation does not establish stack-trace disclosure, attacker-controlled failure, denial-of-service amplification, memory corruption, or another security flaw.
- **Preconditions for meaningful exploitation:** Security impact requires additional evidence such as sensitive error content, a reliably attacker-controlled trigger, resource exhaustion, an authorization bypass, or an underlying exploitable defect. Mere reproducibility is insufficient.
- **Does MATCH alone prove a security weakness?** No. It proves a reproducible HTTP error response, not its cause or security consequence.
- **Primary character:** hardening.
- **Rationale:** `UNKNOWN`, non-scoring, keeps operational failure visible without treating availability symptoms as breach risk absent a security-relevant cause or effect. A qualifying MATCH should deduct 0 points.

### `links_to_insecure_website`

- **Practical security impact:** A covered HTML URL resolves to `http:`. If a browser or other client retrieves or follows it, an on-path attacker may observe or modify the unauthenticated HTTP exchange. Depending on the element, the URL may be only a navigation link or may reference active/passive page content; the scanner does not follow the destination.
- **Preconditions for meaningful exploitation:** A client must use the HTTP reference, the destination must remain available over HTTP without an effective protected upgrade, and an attacker must have a suitable network position or control the destination. Greater impact requires trusted active content, credentials, sensitive data, or user action.
- **Does MATCH alone prove a security weakness?** Yes, at the insecure-reference/hardening level. It does not prove that the URL is reachable, followed, security-sensitive, modified, or used to compromise the assessed site.
- **Primary character:** hardening.
- **Rationale:** `LOW`, scoring, captures a concrete loss of transport assurance if the reference is used while avoiding an unsupported claim of exploit or compromise. A single qualifying MATCH should deduct 2 factor points.

### `service_soap`

- **Practical security impact:** A declared authorized endpoint returned a parseable SOAP 1.1/1.2 Envelope or WSDL document with a SOAP binding. This confirms a SOAP-facing application surface, which may expose operations and XML-processing code, but SOAP is a protocol and not itself a vulnerability.
- **Preconditions for meaningful exploitation:** The service must expose a dangerous or vulnerable operation, weak or missing authorization, unsafe XML processing, sensitive data, or a vulnerable implementation. An attacker must also be able to reach and invoke the relevant behavior; none of these conditions is established by the MATCH.
- **Does MATCH alone prove a security weakness?** No. It proves protocol semantics at an accessible declared path, not anonymous operation access, vulnerable parsing, successful method invocation, or data exposure.
- **Primary character:** exposure.
- **Rationale:** `UNKNOWN`, non-scoring, is consistent with retaining protocol-only observations when access controls and callable behavior are unknown. A qualifying MATCH should remain visible and deduct 0 points.

## B. Counts by approved internal risk

| Internal risk | Count |
|---|---:|
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 4 |
| UNKNOWN | 3 |
| **Total** | **7** |

## C. Approved score-relevance counts

| `affects_score` | Count |
|---|---:|
| true | 4 |
| false | 3 |
| **Total** | **7** |

## D. Approved internal risk differs from SSC severity

Five decisions differ from the SSC severity label:

| Exact SSC issue key | SSC severity | Approved internal risk |
|---|---|---|
| `unsafe_sri_v2` | high | LOW |
| `insecure_ftp` | medium | LOW |
| `contact_information_detected` | low | UNKNOWN |
| `server_error` | low | UNKNOWN |
| `service_soap` | medium | UNKNOWN |

The matching `low`/`LOW` labels for `local_file_path_exposed_via_url_scheme` and `links_to_insecure_website` are independent internal judgments, not automatic mappings.

## E. Approved as UNKNOWN

Three keys should remain `UNKNOWN` and `affects_score=false`: `contact_information_detected`, `server_error`, and `service_soap`. Each MATCH is useful evidence, but it does not establish enough security context for a stable breach-risk penalty.

## F. Recommendation for `unsafe_sri_v2`

Adopt `LOW`, `affects_score=true`, with the existing 2-point LOW factor deduction for one qualifying MATCH. The MATCH proves an SRI control gap or inconsistency, not a compromised resource. Escalation to a higher risk would require separate evidence such as confirmed unauthorized resource modification, a compromised third-party delivery path, or malicious bytes executed in a security-relevant page context. SSC's `high` severity must not drive that escalation.

## G. Prior calibration remains unchanged

Calibration v1.1 does not edit, supersede, or reinterpret any of the 27 approved v1.0 decisions, their 0 HIGH / 6 MEDIUM / 17 LOW / 4 UNKNOWN distribution, or their 23 scoring / 4 non-scoring distribution. It adds only the seven reviewed registry entries and associated documentation/tests. It changes no scoring configuration, taxonomy, scanner, migration, or evidence behavior. Missing entries retain the existing fail-closed resolution.
