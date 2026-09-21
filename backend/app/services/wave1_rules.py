"""Reviewed SSC Wave 1 evaluator definitions and activation.

These are internal, deterministic reproductions of publicly documented security
conditions.  They are not representations of SSC scoring or proprietary
collection logic.  Activation is allowed only against an exact issue version
that belongs to an attested real SSC_API snapshot.
"""
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.catalog_models import (
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.models.rule_models import (
    RuleEngineRule,
    RuleEngineRuleVersion,
    RuleSourceTypeEnum,
    RuleTargetTypeEnum,
)


METHOD_VERSION = "ssc-wave1-observation.v1"
POLICY_VERSION = "ssc-wave1-security-policy.v1"


@dataclass(frozen=True)
class Wave1RuleSpec:
    issue_key: str
    primitive: str
    evidence_root: str
    title: str
    evidence_requirement: str
    logic: str
    remediation: str
    reference: str

    @property
    def rule_key(self) -> str:
        return f"ssc.wave1.{self.issue_key}"

    @property
    def expression(self) -> dict[str, Any]:
        return {
            "operator": "equals",
            "path": f"{self.evidence_root}.evaluations.{self.issue_key}.matched",
            "value": True,
        }

    @property
    def evidence_schema(self) -> dict[str, Any]:
        return {
            "schema_version": METHOD_VERSION,
            "policy_version": POLICY_VERSION,
            "primitive": self.primitive,
            "issue_key": self.issue_key,
            "required_observation": self.evidence_requirement,
            "positive_logic": self.logic,
            "outcomes": ["MATCH", "NO_MATCH", "INDETERMINATE"],
        }


def _spec(key, primitive, root, title, evidence, logic, remediation, reference):
    return Wave1RuleSpec(key, primitive, root, title, evidence, logic, remediation, reference)


WAVE1_RULES = (
    _spec(
        "csp_no_policy_v2", "HTTP_HEADERS", "http", "Content Security Policy (CSP) Missing",
        "Every declared HTML path was fetched successfully; all enforced CSP header instances and CSP meta elements were parsed and retained.",
        "MATCH when a successfully fetched HTML response has neither a valid enforced CSP header nor a valid CSP meta policy; acquisition or parse failure is INDETERMINATE.",
        "Deploy a valid enforced Content-Security-Policy for every covered HTML response; use a restrictive default-src and explicit directives appropriate to the application.",
        "https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-web-security-testing-guide/",
    ),
    _spec(
        "csp_unsafe_policy_v2", "HTTP_HEADERS", "http", "Content Security Policy Contains 'unsafe-*' Directive",
        "Parsed enforced CSP policies for every declared HTML path, including directive tokens and nonce/hash controls.",
        "MATCH when the effective active-content policy permits unsafe-eval or permits unsafe-inline without a nonce/hash control; malformed policy evidence is INDETERMINATE.",
        "Remove unsafe-eval and replace unsafe-inline with nonces or hashes. Keep a restrictive fallback policy and test all covered pages.",
        "https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-web-security-testing-guide/",
    ),
    _spec(
        "csp_too_broad_v2", "HTTP_HEADERS", "http", "Content Security Policy Contains Broad Directives",
        "Parsed enforced CSP policies for every declared HTML path, preserving all policy instances and effective active-content directives.",
        "MATCH when the effective script/object policy permits a wildcard, an unscoped network scheme, or data: active content under the versioned Wave 1 policy; malformed evidence is INDETERMINATE.",
        "Replace wildcard and scheme-wide active-content sources with the smallest explicit host, nonce, or hash allowlist required by the application.",
        "https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-web-security-testing-guide/",
    ),
    _spec(
        "hsts_incorrect_v2", "HTTP_HEADERS", "http", "Website Does Not Implement HSTS Best Practices",
        "All Strict-Transport-Security header instances from a successful HTTPS response, with parsed max-age, includeSubDomains, preload token, scheme, host, and parse status.",
        "MATCH when HSTS is absent, duplicated, malformed, has max-age below 31536000, or omits includeSubDomains on a covered HTTPS response; HTTP-delivered HSTS is ignored.",
        "Return one valid Strict-Transport-Security header over HTTPS with max-age at least 31536000 and includeSubDomains after confirming all subdomains support HTTPS.",
        "https://www.rfc-editor.org/rfc/rfc6797.html",
    ),
    _spec(
        "x_content_type_options_incorrect_v2", "HTTP_HEADERS", "http", "Website Does Not Implement X-Content-Type-Options Best Practices",
        "All X-Content-Type-Options header instances from each successfully fetched declared response.",
        "MATCH when the header is absent, duplicated, or its sole normalized value is not exactly nosniff; acquisition failure is INDETERMINATE.",
        "Return exactly one X-Content-Type-Options: nosniff header and accurate Content-Type metadata on covered responses.",
        "https://owasp.org/www-project-secure-headers/",
    ),
    _spec(
        "x_frame_options_incorrect_v2", "HTTP_HEADERS", "http", "Site Does Not Use Best Practices Against Embedding",
        "All X-Frame-Options and enforced CSP instances, with parsed frame-ancestors directives, from each declared HTML response.",
        "MATCH when neither a restrictive valid CSP frame-ancestors directive nor exactly one valid X-Frame-Options DENY/SAMEORIGIN value protects the response; malformed evidence is INDETERMINATE.",
        "Set a restrictive CSP frame-ancestors directive (preferred) or one X-Frame-Options DENY/SAMEORIGIN fallback on every covered HTML response.",
        "https://www.w3.org/TR/CSP3/; https://owasp.org/www-project-secure-headers/",
    ),
    _spec(
        "domain_missing_https_v2", "HTTP_REDIRECT", "http", "Site Does Not Enforce HTTPS",
        "Successful HTTP and HTTPS attempts for every declared path, complete normalized redirect hops, terminal response, and HTTPS trust result.",
        "MATCH when HTTP serves terminal content without a permanent same-target upgrade to a reachable trusted HTTPS endpoint, or no trusted HTTPS endpoint is available; incomplete attempts are INDETERMINATE.",
        "Serve the site on a publicly trusted HTTPS certificate and permanently redirect every covered HTTP path directly to its HTTPS equivalent.",
        "https://www.rfc-editor.org/rfc/rfc9110.html; https://www.rfc-editor.org/rfc/rfc6797.html",
    ),
    _spec(
        "insecure_https_redirect_pattern_v2", "HTTP_REDIRECT", "http", "Insecure HTTPS Redirect Pattern",
        "Every normalized hop and emitted Location for successful declared HTTP/HTTPS attempts, including schemes, hosts, ports, status codes, final scheme, and stop reason.",
        "MATCH when an HTTPS hop downgrades to HTTP, a chain oscillates from HTTPS back to HTTP, or an HTTP request reaches terminal content before an HTTPS upgrade.",
        "Remove HTTPS-to-HTTP downgrades and redirect loops; make HTTP upgrade directly and permanently to the final HTTPS location.",
        "https://www.rfc-editor.org/rfc/rfc9110.html",
    ),
    _spec(
        "redirect_chain_contains_http_v2", "HTTP_REDIRECT", "http", "Redirect Chain Contains HTTP",
        "Every normalized hop and emitted Location for successful HTTPS-started redirect chains, including stop reason for out-of-scope or bounded termination.",
        "MATCH when a hop after an HTTPS request uses HTTP or an HTTPS hop emits a Location resolving to HTTP; an ordinary HTTP-only chain does not match.",
        "Keep every hop after HTTPS on HTTPS and replace downgrade Location values with their secure destinations.",
        "https://www.rfc-editor.org/rfc/rfc9110.html",
    ),
    _spec(
        "tlscert_expired", "TLS_CERTIFICATE", "tls", "Certificate Is Expired",
        "Leaf DER SHA-256 fingerprint, notAfter, timezone-aware observation time, and computed expiry state from a completed TLS handshake.",
        "MATCH when leaf notAfter is strictly earlier than observation_time; parse or handshake failure is INDETERMINATE.",
        "Renew and deploy the certificate with the complete intended chain, then verify the served leaf and automate renewal monitoring.",
        "https://www.rfc-editor.org/rfc/rfc5280.html; https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    ),
    _spec(
        "tlscert_self_signed", "TLS_CERTIFICATE", "tls", "Certificate Is Self-Signed",
        "Leaf fingerprint, normalized subject and issuer, self-issued comparison, cryptographic self-signature verification, and explicit local fingerprint allowlist decision.",
        "MATCH only when subject equals issuer, the leaf signature verifies with its own public key, and the fingerprint is not explicitly trusted by the versioned local policy.",
        "Replace the self-signed leaf with a certificate chaining to the organization's approved trust anchor, or explicitly review and allowlist the exact fingerprint for a managed private service.",
        "https://www.rfc-editor.org/rfc/rfc5280.html; https://csrc.nist.gov/pubs/sp/800/52/r2/final",
    ),
    _spec(
        "tlscert_weak_signature", "TLS_CERTIFICATE", "tls", "Certificate Signed With Weak Algorithm",
        "Every served certificate's position, fingerprint, signature OID, hash algorithm, parse status, and Wave 1 cryptographic policy version.",
        "MATCH when any parsed served leaf/intermediate uses MD5 or SHA-1; unknown algorithms or incomplete parsing are INDETERMINATE.",
        "Reissue the affected certificate chain using SHA-256 or stronger algorithms supported by the approved cryptographic policy.",
        "https://csrc.nist.gov/pubs/sp/800/52/r2/final; https://www.rfc-editor.org/rfc/rfc5280.html",
    ),
    _spec(
        "insecure_server_certificate_key_size", "TLS_CERTIFICATE", "tls", "Certificate Key Is Smaller Than Recommended",
        "Leaf fingerprint, public-key algorithm, RSA/DSA bit length or EC curve/bit length, parse status, and Wave 1 policy version.",
        "MATCH for RSA/DSA keys below 2048 bits or EC keys below 224 bits; supported stronger keys do not match and unknown key types are INDETERMINATE.",
        "Reissue the certificate with an approved key, such as RSA 2048 bits or stronger or an approved modern elliptic curve.",
        "https://csrc.nist.gov/pubs/sp/800/52/r2/final; https://www.rfc-editor.org/rfc/rfc5280.html",
    ),
    _spec(
        "tlscert_no_revocation", "TLS_CERTIFICATE", "tls", "Certificate Without Revocation Control",
        "Leaf fingerprint, normalized AIA OCSP and CRL distribution endpoints, self-signature state, lifetime, and extension parse status.",
        "MATCH for a non-self-signed certificate valid longer than seven days when neither an OCSP URI nor CRL distribution URI is present; malformed extensions are INDETERMINATE.",
        "Reissue the certificate with a usable OCSP Authority Information Access URI or CRL Distribution Point, unless an explicitly reviewed short-lived-certificate policy applies.",
        "https://www.rfc-editor.org/rfc/rfc5280.html; https://www.rfc-editor.org/rfc/rfc6960.html",
    ),
)

WAVE1_BY_KEY = {spec.issue_key: spec for spec in WAVE1_RULES}

# Reviewed candidates that intentionally remain partial in this wave.
WAVE1_PARTIAL_REASONS = {
    "cookie_missing_http_only": "Session/authentication purpose requires an approved synthetic authentication flow and reviewed cookie-purpose inventory.",
    "cookie_missing_secure_attribute": "Session/authentication purpose requires an approved synthetic authentication flow and reviewed cookie-purpose inventory.",
    "x_xss_protection_incorrect_v2": "Correctness depends on an approved, versioned legacy-browser estate policy.",
    "redirect_to_insecure_website": "An out-of-scope Location does not prove the terminal destination without authorized or passive redirect evidence.",
    "communication_with_server_certificate_issued_by_blacklisted_country": "Issuer jurisdiction requires a reviewed CA registry and internal denylist.",
    "tlscert_excessive_expiration": "The applicable lifetime maximum requires issuance-date CA/B policy history and certificate applicability data.",
    "tlscert_revoked": "Reliable status requires fresh, signed authoritative OCSP/CRL evidence, which this architecture does not acquire.",
    "uses_go_daddy_infrastructure": "CA attribution requires a versioned reviewed CA/SPKI registry; issuer text is not sufficient.",
}


class Wave1ActivationError(ValueError):
    pass


def activate_wave1_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Idempotently activate reviewed rules for attested real SSC API versions."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(
            CatalogSnapshot.source_type == SourceTypeEnum.SSC_API,
            CatalogSnapshot.is_real_baseline.is_(True),
        )
    ).scalars())
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}

    for spec in WAVE1_RULES:
        issue = db.execute(
            select(CatalogIssueType)
            .where(CatalogIssueType.stable_key == spec.issue_key)
        ).scalar_one_or_none()
        if issue is None or not issue.is_active or issue.current_version_id is None:
            unavailable[spec.issue_key] = "exact issue/current version is absent or inactive"
            continue
        issue_version = db.get(CatalogIssueTypeVersion, issue.current_version_id)
        if (
            issue_version is None
            or issue_version.source_type != SourceTypeEnum.SSC_API
            or issue_version.id not in real_versions
        ):
            unavailable[spec.issue_key] = "current definition is not part of an attested real SSC_API baseline"
            continue

        rule = db.execute(
            select(RuleEngineRule).where(RuleEngineRule.stable_key == spec.rule_key).with_for_update()
        ).scalar_one_or_none()
        if rule is None:
            rule = RuleEngineRule(
                stable_key=spec.rule_key,
                catalog_issue_type_id=issue.id,
                is_active=True,
            )
            db.add(rule)
            db.flush()
            counts["rules_created"] += 1
        elif rule.catalog_issue_type_id != issue.id:
            raise Wave1ActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
        else:
            counts["rules_reused"] += 1
            rule.is_active = True

        definition = {
            "catalog_issue_type_version_id": issue_version.id,
            "name": spec.title,
            "description": f"{spec.evidence_requirement} {spec.logic}",
            "target_type": RuleTargetTypeEnum.HOST,
            "rule_expression": spec.expression,
            "evidence_schema": spec.evidence_schema,
            "remediation": spec.remediation,
            "source_type": RuleSourceTypeEnum.SSC_REFERENCE,
            "source_reference": spec.reference,
        }
        versions = db.execute(
            select(RuleEngineRuleVersion).where(RuleEngineRuleVersion.rule_id == rule.id)
        ).scalars().all()
        version = next((candidate for candidate in versions if _same_definition(candidate, definition)), None)
        if version is None:
            latest = db.execute(
                select(func.max(RuleEngineRuleVersion.version_number)).where(RuleEngineRuleVersion.rule_id == rule.id)
            ).scalar()
            version = RuleEngineRuleVersion(
                rule_id=rule.id,
                version_number=(latest or 0) + 1,
                **definition,
            )
            db.add(version)
            db.flush()
            counts["rule_versions_created"] += 1
        rule.current_version_id = version.id
        activated.append(spec.issue_key)

    if commit:
        db.commit()
    return {**counts, "activated": activated, "unavailable": unavailable}


def _same_definition(version: RuleEngineRuleVersion, expected: dict[str, Any]) -> bool:
    return all(getattr(version, key) == value for key, value in expected.items())


def active_wave1_mappings(db: Session) -> list[dict[str, Any]]:
    """Return only exact, active and currently selected Wave 1 mappings."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(
            CatalogSnapshot.source_type == SourceTypeEnum.SSC_API,
            CatalogSnapshot.is_real_baseline.is_(True),
        )
    ).scalars())
    rows = db.execute(
        select(RuleEngineRule, RuleEngineRuleVersion, CatalogIssueType, CatalogIssueTypeVersion)
        .join(RuleEngineRuleVersion, RuleEngineRule.current_version_id == RuleEngineRuleVersion.id)
        .join(CatalogIssueType, RuleEngineRule.catalog_issue_type_id == CatalogIssueType.id)
        .join(CatalogIssueTypeVersion, RuleEngineRuleVersion.catalog_issue_type_version_id == CatalogIssueTypeVersion.id)
        .where(RuleEngineRule.is_active.is_(True))
    ).all()
    mappings = []
    for rule, rule_version, issue, issue_version in rows:
        spec = WAVE1_BY_KEY.get(issue.stable_key)
        if (
            spec is None
            or rule.stable_key != spec.rule_key
            or issue_version.issue_type_id != issue.id
            or issue_version.source_type != SourceTypeEnum.SSC_API
            or issue_version.id not in real_versions
            or rule_version.rule_expression != spec.expression
            or rule_version.evidence_schema != spec.evidence_schema
        ):
            continue
        mappings.append({
            "issue_key": issue.stable_key,
            "issue_version_id": str(issue_version.id),
            "issue_version_number": issue_version.version_number,
            "ssc_severity": issue_version.ssc_severity,
            "rule_key": rule.stable_key,
            "rule_version_id": str(rule_version.id),
            "rule_version_number": rule_version.version_number,
            "primitive": spec.primitive,
        })
    return sorted(mappings, key=lambda item: item["issue_key"])
