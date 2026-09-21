"""Reviewed SSC Wave 2 evaluator definitions and exact-version activation."""
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


METHOD_VERSION = "ssc-wave2-observation.v1"
TLS_POLICY_VERSION = "ssc-wave2-tls-policy.v1"
EMAIL_POLICY_VERSION = "ssc-wave2-email-policy.v1"


@dataclass(frozen=True)
class Wave2RuleSpec:
    issue_key: str
    primitive: str
    evidence_root: str
    target_type: RuleTargetTypeEnum
    title: str
    evidence_requirement: str
    logic: str
    remediation: str
    reference: str
    policy_version: str

    @property
    def rule_key(self) -> str:
        return f"ssc.wave2.{self.issue_key}"

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
            "policy_version": self.policy_version,
            "primitive": self.primitive,
            "issue_key": self.issue_key,
            "required_observation": self.evidence_requirement,
            "positive_logic": self.logic,
            "outcomes": ["MATCH", "NO_MATCH", "INDETERMINATE"],
        }


def _tls(key, title, evidence, logic, remediation):
    return Wave2RuleSpec(
        key, "TLS_HANDSHAKE", "tls", RuleTargetTypeEnum.HOST, title, evidence,
        logic, remediation,
        "https://www.rfc-editor.org/rfc/rfc8996.html; https://www.rfc-editor.org/rfc/rfc9325.html; https://csrc.nist.gov/pubs/sp/800/52/r2/final",
        TLS_POLICY_VERSION,
    )


def _email(key, title, evidence, logic, remediation, reference):
    return Wave2RuleSpec(
        key, "EMAIL_SECURITY", "dns", RuleTargetTypeEnum.DOMAIN, title, evidence,
        logic, remediation, reference, EMAIL_POLICY_VERSION,
    )


WAVE2_RULES = (
    _tls(
        "tls_weak_protocol", "Weak TLS Protocol Supported",
        "For every approved TLS port: bounded, version-pinned TLS 1.0, 1.1, 1.2 and 1.3 attempts with offered/negotiated versions, cipher, outcome and error class.",
        "MATCH only when TLS 1.0 or TLS 1.1 completes negotiation; NO_MATCH requires definitive rejection of both weak versions and a successful TLS 1.2 or TLS 1.3 control; otherwise INDETERMINATE.",
        "Disable TLS 1.0 and TLS 1.1, retain TLS 1.2/1.3 with current configurations, and verify every exposed TLS endpoint.",
    ),
    _email(
        "spf_record_missing", "SPF Record Missing",
        "A definitive TXT answer, NODATA or NXDOMAIN for the exact declared domain, preserving joined TXT records and response status.",
        "MATCH when a definitive response contains no record beginning v=spf1; resolver timeout, SERVFAIL or other acquisition error is INDETERMINATE.",
        "Publish exactly one syntactically valid SPF TXT policy for the declared mail domain.",
        "https://www.rfc-editor.org/rfc/rfc7208.html",
    ),
    _email(
        "spf_record_softfail", "SPF Uses Softfail Without Enforcing DMARC",
        "A valid single SPF policy with parsed terminal all mechanism plus a valid effective DMARC policy for the same declared domain.",
        "MATCH when the terminal mechanism is ~all and DMARC is definitively absent or valid with effective p=none; malformed or unavailable SPF/DMARC evidence is INDETERMINATE.",
        "Move from SPF softfail to a reviewed fail policy and deploy an enforcing DMARC policy after monitoring legitimate mail sources.",
        "https://www.rfc-editor.org/rfc/rfc7208.html; https://www.rfc-editor.org/rfc/rfc9989.html",
    ),
    _email(
        "spf_record_wildcard", "SPF Record Synthesized by DNS Wildcard",
        "Two bounded unpredictable subdomain TXT queries beneath the declared domain, preserving names, statuses and normalized records.",
        "MATCH only when both nonce names return equivalent SPF policies, proving wildcard synthesis; two definitive negative answers are NO_MATCH and mixed/error evidence is INDETERMINATE.",
        "Remove wildcard SPF publication and publish policies only at explicitly managed mail domains.",
        "https://www.rfc-editor.org/rfc/rfc7208.html; https://www.rfc-editor.org/rfc/rfc4592.html",
    ),
    _email(
        "dmarc_record_missing", "DMARC Record Missing",
        "A definitive TXT answer, NODATA or NXDOMAIN at _dmarc.<declared-organizational-domain>, retaining every TXT record and parse result.",
        "MATCH when the exact declared organizational domain has no applicable DMARC record; DNS errors are INDETERMINATE and a present malformed record is not classified as missing.",
        "Publish one valid DMARC TXT record at _dmarc.<domain> and begin with a monitored policy before enforcement.",
        "https://www.rfc-editor.org/rfc/rfc9989.html",
    ),
    _email(
        "dmarc_contains_none", "DMARC Policy Is None",
        "The single valid DMARC record at the exact declared organizational domain, parsed tags and effective p policy.",
        "MATCH when the valid applicable policy has p=none; quarantine/reject is NO_MATCH and invalid, multiple or unavailable evidence is INDETERMINATE.",
        "After validating reports and legitimate senders, set DMARC p=quarantine or p=reject with an appropriate rollout percentage.",
        "https://www.rfc-editor.org/rfc/rfc9989.html",
    ),
    _email(
        "subdomain_dmarc_contains_none", "Subdomain DMARC Policy Is None",
        "For every explicitly configured in-scope subdomain: exact _dmarc TXT evidence, declared organizational-domain relation, parsed direct record or inherited sp/p policy.",
        "MATCH when any declared subdomain has effective policy none; NO_MATCH requires every declared subdomain to resolve deterministically to quarantine/reject; absent scope or ambiguity is INDETERMINATE.",
        "Publish enforcing direct subdomain policies or set an enforcing organizational-domain sp policy for every declared subdomain.",
        "https://www.rfc-editor.org/rfc/rfc9989.html",
    ),
)

WAVE2_BY_KEY = {spec.issue_key: spec for spec in WAVE2_RULES}

WAVE2_PARTIAL_REASONS = {
    "tls_ocsp_stapling": "Python's current TLS socket interface does not expose the server's stapled OCSP bytes for cryptographic parsing and freshness/signature validation.",
    "tls_weak_cipher": "The runtime can positively prove acceptance from constrained handshakes, but its OpenSSL provider cannot offer every prohibited legacy suite; a conclusive negative would be a weak proxy.",
    "spf_record_malformed": "The collector parses syntax, multiple records, include/redirect loops and lookup overflow, but does not yet implement every RFC 7208 macro, void-lookup and nested A/MX permanent-error path.",
    "dkim_record_detected": "Selector discovery requires an approved selector inventory or authorized message sample; selectors are not safely enumerable from DNS.",
    "dkim_weak_signature": "The platform has no authorized message/selector evidence from which to verify the signature algorithm and selected key.",
    "dkim_insufficient_key_length": "The platform has no approved selector inventory or authorized message sample, so an exhaustive key-size observation cannot be made.",
}


class Wave2ActivationError(ValueError):
    pass


def activate_wave2_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Idempotently activate Wave 2 rules only for attested SSC_API versions."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0}
    activated, unavailable = [], {}
    for spec in WAVE2_RULES:
        issue = db.execute(select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)).scalar_one_or_none()
        if issue is None or not issue.is_active or issue.current_version_id is None:
            unavailable[spec.issue_key] = "exact issue/current version is absent or inactive"
            continue
        issue_version = db.get(CatalogIssueTypeVersion, issue.current_version_id)
        if issue_version is None or issue_version.source_type != SourceTypeEnum.SSC_API or issue_version.id not in real_versions:
            unavailable[spec.issue_key] = "current definition is not part of an attested real SSC_API baseline"
            continue
        rule = db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key == spec.rule_key).with_for_update()).scalar_one_or_none()
        if rule is None:
            rule = RuleEngineRule(stable_key=spec.rule_key, catalog_issue_type_id=issue.id, is_active=True)
            db.add(rule)
            db.flush()
            counts["rules_created"] += 1
        elif rule.catalog_issue_type_id != issue.id:
            raise Wave2ActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
        else:
            counts["rules_reused"] += 1
            rule.is_active = True
        definition = {
            "catalog_issue_type_version_id": issue_version.id,
            "name": spec.title,
            "description": f"{spec.evidence_requirement} {spec.logic}",
            "target_type": spec.target_type,
            "rule_expression": spec.expression,
            "evidence_schema": spec.evidence_schema,
            "remediation": spec.remediation,
            "source_type": RuleSourceTypeEnum.SSC_REFERENCE,
            "source_reference": spec.reference,
        }
        versions = db.execute(select(RuleEngineRuleVersion).where(RuleEngineRuleVersion.rule_id == rule.id)).scalars().all()
        version = next((candidate for candidate in versions if _same_definition(candidate, definition)), None)
        if version is None:
            latest = db.execute(select(func.max(RuleEngineRuleVersion.version_number)).where(RuleEngineRuleVersion.rule_id == rule.id)).scalar()
            version = RuleEngineRuleVersion(rule_id=rule.id, version_number=(latest or 0) + 1, **definition)
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


def active_wave2_mappings(db: Session) -> list[dict[str, Any]]:
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
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
        spec = WAVE2_BY_KEY.get(issue.stable_key)
        if (spec is None or rule.stable_key != spec.rule_key or issue_version.issue_type_id != issue.id
                or issue_version.source_type != SourceTypeEnum.SSC_API or issue_version.id not in real_versions
                or rule_version.rule_expression != spec.expression or rule_version.evidence_schema != spec.evidence_schema):
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
