"""Wave 5E bounded DNS service identity rule and exact activation."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.catalog_models import (
    CatalogFactor,
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
from app.services.public_exposure_consumers import (
    PINNED_SSC_BASELINE_HASH,
    get_pinned_public_exposure_consumer,
    public_exposure_rule_expression,
    public_exposure_schema_contract,
    resolve_pinned_consumer_issue_versions,
)
from app.services.service_probe_dns import (
    DNS_QUERY_POLICY_VERSION,
    DNS_SERVICE_EVIDENCE_SCHEMA_VERSION,
    DNS_SERVICE_FRAMEWORK_VERSION,
    DNS_SERVICE_POLICY_VERSION,
    DNS_SERVICE_REQUEST_SHAPE,
    DNS_SERVICE_TOTAL_DEADLINE_SECONDS,
    MAX_DNS_SERVICE_ENDPOINTS,
    MAX_DNS_TCP_RESPONSE_BYTES,
    MAX_DNS_UDP_RESPONSE_BYTES,
)


METHOD_VERSION = "ssc-wave5e-dns-service-public-exposure-observation.v1"
PINNED_SERVICE_DNS_ISSUE_VERSION_ID = "9f512eaa-08d1-4441-86de-170c1f755f82"


@dataclass(frozen=True)
class Wave5ERuleSpec:
    issue_key: str = "service_dns"
    title: str = "DNS Server Accessible"
    remediation: str = (
        "Restrict DNS service exposure to approved protected access paths and maintain it under reviewed controls."
    )
    reference: str = "https://www.rfc-editor.org/rfc/rfc1035.html"
    primitive: str = "DNS_SERVICE_PROTOCOL_IDENTIFICATION"
    target_type: str = "HOST"

    @property
    def rule_key(self) -> str:
        return "ssc.wave5e.service_dns"

    @property
    def expression(self) -> dict[str, Any]:
        expression = public_exposure_rule_expression(self.issue_key)
        if expression is None:
            raise Wave5EActivationError("service_dns: public-exposure consumer is absent")
        return expression

    @property
    def evidence_schema(self) -> dict[str, Any]:
        consumer = get_pinned_public_exposure_consumer(self.issue_key)
        if consumer is None:
            raise Wave5EActivationError("service_dns: public-exposure consumer is absent")
        return {
            "schema_version": METHOD_VERSION,
            "framework_version": DNS_SERVICE_FRAMEWORK_VERSION,
            "policy_version": DNS_SERVICE_POLICY_VERSION,
            "query_policy_version": DNS_QUERY_POLICY_VERSION,
            "evidence_schema_version": DNS_SERVICE_EVIDENCE_SCHEMA_VERSION,
            "primitive": self.primitive,
            "target_type": self.target_type,
            "issue_key": self.issue_key,
            "request_shape": DNS_SERVICE_REQUEST_SHAPE,
            "semantic_class": "PUBLIC_EXPOSURE_REQUIRED",
            "protocol_identity_is_necessary": True,
            "protocol_identity_is_sufficient": False,
            "recursion_required": False,
            "authoritative_response_required": False,
            "max_declared_endpoints": MAX_DNS_SERVICE_ENDPOINTS,
            "udp_response_limit": MAX_DNS_UDP_RESPONSE_BYTES,
            "tcp_response_limit": MAX_DNS_TCP_RESPONSE_BYTES,
            "total_deadline_seconds": DNS_SERVICE_TOTAL_DEADLINE_SECONDS,
            "public_exposure_context": public_exposure_schema_contract(consumer),
            "required_observation": (
                "A complete, bounded, correlated DNS response to the fixed RD=0 A/IN identity query from an "
                "explicitly declared UDP or TCP endpoint, plus current PUBLIC_EXPOSURE_CONTEXT proving a "
                "PUBLIC_ROUTABLE pinned destination and trusted EXTERNAL_PUBLIC deployment-manifest vantage."
            ),
            "no_match_boundary": (
                "Wave 5E defines neither deterministic protocol NO_MATCH nor exposure NO_MATCH; an open port, "
                "absence, transport failure, or untrusted/non-public exposure context is NOT_ASSESSED."
            ),
            "outcomes": ["MATCH", "INDETERMINATE"],
        }

    @property
    def evidence_requirement(self) -> str:
        return self.evidence_schema["required_observation"]

    @property
    def logic(self) -> str:
        return (
            "DNS protocol identity is necessary but insufficient. Final MATCH requires PUBLIC_ROUTABLE pinned "
            "destination and trusted EXTERNAL_PUBLIC deployment-manifest vantage through PUBLIC_EXPOSURE_CONTEXT; "
            "all other protocol or exposure states are INDETERMINATE / NOT_ASSESSED."
        )


WAVE5E_RULES = (Wave5ERuleSpec(),)
WAVE5E_BY_KEY = {spec.issue_key: spec for spec in WAVE5E_RULES}
WAVE5E_ACTIVE_RULES = WAVE5E_RULES
WAVE5E_ACTIVE_BY_KEY = WAVE5E_BY_KEY


class Wave5EActivationError(ValueError):
    pass


def activate_wave5e_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    pinned = _resolve_pinned_issue_versions(db)
    consumers = resolve_pinned_consumer_issue_versions(db)
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0, "rules_deactivated": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE5E_RULES:
        issue = db.execute(
            select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)
        ).scalar_one_or_none()
        version = db.get(CatalogIssueTypeVersion, issue.current_version_id) if issue and issue.current_version_id else None
        expected = pinned.get(spec.issue_key)
        factor = db.get(CatalogFactor, issue.factor_id) if issue is not None else None
        exact = (
            issue is not None
            and issue.is_active
            and version is not None
            and expected is not None
            and version.id == expected.id
            and str(version.id) == PINNED_SERVICE_DNS_ISSUE_VERSION_ID
            and version.version_number == 1
            and version.name == "DNS Server Accessible"
            and version.ssc_severity == "medium"
            and factor is not None
            and factor.code == "network_security"
            and version.source_type == SourceTypeEnum.SSC_API
            and consumers.get(spec.issue_key) is not None
        )
        if not exact:
            unavailable[spec.issue_key] = (
                "current definition is not exact issue-version 9f512eaa-08d1-4441-86de-170c1f755f82 "
                "in the pinned attested SSC_API baseline"
            )
            _deactivate(db, spec.rule_key, counts)
            continue
        rule = db.execute(
            select(RuleEngineRule).where(RuleEngineRule.stable_key == spec.rule_key).with_for_update()
        ).scalar_one_or_none()
        if rule is None:
            rule = RuleEngineRule(stable_key=spec.rule_key, catalog_issue_type_id=issue.id, is_active=True)
            db.add(rule)
            db.flush()
            counts["rules_created"] += 1
        elif rule.catalog_issue_type_id != issue.id:
            raise Wave5EActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
        else:
            rule.is_active = True
            counts["rules_reused"] += 1
        definition = {
            "catalog_issue_type_version_id": version.id,
            "name": spec.title,
            "description": spec.evidence_schema["required_observation"],
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
        rule_version = next((candidate for candidate in versions if _same_definition(candidate, definition)), None)
        if rule_version is None:
            latest = db.execute(
                select(func.max(RuleEngineRuleVersion.version_number)).where(RuleEngineRuleVersion.rule_id == rule.id)
            ).scalar()
            rule_version = RuleEngineRuleVersion(rule_id=rule.id, version_number=(latest or 0) + 1, **definition)
            db.add(rule_version)
            db.flush()
            counts["rule_versions_created"] += 1
        rule.current_version_id = rule_version.id
        activated.append(spec.issue_key)
    if commit:
        db.commit()
    return {**counts, "implemented": ["service_dns"], "activated": activated, "inactive": [], "unavailable": unavailable}


def active_wave5e_mappings(db: Session) -> list[dict[str, Any]]:
    pinned = _resolve_pinned_issue_versions(db)
    consumer_ids = {version.id for version in resolve_pinned_consumer_issue_versions(db).values()}
    rows = db.execute(
        select(RuleEngineRule, RuleEngineRuleVersion, CatalogIssueType, CatalogIssueTypeVersion)
        .join(RuleEngineRuleVersion, RuleEngineRule.current_version_id == RuleEngineRuleVersion.id)
        .join(CatalogIssueType, RuleEngineRule.catalog_issue_type_id == CatalogIssueType.id)
        .join(CatalogIssueTypeVersion, RuleEngineRuleVersion.catalog_issue_type_version_id == CatalogIssueTypeVersion.id)
        .where(RuleEngineRule.is_active.is_(True))
    ).all()
    result = []
    for rule, rule_version, issue, version in rows:
        spec, expected = WAVE5E_ACTIVE_BY_KEY.get(issue.stable_key), pinned.get(issue.stable_key)
        if (
            spec is None or rule.stable_key != spec.rule_key or expected is None or version.id != expected.id
            or str(version.id) != PINNED_SERVICE_DNS_ISSUE_VERSION_ID
            or version.issue_type_id != issue.id or version.source_type != SourceTypeEnum.SSC_API
            or version.id not in consumer_ids or rule_version.rule_expression != spec.expression
            or rule_version.evidence_schema != spec.evidence_schema
        ):
            continue
        result.append({
            "issue_key": issue.stable_key,
            "issue_version_id": str(version.id),
            "issue_version_number": version.version_number,
            "ssc_severity": version.ssc_severity,
            "rule_key": rule.stable_key,
            "rule_version_id": str(rule_version.id),
            "rule_version_number": rule_version.version_number,
            "primitive": spec.primitive,
        })
    return result


def _resolve_pinned_issue_versions(db: Session) -> dict[str, CatalogIssueTypeVersion]:
    rows = db.execute(
        select(CatalogIssueType, CatalogIssueTypeVersion)
        .join(CatalogIssueTypeVersion, CatalogIssueTypeVersion.issue_type_id == CatalogIssueType.id)
        .join(CatalogSnapshotItem, CatalogSnapshotItem.issue_type_version_id == CatalogIssueTypeVersion.id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(
            CatalogSnapshot.content_hash == PINNED_SSC_BASELINE_HASH,
            CatalogSnapshot.source_type == SourceTypeEnum.SSC_API,
            CatalogSnapshot.is_real_baseline.is_(True),
            CatalogIssueType.stable_key == "service_dns",
            CatalogIssueTypeVersion.id == PINNED_SERVICE_DNS_ISSUE_VERSION_ID,
        )
    ).all()
    return {issue.stable_key: version for issue, version in rows}


def _same_definition(version: RuleEngineRuleVersion, expected: dict[str, Any]) -> bool:
    return all(getattr(version, key) == value for key, value in expected.items())


def _deactivate(db: Session, rule_key: str, counts: dict[str, int]) -> None:
    rule = db.execute(
        select(RuleEngineRule).where(RuleEngineRule.stable_key == rule_key).with_for_update()
    ).scalar_one_or_none()
    if rule is not None and rule.is_active:
        rule.is_active = False
        counts["rules_deactivated"] += 1
