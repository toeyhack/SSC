"""Wave 5D exact HTTP product identity rules and independent activation."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.catalog_models import CatalogIssueType, CatalogIssueTypeVersion, CatalogSnapshot, CatalogSnapshotItem, SourceTypeEnum
from app.models.rule_models import RuleEngineRule, RuleEngineRuleVersion, RuleSourceTypeEnum, RuleTargetTypeEnum
from app.services.public_exposure_consumers import (
    PINNED_SSC_BASELINE_HASH,
    get_pinned_public_exposure_consumer,
    public_exposure_rule_expression,
    public_exposure_schema_contract,
    resolve_pinned_consumer_issue_versions,
)
from app.services.service_probe_http_product import (
    COUCHDB_IDENTITY_POLICY_VERSION,
    ELASTICSEARCH_IDENTITY_POLICY_VERSION,
    HTTP_PRODUCT_EVIDENCE_SCHEMA_VERSION,
    HTTP_PRODUCT_FRAMEWORK_VERSION,
    HTTP_PRODUCT_POLICY_VERSION,
    MAX_HTTP_PRODUCT_RESPONSE_BYTES,
)


METHOD_VERSION = "ssc-wave5d-http-product-public-exposure-observation.v1"


@dataclass(frozen=True)
class Wave5DRuleSpec:
    issue_key: str
    product: str
    title: str
    remediation: str
    reference: str
    identity_policy_version: str
    primitive: str = "HTTP_EXACT_PRODUCT_IDENTIFICATION"
    target_type: str = "HOST"

    @property
    def rule_key(self) -> str:
        return f"ssc.wave5d.{self.issue_key}"

    @property
    def expression(self) -> dict[str, Any]:
        expression = public_exposure_rule_expression(self.issue_key)
        if expression is None:
            raise Wave5DActivationError(f"{self.issue_key}: public-exposure consumer is absent")
        return expression

    @property
    def evidence_schema(self) -> dict[str, Any]:
        consumer = get_pinned_public_exposure_consumer(self.issue_key)
        if consumer is None:
            raise Wave5DActivationError(f"{self.issue_key}: public-exposure consumer is absent")
        return {
            "schema_version": METHOD_VERSION,
            "framework_version": HTTP_PRODUCT_FRAMEWORK_VERSION,
            "policy_version": HTTP_PRODUCT_POLICY_VERSION,
            "identity_policy_version": self.identity_policy_version,
            "evidence_schema_version": HTTP_PRODUCT_EVIDENCE_SCHEMA_VERSION,
            "primitive": self.primitive,
            "target_type": self.target_type,
            "product": self.product,
            "issue_key": self.issue_key,
            "request_model": "GET_ROOT_ONLY",
            "method": "GET",
            "path": "/",
            "response_body_limit": MAX_HTTP_PRODUCT_RESPONSE_BYTES,
            "semantic_class": "PUBLIC_EXPOSURE_REQUIRED",
            "exact_product_required": True,
            "protocol_identity_is_sufficient": False,
            "product_identity_is_sufficient": False,
            "public_exposure_context": public_exposure_schema_contract(consumer),
            "required_observation": (
                "A complete bounded exact-product root response from an explicitly declared HTTP/HTTPS endpoint, "
                "plus current PUBLIC_EXPOSURE_CONTEXT proving PUBLIC_ROUTABLE and trusted EXTERNAL_PUBLIC vantage."
            ),
            "no_match_boundary": (
                "Product NO_MATCH is limited to a complete conflict-free signature of another reviewed product; "
                "the public-exposure consumer defines no exposure-level NO_MATCH."
            ),
            "indeterminate_boundary": (
                "Authentication challenges, generic or malformed content, transport/TLS failure, incomplete data, "
                "compatible APIs, conflicts, and non-public/unknown/stale exposure context are NOT_ASSESSED."
            ),
            "outcomes": ["MATCH", "INDETERMINATE"],
        }

    @property
    def evidence_requirement(self) -> str:
        return self.evidence_schema["required_observation"]

    @property
    def logic(self) -> str:
        return (
            "Exact-product MATCH is necessary but insufficient. Final MATCH requires PUBLIC_ROUTABLE destination "
            "and trusted EXTERNAL_PUBLIC deployment-manifest vantage through PUBLIC_EXPOSURE_CONTEXT v1; all other "
            "exposure compositions are INDETERMINATE / NOT_ASSESSED."
        )


WAVE5D_RULES = (
    Wave5DRuleSpec(
        "service_couchdb",
        "couchdb",
        "Apache CouchDB Service Observed",
        "Restrict Apache CouchDB exposure to approved protected access paths and maintain it under reviewed controls.",
        "https://docs.couchdb.org/en/stable/api/server/common.html#get--",
        COUCHDB_IDENTITY_POLICY_VERSION,
    ),
    Wave5DRuleSpec(
        "service_elasticsearch",
        "elasticsearch",
        "Elasticsearch Service Observed",
        "Restrict Elasticsearch exposure to approved protected access paths and maintain it under reviewed controls.",
        "https://www.elastic.co/guide/en/elasticsearch/reference/current/rest-api-root.html",
        ELASTICSEARCH_IDENTITY_POLICY_VERSION,
    ),
)
WAVE5D_BY_KEY = {spec.issue_key: spec for spec in WAVE5D_RULES}
WAVE5D_IMPLEMENTED_KEYS = frozenset(WAVE5D_BY_KEY)
WAVE5D_ACTIVE_KEYS: frozenset[str] = frozenset({"service_couchdb", "service_elasticsearch"})
WAVE5D_ACTIVE_RULES = tuple(spec for spec in WAVE5D_RULES if spec.issue_key in WAVE5D_ACTIVE_KEYS)
WAVE5D_ACTIVE_BY_KEY = {spec.issue_key: spec for spec in WAVE5D_ACTIVE_RULES}
WAVE5D_PENDING_RULES = tuple(spec for spec in WAVE5D_RULES if spec.issue_key not in WAVE5D_ACTIVE_KEYS)
WAVE5D_CLOSURE_BLOCKERS: dict[str, tuple[str, ...]] = {}
WAVE5D_PARTIAL_REASONS: dict[str, str] = {}


class Wave5DActivationError(ValueError):
    pass


def activate_wave5d_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    pinned = _resolve_pinned_issue_versions(db)
    consumers = resolve_pinned_consumer_issue_versions(db)
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0, "rules_deactivated": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE5D_ACTIVE_RULES:
        issue = db.execute(select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)).scalar_one_or_none()
        version = db.get(CatalogIssueTypeVersion, issue.current_version_id) if issue and issue.current_version_id else None
        expected = pinned.get(spec.issue_key)
        if (
            issue is None or not issue.is_active or version is None or expected is None
            or version.id != expected.id or version.source_type != SourceTypeEnum.SSC_API
            or consumers.get(spec.issue_key) is None
        ):
            unavailable[spec.issue_key] = "current definition is not the reviewed exact version in the pinned attested SSC_API baseline"
            _deactivate(db, spec.rule_key, counts)
            continue
        rule = db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key == spec.rule_key).with_for_update()).scalar_one_or_none()
        if rule is None:
            rule = RuleEngineRule(stable_key=spec.rule_key, catalog_issue_type_id=issue.id, is_active=True)
            db.add(rule)
            db.flush()
            counts["rules_created"] += 1
        elif rule.catalog_issue_type_id != issue.id:
            raise Wave5DActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
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
        versions = db.execute(select(RuleEngineRuleVersion).where(RuleEngineRuleVersion.rule_id == rule.id)).scalars().all()
        rule_version = next((candidate for candidate in versions if _same_definition(candidate, definition)), None)
        if rule_version is None:
            latest = db.execute(select(func.max(RuleEngineRuleVersion.version_number)).where(RuleEngineRuleVersion.rule_id == rule.id)).scalar()
            rule_version = RuleEngineRuleVersion(rule_id=rule.id, version_number=(latest or 0) + 1, **definition)
            db.add(rule_version)
            db.flush()
            counts["rule_versions_created"] += 1
        rule.current_version_id = rule_version.id
        activated.append(spec.issue_key)
    pending_keys = [spec.rule_key for spec in WAVE5D_PENDING_RULES]
    if pending_keys:
        for rule in db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key.in_(pending_keys)).with_for_update()).scalars():
            if rule.is_active:
                rule.is_active = False
                counts["rules_deactivated"] += 1
    if commit:
        db.commit()
    return {
        **counts,
        "implemented": sorted(WAVE5D_IMPLEMENTED_KEYS),
        "activated": activated,
        "inactive": [spec.issue_key for spec in WAVE5D_PENDING_RULES],
        "blockers": {key: list(value) for key, value in WAVE5D_CLOSURE_BLOCKERS.items()},
        "unavailable": unavailable,
    }


def active_wave5d_mappings(db: Session) -> list[dict[str, Any]]:
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
        spec, expected = WAVE5D_ACTIVE_BY_KEY.get(issue.stable_key), pinned.get(issue.stable_key)
        if (
            spec is None or rule.stable_key != spec.rule_key or expected is None or version.id != expected.id
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
    return sorted(result, key=lambda item: item["issue_key"])


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
            CatalogIssueType.stable_key.in_(WAVE5D_IMPLEMENTED_KEYS),
        )
    ).all()
    return {issue.stable_key: version for issue, version in rows}


def _same_definition(version: RuleEngineRuleVersion, expected: dict[str, Any]) -> bool:
    return all(getattr(version, key) == value for key, value in expected.items())


def _deactivate(db: Session, rule_key: str, counts: dict[str, int]) -> None:
    rule = db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key == rule_key).with_for_update()).scalar_one_or_none()
    if rule is not None and rule.is_active:
        rule.is_active = False
        counts["rules_deactivated"] += 1
