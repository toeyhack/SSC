"""Reviewed Wave 5B.1 LDAP and Oracle service rules."""
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
from app.services.service_probe_database import (
    DATABASE_PROBE_BUILDER_VERSION,
    DATABASE_PROBE_FRAMEWORK_VERSION,
    WAVE5B_SERVICE_POLICY_VERSION,
)
from app.services.service_probes import (
    MAX_SERVICE_PROBE_OUTBOUND_BYTES,
    MAX_SERVICE_PROBE_RESPONSE_BYTES,
)
from app.services.public_exposure_consumers import (
    get_pinned_public_exposure_consumer,
    public_exposure_rule_expression,
    public_exposure_schema_contract,
    resolve_pinned_consumer_issue_versions,
)


METHOD_VERSION = "ssc-wave5b-database-service-observation.v1"
PUBLIC_EXPOSURE_METHOD_VERSION = "ssc-wave5b-database-service-public-exposure-observation.v2"


@dataclass(frozen=True)
class Wave5BRuleSpec:
    issue_key: str
    protocol: str
    title: str
    request_model: str
    match_condition: str
    remediation: str
    reference: str
    primitive: str = "SERVICE_PROTOCOL_IDENTIFICATION"

    @property
    def rule_key(self) -> str:
        return f"ssc.wave5b.{self.issue_key}"

    @property
    def evidence_requirement(self) -> str:
        return (
            f"One explicitly declared TCP endpoint completing the bounded plaintext {self.protocol} exchange with "
            "exact framework, policy, builder and probe versions, compact structural counts, response hash, "
            "correlation result, byte counts, stop state and timestamps; no raw request or response is retained."
        )

    @property
    def no_match_boundary(self) -> str:
        return "Wave 5B.1 defines no deterministic NO_MATCH; wrong, foreign, or arbitrary responses remain INDETERMINATE."

    @property
    def indeterminate_boundary(self) -> str:
        return (
            "Open port alone, connection failure, timeout, reset, peer close, malformed or truncated framing, "
            "response-limit exhaustion, unsupported TLS/transport, arbitrary bytes, or insufficient protocol "
            "semantics are INDETERMINATE."
        )

    @property
    def logic(self) -> str:
        if get_pinned_public_exposure_consumer(self.issue_key) is not None:
            return (
                f"Protocol prerequisite: {self.match_condition} Final MATCH requires the protocol prerequisite plus "
                "PUBLIC_ROUTABLE target address and trusted EXTERNAL_PUBLIC deployment-manifest vantage through "
                "PUBLIC_EXPOSURE_CONTEXT v1. All other exposure compositions are INDETERMINATE / NOT_ASSESSED; "
                "there is no deterministic exposure NO_MATCH."
            )
        return f"{self.match_condition} {self.no_match_boundary} {self.indeterminate_boundary}"

    @property
    def expression(self) -> dict[str, Any]:
        exposure_expression = public_exposure_rule_expression(self.issue_key)
        if exposure_expression is not None:
            return exposure_expression
        return {
            "operator": "equals",
            "path": f"tcp.evaluations.{self.issue_key}.matched",
            "value": True,
        }

    @property
    def evidence_schema(self) -> dict[str, Any]:
        consumer = get_pinned_public_exposure_consumer(self.issue_key)
        schema = {
            "schema_version": PUBLIC_EXPOSURE_METHOD_VERSION if consumer is not None else METHOD_VERSION,
            "framework_version": DATABASE_PROBE_FRAMEWORK_VERSION,
            "policy_version": WAVE5B_SERVICE_POLICY_VERSION,
            "builder_version": DATABASE_PROBE_BUILDER_VERSION,
            "primitive": self.primitive,
            "protocol": self.protocol,
            "issue_key": self.issue_key,
            "request_model": self.request_model,
            "required_observation": self.evidence_requirement,
            "match_condition": self.match_condition,
            "no_match_boundary": self.no_match_boundary,
            "indeterminate_boundary": self.indeterminate_boundary,
            "limits": {
                "response_bytes": MAX_SERVICE_PROBE_RESPONSE_BYTES,
                "outbound_bytes": MAX_SERVICE_PROBE_OUTBOUND_BYTES,
            },
            "tls_mode": "plaintext-only; no implicit TLS, TCPS, StartTLS, or redirect following",
            "outcomes": ["MATCH", "INDETERMINATE"],
        }
        if consumer is not None:
            schema["protocol_identity_requirement"] = self.evidence_requirement
            schema["protocol_match_condition"] = self.match_condition
            schema["protocol_identity_is_sufficient"] = False
            schema["public_exposure_context"] = public_exposure_schema_contract(consumer)
            schema["required_observation"] = (
                f"{self.evidence_requirement} Protocol/service identity is necessary but insufficient; the final SSC "
                "evaluation additionally requires PUBLIC_EXPOSURE_CONTEXT v1."
            )
        return schema


WAVE5B_RULES = (
    Wave5BRuleSpec(
        "service_ldap",
        "LDAPv3 RootDSE base-object search",
        "LDAP Server Accessible",
        "CORRELATED_FIXED_PAYLOAD",
        "MATCH only for a complete definite-length BER sequence with message ID 1, zero or more legal SearchResultEntry/SearchResultReference messages, and a structurally valid final SearchResultDone.",
        "Restrict LDAP exposure to approved clients and require separately reviewed protected and authenticated directory access.",
        "https://www.rfc-editor.org/rfc/rfc4511.html",
    ),
    Wave5BRuleSpec(
        "service_oracle_db",
        "Oracle Net/TNS CONNECT",
        "Oracle Database Server Accessible",
        "ENDPOINT_AWARE_PAYLOAD",
        "MATCH only for one complete structurally valid Oracle Net ACCEPT, REFUSE, or REDIRECT packet; REDIRECT is never followed.",
        "Restrict Oracle Net exposure to approved clients and networks and review listener access controls.",
        "https://docs.oracle.com/en/database/oracle/oracle-database/26/netag/packet-examples.html",
    ),
)
WAVE5B_BY_KEY = {spec.issue_key: spec for spec in WAVE5B_RULES}
WAVE5B_ACTIVE_KEYS = frozenset({"service_ldap", "service_oracle_db"})
WAVE5B_ACTIVE_RULES = tuple(spec for spec in WAVE5B_RULES if spec.issue_key in WAVE5B_ACTIVE_KEYS)
WAVE5B_ACTIVE_BY_KEY = {spec.issue_key: spec for spec in WAVE5B_ACTIVE_RULES}
WAVE5B_PENDING_RULES = tuple(spec for spec in WAVE5B_RULES if spec.issue_key not in WAVE5B_ACTIVE_KEYS)
WAVE5B_PARTIAL_REASONS: dict[str, str] = {}


class Wave5BActivationError(ValueError):
    pass


def activate_wave5b_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Activate only the approved Wave 5B.1 closure set and retire pending rules."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    pinned_consumers = resolve_pinned_consumer_issue_versions(db)
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0, "rules_deactivated": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    pending_rule_keys = [spec.rule_key for spec in WAVE5B_PENDING_RULES]
    if pending_rule_keys:
        pending_rules = db.execute(
            select(RuleEngineRule)
            .where(RuleEngineRule.stable_key.in_(pending_rule_keys))
            .with_for_update()
        ).scalars()
        for rule in pending_rules:
            if rule.is_active:
                rule.is_active = False
                counts["rules_deactivated"] += 1
    for spec in WAVE5B_ACTIVE_RULES:
        issue = db.execute(select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)).scalar_one_or_none()
        if issue is None or not issue.is_active or issue.current_version_id is None:
            unavailable[spec.issue_key] = "exact issue/current version is absent or inactive"
            _deactivate_rule_if_active(db, spec.rule_key, counts)
            continue
        issue_version = db.get(CatalogIssueTypeVersion, issue.current_version_id)
        consumer = get_pinned_public_exposure_consumer(spec.issue_key)
        expected_consumer_version = pinned_consumers.get(spec.issue_key)
        if consumer is not None and (
            issue_version is None or expected_consumer_version is None
            or issue_version.id != expected_consumer_version.id
        ):
            unavailable[spec.issue_key] = "current definition is not the reviewed version in the pinned attested SSC_API baseline"
            _deactivate_rule_if_active(db, spec.rule_key, counts)
            continue
        if consumer is None and (
            issue_version is None or issue_version.source_type != SourceTypeEnum.SSC_API or issue_version.id not in real_versions
        ):
            unavailable[spec.issue_key] = "current definition is not part of an attested real SSC_API baseline"
            _deactivate_rule_if_active(db, spec.rule_key, counts)
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
            raise Wave5BActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
        else:
            rule.is_active = True
            counts["rules_reused"] += 1
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
            version = RuleEngineRuleVersion(rule_id=rule.id, version_number=(latest or 0) + 1, **definition)
            db.add(version)
            db.flush()
            counts["rule_versions_created"] += 1
        rule.current_version_id = version.id
        activated.append(spec.issue_key)
    if commit:
        db.commit()
    return {
        **counts,
        "activated": activated,
        "inactive": [spec.issue_key for spec in WAVE5B_PENDING_RULES],
        "unavailable": unavailable,
    }


def _same_definition(version: RuleEngineRuleVersion, expected: dict[str, Any]) -> bool:
    return all(getattr(version, key) == value for key, value in expected.items())


def _deactivate_rule_if_active(db: Session, rule_key: str, counts: dict[str, int]) -> None:
    rule = db.execute(
        select(RuleEngineRule).where(RuleEngineRule.stable_key == rule_key).with_for_update()
    ).scalar_one_or_none()
    if rule is not None and rule.is_active:
        rule.is_active = False
        counts["rules_deactivated"] += 1


def active_wave5b_mappings(db: Session) -> list[dict[str, Any]]:
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    pinned_consumer_ids = {
        version.id for version in resolve_pinned_consumer_issue_versions(db).values()
    }
    rows = db.execute(
        select(RuleEngineRule, RuleEngineRuleVersion, CatalogIssueType, CatalogIssueTypeVersion)
        .join(RuleEngineRuleVersion, RuleEngineRule.current_version_id == RuleEngineRuleVersion.id)
        .join(CatalogIssueType, RuleEngineRule.catalog_issue_type_id == CatalogIssueType.id)
        .join(CatalogIssueTypeVersion, RuleEngineRuleVersion.catalog_issue_type_version_id == CatalogIssueTypeVersion.id)
        .where(RuleEngineRule.is_active.is_(True))
    ).all()
    mappings = []
    for rule, rule_version, issue, issue_version in rows:
        spec = WAVE5B_ACTIVE_BY_KEY.get(issue.stable_key)
        consumer = get_pinned_public_exposure_consumer(issue.stable_key)
        if (
            spec is None or rule.stable_key != spec.rule_key
            or issue_version.issue_type_id != issue.id
            or issue_version.source_type != SourceTypeEnum.SSC_API
            or issue_version.id not in real_versions
            or (consumer is not None and issue_version.id not in pinned_consumer_ids)
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
