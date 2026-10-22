"""Reviewed Wave 3A service-identification rules and exact-version activation."""
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
from app.services.service_probes import SERVICE_PROBE_POLICY_VERSION
from app.services.scan_executors import TCP_CONNECT_POLICY_VERSION
from app.services.public_exposure_consumers import (
    get_pinned_public_exposure_consumer,
    public_exposure_rule_expression,
    public_exposure_schema_contract,
    resolve_pinned_consumer_issue_versions,
)


METHOD_VERSION = "ssc-wave3a-service-observation.v1"
PUBLIC_EXPOSURE_METHOD_VERSION = "ssc-wave3a-service-public-exposure-observation.v2"


@dataclass(frozen=True)
class Wave3ARuleSpec:
    issue_key: str
    protocol: str
    title: str
    match_condition: str
    no_match_boundary: str
    indeterminate_boundary: str
    remediation: str
    reference: str
    primitive: str = "SERVICE_PROTOCOL_IDENTIFICATION"
    evidence_root: str = "tcp"
    policy_version: str = SERVICE_PROBE_POLICY_VERSION
    evidence_requirement_override: str | None = None

    @property
    def rule_key(self) -> str:
        return f"ssc.wave3a.{self.issue_key}"

    @property
    def evidence_requirement(self) -> str:
        if self.evidence_requirement_override is not None:
            return self.evidence_requirement_override
        return (
            f"A declared TCP {self.protocol} probe with bounded connect/read/write budgets, exact adapter and policy "
            "versions, response class/magic/version where available, response hash, stop reason and timestamps."
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
            "policy_version": self.policy_version,
            "primitive": self.primitive,
            "protocol": self.protocol,
            "issue_key": self.issue_key,
            "required_observation": self.evidence_requirement,
            "match_condition": self.match_condition,
            "no_match_boundary": self.no_match_boundary,
            "indeterminate_boundary": self.indeterminate_boundary,
            "outcomes": ["MATCH", "NO_MATCH", "INDETERMINATE"],
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
            schema["outcomes"] = ["MATCH", "INDETERMINATE"]
        return schema


_FOREIGN_NEGATIVE = (
    "NO_MATCH only when the bounded exchange returns a complete, protocol-valid response identified as a different "
    "supported protocol; TCP-open or arbitrary bytes are not negative evidence."
)
_INDETERMINATE = (
    "Timeout, reset, acquisition error, malformed or truncated response, ambiguous banner, unsupported transport, "
    "or incomplete exchange is INDETERMINATE."
)


WAVE3A_RULES = (
    Wave3ARuleSpec(
        "service_vnc", "vnc", "VNC Service Observed",
        "MATCH only for an exact complete RFB 003.003, 003.007, or 003.008 server greeting followed by the bounded client version reply.",
        _FOREIGN_NEGATIVE, _INDETERMINATE,
        "Restrict VNC exposure to approved management networks and require a separately reviewed authenticated access control.",
        "https://www.rfc-editor.org/rfc/rfc6143.html",
    ),
    Wave3ARuleSpec(
        "service_rsync", "rsync", "rsync Service Observed",
        "MATCH only for a complete @RSYNCD major.minor daemon greeting, followed by a bounded client greeting and #exit without module enumeration.",
        _FOREIGN_NEGATIVE, _INDETERMINATE,
        "Restrict rsync daemon exposure and review module access controls; do not expose unnecessary daemon listeners.",
        "https://download.samba.org/pub/rsync/rsync.1",
    ),
    Wave3ARuleSpec(
        "service_redis", "redis", "Redis Service Observed",
        "MATCH only when a bounded RESP PING returns exact +PONG or a protocol-valid Redis NOAUTH/NOPERM response; no authentication follows.",
        _FOREIGN_NEGATIVE, _INDETERMINATE,
        "Bind Redis to approved networks, require access controls, and prevent direct perimeter exposure.",
        "https://redis.io/docs/latest/develop/reference/protocol-spec/",
    ),
    Wave3ARuleSpec(
        "service_socks_proxy", "socks5", "SOCKS Proxy Service Detected",
        "MATCH only when a minimal SOCKS5 no-auth method offer receives an exact two-byte version-5 method-selection response; no connect request follows.",
        _FOREIGN_NEGATIVE, _INDETERMINATE,
        "Remove unintended proxy exposure and restrict approved SOCKS services to authorized clients and destinations.",
        "https://www.rfc-editor.org/rfc/rfc1928.html",
    ),
    Wave3ARuleSpec(
        "service_telnet", "telnet", "Telnet Service Observed",
        "MATCH only when a bounded IAC DO SUPPRESS-GO-AHEAD request receives the corresponding protocol-valid IAC WILL or IAC WONT response.",
        _FOREIGN_NEGATIVE, _INDETERMINATE,
        "Disable Telnet where possible and replace it with an approved encrypted management protocol on restricted networks.",
        "https://www.rfc-editor.org/rfc/rfc854.html",
    ),
    Wave3ARuleSpec(
        "service_smb", "smb2", "SMB Service Observed",
        "MATCH only when a minimal SMB2 negotiate request receives a correctly framed SMB2 negotiate or SMB2 error response with matching command semantics.",
        _FOREIGN_NEGATIVE, _INDETERMINATE,
        "Restrict SMB to approved internal networks, remove perimeter exposure, and enforce current SMB security policy.",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/",
    ),
    Wave3ARuleSpec(
        "open_port", "tcp-connect", "Open Port Discovered",
        "MATCH when at least one explicitly declared approved TCP port completes a connection and current PUBLIC_EXPOSURE_CONTEXT proves a PUBLIC_ROUTABLE destination observed from a trusted EXTERNAL_PUBLIC vantage.",
        "The raw connect primitive returns NO_MATCH only when every declared port produces a pinned-destination connection refusal; public-exposure composition remains positive-only.",
        "Timeout, filtering, network/host unreachable, transport failure, absent or invalid declared scope, non-public address, unknown/internal vantage, wrong evidence source, or stale exposure policy is INDETERMINATE / NOT_ASSESSED.",
        "Disable unnecessary listeners or restrict them to explicitly approved source networks.",
        "SSC_API Golden metadata; https://www.rfc-editor.org/rfc/rfc9293.html",
        primitive="TCP_CONNECT_REACHABILITY",
        policy_version=TCP_CONNECT_POLICY_VERSION,
        evidence_requirement_override=(
            "A bounded ordinary TCP connect to no more than ten explicitly declared approved ports on the pinned target, "
            "retaining only port, stable connect outcome, and elapsed milliseconds; no application bytes are sent or read."
        ),
    ),
)

WAVE3A_BY_KEY = {spec.issue_key: spec for spec in WAVE3A_RULES}


class Wave3AActivationError(ValueError):
    pass


def activate_wave3a_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Idempotently activate Wave 3A only for attested exact SSC_API versions."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    pinned_consumers = resolve_pinned_consumer_issue_versions(db)
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0, "rules_deactivated": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE3A_RULES:
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
        rule = db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key == spec.rule_key).with_for_update()).scalar_one_or_none()
        if rule is None:
            rule = RuleEngineRule(stable_key=spec.rule_key, catalog_issue_type_id=issue.id, is_active=True)
            db.add(rule)
            db.flush()
            counts["rules_created"] += 1
        elif rule.catalog_issue_type_id != issue.id:
            raise Wave3AActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
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


def _deactivate_rule_if_active(db: Session, rule_key: str, counts: dict[str, int]) -> None:
    rule = db.execute(
        select(RuleEngineRule).where(RuleEngineRule.stable_key == rule_key).with_for_update()
    ).scalar_one_or_none()
    if rule is not None and rule.is_active:
        rule.is_active = False
        counts["rules_deactivated"] += 1


def active_wave3a_mappings(db: Session) -> list[dict[str, Any]]:
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
        spec = WAVE3A_BY_KEY.get(issue.stable_key)
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
