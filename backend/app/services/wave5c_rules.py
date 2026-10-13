"""Wave 5C protocol implementations and reviewed SSC rule activation."""
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
from app.services.public_exposure_consumers import (
    PINNED_SSC_BASELINE_HASH,
    get_pinned_public_exposure_consumer,
    public_exposure_rule_expression,
    public_exposure_schema_contract,
    resolve_pinned_consumer_issue_versions,
)
from app.services.service_probe_framed import (
    FRAMED_PROBE_BUILDER_VERSION,
    FRAMED_PROBE_FRAMEWORK_VERSION,
    WAVE5C_SERVICE_POLICY_VERSION,
)
from app.services.service_probes import (
    MAX_SERVICE_PROBE_OUTBOUND_BYTES,
    MAX_SERVICE_PROBE_RESPONSE_BYTES,
)


METHOD_VERSION = "ssc-wave5c-framed-service-observation.v1"
PUBLIC_EXPOSURE_METHOD_VERSION = "ssc-wave5c-framed-service-public-exposure-observation.v2"


@dataclass(frozen=True)
class Wave5CRuleSpec:
    issue_key: str
    protocol: str
    title: str
    request_model: str
    match_condition: str
    remediation: str
    reference: str
    primitive: str = "SERVICE_PROTOCOL_IDENTIFICATION"
    target_type: str = "HOST"

    @property
    def rule_key(self) -> str:
        return f"ssc.wave5c.{self.issue_key}"

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
        evidence_requirement = (
            "One complete protocol-valid bounded identification exchange on an explicitly declared TCP "
            "endpoint, with compact structural evidence and no raw or optional server content."
        )
        schema = {
            "schema_version": PUBLIC_EXPOSURE_METHOD_VERSION if consumer is not None else METHOD_VERSION,
            "framework_version": FRAMED_PROBE_FRAMEWORK_VERSION,
            "policy_version": WAVE5C_SERVICE_POLICY_VERSION,
            "builder_version": FRAMED_PROBE_BUILDER_VERSION,
            "primitive": self.primitive,
            "target_type": self.target_type,
            "protocol": self.protocol,
            "issue_key": self.issue_key,
            "request_model": self.request_model,
            "required_observation": evidence_requirement,
            "match_condition": self.match_condition,
            "no_match_boundary": "Wave 5C v1 defines no deterministic NO_MATCH.",
            "indeterminate_boundary": (
                "Open TCP alone, timeout, reset, peer close, malformed/truncated/oversized data, response-limit "
                "exhaustion, TLS-only or foreign bytes, and incomplete or ambiguous protocol evidence are INDETERMINATE."
            ),
            "limits": {
                "response_bytes": MAX_SERVICE_PROBE_RESPONSE_BYTES,
                "outbound_bytes": MAX_SERVICE_PROBE_OUTBOUND_BYTES,
            },
            "tls_mode": "plaintext identification only; never continue negotiated TLS or authentication",
            "outcomes": ["MATCH", "INDETERMINATE"],
        }
        if consumer is not None:
            schema["protocol_identity_requirement"] = evidence_requirement
            schema["protocol_match_condition"] = self.match_condition
            schema["protocol_identity_is_sufficient"] = False
            schema["public_exposure_context"] = public_exposure_schema_contract(consumer)
            schema["required_observation"] = (
                f"{evidence_requirement} Protocol/service identity is necessary but insufficient; the final SSC "
                "evaluation additionally requires PUBLIC_EXPOSURE_CONTEXT v1."
            )
        else:
            schema["semantic_class"] = "PROTOCOL_IDENTITY_ONLY"
            schema["protocol_identity_is_sufficient"] = True
        return schema

    @property
    def evidence_requirement(self) -> str:
        return self.evidence_schema["required_observation"]

    @property
    def logic(self) -> str:
        if get_pinned_public_exposure_consumer(self.issue_key) is not None:
            return (
                f"Protocol prerequisite: {self.match_condition} Final MATCH requires the protocol prerequisite plus "
                "PUBLIC_ROUTABLE target address and trusted EXTERNAL_PUBLIC deployment-manifest vantage through "
                "PUBLIC_EXPOSURE_CONTEXT v1. All other exposure compositions are INDETERMINATE / NOT_ASSESSED; "
                "there is no deterministic exposure NO_MATCH."
            )
        return (
            f"{self.match_condition} Protocol identity is the complete applicability predicate; "
            "PUBLIC_EXPOSURE_CONTEXT is not required."
        )


WAVE5C_RULES = (
    Wave5CRuleSpec(
        "minecraft_server",
        "Minecraft Java Server List Ping status",
        "Minecraft Server Accessible",
        "ENDPOINT_AWARE_PAYLOAD",
        "MATCH only for a complete status frame with packet ID zero and bounded strict JSON containing a valid version name and integer protocol.",
        "Restrict unintended Minecraft service exposure and maintain the server and extensions under reviewed security controls.",
        "https://c4k3.github.io/wiki.vg/Server_List_Ping.html",
    ),
    Wave5CRuleSpec(
        "service_pptp",
        "PPTP Start-Control-Connection",
        "PPTP Service Accessible",
        "FIXED_PAYLOAD",
        "MATCH only for a complete legal 156-byte Start-Control-Connection-Reply, including protocol-specific rejection results.",
        "Remove obsolete PPTP or restrict it to approved networks and migrate to a reviewed secure VPN protocol.",
        "https://www.rfc-editor.org/rfc/rfc2637.html",
    ),
    Wave5CRuleSpec(
        "service_rdp",
        "TPKT/X.224 with RDP Negotiation",
        "RDP Service Observed",
        "FIXED_PAYLOAD",
        "MATCH only for a complete X.224 Connection Confirm containing a legal RDP Negotiation Response or Failure; a bare Connection Confirm is INDETERMINATE.",
        "Place RDP behind an approved protected access path and restrict direct exposure to explicitly authorized clients.",
        "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/13757f8f-66db-4273-9d2c-385c33b1e483",
    ),
)
WAVE5C_BY_KEY = {spec.issue_key: spec for spec in WAVE5C_RULES}
WAVE5C_IMPLEMENTED_KEYS = frozenset(WAVE5C_BY_KEY)

WAVE5C_ACTIVE_KEYS: frozenset[str] = frozenset({"minecraft_server", "service_rdp"})
WAVE5C_ACTIVE_RULES = tuple(spec for spec in WAVE5C_RULES if spec.issue_key in WAVE5C_ACTIVE_KEYS)
WAVE5C_ACTIVE_BY_KEY = {spec.issue_key: spec for spec in WAVE5C_ACTIVE_RULES}
WAVE5C_PENDING_RULES = tuple(spec for spec in WAVE5C_RULES if spec.issue_key not in WAVE5C_ACTIVE_KEYS)
WAVE5C_CLOSURE_BLOCKERS = {
    "service_pptp": ("IMPLEMENTED_PENDING_INTEROP",),
}
WAVE5C_PARTIAL_REASONS = {
    "service_pptp": (
        "The bounded PPTP control implementation and PUBLIC_EXPOSURE_CONTEXT consumer semantics are complete, but "
        "real PPTP server interoperability remains pending; the SSC rule is inactive."
    ),
}


class Wave5CActivationError(ValueError):
    pass


def activate_wave5c_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Activate the exact reviewed closure set and retire pending managed rules."""
    pinned_versions = _resolve_wave5c_pinned_issue_versions(db)
    pinned_consumers = resolve_pinned_consumer_issue_versions(db)
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0, "rules_deactivated": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE5C_ACTIVE_RULES:
        issue = db.execute(
            select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)
        ).scalar_one_or_none()
        issue_version = db.get(CatalogIssueTypeVersion, issue.current_version_id) if issue and issue.current_version_id else None
        if issue is None or not issue.is_active or issue_version is None:
            unavailable[spec.issue_key] = "exact issue/current version is absent or inactive"
            _deactivate_rule_if_active(db, spec.rule_key, counts)
            continue
        expected_version = pinned_versions.get(spec.issue_key)
        consumer = get_pinned_public_exposure_consumer(spec.issue_key)
        if (
            expected_version is None or issue_version.id != expected_version.id
            or issue_version.source_type != SourceTypeEnum.SSC_API
            or (consumer is not None and pinned_consumers.get(spec.issue_key) is None)
        ):
            unavailable[spec.issue_key] = (
                "current definition is not the reviewed version in the exact pinned attested SSC_API baseline"
            )
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
            raise Wave5CActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
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

    pending_keys = [spec.rule_key for spec in WAVE5C_PENDING_RULES]
    pending = db.execute(
        select(RuleEngineRule).where(RuleEngineRule.stable_key.in_(pending_keys)).with_for_update()
    ).scalars()
    for rule in pending:
        if rule.is_active:
            rule.is_active = False
            counts["rules_deactivated"] += 1
    if commit:
        db.commit()
    return {
        **counts,
        "implemented": sorted(WAVE5C_IMPLEMENTED_KEYS),
        "activated": activated,
        "inactive": [spec.issue_key for spec in WAVE5C_PENDING_RULES],
        "blockers": {key: list(value) for key, value in WAVE5C_CLOSURE_BLOCKERS.items()},
        "unavailable": unavailable,
    }


def active_wave5c_mappings(db: Session) -> list[dict[str, Any]]:
    pinned_versions = _resolve_wave5c_pinned_issue_versions(db)
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
        spec = WAVE5C_ACTIVE_BY_KEY.get(issue.stable_key)
        consumer = get_pinned_public_exposure_consumer(issue.stable_key)
        expected = pinned_versions.get(issue.stable_key)
        if (
            spec is None or rule.stable_key != spec.rule_key
            or expected is None or issue_version.id != expected.id
            or issue_version.issue_type_id != issue.id
            or issue_version.source_type != SourceTypeEnum.SSC_API
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


def _resolve_wave5c_pinned_issue_versions(db: Session) -> dict[str, CatalogIssueTypeVersion]:
    rows = db.execute(
        select(CatalogIssueType, CatalogIssueTypeVersion)
        .join(CatalogIssueTypeVersion, CatalogIssueTypeVersion.issue_type_id == CatalogIssueType.id)
        .join(CatalogSnapshotItem, CatalogSnapshotItem.issue_type_version_id == CatalogIssueTypeVersion.id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(
            CatalogSnapshot.content_hash == PINNED_SSC_BASELINE_HASH,
            CatalogSnapshot.source_type == SourceTypeEnum.SSC_API,
            CatalogSnapshot.is_real_baseline.is_(True),
            CatalogIssueType.stable_key.in_(WAVE5C_IMPLEMENTED_KEYS),
        )
    ).all()
    return {issue.stable_key: version for issue, version in rows}


def _same_definition(version: RuleEngineRuleVersion, expected: dict[str, Any]) -> bool:
    return all(getattr(version, key) == value for key, value in expected.items())


def _deactivate_rule_if_active(db: Session, rule_key: str, counts: dict[str, int]) -> None:
    rule = db.execute(
        select(RuleEngineRule).where(RuleEngineRule.stable_key == rule_key).with_for_update()
    ).scalar_one_or_none()
    if rule is not None and rule.is_active:
        rule.is_active = False
        counts["rules_deactivated"] += 1
