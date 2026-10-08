"""Wave 5C protocol implementations and independently gated SSC rules.

The current repository has no authoritative contract proving both a
public-routable target and an approved external scan vantage.  Consequently
all Wave 5C SSC rules remain inactive even when protocol identification
succeeds.
"""
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.catalog_models import (
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.models.rule_models import RuleEngineRule, RuleEngineRuleVersion
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
        return {
            "operator": "equals",
            "path": f"tcp.evaluations.{self.issue_key}.matched",
            "value": True,
        }

    @property
    def evidence_schema(self) -> dict[str, Any]:
        return {
            "schema_version": METHOD_VERSION,
            "framework_version": FRAMED_PROBE_FRAMEWORK_VERSION,
            "policy_version": WAVE5C_SERVICE_POLICY_VERSION,
            "builder_version": FRAMED_PROBE_BUILDER_VERSION,
            "primitive": self.primitive,
            "target_type": self.target_type,
            "protocol": self.protocol,
            "issue_key": self.issue_key,
            "request_model": self.request_model,
            "required_observation": (
                "One complete protocol-valid bounded identification exchange on an explicitly declared TCP "
                "endpoint, with compact structural evidence and no raw or optional server content."
            ),
            "required_exposure_context": (
                "Authoritative proof that the target is public-routable/Internet-facing and that the observation "
                "came from an approved external/public scan vantage."
            ),
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

# Deliberately empty: the repository has no authoritative public-target plus
# external-vantage context.  Protocol MATCH alone cannot activate these SSC
# semantics.
WAVE5C_ACTIVE_KEYS: frozenset[str] = frozenset()
WAVE5C_ACTIVE_RULES = tuple(spec for spec in WAVE5C_RULES if spec.issue_key in WAVE5C_ACTIVE_KEYS)
WAVE5C_ACTIVE_BY_KEY = {spec.issue_key: spec for spec in WAVE5C_ACTIVE_RULES}
WAVE5C_PENDING_RULES = tuple(spec for spec in WAVE5C_RULES if spec.issue_key not in WAVE5C_ACTIVE_KEYS)
WAVE5C_CLOSURE_BLOCKERS = {
    "minecraft_server": ("IMPLEMENTED_PENDING_EXPOSURE_CONTEXT",),
    "service_pptp": ("IMPLEMENTED_PENDING_EXPOSURE_CONTEXT", "IMPLEMENTED_PENDING_INTEROP"),
    "service_rdp": ("IMPLEMENTED_PENDING_EXPOSURE_CONTEXT",),
}
WAVE5C_PARTIAL_REASONS = {
    "minecraft_server": (
        "The bounded Java status implementation and real vanilla-server interoperability are complete, but the "
        "repository has no authoritative public-target plus approved external-vantage context; the SSC rule is inactive."
    ),
    "service_pptp": (
        "The bounded PPTP control implementation and deterministic fixtures are complete, but real PPTP server "
        "interoperability and authoritative public-target plus approved external-vantage context are both pending; "
        "the SSC rule is inactive."
    ),
    "service_rdp": (
        "The bounded RDP negotiation implementation and real xrdp interoperability are complete, but the repository "
        "has no authoritative public-target plus approved external-vantage context; the SSC rule is inactive."
    ),
}


def activate_wave5c_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Reconcile Wave 5C safely; no key is closure-approved for activation."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    unavailable: dict[str, str] = {}
    for spec in WAVE5C_RULES:
        issue = db.execute(
            select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)
        ).scalar_one_or_none()
        issue_version = db.get(CatalogIssueTypeVersion, issue.current_version_id) if issue and issue.current_version_id else None
        if issue is None or not issue.is_active or issue_version is None:
            unavailable[spec.issue_key] = "exact issue/current version is absent or inactive"
        elif issue_version.source_type != SourceTypeEnum.SSC_API or issue_version.id not in real_versions:
            unavailable[spec.issue_key] = "current definition is not part of an attested real SSC_API baseline"

    deactivated = 0
    managed_keys = [spec.rule_key for spec in WAVE5C_RULES]
    existing = db.execute(
        select(RuleEngineRule).where(RuleEngineRule.stable_key.in_(managed_keys)).with_for_update()
    ).scalars()
    for rule in existing:
        if rule.is_active:
            rule.is_active = False
            deactivated += 1
    if commit:
        db.commit()
    return {
        "rules_created": 0,
        "rule_versions_created": 0,
        "rules_reused": 0,
        "rules_deactivated": deactivated,
        "implemented": sorted(WAVE5C_IMPLEMENTED_KEYS),
        "activated": [],
        "inactive": sorted(WAVE5C_IMPLEMENTED_KEYS),
        "blockers": {key: list(value) for key, value in WAVE5C_CLOSURE_BLOCKERS.items()},
        "unavailable": unavailable,
    }


def active_wave5c_mappings(db: Session) -> list[dict[str, Any]]:
    """Return no mappings until exposure/vantage and all closure gates exist."""
    # Querying guards against a stale externally-created active rule while the
    # approved set is empty; reconciliation remains the mutating operation.
    _ = db.execute(
        select(RuleEngineRuleVersion.id)
        .join(RuleEngineRule, RuleEngineRule.current_version_id == RuleEngineRuleVersion.id)
        .where(RuleEngineRule.is_active.is_(True), RuleEngineRule.stable_key.in_([spec.rule_key for spec in WAVE5C_RULES]))
    ).first()
    return []
