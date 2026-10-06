"""Reviewed Wave 5A staged text-service rules and exact-version activation."""
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
from app.services.service_probe_text import (
    SMTP_STANDARD_PORT_POLICY_VERSION,
    SMTP_STANDARD_PORTS,
    WAVE5A_SERVICE_POLICY_VERSION,
)
from app.services.service_probes import (
    MAX_SERVICE_PROBE_LINE_BYTES,
    MAX_SERVICE_PROBE_LINES,
    MAX_SERVICE_PROBE_OUTBOUND_BYTES,
    MAX_SERVICE_PROBE_RESPONSE_BYTES,
    MAX_SERVICE_PROBE_STAGES,
    SERVICE_PROBE_FRAMEWORK_VERSION,
)


METHOD_VERSION = "ssc-wave5a-staged-text-service-observation.v1"


@dataclass(frozen=True)
class Wave5ARuleSpec:
    issue_key: str
    protocol: str
    title: str
    match_condition: str
    no_match_boundary: str
    remediation: str
    reference: str
    primitive: str = "SERVICE_PROTOCOL_IDENTIFICATION"

    @property
    def rule_key(self) -> str:
        return f"ssc.wave5a.{self.issue_key}"

    @property
    def evidence_requirement(self) -> str:
        return (
            f"One explicitly declared TCP endpoint completing the bounded two-stage {self.protocol.upper()} exchange "
            "on one connection, with per-stage hashes/classes, exact adapter/framework/policy versions, byte and line "
            "budgets, stop reason, and timestamps; no raw greeting or capability transcript is retained."
        )

    @property
    def indeterminate_boundary(self) -> str:
        return (
            "Connection refusal, timeout, reset, peer close, write/read failure, malformed or incomplete framing, "
            "unknown banner, response/line budget exhaustion, and unsupported plaintext/TLS mode are INDETERMINATE."
        )

    @property
    def logic(self) -> str:
        return f"{self.match_condition} {self.no_match_boundary} {self.indeterminate_boundary}"

    @property
    def expression(self) -> dict[str, Any]:
        return {
            "operator": "equals",
            "path": f"tcp.evaluations.{self.issue_key}.matched",
            "value": True,
        }

    @property
    def evidence_schema(self) -> dict[str, Any]:
        schema = {
            "schema_version": METHOD_VERSION,
            "framework_version": SERVICE_PROBE_FRAMEWORK_VERSION,
            "policy_version": WAVE5A_SERVICE_POLICY_VERSION,
            "primitive": self.primitive,
            "protocol": self.protocol,
            "issue_key": self.issue_key,
            "required_observation": self.evidence_requirement,
            "match_condition": self.match_condition,
            "no_match_boundary": self.no_match_boundary,
            "indeterminate_boundary": self.indeterminate_boundary,
            "limits": {
                "stages": MAX_SERVICE_PROBE_STAGES,
                "response_bytes": MAX_SERVICE_PROBE_RESPONSE_BYTES,
                "outbound_bytes": MAX_SERVICE_PROBE_OUTBOUND_BYTES,
                "line_bytes": MAX_SERVICE_PROBE_LINE_BYTES,
                "lines": MAX_SERVICE_PROBE_LINES,
            },
            "tls_mode": "plaintext-only; no implicit TLS or STARTTLS",
            "outcomes": ["MATCH", "NO_MATCH", "INDETERMINATE"],
        }
        if self.protocol == "smtp":
            schema["port_policy"] = {
                "version": SMTP_STANDARD_PORT_POLICY_VERSION,
                "standard_tcp_ports": sorted(SMTP_STANDARD_PORTS),
            }
        return schema


_INDETERMINATE_ONLY_NEGATIVE = (
    "No protocol-negative result is inferred from a wrong reply, arbitrary bytes, a greeting alone, or TCP reachability."
)


WAVE5A_RULES = (
    Wave5ARuleSpec(
        "service_ftp",
        "ftp",
        "FTP Service Observed",
        "MATCH only for a complete FTP 220 greeting followed by an exact NOOP command and complete FTP 200 reply, including same-code multiline termination.",
        _INDETERMINATE_ONLY_NEGATIVE,
        "Restrict FTP exposure to approved networks and replace plaintext FTP with an approved protected file-transfer service where possible.",
        "https://www.rfc-editor.org/rfc/rfc959.html",
    ),
    Wave5ARuleSpec(
        "service_imap",
        "imap",
        "IMAP Service Observed",
        "MATCH only for a legal IMAP OK/PREAUTH greeting followed by one A001 CAPABILITY command, a valid untagged CAPABILITY response, and matching A001 OK completion.",
        _INDETERMINATE_ONLY_NEGATIVE,
        "Restrict IMAP exposure to approved mail clients and require separately reviewed protected and authenticated access.",
        "https://www.rfc-editor.org/rfc/rfc9051.html",
    ),
    Wave5ARuleSpec(
        "service_pop3",
        "pop3",
        "POP3 Service Observed",
        "MATCH only for a complete POP3 +OK greeting followed by one CAPA command and a valid +OK capability response with exact dot termination.",
        _INDETERMINATE_ONLY_NEGATIVE,
        "Restrict POP3 exposure to approved mail clients and require separately reviewed protected and authenticated access.",
        "https://www.rfc-editor.org/rfc/rfc1939.html",
    ),
    Wave5ARuleSpec(
        "mail_server_unusual_port",
        "smtp",
        "SMTP Server on Unusual Port",
        "MATCH only after a legal SMTP 220 greeting and complete 250 EHLO response positively identify SMTP, and the declared port is outside smtp-standard-ports.v1 {25,465,587}.",
        "NO_MATCH only after the same positive SMTP exchange when the declared port is 25, 465, or 587; port alone never identifies SMTP.",
        "Move approved SMTP service to a standard policy port or document and restrict the exceptional listener.",
        "https://www.rfc-editor.org/rfc/rfc5321.html",
    ),
)

WAVE5A_BY_KEY = {spec.issue_key: spec for spec in WAVE5A_RULES}


class Wave5AActivationError(ValueError):
    pass


def activate_wave5a_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Idempotently activate Wave 5A only for attested current SSC_API versions."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE5A_RULES:
        issue = db.execute(select(CatalogIssueType).where(CatalogIssueType.stable_key == spec.issue_key)).scalar_one_or_none()
        if issue is None or not issue.is_active or issue.current_version_id is None:
            unavailable[spec.issue_key] = "exact issue/current version is absent or inactive"
            continue
        issue_version = db.get(CatalogIssueTypeVersion, issue.current_version_id)
        if issue_version is None or issue_version.source_type != SourceTypeEnum.SSC_API or issue_version.id not in real_versions:
            unavailable[spec.issue_key] = "current definition is not part of an attested real SSC_API baseline"
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
            raise Wave5AActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
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
    return {**counts, "activated": activated, "unavailable": unavailable}


def _same_definition(version: RuleEngineRuleVersion, expected: dict[str, Any]) -> bool:
    return all(getattr(version, key) == value for key, value in expected.items())


def active_wave5a_mappings(db: Session) -> list[dict[str, Any]]:
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
        spec = WAVE5A_BY_KEY.get(issue.stable_key)
        if (
            spec is None or rule.stable_key != spec.rule_key
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
