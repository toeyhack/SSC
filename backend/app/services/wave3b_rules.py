"""Reviewed Wave 3B bounded HTTP-content rules and exact-version activation."""
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
from app.services.http_content import HTTP_CONTENT_METHOD_VERSION, HTTP_CONTENT_POLICY_VERSION


@dataclass(frozen=True)
class Wave3BRuleSpec:
    issue_key: str
    title: str
    evidence_requirement: str
    match_condition: str
    no_match_boundary: str
    indeterminate_boundary: str
    remediation: str
    reference: str
    primitive: str = "HTTP_CONTENT"
    evidence_root: str = "http"

    @property
    def rule_key(self) -> str:
        return f"ssc.wave3b.{self.issue_key}"

    @property
    def logic(self) -> str:
        return f"{self.match_condition} {self.no_match_boundary} {self.indeterminate_boundary}"

    @property
    def expression(self) -> dict[str, Any]:
        return {
            "operator": "equals",
            "path": f"http.evaluations.{self.issue_key}.matched",
            "value": True,
        }

    @property
    def evidence_schema(self) -> dict[str, Any]:
        return {
            "schema_version": HTTP_CONTENT_METHOD_VERSION,
            "policy_version": HTTP_CONTENT_POLICY_VERSION,
            "primitive": self.primitive,
            "issue_key": self.issue_key,
            "required_observation": self.evidence_requirement,
            "match_condition": self.match_condition,
            "no_match_boundary": self.no_match_boundary,
            "indeterminate_boundary": self.indeterminate_boundary,
            "direct_classification": (
                "VERIFIED_DIRECT: bounded evidence from explicitly declared authorized target URLs; "
                "no claim of SSC collection-method equivalence"
            ),
            "outcomes": ["MATCH", "NO_MATCH", "INDETERMINATE"],
        }


_HTML_INDETERMINATE = (
    "Missing or failed response, blocked/non-2xx response, truncated body, unsupported content type or encoding, "
    "malformed content, undeclared path coverage, or an exceeded observation bound is INDETERMINATE."
)
_HTML_NO_MATCH = (
    "NO_MATCH only when every declared response is fetched completely and parsed as HTML and none satisfies the condition."
)


WAVE3B_RULES = (
    Wave3BRuleSpec(
        "unsafe_sri_v2", "Unsafe Implementation Of Subresource Integrity",
        "Declared HTML page identity, each covered external script/stylesheet URL hash, crossorigin mode, integrity algorithm/token hashes, bounded same-origin fetch result, and recomputed digest result; resource bytes are not retained.",
        "MATCH when a covered external script or stylesheet lacks SRI, has invalid or disallowed integrity metadata, or fetched bytes fail every digest using the strongest supported algorithm represented in its metadata.",
        "NO_MATCH only when complete declared HTML contains no covered resources or every covered resource has valid permitted metadata and at least one digest using its strongest represented supported algorithm verifies.",
        "Page/resource failure, truncation, cross-origin or otherwise out-of-scope resource, unsafe redirect, unsupported content, exhausted fetch budget, or incomplete digest evidence is INDETERMINATE.",
        "Add valid SHA-256, SHA-384, or SHA-512 integrity metadata to covered scripts and stylesheets and keep deployed bytes consistent with it.",
        "https://www.w3.org/TR/SRI/",
    ),
    Wave3BRuleSpec(
        "insecure_ftp", "Non-standard links detected: Unsafe File Transfer Protocol",
        "Declared HTML page, element/attribute, resolved ftp scheme, and hash-only destination evidence; the destination is never followed.",
        "MATCH when a covered static HTML URL uses the ftp: scheme.", _HTML_NO_MATCH, _HTML_INDETERMINATE,
        "Replace FTP links with an approved encrypted transfer mechanism and remove obsolete references.",
        "https://www.rfc-editor.org/rfc/rfc959.html",
    ),
    Wave3BRuleSpec(
        "contact_information_detected", "Non-standard links detected: Contact information displayed",
        "Declared HTML page, href element, contact URI scheme, and a hash-only contact value.",
        "MATCH when a covered href uses mailto:, tel:, sms:, whatsapp:, or viber: under the versioned policy.",
        _HTML_NO_MATCH, _HTML_INDETERMINATE,
        "Review whether direct contact links are intended and remove or replace unnecessary exposed contact routes.",
        "https://www.rfc-editor.org/rfc/rfc6068.html",
    ),
    Wave3BRuleSpec(
        "local_file_path_exposed_via_url_scheme", "Non-standard links detected: Local file path exposed",
        "Declared HTML page, element/attribute, resolved file scheme, and hash-only destination evidence; the destination is never followed.",
        "MATCH when a covered static HTML URL uses the file: scheme.", _HTML_NO_MATCH, _HTML_INDETERMINATE,
        "Remove local file URI references from externally served content and use an intended application resource URL.",
        "https://www.rfc-editor.org/rfc/rfc8089.html",
    ),
    Wave3BRuleSpec(
        "server_error", "Server error detected",
        "Two bounded safe GET attempts for each declared URL, retaining terminal status, response-header hash, timestamp, and stop reason.",
        "MATCH when the same declared URL returns an HTTP 5xx status on both bounded attempts.",
        "NO_MATCH only when every declared URL completes both attempts without a reproducible 5xx.",
        "Any failed/incomplete attempt, an undeclared path set, or exactly one 5xx in a pair is INDETERMINATE.",
        "Correct the repeatable server-side failure and add availability/error monitoring for the affected endpoint.",
        "https://www.rfc-editor.org/rfc/rfc9110.html#name-server-error-5xx",
    ),
    Wave3BRuleSpec(
        "links_to_insecure_website", "Site links to insecure websites",
        "Declared HTML page, element/attribute, resolved http scheme, and hash-only destination evidence; the destination is never followed.",
        "MATCH when a covered static HTML URL resolves to the http: scheme.", _HTML_NO_MATCH, _HTML_INDETERMINATE,
        "Replace insecure HTTP references with verified HTTPS destinations.",
        "https://www.rfc-editor.org/rfc/rfc9110.html",
    ),
    Wave3BRuleSpec(
        "service_soap", "SOAP Server Accessible",
        "Declared authorized endpoint, bounded complete XML body hash, parse result, root-name evidence, and SOAP Envelope or WSDL SOAP-binding semantic marker.",
        "MATCH when an endpoint returns a parseable SOAP 1.1/1.2 Envelope or WSDL document containing a SOAP binding.",
        "NO_MATCH only when every declared endpoint is fetched and completely parsed as supported HTML/XML content with no SOAP/WSDL semantic.",
        "No declared path, failed/blocked response, truncation, unsupported content, malformed XML, or ambiguous namespace evidence is INDETERMINATE.",
        "Remove unintended SOAP exposure or restrict the service to approved clients and authenticated application paths.",
        "https://www.w3.org/TR/soap12-part1/; https://www.w3.org/TR/wsdl20/",
    ),
)

WAVE3B_BY_KEY = {spec.issue_key: spec for spec in WAVE3B_RULES}


class Wave3BActivationError(ValueError):
    pass


def activate_wave3b_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Idempotently activate Wave 3B only for attested exact SSC_API versions."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE3B_RULES:
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
            raise Wave3BActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
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


def active_wave3b_mappings(db: Session) -> list[dict[str, Any]]:
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
        spec = WAVE3B_BY_KEY.get(issue.stable_key)
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
