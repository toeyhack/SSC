"""CLI inventory and internal detector provisioning using the existing versioned models."""
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.catalog_models import CatalogFactor, CatalogIssueType, CatalogIssueTypeVersion
from app.models.models import Domain, Host, Organization
from app.models.rule_models import RuleEngineRule, RuleEngineRuleVersion
from app.schemas.catalog import FactorCreate, IssueTypeVersionCreate
from app.schemas.inventory import DomainCreate, HostCreate, OrganizationCreate
from app.schemas.rules import RuleVersionCreate
from app.services.scan_executors import _clean_host_identifier


class DetectorDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stable_key: str = Field(min_length=1, max_length=128)
    factor: FactorCreate
    issue: IssueTypeVersionCreate
    rule: RuleVersionCreate

    @model_validator(mode="after")
    def validate_internal(self):
        if self.issue.source_type.value != "MANUAL" or self.rule.source_type.value != "INTERNAL":
            raise ValueError("Internal detector bundles require MANUAL catalog and INTERNAL rule source types")
        if self.issue.version_number is not None or self.rule.version_number is not None:
            raise ValueError("Version numbers are assigned by the loader")
        expression = self.rule.rule_expression
        if expression.get("operator") not in {"exists", "missing", "equals", "not_equals", "contains", "regex"}:
            raise ValueError("Unsupported rule operator")
        if not isinstance(expression.get("path"), str) or not expression["path"]:
            raise ValueError("Rule path must be a nonempty string")
        if expression.get("operator") == "regex":
            if not isinstance(expression.get("pattern"), str):
                raise ValueError("Regex pattern is required")
            try:
                re.compile(expression["pattern"])
            except re.error as exc:
                raise ValueError("Invalid regex pattern") from exc
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", self.stable_key):
            raise ValueError("Detector stable_key must contain lowercase letters, digits, dot, underscore or dash")
        return self


class DetectorBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["ssc.detectors.v1"]
    detectors: list[DetectorDefinition] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_keys(self):
        if len({d.stable_key for d in self.detectors}) != len(self.detectors):
            raise ValueError("Duplicate detector stable_key")
        factors = {}
        for detector in self.detectors:
            definition = detector.factor.model_dump()
            if detector.factor.code in factors and factors[detector.factor.code] != definition:
                raise ValueError("Conflicting factor definitions within bundle")
            factors[detector.factor.code] = definition
        return self


def add_inventory_target(db: Session, *, organization: str, domain_name: str, hostname: str | None,
                         ip: str | None, approved: bool, allow_sensitive: bool, approval_notes: str | None):
    org_input = OrganizationCreate(name=organization)
    domain_name = _clean_host_identifier(domain_name, "domain")
    if hostname:
        hostname = _clean_host_identifier(hostname, "hostname")
    if ip:
        import ipaddress
        ip = str(ipaddress.ip_address(ip))
        if not hostname:
            raise ValueError("--ip requires --hostname")
    org = db.execute(select(Organization).where(Organization.name == org_input.name)).scalar_one_or_none()
    if org is None:
        org = Organization(**org_input.model_dump())
        db.add(org)
        db.flush()
    if not org.active:
        raise ValueError("Organization is inactive")
    domain = db.execute(select(Domain).where(Domain.organization_id == org.id, Domain.name == domain_name)).scalar_one_or_none()
    if domain is None:
        domain = Domain(**DomainCreate(organization_id=org.id, name=domain_name).model_dump())
        db.add(domain)
        db.flush()
    if not domain.active:
        raise ValueError("Domain is inactive")
    target = domain
    if hostname:
        target = db.execute(select(Host).where(Host.domain_id == domain.id, Host.hostname == hostname)).scalar_one_or_none()
        if target is None:
            target = Host(**HostCreate(domain_id=domain.id, hostname=hostname, ip=ip).model_dump())
            db.add(target)
        elif ip is not None and target.ip != ip:
            raise ValueError("Existing host has a different IP; review inventory before changing it")
    db.flush()
    if not target.active:
        raise ValueError("Target is inactive")
    if approved:
        target.approved_for_scan = True
    if allow_sensitive:
        if not (approved or target.approved_for_scan):
            raise ValueError("Sensitive network permission requires target approval")
        target.allow_sensitive_network_scan = True
    if approval_notes is not None:
        target.scan_approval_notes = approval_notes
    db.commit()
    return {"id": str(target.id), "organization_id": str(org.id), "name": hostname or domain_name, "approved_for_scan": target.approved_for_scan,
            "allow_sensitive_network_scan": target.allow_sensitive_network_scan}


def load_detector_bundle(db: Session, data) -> dict:
    bundle = DetectorBundle.model_validate(data)
    counts = {"factors_created": 0, "issues_created": 0, "issue_versions_created": 0, "rules_created": 0, "rule_versions_created": 0}
    for detector in bundle.detectors:
        factor = db.execute(select(CatalogFactor).where(CatalogFactor.code == detector.factor.code)).scalar_one_or_none()
        if factor is None:
            factor = CatalogFactor(**detector.factor.model_dump())
            db.add(factor)
            db.flush()
            counts["factors_created"] += 1
        if not factor.is_active:
            raise ValueError("Detector factor is inactive")
        issue = db.execute(select(CatalogIssueType).where(CatalogIssueType.stable_key == detector.stable_key)).scalar_one_or_none()
        if issue is None:
            issue = CatalogIssueType(stable_key=detector.stable_key, factor_id=factor.id)
            db.add(issue)
            db.flush()
            counts["issues_created"] += 1
        elif issue.factor_id != factor.id or not issue.is_active:
            raise ValueError("Existing issue has a different factor or is inactive")
        issue_data = detector.issue.model_dump(exclude={"make_current", "version_number"}, exclude_none=True)
        issue_versions = db.execute(select(CatalogIssueTypeVersion).where(CatalogIssueTypeVersion.issue_type_id == issue.id)).scalars().all()
        issue_version = next((v for v in issue_versions if all(getattr(v, k) == value for k, value in issue_data.items())), None)
        if issue_version is None:
            issue_version = CatalogIssueTypeVersion(issue_type_id=issue.id, version_number=max((v.version_number for v in issue_versions), default=0) + 1, **issue_data)
            db.add(issue_version)
            db.flush()
            counts["issue_versions_created"] += 1
        issue.current_version_id = issue_version.id
        rule = db.execute(select(RuleEngineRule).where(RuleEngineRule.stable_key == detector.stable_key).with_for_update()).scalar_one_or_none()
        if rule is None:
            rule = RuleEngineRule(stable_key=detector.stable_key, catalog_issue_type_id=issue.id)
            db.add(rule)
            db.flush()
            counts["rules_created"] += 1
        elif rule.catalog_issue_type_id != issue.id or not rule.is_active:
            raise ValueError("Existing rule has a different catalog linkage or is inactive")
        rule_data = detector.rule.model_dump(exclude={"make_current", "version_number"}, exclude_none=True)
        versions = db.execute(select(RuleEngineRuleVersion).where(RuleEngineRuleVersion.rule_id == rule.id)).scalars().all()
        version = next((v for v in versions if all(getattr(v, k) == value for k, value in rule_data.items())), None)
        if version is None:
            version = RuleEngineRuleVersion(rule_id=rule.id, version_number=max((v.version_number for v in versions), default=0) + 1, **rule_data)
            db.add(version)
            db.flush()
            counts["rule_versions_created"] += 1
        rule.current_version_id = version.id
    db.commit()
    return counts
