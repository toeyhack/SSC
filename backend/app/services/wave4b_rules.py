"""Reviewed Wave 4B bounded SPF permanent-error rule activation."""
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
from app.services.spf import SPF_PARSER_VERSION, SPF_POLICY_VERSION


METHOD_VERSION = "ssc-wave4b-spf-observation.v1"
REFERENCE = "https://www.rfc-editor.org/rfc/rfc7208.html"


@dataclass(frozen=True)
class Wave4BRuleSpec:
    issue_key: str = "spf_record_malformed"
    title: str = "Malformed SPF Record"
    primitive: str = "EMAIL_SECURITY"

    @property
    def reference(self) -> str:
        return REFERENCE

    @property
    def rule_key(self) -> str:
        return f"ssc.wave4b.{self.issue_key}"

    @property
    def expression(self) -> dict[str, Any]:
        return {
            "operator": "equals",
            "path": "dns.evaluations.spf_record_malformed.matched",
            "value": True,
        }

    @property
    def evidence_requirement(self) -> str:
        return (
            "Exact-domain bounded TXT acquisition with strict SPF1 record selection, complete selected-record "
            "syntax and macro validation, path-sensitive RFC DNS-term/void accounting, and compact bounded "
            "include, redirect, A, AAAA, MX and exists traversal evidence."
        )

    @property
    def logic(self) -> str:
        return (
            "MATCH only for an unconditional RFC 7208 selection/grammar permanent error or when every feasible "
            "runtime branch deterministically ends in permerror. NO_MATCH requires definitive SPF absence or "
            "complete bounded evidence with no permanent-error branch. Missing runtime context, mixed branches, "
            "DNS uncertainty, undefined expansion, unsupported state, or operational exhaustion is INDETERMINATE."
        )

    @property
    def evidence_schema(self) -> dict[str, Any]:
        return {
            "schema_version": METHOD_VERSION,
            "parser_version": SPF_PARSER_VERSION,
            "policy_version": SPF_POLICY_VERSION,
            "primitive": self.primitive,
            "issue_key": self.issue_key,
            "required_observation": self.evidence_requirement,
            "match_condition": "deterministic RFC 7208 permerror under all feasible runtime branches",
            "no_match_boundary": "definitive absence or complete bounded proof of no permerror branch",
            "indeterminate_boundary": (
                "runtime-context dependency, mixed safe/permerror paths, DNS uncertainty, undefined expansion, "
                "unsupported state, or scanner operational exhaustion"
            ),
            "rfc_limits": {"dns_terms": 10, "void_lookups": 2, "mx_exchange_hosts": 10},
            "operational_limits": {
                "logical_dns_queries": 256,
                "elapsed_seconds": 20,
                "dns_response_bytes": 16384,
                "selected_spf_record_bytes": 8192,
                "abstract_states": 64,
                "evaluator_steps": 512,
                "query_trace_entries": 256,
            },
            "outcomes": ["MATCH", "NO_MATCH", "INDETERMINATE"],
        }


WAVE4B_RULES = (Wave4BRuleSpec(),)
WAVE4B_BY_KEY = {spec.issue_key: spec for spec in WAVE4B_RULES}


class Wave4BActivationError(ValueError):
    pass


def activate_wave4b_rules(db: Session, *, commit: bool = True) -> dict[str, Any]:
    """Idempotently activate Wave 4B only for an attested exact SSC_API version."""
    real_versions = set(db.execute(
        select(CatalogSnapshotItem.issue_type_version_id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(CatalogSnapshot.source_type == SourceTypeEnum.SSC_API, CatalogSnapshot.is_real_baseline.is_(True))
    ).scalars())
    counts = {"rules_created": 0, "rule_versions_created": 0, "rules_reused": 0}
    activated: list[str] = []
    unavailable: dict[str, str] = {}
    for spec in WAVE4B_RULES:
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
            raise Wave4BActivationError(f"{spec.rule_key}: existing rule has different catalog linkage")
        else:
            rule.is_active = True
            counts["rules_reused"] += 1
        definition = {
            "catalog_issue_type_version_id": issue_version.id,
            "name": spec.title,
            "description": f"{spec.evidence_requirement} {spec.logic}",
            "target_type": RuleTargetTypeEnum.DOMAIN,
            "rule_expression": spec.expression,
            "evidence_schema": spec.evidence_schema,
            "remediation": "Publish exactly one RFC 7208-valid SPF policy whose bounded evaluation does not produce permerror.",
            "source_type": RuleSourceTypeEnum.SSC_REFERENCE,
            "source_reference": REFERENCE,
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


def active_wave4b_mappings(db: Session) -> list[dict[str, Any]]:
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
        spec = WAVE4B_BY_KEY.get(issue.stable_key)
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
