"""Immutable, version-aware authority for SSC public-exposure consumers.

Membership is reviewed against one exact SSC_API baseline.  Runtime callers
cannot opt an issue into this registry through evidence or rule schema fields.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
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
from app.services.public_exposure import (
    ADDRESS_SCOPE_POLICY_VERSION,
    EXPOSURE_COMPOSITION_POLICY_VERSION,
    PUBLIC_EXPOSURE_SCHEMA_VERSION,
    VANTAGE_POLICY_VERSION,
)


PINNED_SSC_BASELINE_HASH = "0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8"
PUBLIC_EXPOSURE_CONSUMER_POLICY_VERSION = "ssc-public-exposure-consumers.v1"
PUBLIC_EXPOSURE_REQUIRED = "PUBLIC_EXPOSURE_REQUIRED"


@dataclass(frozen=True)
class PublicExposureConsumer:
    baseline_hash: str
    issue_key: str
    semantic_class: str
    evidence_root: str
    required_evidence_source: str
    consumer_policy_version: str = PUBLIC_EXPOSURE_CONSUMER_POLICY_VERSION

    @property
    def expression_path(self) -> str:
        return (
            f"{self.evidence_root}.evaluations.{self.issue_key}."
            "exposure_context.composition.matched"
        )


def _entry(issue_key: str, evidence_root: str, required_evidence_source: str) -> PublicExposureConsumer:
    return PublicExposureConsumer(
        baseline_hash=PINNED_SSC_BASELINE_HASH,
        issue_key=issue_key,
        semantic_class=PUBLIC_EXPOSURE_REQUIRED,
        evidence_root=evidence_root,
        required_evidence_source=required_evidence_source,
    )


_ENTRIES = (
    _entry("service_rsync", "tcp", "SCANNER_TCP"),
    _entry("service_redis", "tcp", "SCANNER_TCP"),
    _entry("service_socks_proxy", "tcp", "SCANNER_TCP"),
    _entry("service_smb", "tcp", "SCANNER_TCP"),
    _entry("service_soap", "http", "SCANNER_HTTP"),
    _entry("service_ftp", "tcp", "SCANNER_TCP"),
    _entry("service_imap", "tcp", "SCANNER_TCP"),
    _entry("service_pop3", "tcp", "SCANNER_TCP"),
    _entry("service_ldap", "tcp", "SCANNER_TCP"),
)

PUBLIC_EXPOSURE_CONSUMERS = MappingProxyType(
    {(entry.baseline_hash, entry.issue_key): entry for entry in _ENTRIES}
)
PUBLIC_EXPOSURE_REQUIRED_ISSUE_KEYS = frozenset(entry.issue_key for entry in _ENTRIES)


def get_public_exposure_consumer(
    baseline_hash: str | None,
    issue_key: str,
) -> PublicExposureConsumer | None:
    if not isinstance(baseline_hash, str):
        return None
    return PUBLIC_EXPOSURE_CONSUMERS.get((baseline_hash, issue_key))


def get_pinned_public_exposure_consumer(issue_key: str) -> PublicExposureConsumer | None:
    return get_public_exposure_consumer(PINNED_SSC_BASELINE_HASH, issue_key)


def public_exposure_rule_expression(issue_key: str) -> dict[str, Any] | None:
    consumer = get_pinned_public_exposure_consumer(issue_key)
    if consumer is None:
        return None
    return {"operator": "equals", "path": consumer.expression_path, "value": True}


def public_exposure_schema_contract(consumer: PublicExposureConsumer) -> dict[str, Any]:
    return {
        "semantic_class": consumer.semantic_class,
        "consumer_policy_version": consumer.consumer_policy_version,
        "baseline_content_hash": consumer.baseline_hash,
        "required_evidence_source": consumer.required_evidence_source,
        "required_context": {
            "schema_version": PUBLIC_EXPOSURE_SCHEMA_VERSION,
            "address_scope_policy_version": ADDRESS_SCOPE_POLICY_VERSION,
            "vantage_policy_version": VANTAGE_POLICY_VERSION,
            "composition_policy_version": EXPOSURE_COMPOSITION_POLICY_VERSION,
        },
        "positive_predicate": (
            "Protocol/service MATCH plus PUBLIC_ROUTABLE target address plus trusted EXTERNAL_PUBLIC "
            "deployment-manifest vantage produces exposure MATCH."
        ),
        "indeterminate_boundary": (
            "Unknown or internal vantage, non-public destination, missing or stale policy context, and protocol "
            "indeterminate remain INDETERMINATE / NOT_ASSESSED."
        ),
        "no_match_boundary": "This public-exposure consumer defines no deterministic exposure NO_MATCH.",
        "outcomes": ["MATCH", "INDETERMINATE"],
    }


def exposure_context_uses_current_policies(
    consumer: PublicExposureConsumer,
    evidence: dict[str, Any],
) -> bool:
    """Validate version boundaries independently of the caller's rule schema."""
    root = evidence.get(consumer.evidence_root)
    evaluations = root.get("evaluations") if isinstance(root, dict) else None
    evaluation = evaluations.get(consumer.issue_key) if isinstance(evaluations, dict) else None
    context = evaluation.get("exposure_context") if isinstance(evaluation, dict) else None
    address_scope = context.get("address_scope") if isinstance(context, dict) else None
    vantage = context.get("vantage") if isinstance(context, dict) else None
    composition = context.get("composition") if isinstance(context, dict) else None
    return bool(
        isinstance(context, dict)
        and context.get("schema_version") == PUBLIC_EXPOSURE_SCHEMA_VERSION
        and isinstance(address_scope, dict)
        and address_scope.get("policy_version") == ADDRESS_SCOPE_POLICY_VERSION
        and isinstance(vantage, dict)
        and vantage.get("policy_version") == VANTAGE_POLICY_VERSION
        and isinstance(composition, dict)
        and composition.get("policy_version") == EXPOSURE_COMPOSITION_POLICY_VERSION
    )


def resolve_pinned_consumer_issue_versions(db: Session) -> dict[str, CatalogIssueTypeVersion]:
    """Resolve registry entries only through the exact attested snapshot."""
    rows = db.execute(
        select(CatalogIssueType, CatalogIssueTypeVersion)
        .join(CatalogIssueTypeVersion, CatalogIssueTypeVersion.issue_type_id == CatalogIssueType.id)
        .join(CatalogSnapshotItem, CatalogSnapshotItem.issue_type_version_id == CatalogIssueTypeVersion.id)
        .join(CatalogSnapshot, CatalogSnapshot.id == CatalogSnapshotItem.catalog_snapshot_id)
        .where(
            CatalogSnapshot.content_hash == PINNED_SSC_BASELINE_HASH,
            CatalogSnapshot.source_type == SourceTypeEnum.SSC_API,
            CatalogSnapshot.is_real_baseline.is_(True),
            CatalogIssueType.stable_key.in_(PUBLIC_EXPOSURE_REQUIRED_ISSUE_KEYS),
        )
    ).all()
    return {issue.stable_key: version for issue, version in rows}
