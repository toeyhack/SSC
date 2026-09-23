"""Versioned assessment scope definitions resolved against immutable catalog snapshots."""
import hashlib
import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.catalog_models import (
    CatalogFactor,
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)
from app.schemas.results import AssessmentProfileSummary, ResultRecord
from app.services.wave1_rules import WAVE1_BY_KEY
from app.services.wave2_rules import WAVE2_BY_KEY


V1_BASELINE_CONTENT_HASH = "0fe2bc8ffb7e3f734d4e88f70b11cffa6e8e9e47e722dc62107f6ff09694eca8"
V1_FACTOR_CODES = (
    "application_security",
    "network_security",
    "dns_health",
    "patching_cadence",
)
V1_FACTOR_TOTALS = {
    "application_security": 61,
    "network_security": 68,
    "dns_health": 10,
    "patching_cadence": 21,
}
V1_TOTAL_ISSUES = 160
FULL_BASELINE_TOTAL_ISSUES = 202


class AssessmentProfileError(ValueError):
    pass


class AssessmentProfileDefinition(ResultRecord):
    name: str = "ssc-v1"
    version: str = "1.0"
    baseline_content_hash: str = V1_BASELINE_CONTENT_HASH
    scoring_model_name: str = "internal-exposure"
    scoring_model_version: str = "1.0"
    in_scope_factor_codes: tuple[str, ...] = V1_FACTOR_CODES

    def content_hash(self) -> str:
        payload = json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"), allow_nan=False)
        return hashlib.sha256(payload.encode()).hexdigest()

    def summary(self) -> AssessmentProfileSummary:
        return AssessmentProfileSummary(
            name=self.name,
            version=self.version,
            definition_hash=self.content_hash(),
            baseline_content_hash=self.baseline_content_hash,
            scoring_model_name=self.scoring_model_name,
            scoring_model_version=self.scoring_model_version,
            in_scope_factor_codes=list(self.in_scope_factor_codes),
        )


@dataclass(frozen=True)
class ProfileIssue:
    stable_key: str
    catalog_issue_type_version_id: str
    factor_code: str
    factor_name: str
    ssc_severity: str | None
    supported_capability: bool


@dataclass(frozen=True)
class ResolvedAssessmentProfile:
    definition: AssessmentProfileDefinition
    issues: tuple[ProfileIssue, ...]

    @property
    def summary(self) -> AssessmentProfileSummary:
        return self.definition.summary()


V1_ASSESSMENT_PROFILE = AssessmentProfileDefinition()


def load_v1_assessment_profile(db: Session) -> ResolvedAssessmentProfile | None:
    """Resolve the fixed V1 profile only from its exact attested baseline snapshot."""
    snapshot = db.execute(
        select(CatalogSnapshot)
        .where(
            CatalogSnapshot.content_hash == V1_ASSESSMENT_PROFILE.baseline_content_hash,
            CatalogSnapshot.source_type == SourceTypeEnum.SSC_API,
            CatalogSnapshot.is_real_baseline.is_(True),
        )
        .order_by(CatalogSnapshot.imported_at.desc())
    ).scalars().first()
    if snapshot is None:
        return None

    rows = db.execute(
        select(CatalogSnapshotItem, CatalogIssueTypeVersion, CatalogIssueType, CatalogFactor)
        .join(CatalogIssueTypeVersion, CatalogSnapshotItem.issue_type_version_id == CatalogIssueTypeVersion.id)
        .join(CatalogIssueType, CatalogIssueTypeVersion.issue_type_id == CatalogIssueType.id)
        .join(CatalogFactor, CatalogIssueType.factor_id == CatalogFactor.id)
        .where(CatalogSnapshotItem.catalog_snapshot_id == snapshot.id)
        .order_by(CatalogSnapshotItem.factor_position, CatalogSnapshotItem.issue_position, CatalogIssueType.stable_key)
    ).all()
    supported_keys = set(WAVE1_BY_KEY) | set(WAVE2_BY_KEY)
    issues = tuple(
        ProfileIssue(
            stable_key=issue_type.stable_key,
            catalog_issue_type_version_id=str(issue_version.id),
            factor_code=factor.code,
            factor_name=factor.name,
            ssc_severity=issue_version.ssc_severity,
            supported_capability=issue_type.stable_key in supported_keys,
        )
        for _, issue_version, issue_type, factor in rows
    )
    _validate_profile_membership(issues)
    return ResolvedAssessmentProfile(definition=V1_ASSESSMENT_PROFILE, issues=issues)


def _validate_profile_membership(issues: tuple[ProfileIssue, ...]) -> None:
    if len(issues) != FULL_BASELINE_TOTAL_ISSUES or len({item.stable_key for item in issues}) != len(issues):
        raise AssessmentProfileError("V1 profile baseline must contain 202 unique exact issue versions")
    counts = {code: 0 for code in V1_FACTOR_CODES}
    for issue in issues:
        if issue.factor_code in counts:
            counts[issue.factor_code] += 1
    if counts != V1_FACTOR_TOTALS or sum(counts.values()) != V1_TOTAL_ISSUES:
        raise AssessmentProfileError(f"V1 profile membership mismatch: {counts}")
    if sum(issue.supported_capability for issue in issues if issue.factor_code in V1_FACTOR_CODES) != 21:
        raise AssessmentProfileError("V1 profile must resolve the 21 reviewed supported capabilities")
