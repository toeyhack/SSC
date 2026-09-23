import hashlib
import json
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.models import models as _models  # Register inventory relationships for standalone CLI use.
from app.models.catalog_models import (
    BreachRiskEnum,
    CatalogFactor,
    CatalogIssueType,
    CatalogIssueTypeVersion,
    CatalogSnapshot,
    CatalogSnapshotItem,
    SourceTypeEnum,
)


BASELINE_SCHEMA_VERSION = "phase1b.ssc_licensed_ui.v1"
_CODE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")


class GoldenBaselineImportError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class ThreatLevelEnum(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    POSITIVE = "POSITIVE"
    UNKNOWN = "UNKNOWN"


class BaselineIssueInput(BaseModel):
    stable_key: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    breach_risk: BreachRiskEnum
    threat_level: ThreatLevelEnum | None = None
    ssc_severity: str | None = Field(default=None, max_length=128)
    ssc_metadata: dict | None = None
    affects_score: bool = True
    source_reference: str | None = Field(default=None, max_length=1024)
    position: int | None = Field(default=None, ge=1)

    @field_validator("stable_key")
    @classmethod
    def stable_key_must_be_canonical(cls, value: str) -> str:
        value = value.strip()
        if not _CODE_PATTERN.fullmatch(value):
            raise ValueError("stable_key must use lowercase letters, numbers, dots, hyphens, or underscores")
        return value

    @field_validator("name")
    @classmethod
    def trim_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("description", "source_reference")
    @classmethod
    def trim_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class BaselineFactorInput(BaseModel):
    code: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    position: int | None = Field(default=None, ge=1)
    issues: list[BaselineIssueInput] = Field(min_length=1)

    @field_validator("code")
    @classmethod
    def code_must_be_canonical(cls, value: str) -> str:
        value = value.strip()
        if not _CODE_PATTERN.fullmatch(value):
            raise ValueError("factor code must use lowercase letters, numbers, dots, hyphens, or underscores")
        return value

    @field_validator("name")
    @classmethod
    def trim_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("description")
    @classmethod
    def trim_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @model_validator(mode="after")
    def validate_issue_ordering(self):
        _validate_optional_positions(
            [issue.position for issue in self.issues],
            f"issues for factor {self.code}",
        )
        return self


class GoldenBaselineInput(BaseModel):
    schema_version: Literal["phase1b.ssc_licensed_ui.v1"]
    name: str = Field(min_length=1, max_length=255)
    source_type: Literal["SSC_LICENSED_UI"]
    source_reference: str | None = Field(default=None, max_length=1024)
    captured_at: datetime
    notes: str | None = None
    factors: list[BaselineFactorInput] = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def trim_required_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value

    @field_validator("source_reference", "notes")
    @classmethod
    def trim_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("captured_at")
    @classmethod
    def captured_at_must_be_timezone_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("captured_at must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_baseline_consistency(self):
        _validate_optional_positions([factor.position for factor in self.factors], "factors")

        factor_codes: set[str] = set()
        issue_keys: set[str] = set()
        issue_names_by_factor: dict[str, set[str]] = {}

        for factor in self.factors:
            if factor.code in factor_codes:
                raise ValueError(f"duplicate factor code: {factor.code}")
            factor_codes.add(factor.code)

            normalized_names = issue_names_by_factor.setdefault(factor.code, set())
            for issue in factor.issues:
                if issue.stable_key in issue_keys:
                    raise ValueError(f"duplicate issue stable_key: {issue.stable_key}")
                issue_keys.add(issue.stable_key)

                normalized_name = _normalize_name(issue.name)
                if normalized_name in normalized_names:
                    raise ValueError(f"duplicate issue name within factor {factor.code}: {issue.name}")
                normalized_names.add(normalized_name)

        return self


class BaselineFactorAction(BaseModel):
    code: str
    name: str
    position: int
    action: Literal["create", "reuse"]
    warnings: list[str] = Field(default_factory=list)


class BaselineIssueAction(BaseModel):
    stable_key: str
    name: str
    factor_code: str
    factor_position: int
    issue_position: int
    issue_action: Literal["create", "reuse"]
    version_action: Literal["create", "reuse_current", "reuse_existing"]
    issue_type_id: UUID | None = None
    issue_type_version_id: UUID | None = None
    version_number: int | None = None
    warnings: list[str] = Field(default_factory=list)


class GoldenBaselineImportResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    dry_run: bool
    content_hash: str
    snapshot_action: Literal["create", "reused_existing"]
    snapshot_id: UUID | None = None
    imported_at: datetime | None = None
    factors_created: int = 0
    factors_reused: int = 0
    issues_created: int = 0
    issues_reused: int = 0
    versions_created: int = 0
    versions_reused: int = 0
    snapshot_items: int = 0
    factor_actions: list[BaselineFactorAction] = Field(default_factory=list)
    issue_actions: list[BaselineIssueAction] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def load_golden_baseline_file(path: str | Path) -> GoldenBaselineInput:
    with Path(path).open("r", encoding="utf-8") as baseline_file:
        data = json.load(baseline_file)
    return GoldenBaselineInput.model_validate(data)


def compute_baseline_content_hash(baseline: GoldenBaselineInput) -> str:
    if baseline.source_type == "SSC_API":
        # Capture time, whitespace and source list ordering are not taxonomy changes.
        payload = {}
        for endpoint, capture in baseline.raw_source.items():
            response = json.loads(capture["body"])
            if isinstance(response, dict) and isinstance(response.get("entries"), list):
                response["entries"] = sorted(response["entries"], key=lambda entry: entry["key"])
            payload[endpoint] = response
        canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    payload = baseline.model_dump(mode="json", exclude_none=True)
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def import_golden_baseline(
    db: Session,
    baseline: GoldenBaselineInput,
    *,
    dry_run: bool = False,
    attest_real_source: bool = False,
) -> GoldenBaselineImportResult:
    content_hash = compute_baseline_content_hash(baseline)
    existing_snapshot = _get_existing_snapshot(db, content_hash, baseline.source_type)
    if existing_snapshot is not None:
        if attest_real_source and not existing_snapshot.is_real_baseline:
            raise GoldenBaselineImportError([
                "Existing snapshot was not attested as real SSC data; immutable history cannot be relabeled. "
                "Provide a new verified capture with its actual capture timestamp."
            ])
        warnings = ["Exact baseline content hash already imported; no catalog rows were changed."]
        if not dry_run and existing_snapshot.is_real_baseline and baseline.source_type == "SSC_API":
            from app.services.wave1_rules import activate_wave1_rules
            from app.services.wave2_rules import activate_wave2_rules
            from app.services.wave3a_rules import activate_wave3a_rules
            activation1 = activate_wave1_rules(db, commit=False)
            activation2 = activate_wave2_rules(db, commit=False)
            activation3a = activate_wave3a_rules(db)
            warnings.append(f"Wave 1 evaluators active: {len(activation1['activated'])}.")
            warnings.append(f"Wave 2 evaluators active: {len(activation2['activated'])}.")
            warnings.append(f"Wave 3A evaluators active: {len(activation3a['activated'])}.")
        return GoldenBaselineImportResult(
            dry_run=dry_run,
            content_hash=content_hash,
            snapshot_action="reused_existing",
            snapshot_id=existing_snapshot.id,
            imported_at=existing_snapshot.imported_at,
            factors_reused=len(baseline.factors),
            issues_reused=sum(len(factor.issues) for factor in baseline.factors),
            snapshot_items=len(existing_snapshot.items),
            warnings=warnings,
        )

    plan = _build_import_plan(db, baseline, content_hash)
    if dry_run:
        return plan

    imported_at = datetime.now(timezone.utc)
    try:
        version_by_key: dict[str, CatalogIssueTypeVersion] = {}
        issue_actions: list[BaselineIssueAction] = []

        for factor_input in baseline.factors:
            factor_position = _factor_position(baseline, factor_input)
            factor = db.execute(
                select(CatalogFactor).where(CatalogFactor.code == factor_input.code)
            ).scalar_one_or_none()
            if factor is None:
                factor = CatalogFactor(
                    code=factor_input.code,
                    name=factor_input.name,
                    description=factor_input.description,
                    display_order=factor_position,
                    is_active=True,
                )
                db.add(factor)
                db.flush()
            for issue_input in factor_input.issues:
                issue_position = _issue_position(factor_input, issue_input)
                issue = db.execute(
                    select(CatalogIssueType)
                    .where(CatalogIssueType.stable_key == issue_input.stable_key)
                    .options(joinedload(CatalogIssueType.current_version), joinedload(CatalogIssueType.versions))
                ).unique().scalar_one_or_none()
                issue_action: Literal["create", "reuse"] = "reuse"
                if issue is None:
                    issue = CatalogIssueType(
                        stable_key=issue_input.stable_key,
                        factor_id=factor.id,
                        is_active=True,
                    )
                    db.add(issue)
                    db.flush()
                    issue_action = "create"

                version, version_action = _get_or_create_version(
                    db,
                    issue,
                    issue_input,
                    baseline,
                    content_hash,
                )
                issue.current_version_id = version.id
                version_by_key[issue_input.stable_key] = version
                issue_actions.append(
                    BaselineIssueAction(
                        stable_key=issue_input.stable_key,
                        name=issue_input.name,
                        factor_code=factor_input.code,
                        factor_position=factor_position,
                        issue_position=issue_position,
                        issue_action=issue_action,
                        version_action=version_action,
                        issue_type_id=issue.id,
                        issue_type_version_id=version.id,
                        version_number=version.version_number,
                    )
                )

        snapshot = CatalogSnapshot(
            name=baseline.name,
            source_type=SourceTypeEnum(baseline.source_type),
            source_reference=baseline.source_reference,
            captured_at=baseline.captured_at,
            imported_at=imported_at,
            content_hash=content_hash,
            notes=baseline.notes,
            normalized_schema_version=baseline.schema_version,
            normalized_payload=baseline.model_dump(mode="json", exclude={"raw_source"}),
            raw_source=getattr(baseline, "raw_source", None),
            is_real_baseline=attest_real_source,
        )
        db.add(snapshot)
        db.flush()

        for factor_input in baseline.factors:
            for issue_input in factor_input.issues:
                db.add(
                    CatalogSnapshotItem(
                        catalog_snapshot_id=snapshot.id,
                        issue_type_version_id=version_by_key[issue_input.stable_key].id,
                        factor_position=_factor_position(baseline, factor_input),
                        issue_position=_issue_position(factor_input, issue_input),
                    )
                )

        db.flush()
        if baseline.source_type == "SSC_API" and attest_real_source:
            from app.services.wave1_rules import activate_wave1_rules
            from app.services.wave2_rules import activate_wave2_rules
            from app.services.wave3a_rules import activate_wave3a_rules
            activate_wave1_rules(db, commit=False)
            activate_wave2_rules(db, commit=False)
            activate_wave3a_rules(db, commit=False)

        db.commit()
    except IntegrityError as exc:
        db.rollback()
        existing_snapshot = _get_existing_snapshot(db, content_hash, baseline.source_type)
        if existing_snapshot is not None:
            return GoldenBaselineImportResult(
                dry_run=False,
                content_hash=content_hash,
                snapshot_action="reused_existing",
                snapshot_id=existing_snapshot.id,
                imported_at=existing_snapshot.imported_at,
                warnings=["Exact baseline was imported concurrently; reused the existing snapshot."],
            )
        raise GoldenBaselineImportError(["catalog import violated a database constraint"]) from exc

    return GoldenBaselineImportResult(
        dry_run=False,
        content_hash=content_hash,
        snapshot_action="create",
        snapshot_id=snapshot.id,
        imported_at=imported_at,
        factors_created=plan.factors_created,
        factors_reused=plan.factors_reused,
        issues_created=sum(1 for action in issue_actions if action.issue_action == "create"),
        issues_reused=sum(1 for action in issue_actions if action.issue_action == "reuse"),
        versions_created=sum(1 for action in issue_actions if action.version_action == "create"),
        versions_reused=sum(1 for action in issue_actions if action.version_action != "create"),
        snapshot_items=len(issue_actions),
        factor_actions=plan.factor_actions,
        issue_actions=issue_actions,
        warnings=plan.warnings,
    )


def _build_import_plan(
    db: Session,
    baseline: GoldenBaselineInput,
    content_hash: str,
) -> GoldenBaselineImportResult:
    errors = _find_reconciliation_errors(db, baseline)
    if errors:
        raise GoldenBaselineImportError(errors)

    factor_actions: list[BaselineFactorAction] = []
    issue_actions: list[BaselineIssueAction] = []
    warnings: list[str] = []

    for factor_input in baseline.factors:
        factor_position = _factor_position(baseline, factor_input)
        factor = db.execute(
            select(CatalogFactor).where(CatalogFactor.code == factor_input.code)
        ).scalar_one_or_none()
        factor_warnings: list[str] = []
        factor_action: Literal["create", "reuse"] = "create"
        if factor is not None:
            factor_action = "reuse"
            if factor.name != factor_input.name:
                factor_warnings.append("Existing factor name differs; importer will reuse without overwriting.")
            if (factor.description or None) != (factor_input.description or None):
                factor_warnings.append("Existing factor description differs; importer will reuse without overwriting.")
            if factor.display_order != factor_position:
                factor_warnings.append("Existing factor display_order differs; snapshot item ordering will preserve source order.")
        warnings.extend(f"{factor_input.code}: {warning}" for warning in factor_warnings)
        factor_actions.append(
            BaselineFactorAction(
                code=factor_input.code,
                name=factor_input.name,
                position=factor_position,
                action=factor_action,
                warnings=factor_warnings,
            )
        )

        for issue_input in factor_input.issues:
            issue_position = _issue_position(factor_input, issue_input)
            issue = db.execute(
                select(CatalogIssueType)
                .where(CatalogIssueType.stable_key == issue_input.stable_key)
                .options(joinedload(CatalogIssueType.current_version), joinedload(CatalogIssueType.versions))
            ).unique().scalar_one_or_none()
            if issue is None:
                issue_actions.append(
                    BaselineIssueAction(
                        stable_key=issue_input.stable_key,
                        name=issue_input.name,
                        factor_code=factor_input.code,
                        factor_position=factor_position,
                        issue_position=issue_position,
                        issue_action="create",
                        version_action="create",
                    )
                )
                continue

            matching_version = _find_matching_definition(issue.versions, issue_input)
            if issue.current_version is not None and _version_definition_matches(issue.current_version, issue_input):
                version_action: Literal["create", "reuse_current", "reuse_existing"] = "reuse_current"
                version = issue.current_version
            elif matching_version is not None:
                version_action = "reuse_existing"
                version = matching_version
            else:
                version_action = "create"
                version = None

            issue_actions.append(
                BaselineIssueAction(
                    stable_key=issue_input.stable_key,
                    name=issue_input.name,
                    factor_code=factor_input.code,
                    factor_position=factor_position,
                    issue_position=issue_position,
                    issue_action="reuse",
                    version_action=version_action,
                    issue_type_id=issue.id,
                    issue_type_version_id=version.id if version is not None else None,
                    version_number=version.version_number if version is not None else None,
                )
            )

    return GoldenBaselineImportResult(
        dry_run=True,
        content_hash=content_hash,
        snapshot_action="create",
        factors_created=sum(1 for action in factor_actions if action.action == "create"),
        factors_reused=sum(1 for action in factor_actions if action.action == "reuse"),
        issues_created=sum(1 for action in issue_actions if action.issue_action == "create"),
        issues_reused=sum(1 for action in issue_actions if action.issue_action == "reuse"),
        versions_created=sum(1 for action in issue_actions if action.version_action == "create"),
        versions_reused=sum(1 for action in issue_actions if action.version_action != "create"),
        snapshot_items=len(issue_actions),
        factor_actions=factor_actions,
        issue_actions=issue_actions,
        warnings=warnings,
    )


def _get_or_create_version(
    db: Session,
    issue: CatalogIssueType,
    issue_input: BaselineIssueInput,
    baseline: GoldenBaselineInput,
    content_hash: str,
) -> tuple[CatalogIssueTypeVersion, Literal["create", "reuse_current", "reuse_existing"]]:
    if issue.current_version is not None and _version_definition_matches(issue.current_version, issue_input):
        return issue.current_version, "reuse_current"

    existing = _find_matching_definition(issue.versions, issue_input)
    if existing is not None:
        return existing, "reuse_existing"

    latest = db.execute(
        select(func.max(CatalogIssueTypeVersion.version_number)).where(
            CatalogIssueTypeVersion.issue_type_id == issue.id
        )
    ).scalar()
    version = CatalogIssueTypeVersion(
        issue_type_id=issue.id,
        version_number=(latest or 0) + 1,
        name=issue_input.name,
        description=issue_input.description,
        breach_risk=issue_input.breach_risk,
        threat_level=issue_input.threat_level.value if issue_input.threat_level else None,
        ssc_severity=issue_input.ssc_severity,
        ssc_metadata=issue_input.ssc_metadata,
        affects_score=issue_input.affects_score,
        source_type=SourceTypeEnum(baseline.source_type),
        source_reference=issue_input.source_reference or baseline.source_reference,
        source_snapshot_hash=content_hash,
        effective_from=baseline.captured_at,
    )
    db.add(version)
    db.flush()
    return version, "create"


def _find_reconciliation_errors(db: Session, baseline: GoldenBaselineInput) -> list[str]:
    errors: list[str] = []
    existing_issues = db.execute(
        select(CatalogIssueType)
        .options(
            joinedload(CatalogIssueType.factor),
            joinedload(CatalogIssueType.current_version),
        )
    ).unique().scalars().all()

    current_name_index: dict[tuple[str, str], CatalogIssueType] = {}
    for issue in existing_issues:
        if issue.factor is not None and issue.current_version is not None:
            current_name_index[
                (issue.factor.code, _normalize_name(issue.current_version.name))
            ] = issue

    existing_by_key = {issue.stable_key: issue for issue in existing_issues}

    for factor_input in baseline.factors:
        for issue_input in factor_input.issues:
            existing_issue = existing_by_key.get(issue_input.stable_key)
            if existing_issue is not None:
                existing_factor_code = existing_issue.factor.code if existing_issue.factor else None
                if existing_factor_code != factor_input.code:
                    errors.append(
                        f"{issue_input.stable_key}: existing issue belongs to factor "
                        f"{existing_factor_code or existing_issue.factor_id}; "
                        f"baseline assigns it to {factor_input.code}"
                    )
                continue

            same_name_issue = current_name_index.get((factor_input.code, _normalize_name(issue_input.name)))
            if same_name_issue is not None and baseline.source_type != "SSC_API":
                errors.append(
                    f"{issue_input.stable_key}: issue name {issue_input.name!r} matches existing stable_key "
                    f"{same_name_issue.stable_key!r}; provide the existing stable_key or resolve the rename manually"
                )

    return errors


def _get_existing_snapshot(db: Session, content_hash: str, source_type: str = "SSC_LICENSED_UI") -> CatalogSnapshot | None:
    stmt = (
        select(CatalogSnapshot)
        .where(
            CatalogSnapshot.source_type == SourceTypeEnum(source_type),
            CatalogSnapshot.content_hash == content_hash,
        )
        .options(joinedload(CatalogSnapshot.items))
        .order_by(CatalogSnapshot.created_at)
    )
    return db.execute(stmt).unique().scalars().first()


def _find_matching_definition(
    versions: list[CatalogIssueTypeVersion],
    issue_input: BaselineIssueInput,
) -> CatalogIssueTypeVersion | None:
    for version in versions:
        if _version_definition_matches(version, issue_input):
            return version
    return None


def _version_definition_matches(version: CatalogIssueTypeVersion, issue_input: BaselineIssueInput) -> bool:
    return _definition_tuple_from_version(version) == _definition_tuple_from_input(issue_input)


def _definition_tuple_from_version(version: CatalogIssueTypeVersion) -> tuple[Any, ...]:
    return (
        version.name,
        version.description or None,
        _enum_value(version.breach_risk),
        version.threat_level,
        bool(version.affects_score),
        version.ssc_severity,
        version.ssc_metadata,
    )


def _definition_tuple_from_input(issue_input: BaselineIssueInput) -> tuple[Any, ...]:
    return (
        issue_input.name,
        issue_input.description or None,
        issue_input.breach_risk.value,
        issue_input.threat_level.value if issue_input.threat_level else None,
        issue_input.affects_score,
        issue_input.ssc_severity,
        issue_input.ssc_metadata,
    )


def _validate_optional_positions(positions: list[int | None], label: str):
    provided = [position for position in positions if position is not None]
    if not provided:
        return
    if len(provided) != len(positions):
        raise ValueError(f"{label} must either omit all positions or provide every position")
    expected = set(range(1, len(positions) + 1))
    if set(provided) != expected:
        raise ValueError(f"{label} positions must be contiguous starting at 1")


def _factor_position(baseline: GoldenBaselineInput, factor: BaselineFactorInput) -> int:
    return factor.position if factor.position is not None else baseline.factors.index(factor) + 1


def _issue_position(factor: BaselineFactorInput, issue: BaselineIssueInput) -> int:
    return issue.position if issue.position is not None else factor.issues.index(issue) + 1


def _normalize_name(value: str) -> str:
    return " ".join(value.casefold().split())


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value
