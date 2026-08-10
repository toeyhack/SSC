from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.scan_models import FindingStatusEnum, ScanStatusEnum, ScanTargetTypeEnum
from app.schemas.rules import RuleRead, RuleVersionRead


class ScanJobTargetBase(BaseModel):
    target_type: ScanTargetTypeEnum
    organization_id: UUID | None = None
    domain_id: UUID | None = None
    host_id: UUID | None = None
    evidence: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_single_target_reference(self):
        references = {
            ScanTargetTypeEnum.ORGANIZATION: self.organization_id,
            ScanTargetTypeEnum.DOMAIN: self.domain_id,
            ScanTargetTypeEnum.HOST: self.host_id,
        }
        if references[self.target_type] is None:
            raise ValueError(f"{self.target_type.value} target requires its matching id")

        non_matching = [
            value
            for target_type, value in references.items()
            if target_type != self.target_type and value is not None
        ]
        if non_matching:
            raise ValueError("scan target must set only the id matching target_type")
        return self


class ScanJobTargetCreate(ScanJobTargetBase):
    pass


class ScanJobTargetRead(ScanJobTargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_job_id: UUID
    created_at: datetime


class ScanJobCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    requested_by: str | None = Field(default=None, max_length=255)
    notes: str | None = None
    rule_ids: list[UUID] | None = None
    targets: list[ScanJobTargetCreate] = Field(min_length=1)


class ScanJobRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    status: ScanStatusEnum
    requested_by: str | None
    notes: str | None
    selected_rule_ids: list[str] | None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    targets: list[ScanJobTargetRead] = Field(default_factory=list)


class ScanRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_job_id: UUID
    status: ScanStatusEnum
    started_at: datetime
    completed_at: datetime | None
    summary: dict[str, Any] | None
    error_message: str | None
    created_at: datetime


class ScanFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scan_run_id: UUID
    scan_job_id: UUID
    scan_job_target_id: UUID
    target_type: ScanTargetTypeEnum
    organization_id: UUID | None
    domain_id: UUID | None
    host_id: UUID | None
    rule_id: UUID
    rule_version_id: UUID
    catalog_issue_type_id: UUID | None
    catalog_issue_type_version_id: UUID | None
    status: FindingStatusEnum
    evidence: dict[str, Any] | None
    observed_at: datetime
    created_at: datetime
    rule: RuleRead | None = None
    rule_version: RuleVersionRead | None = None
