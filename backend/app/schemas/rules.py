from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.rule_models import RuleSourceTypeEnum, RuleTargetTypeEnum
from app.schemas.catalog import IssueTypeRead


class RuleBase(BaseModel):
    stable_key: str = Field(min_length=1, max_length=128)
    catalog_issue_type_id: UUID | None = None
    is_active: bool = True

    @field_validator("stable_key")
    @classmethod
    def normalize_stable_key(cls, value: str) -> str:
        return value.strip().lower()


class RuleCreate(RuleBase):
    current_version_id: UUID | None = None


class RuleUpdate(BaseModel):
    stable_key: str | None = Field(default=None, min_length=1, max_length=128)
    catalog_issue_type_id: UUID | None = None
    current_version_id: UUID | None = None
    is_active: bool | None = None

    @field_validator("stable_key")
    @classmethod
    def normalize_stable_key(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip().lower()


class RuleVersionBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    target_type: RuleTargetTypeEnum
    rule_expression: dict[str, Any] = Field(min_length=1)
    evidence_schema: dict[str, Any] | None = None
    remediation: str | None = None
    source_type: RuleSourceTypeEnum = RuleSourceTypeEnum.MANUAL
    source_reference: str | None = Field(default=None, max_length=1024)
    effective_from: datetime | None = None
    effective_to: datetime | None = None

    @field_validator("name", "description", "remediation", "source_reference")
    @classmethod
    def trim_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class RuleVersionCreate(RuleVersionBase):
    version_number: int | None = Field(default=None, ge=1)
    make_current: bool = False


class RuleVersionRead(RuleVersionBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: UUID
    version_number: int
    effective_from: datetime
    created_at: datetime


class RuleRead(RuleBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    current_version_id: UUID | None
    created_at: datetime
    updated_at: datetime
    catalog_issue_type: IssueTypeRead | None = None
    current_version: RuleVersionRead | None = None
