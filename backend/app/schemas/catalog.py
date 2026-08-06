from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.models.catalog_models import BreachRiskEnum, SourceTypeEnum


class FactorBase(BaseModel):
    code: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    display_order: int = 0
    is_active: bool = True


class FactorCreate(FactorBase):
    pass


class FactorUpdate(BaseModel):
    code: str | None = Field(default=None, min_length=1, max_length=128)
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    display_order: int | None = None
    is_active: bool | None = None


class FactorRead(FactorBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class IssueTypeVersionBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    breach_risk: BreachRiskEnum
    threat_level: str | None = Field(default=None, max_length=64)
    affects_score: bool = True
    source_type: SourceTypeEnum
    source_reference: str | None = Field(default=None, max_length=1024)
    source_snapshot_hash: str | None = Field(default=None, max_length=128)
    effective_from: datetime | None = None
    effective_to: datetime | None = None


class IssueTypeVersionCreate(IssueTypeVersionBase):
    version_number: int | None = Field(default=None, ge=1)
    make_current: bool = False


class IssueTypeVersionRead(IssueTypeVersionBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    issue_type_id: UUID
    version_number: int
    effective_from: datetime
    created_at: datetime


class IssueTypeCreate(BaseModel):
    stable_key: str = Field(min_length=1, max_length=128)
    factor_id: UUID
    current_version_id: UUID | None = None
    is_active: bool = True


class IssueTypeUpdate(BaseModel):
    stable_key: str | None = Field(default=None, min_length=1, max_length=128)
    factor_id: UUID | None = None
    current_version_id: UUID | None = None
    is_active: bool | None = None


class IssueTypeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    stable_key: str
    factor_id: UUID
    current_version_id: UUID | None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    factor: FactorRead | None = None
    current_version: IssueTypeVersionRead | None = None


class CatalogSnapshotItemCreate(BaseModel):
    issue_type_version_id: UUID
    factor_position: int | None = None
    issue_position: int | None = None


class CatalogSnapshotItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    catalog_snapshot_id: UUID
    issue_type_version_id: UUID
    factor_position: int | None
    issue_position: int | None
    issue_version: IssueTypeVersionRead | None = None


class CatalogSnapshotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    source_type: SourceTypeEnum
    source_reference: str | None = Field(default=None, max_length=1024)
    captured_at: datetime | None = None
    imported_at: datetime | None = None
    content_hash: str = Field(min_length=1, max_length=128)
    notes: str | None = None
    items: list[CatalogSnapshotItemCreate] = Field(default_factory=list)


class CatalogSnapshotRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    source_type: SourceTypeEnum
    source_reference: str | None
    captured_at: datetime
    imported_at: datetime
    content_hash: str
    notes: str | None
    created_at: datetime
    items: list[CatalogSnapshotItemRead] = Field(default_factory=list)
