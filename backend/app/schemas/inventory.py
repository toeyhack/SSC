from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class OrganizationBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    active: bool = True

    @field_validator("name", "description")
    @classmethod
    def trim_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class OrganizationCreate(OrganizationBase):
    pass


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    active: bool | None = None

    @field_validator("name", "description")
    @classmethod
    def trim_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class OrganizationRead(OrganizationBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime


class DomainBase(BaseModel):
    organization_id: UUID
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    active: bool = True

    @field_validator("name")
    @classmethod
    def normalize_domain_name(cls, value: str) -> str:
        return value.strip().lower().rstrip(".")

    @field_validator("description")
    @classmethod
    def trim_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class DomainCreate(DomainBase):
    pass


class DomainUpdate(BaseModel):
    organization_id: UUID | None = None
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    active: bool | None = None

    @field_validator("name")
    @classmethod
    def normalize_domain_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip().lower().rstrip(".")

    @field_validator("description")
    @classmethod
    def trim_description(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class DomainRead(DomainBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime
    organization: OrganizationRead | None = None


class HostBase(BaseModel):
    domain_id: UUID
    hostname: str = Field(min_length=1, max_length=255)
    ip: str | None = Field(default=None, max_length=64)
    description: str | None = None
    active: bool = True

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        return value.strip().lower().rstrip(".")

    @field_validator("ip", "description")
    @classmethod
    def trim_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class HostCreate(HostBase):
    pass


class HostUpdate(BaseModel):
    domain_id: UUID | None = None
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    ip: str | None = Field(default=None, max_length=64)
    description: str | None = None
    active: bool | None = None

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip().lower().rstrip(".")

    @field_validator("ip", "description")
    @classmethod
    def trim_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class HostRead(HostBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime
    domain: DomainRead | None = None


class HostGroupBase(BaseModel):
    organization_id: UUID
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    active: bool = True

    @field_validator("name", "description")
    @classmethod
    def trim_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class HostGroupCreate(HostGroupBase):
    pass


class HostGroupUpdate(BaseModel):
    organization_id: UUID | None = None
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None
    active: bool | None = None

    @field_validator("name", "description")
    @classmethod
    def trim_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None


class HostGroupRead(HostGroupBase):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    created_at: datetime
    updated_at: datetime
    organization: OrganizationRead | None = None


class HostGroupMemberCreate(BaseModel):
    host_id: UUID


class HostGroupMemberRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    host_id: UUID
    host_group_id: UUID
    created_at: datetime
    host: HostRead | None = None
