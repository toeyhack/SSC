from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, DateTime, func, Text, Enum
from sqlalchemy.dialects.postgresql import UUID
import enum
import uuid
from app.db.session import Base
from sqlalchemy.orm import relationship


class BreachRiskEnum(str, enum.Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"
    POSITIVE = "POSITIVE"
    UNKNOWN = "UNKNOWN"


class SourceTypeEnum(str, enum.Enum):
    MANUAL = "MANUAL"
    SSC_LICENSED_UI = "SSC_LICENSED_UI"
    SSC_PUBLIC_WEB = "SSC_PUBLIC_WEB"
    SSC_API = "SSC_API"


class CatalogFactor(Base):
    __tablename__ = "catalog_factors"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    code = Column(String(128), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    display_order = Column(Integer, nullable=True, default=0)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    issue_types = relationship("CatalogIssueType", back_populates="factor")


class CatalogIssueType(Base):
    __tablename__ = "catalog_issue_types"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stable_key = Column(String(128), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    factor_id = Column(UUID(as_uuid=True), ForeignKey("catalog_factors.id"), nullable=False)
    current_version_id = Column(UUID(as_uuid=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    factor = relationship("CatalogFactor", back_populates="issue_types")
    versions = relationship("CatalogIssueTypeVersion", back_populates="issue_type")


class CatalogIssueTypeVersion(Base):
    __tablename__ = "catalog_issue_type_versions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issue_type_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_types.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    breach_risk = Column(Enum(BreachRiskEnum), nullable=False)
    threat_level = Column(String(64), nullable=True)
    affects_score = Column(Boolean, default=True, nullable=False)
    source_type = Column(Enum(SourceTypeEnum), nullable=False)
    source_reference = Column(String(1024), nullable=True)
    source_snapshot_hash = Column(String(128), nullable=True)
    effective_from = Column(DateTime(timezone=True), server_default=func.now())
    effective_to = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    issue_type = relationship("CatalogIssueType", back_populates="versions")


class CatalogSnapshot(Base):
    __tablename__ = "catalog_snapshots"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    source_type = Column(Enum(SourceTypeEnum), nullable=False)
    source_reference = Column(String(1024), nullable=True)
    captured_at = Column(DateTime(timezone=True), server_default=func.now())
    imported_at = Column(DateTime(timezone=True), server_default=func.now())
    content_hash = Column(String(128), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    items = relationship("CatalogSnapshotItem", back_populates="snapshot")


class CatalogSnapshotItem(Base):
    __tablename__ = "catalog_snapshot_items"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    catalog_snapshot_id = Column(UUID(as_uuid=True), ForeignKey("catalog_snapshots.id"), nullable=False)
    issue_type_version_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_type_versions.id"), nullable=False)
    factor_position = Column(Integer, nullable=True)
    issue_position = Column(Integer, nullable=True)

    snapshot = relationship("CatalogSnapshot", back_populates="items")
    issue_version = relationship("CatalogIssueTypeVersion")
