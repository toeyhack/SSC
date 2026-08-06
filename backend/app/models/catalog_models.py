from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
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
    display_order = Column(Integer, nullable=False, default=0, server_default="0")
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    issue_types = relationship("CatalogIssueType", back_populates="factor")


class CatalogIssueType(Base):
    __tablename__ = "catalog_issue_types"
    __table_args__ = (
        Index("ix_catalog_issue_types_factor_id", "factor_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stable_key = Column(String(128), unique=True, nullable=False)
    factor_id = Column(UUID(as_uuid=True), ForeignKey("catalog_factors.id"), nullable=False)
    current_version_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_type_versions.id"), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    factor = relationship("CatalogFactor", back_populates="issue_types")
    current_version = relationship(
        "CatalogIssueTypeVersion",
        foreign_keys=[current_version_id],
        post_update=True,
    )
    versions = relationship(
        "CatalogIssueTypeVersion",
        back_populates="issue_type",
        foreign_keys="CatalogIssueTypeVersion.issue_type_id",
        order_by="CatalogIssueTypeVersion.version_number",
    )


class CatalogIssueTypeVersion(Base):
    __tablename__ = "catalog_issue_type_versions"
    __table_args__ = (
        UniqueConstraint("issue_type_id", "version_number", name="uq_catalog_issue_type_versions_issue_version"),
        Index("ix_catalog_issue_type_versions_issue_type_id", "issue_type_id"),
        Index("ix_catalog_issue_type_versions_breach_risk", "breach_risk"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issue_type_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_types.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    breach_risk = Column(
        Enum(
            BreachRiskEnum,
            name="catalog_breach_risk",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    threat_level = Column(String(64), nullable=True)
    affects_score = Column(Boolean, default=True, nullable=False)
    source_type = Column(
        Enum(
            SourceTypeEnum,
            name="catalog_source_type",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    source_reference = Column(String(1024), nullable=True)
    source_snapshot_hash = Column(String(128), nullable=True)
    effective_from = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    effective_to = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    issue_type = relationship(
        "CatalogIssueType",
        back_populates="versions",
        foreign_keys=[issue_type_id],
    )


class CatalogSnapshot(Base):
    __tablename__ = "catalog_snapshots"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    source_type = Column(
        Enum(
            SourceTypeEnum,
            name="catalog_source_type",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    source_reference = Column(String(1024), nullable=True)
    captured_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    imported_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    content_hash = Column(String(128), nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    items = relationship("CatalogSnapshotItem", back_populates="snapshot")


class CatalogSnapshotItem(Base):
    __tablename__ = "catalog_snapshot_items"
    __table_args__ = (
        UniqueConstraint(
            "catalog_snapshot_id",
            "issue_type_version_id",
            name="uq_catalog_snapshot_items_snapshot_version",
        ),
        Index("ix_catalog_snapshot_items_catalog_snapshot_id", "catalog_snapshot_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    catalog_snapshot_id = Column(UUID(as_uuid=True), ForeignKey("catalog_snapshots.id"), nullable=False)
    issue_type_version_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_type_versions.id"), nullable=False)
    factor_position = Column(Integer, nullable=True)
    issue_position = Column(Integer, nullable=True)

    snapshot = relationship("CatalogSnapshot", back_populates="items")
    issue_version = relationship("CatalogIssueTypeVersion")
