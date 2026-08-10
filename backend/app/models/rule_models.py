import enum
import uuid

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class RuleSourceTypeEnum(str, enum.Enum):
    MANUAL = "MANUAL"
    INTERNAL = "INTERNAL"
    SSC_REFERENCE = "SSC_REFERENCE"


class RuleTargetTypeEnum(str, enum.Enum):
    DOMAIN = "DOMAIN"
    HOST = "HOST"
    URL = "URL"
    CERTIFICATE = "CERTIFICATE"
    IP = "IP"
    ORGANIZATION = "ORGANIZATION"


class RuleEngineRule(Base):
    __tablename__ = "rule_engine_rules"
    __table_args__ = (
        Index("ix_rule_engine_rules_catalog_issue_type_id", "catalog_issue_type_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    stable_key = Column(String(128), unique=True, nullable=False)
    catalog_issue_type_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_types.id"), nullable=True)
    current_version_id = Column(UUID(as_uuid=True), ForeignKey("rule_engine_rule_versions.id"), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    catalog_issue_type = relationship("CatalogIssueType")
    current_version = relationship(
        "RuleEngineRuleVersion",
        foreign_keys=[current_version_id],
        post_update=True,
    )
    versions = relationship(
        "RuleEngineRuleVersion",
        back_populates="rule",
        foreign_keys="RuleEngineRuleVersion.rule_id",
        order_by="RuleEngineRuleVersion.version_number",
    )


class RuleEngineRuleVersion(Base):
    __tablename__ = "rule_engine_rule_versions"
    __table_args__ = (
        UniqueConstraint("rule_id", "version_number", name="uq_rule_engine_rule_versions_rule_version"),
        Index("ix_rule_engine_rule_versions_rule_id", "rule_id"),
        Index("ix_rule_engine_rule_versions_target_type", "target_type"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("rule_engine_rules.id"), nullable=False)
    version_number = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    target_type = Column(
        Enum(
            RuleTargetTypeEnum,
            name="rule_engine_target_type",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    rule_expression = Column(JSONB, nullable=False)
    evidence_schema = Column(JSONB, nullable=True)
    remediation = Column(Text, nullable=True)
    source_type = Column(
        Enum(
            RuleSourceTypeEnum,
            name="rule_engine_source_type",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    source_reference = Column(String(1024), nullable=True)
    effective_from = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    effective_to = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    rule = relationship(
        "RuleEngineRule",
        back_populates="versions",
        foreign_keys=[rule_id],
    )
