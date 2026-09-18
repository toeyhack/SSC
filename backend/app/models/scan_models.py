import enum
import uuid

from sqlalchemy import Boolean, Column, DateTime, Enum, ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.db.session import Base


class ScanStatusEnum(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"


class ScanTargetTypeEnum(str, enum.Enum):
    ORGANIZATION = "ORGANIZATION"
    DOMAIN = "DOMAIN"
    HOST = "HOST"


class FindingStatusEnum(str, enum.Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class EvidenceSourceEnum(str, enum.Enum):
    MANUAL = "MANUAL"
    SCANNER_HTTP = "SCANNER_HTTP"
    SCANNER_TLS = "SCANNER_TLS"
    SCANNER_DNS = "SCANNER_DNS"
    SCANNER_TCP = "SCANNER_TCP"


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_status", "status"),
        Index("ix_scan_jobs_created_at", "created_at"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    status = Column(
        Enum(
            ScanStatusEnum,
            name="scan_status",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
        default=ScanStatusEnum.QUEUED,
    )
    requested_by = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    selected_rule_ids = Column(JSONB, nullable=True)
    collect_observations = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    targets = relationship("ScanJobTarget", back_populates="scan_job")
    runs = relationship("ScanRun", back_populates="scan_job")


class ScanJobTarget(Base):
    __tablename__ = "scan_job_targets"
    __table_args__ = (
        Index("ix_scan_job_targets_scan_job_id", "scan_job_id"),
        Index("ix_scan_job_targets_target_type", "target_type"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    target_type = Column(
        Enum(
            ScanTargetTypeEnum,
            name="scan_target_type",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id"), nullable=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=True)
    evidence = Column(JSONB, nullable=True)
    scan_config = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan_job = relationship("ScanJob", back_populates="targets")
    organization = relationship("Organization")
    domain = relationship("Domain")
    host = relationship("Host")
    observations = relationship("ScanObservation", back_populates="scan_job_target")


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        Index("ix_scan_runs_scan_job_id", "scan_job_id"),
        Index("ix_scan_runs_status", "status"),
        Index("ix_scan_runs_started_at", "started_at"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    status = Column(
        Enum(
            ScanStatusEnum,
            name="scan_status",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
        default=ScanStatusEnum.RUNNING,
    )
    started_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    summary = Column(JSONB, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan_job = relationship("ScanJob", back_populates="runs")
    findings = relationship("ScanFinding", back_populates="scan_run")
    observations = relationship("ScanObservation", back_populates="scan_run")


class ScanObservation(Base):
    __tablename__ = "scan_observations"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "scan_job_target_id",
            "evidence_source",
            name="uq_scan_observations_run_target_source",
        ),
        Index("ix_scan_observations_scan_run_id", "scan_run_id"),
        Index("ix_scan_observations_scan_job_target_id", "scan_job_target_id"),
        Index("ix_scan_observations_evidence_source", "evidence_source"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_run_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    scan_job_target_id = Column(UUID(as_uuid=True), ForeignKey("scan_job_targets.id"), nullable=False)
    evidence_source = Column(
        Enum(
            EvidenceSourceEnum,
            name="scan_evidence_source",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    evidence = Column(JSONB, nullable=False)
    observed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan_run = relationship("ScanRun", back_populates="observations")
    scan_job = relationship("ScanJob")
    scan_job_target = relationship("ScanJobTarget", back_populates="observations")


class ScanFinding(Base):
    __tablename__ = "scan_findings"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "scan_job_target_id",
            "rule_version_id",
            name="uq_scan_findings_run_target_rule_version",
        ),
        Index("ix_scan_findings_scan_run_id", "scan_run_id"),
        Index("ix_scan_findings_rule_version_id", "rule_version_id"),
        Index("ix_scan_findings_status", "status"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_run_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    scan_job_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    scan_job_target_id = Column(UUID(as_uuid=True), ForeignKey("scan_job_targets.id"), nullable=False)
    target_type = Column(
        Enum(
            ScanTargetTypeEnum,
            name="scan_target_type",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
    )
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=True)
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id"), nullable=True)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=True)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("rule_engine_rules.id"), nullable=False)
    rule_version_id = Column(UUID(as_uuid=True), ForeignKey("rule_engine_rule_versions.id"), nullable=False)
    catalog_issue_type_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_types.id"), nullable=True)
    catalog_issue_type_version_id = Column(UUID(as_uuid=True), ForeignKey("catalog_issue_type_versions.id"), nullable=True)
    status = Column(
        Enum(
            FindingStatusEnum,
            name="finding_status",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=False,
        default=FindingStatusEnum.OPEN,
    )
    evidence = Column(JSONB, nullable=True)
    evidence_source = Column(
        Enum(
            EvidenceSourceEnum,
            name="scan_evidence_source",
            native_enum=False,
            create_constraint=True,
            length=32,
        ),
        nullable=True,
    )
    observed_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    scan_run = relationship("ScanRun", back_populates="findings")
    scan_job = relationship("ScanJob")
    scan_job_target = relationship("ScanJobTarget")
    rule = relationship("RuleEngineRule")
    rule_version = relationship("RuleEngineRuleVersion")
    catalog_issue_type = relationship("CatalogIssueType")
    catalog_issue_type_version = relationship("CatalogIssueTypeVersion")
