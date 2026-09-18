from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, DateTime, func, Text, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from app.db.session import Base
from sqlalchemy.orm import relationship

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    approved_for_scan = Column(Boolean, default=False, nullable=False)
    allow_sensitive_network_scan = Column(Boolean, default=False, nullable=False)
    scan_approval_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    domains = relationship("Domain", back_populates="organization")
    host_groups = relationship("HostGroup", back_populates="organization")

class Domain(Base):
    __tablename__ = "domains"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_domains_org_name"),
        Index("ix_domains_organization_id", "organization_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    approved_for_scan = Column(Boolean, default=False, nullable=False)
    allow_sensitive_network_scan = Column(Boolean, default=False, nullable=False)
    scan_approval_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="domains")
    hosts = relationship("Host", back_populates="domain")

class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (
        UniqueConstraint("domain_id", "hostname", name="uq_hosts_domain_hostname"),
        Index("ix_hosts_domain_id", "domain_id"),
        Index("ix_hosts_ip", "ip"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id"), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    approved_for_scan = Column(Boolean, default=False, nullable=False)
    allow_sensitive_network_scan = Column(Boolean, default=False, nullable=False)
    scan_approval_notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    domain = relationship("Domain", back_populates="hosts")
    group_memberships = relationship("HostGroupMember", back_populates="host")

class HostGroup(Base):
    __tablename__ = "host_groups"
    __table_args__ = (
        UniqueConstraint("organization_id", "name", name="uq_host_groups_org_name"),
        Index("ix_host_groups_organization_id", "organization_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

    organization = relationship("Organization", back_populates="host_groups")
    members = relationship("HostGroupMember", back_populates="host_group")

class HostGroupMember(Base):
    __tablename__ = "host_group_members"
    __table_args__ = (
        UniqueConstraint("host_id", "host_group_id", name="uq_host_group_members_host_group"),
        Index("ix_host_group_members_host_id", "host_id"),
        Index("ix_host_group_members_host_group_id", "host_group_id"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    host_group_id = Column(UUID(as_uuid=True), ForeignKey("host_groups.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)

    host = relationship("Host", back_populates="group_memberships")
    host_group = relationship("HostGroup", back_populates="members")

class Factor(Base):
    __tablename__ = "factors"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key = Column(String(128), unique=True, nullable=False)
    name = Column(String(255), nullable=False)

class IssueType(Base):
    __tablename__ = "issue_types"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key = Column(String(128), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    factor_id = Column(UUID(as_uuid=True), ForeignKey("factors.id"), nullable=True)

class IssueTypeVersion(Base):
    __tablename__ = "issue_type_versions"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issue_type_id = Column(UUID(as_uuid=True), ForeignKey("issue_types.id"), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    payload = Column(JSONB, nullable=False)
    effective_from = Column(DateTime(timezone=True), server_default=func.now())

class ScoringModel(Base):
    __tablename__ = "scoring_models"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    version = Column(String(64), nullable=False)
    weights = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
