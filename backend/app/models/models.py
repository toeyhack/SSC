from sqlalchemy import Column, String, Boolean, Integer, ForeignKey, DateTime, func, Text
from sqlalchemy.dialects.postgresql import UUID, JSONB
import uuid
from app.db.session import Base
from sqlalchemy.orm import relationship

class Organization(Base):
    __tablename__ = "organizations"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), unique=True, nullable=False)

class Domain(Base):
    __tablename__ = "domains"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    active = Column(Boolean, default=True)
    organization = relationship("Organization")

class Host(Base):
    __tablename__ = "hosts"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain_id = Column(UUID(as_uuid=True), ForeignKey("domains.id"), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip = Column(String(64), nullable=True)
    active = Column(Boolean, default=True)
    domain = relationship("Domain")

class HostGroup(Base):
    __tablename__ = "host_groups"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)

class HostGroupMember(Base):
    __tablename__ = "host_group_members"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_id = Column(UUID(as_uuid=True), ForeignKey("hosts.id"), nullable=False)
    host_group_id = Column(UUID(as_uuid=True), ForeignKey("host_groups.id"), nullable=False)

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
