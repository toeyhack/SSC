"""Append-only result snapshots referencing an exact scan run and scoring definition."""
import uuid
from sqlalchemy import Column, DateTime, ForeignKey, Index, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from app.db.session import Base


class ScoreResult(Base):
    __tablename__ = "score_results"
    __table_args__ = (
        UniqueConstraint(
            "scan_run_id",
            "scoring_model_hash",
            "assessment_profile_hash",
            name="uq_score_results_run_model_profile",
        ),
        Index(
            "uq_score_results_run_model_no_profile",
            "scan_run_id",
            "scoring_model_hash",
            unique=True,
            postgresql_where=text("assessment_profile_hash IS NULL"),
        ),
    )
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_run_id = Column(UUID(as_uuid=True), ForeignKey("scan_runs.id"), nullable=False)
    scoring_model_name = Column(String(255), nullable=False)
    scoring_model_version = Column(String(64), nullable=False)
    scoring_model_hash = Column(String(64), nullable=False)
    assessment_profile_name = Column(String(255), nullable=True)
    assessment_profile_version = Column(String(64), nullable=True)
    assessment_profile_hash = Column(String(64), nullable=True)
    result = Column(JSONB, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
