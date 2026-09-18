"""phase 5 immutable scoring results"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0007_phase5_score_results"
down_revision = "0006_phase4b_executors"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("score_results",
        sa.Column("id", UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_run_id", UUID(as_uuid=True), sa.ForeignKey("scan_runs.id"), nullable=False),
        sa.Column("scoring_model_name", sa.String(255), nullable=False),
        sa.Column("scoring_model_version", sa.String(64), nullable=False),
        sa.Column("scoring_model_hash", sa.String(64), nullable=False),
        sa.Column("result", JSONB(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("scan_run_id", "scoring_model_hash", name="uq_score_results_run_model"))


def downgrade():
    op.drop_table("score_results")
