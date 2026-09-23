"""Version persisted score snapshots by V1 assessment profile.

Revision ID: 0010_v1_assessment
Revises: 0009_wave1_ssc_evaluators
"""
from alembic import op
import sqlalchemy as sa


revision = "0010_v1_assessment"
down_revision = "0009_wave1_ssc_evaluators"
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint("uq_score_results_run_model", "score_results", type_="unique")
    op.add_column("score_results", sa.Column("assessment_profile_name", sa.String(255), nullable=True))
    op.add_column("score_results", sa.Column("assessment_profile_version", sa.String(64), nullable=True))
    op.add_column("score_results", sa.Column("assessment_profile_hash", sa.String(64), nullable=True))
    op.create_unique_constraint(
        "uq_score_results_run_model_profile",
        "score_results",
        ["scan_run_id", "scoring_model_hash", "assessment_profile_hash"],
    )
    op.create_index(
        "uq_score_results_run_model_no_profile",
        "score_results",
        ["scan_run_id", "scoring_model_hash"],
        unique=True,
        postgresql_where=sa.text("assessment_profile_hash IS NULL"),
    )


def downgrade():
    op.drop_index("uq_score_results_run_model_no_profile", table_name="score_results")
    op.drop_constraint("uq_score_results_run_model_profile", "score_results", type_="unique")
    op.drop_column("score_results", "assessment_profile_hash")
    op.drop_column("score_results", "assessment_profile_version")
    op.drop_column("score_results", "assessment_profile_name")
    op.create_unique_constraint(
        "uq_score_results_run_model",
        "score_results",
        ["scan_run_id", "scoring_model_hash"],
    )
