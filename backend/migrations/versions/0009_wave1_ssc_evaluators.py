"""Pin evaluator versions to exact catalog issue definitions.

Revision ID: 0009_wave1_ssc_evaluators
Revises: 0008_ssc_api_baseline
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0009_wave1_ssc_evaluators"
down_revision = "0008_ssc_api_baseline"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "rule_engine_rule_versions",
        sa.Column("catalog_issue_type_version_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_rule_versions_catalog_issue_version",
        "rule_engine_rule_versions",
        "catalog_issue_type_versions",
        ["catalog_issue_type_version_id"],
        ["id"],
    )
    op.create_index(
        "ix_rule_engine_rule_versions_catalog_issue_version_id",
        "rule_engine_rule_versions",
        ["catalog_issue_type_version_id"],
    )


def downgrade():
    op.drop_index(
        "ix_rule_engine_rule_versions_catalog_issue_version_id",
        table_name="rule_engine_rule_versions",
    )
    op.drop_constraint(
        "fk_rule_versions_catalog_issue_version",
        "rule_engine_rule_versions",
        type_="foreignkey",
    )
    op.drop_column("rule_engine_rule_versions", "catalog_issue_type_version_id")
