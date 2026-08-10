"""phase 3 rule engine

Revision ID: 0004_phase3_rule_engine
Revises: 0003_phase2_asset_inventory
Create Date: 2026-08-10 15:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
import sqlalchemy.dialects.postgresql as pg


revision = "0004_phase3_rule_engine"
down_revision = "0003_phase2_asset_inventory"
branch_labels = None
depends_on = None


rule_source_type_enum = sa.Enum(
    "MANUAL",
    "INTERNAL",
    "SSC_REFERENCE",
    name="rule_engine_source_type",
    native_enum=False,
    create_constraint=True,
    length=32,
)

rule_target_type_enum = sa.Enum(
    "DOMAIN",
    "HOST",
    "URL",
    "CERTIFICATE",
    "IP",
    "ORGANIZATION",
    name="rule_engine_target_type",
    native_enum=False,
    create_constraint=True,
    length=32,
)


def upgrade():
    op.create_table(
        "rule_engine_rules",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("stable_key", sa.String(length=128), nullable=False),
        sa.Column("catalog_issue_type_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("current_version_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["catalog_issue_type_id"], ["catalog_issue_types.id"]),
        sa.UniqueConstraint("stable_key", name="uq_rule_engine_rules_stable_key"),
    )
    op.create_index("ix_rule_engine_rules_catalog_issue_type_id", "rule_engine_rules", ["catalog_issue_type_id"])

    op.create_table(
        "rule_engine_rule_versions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("rule_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("target_type", rule_target_type_enum, nullable=False),
        sa.Column("rule_expression", pg.JSONB(), nullable=False),
        sa.Column("evidence_schema", pg.JSONB(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("source_type", rule_source_type_enum, nullable=False),
        sa.Column("source_reference", sa.String(length=1024), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["rule_id"], ["rule_engine_rules.id"]),
        sa.UniqueConstraint("rule_id", "version_number", name="uq_rule_engine_rule_versions_rule_version"),
    )
    op.create_index("ix_rule_engine_rule_versions_rule_id", "rule_engine_rule_versions", ["rule_id"])
    op.create_index("ix_rule_engine_rule_versions_target_type", "rule_engine_rule_versions", ["target_type"])

    op.create_foreign_key(
        "fk_rule_engine_rules_current_version_id",
        "rule_engine_rules",
        "rule_engine_rule_versions",
        ["current_version_id"],
        ["id"],
    )


def downgrade():
    op.drop_constraint("fk_rule_engine_rules_current_version_id", "rule_engine_rules", type_="foreignkey")
    op.drop_index("ix_rule_engine_rule_versions_target_type", table_name="rule_engine_rule_versions")
    op.drop_index("ix_rule_engine_rule_versions_rule_id", table_name="rule_engine_rule_versions")
    op.drop_table("rule_engine_rule_versions")
    op.drop_index("ix_rule_engine_rules_catalog_issue_type_id", table_name="rule_engine_rules")
    op.drop_table("rule_engine_rules")
