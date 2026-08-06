"""phase 1a issue catalog

Revision ID: 0002_phase1a_catalog
Revises: 0001_initial
Create Date: 2026-08-06 18:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
import sqlalchemy.dialects.postgresql as pg


revision = "0002_phase1a_catalog"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


breach_risk_enum = sa.Enum(
    "HIGH",
    "MEDIUM",
    "LOW",
    "INFORMATIONAL",
    "POSITIVE",
    "UNKNOWN",
    name="catalog_breach_risk",
    native_enum=False,
    create_constraint=True,
    length=32,
)

source_type_enum = sa.Enum(
    "MANUAL",
    "SSC_LICENSED_UI",
    "SSC_PUBLIC_WEB",
    "SSC_API",
    name="catalog_source_type",
    native_enum=False,
    create_constraint=True,
    length=32,
)


def upgrade():
    op.create_table(
        "catalog_factors",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("code", sa.String(length=128), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("display_order", sa.Integer(), server_default="0", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("code", name="uq_catalog_factors_code"),
    )

    op.create_table(
        "catalog_issue_types",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("stable_key", sa.String(length=128), nullable=False),
        sa.Column("factor_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("current_version_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["factor_id"], ["catalog_factors.id"]),
        sa.UniqueConstraint("stable_key", name="uq_catalog_issue_types_stable_key"),
    )
    op.create_index("ix_catalog_issue_types_factor_id", "catalog_issue_types", ["factor_id"])

    op.create_table(
        "catalog_issue_type_versions",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("issue_type_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("breach_risk", breach_risk_enum, nullable=False),
        sa.Column("threat_level", sa.String(length=64), nullable=True),
        sa.Column("affects_score", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("source_type", source_type_enum, nullable=False),
        sa.Column("source_reference", sa.String(length=1024), nullable=True),
        sa.Column("source_snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column("effective_from", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["issue_type_id"], ["catalog_issue_types.id"]),
        sa.UniqueConstraint(
            "issue_type_id",
            "version_number",
            name="uq_catalog_issue_type_versions_issue_version",
        ),
    )
    op.create_index(
        "ix_catalog_issue_type_versions_issue_type_id",
        "catalog_issue_type_versions",
        ["issue_type_id"],
    )
    op.create_index(
        "ix_catalog_issue_type_versions_breach_risk",
        "catalog_issue_type_versions",
        ["breach_risk"],
    )

    op.create_foreign_key(
        "fk_catalog_issue_types_current_version_id",
        "catalog_issue_types",
        "catalog_issue_type_versions",
        ["current_version_id"],
        ["id"],
    )

    op.create_table(
        "catalog_snapshots",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("source_type", source_type_enum, nullable=False),
        sa.Column("source_reference", sa.String(length=1024), nullable=True),
        sa.Column("captured_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("content_hash", sa.String(length=128), nullable=False),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )

    op.create_table(
        "catalog_snapshot_items",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("catalog_snapshot_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("issue_type_version_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("factor_position", sa.Integer(), nullable=True),
        sa.Column("issue_position", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["catalog_snapshot_id"], ["catalog_snapshots.id"]),
        sa.ForeignKeyConstraint(["issue_type_version_id"], ["catalog_issue_type_versions.id"]),
        sa.UniqueConstraint(
            "catalog_snapshot_id",
            "issue_type_version_id",
            name="uq_catalog_snapshot_items_snapshot_version",
        ),
    )
    op.create_index(
        "ix_catalog_snapshot_items_catalog_snapshot_id",
        "catalog_snapshot_items",
        ["catalog_snapshot_id"],
    )


def downgrade():
    op.drop_index("ix_catalog_snapshot_items_catalog_snapshot_id", table_name="catalog_snapshot_items")
    op.drop_table("catalog_snapshot_items")
    op.drop_table("catalog_snapshots")
    op.drop_constraint(
        "fk_catalog_issue_types_current_version_id",
        "catalog_issue_types",
        type_="foreignkey",
    )
    op.drop_index("ix_catalog_issue_type_versions_breach_risk", table_name="catalog_issue_type_versions")
    op.drop_index("ix_catalog_issue_type_versions_issue_type_id", table_name="catalog_issue_type_versions")
    op.drop_table("catalog_issue_type_versions")
    op.drop_index("ix_catalog_issue_types_factor_id", table_name="catalog_issue_types")
    op.drop_table("catalog_issue_types")
    op.drop_table("catalog_factors")
