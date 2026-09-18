"""phase 4b authorized scan executors

Revision ID: 0006_phase4b_executors
Revises: 0005_phase4_scan_engine
Create Date: 2026-08-10 17:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
import sqlalchemy.dialects.postgresql as pg


revision = "0006_phase4b_executors"
down_revision = "0005_phase4_scan_engine"
branch_labels = None
depends_on = None


evidence_source_enum = sa.Enum(
    "MANUAL",
    "SCANNER_HTTP",
    "SCANNER_TLS",
    "SCANNER_DNS",
    "SCANNER_TCP",
    name="scan_evidence_source",
    native_enum=False,
    create_constraint=True,
    length=32,
)


def upgrade():
    for table_name in ("organizations", "domains", "hosts"):
        op.add_column(table_name, sa.Column("approved_for_scan", sa.Boolean(), server_default=sa.text("false"), nullable=False))
        op.add_column(table_name, sa.Column("allow_sensitive_network_scan", sa.Boolean(), server_default=sa.text("false"), nullable=False))
        op.add_column(table_name, sa.Column("scan_approval_notes", sa.Text(), nullable=True))

    op.add_column("scan_jobs", sa.Column("collect_observations", sa.Boolean(), server_default=sa.text("false"), nullable=False))
    op.add_column("scan_job_targets", sa.Column("scan_config", pg.JSONB(), nullable=True))

    op.create_table(
        "scan_observations",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_run_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_job_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_job_target_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_source", evidence_source_enum, nullable=False),
        sa.Column("evidence", pg.JSONB(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"]),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
        sa.ForeignKeyConstraint(["scan_job_target_id"], ["scan_job_targets.id"]),
        sa.UniqueConstraint(
            "scan_run_id",
            "scan_job_target_id",
            "evidence_source",
            name="uq_scan_observations_run_target_source",
        ),
    )
    op.create_index("ix_scan_observations_scan_run_id", "scan_observations", ["scan_run_id"])
    op.create_index("ix_scan_observations_scan_job_target_id", "scan_observations", ["scan_job_target_id"])
    op.create_index("ix_scan_observations_evidence_source", "scan_observations", ["evidence_source"])

    op.add_column("scan_findings", sa.Column("evidence_source", evidence_source_enum, nullable=True))


def downgrade():
    op.drop_column("scan_findings", "evidence_source")
    op.drop_index("ix_scan_observations_evidence_source", table_name="scan_observations")
    op.drop_index("ix_scan_observations_scan_job_target_id", table_name="scan_observations")
    op.drop_index("ix_scan_observations_scan_run_id", table_name="scan_observations")
    op.drop_table("scan_observations")

    op.drop_column("scan_job_targets", "scan_config")
    op.drop_column("scan_jobs", "collect_observations")

    for table_name in ("hosts", "domains", "organizations"):
        op.drop_column(table_name, "scan_approval_notes")
        op.drop_column(table_name, "allow_sensitive_network_scan")
        op.drop_column(table_name, "approved_for_scan")
