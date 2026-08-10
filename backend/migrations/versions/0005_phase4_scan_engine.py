"""phase 4 scan engine

Revision ID: 0005_phase4_scan_engine
Revises: 0004_phase3_rule_engine
Create Date: 2026-08-10 16:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
import sqlalchemy.dialects.postgresql as pg


revision = "0005_phase4_scan_engine"
down_revision = "0004_phase3_rule_engine"
branch_labels = None
depends_on = None


scan_status_enum = sa.Enum(
    "QUEUED",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELED",
    name="scan_status",
    native_enum=False,
    create_constraint=True,
    length=32,
)

scan_target_type_enum = sa.Enum(
    "ORGANIZATION",
    "DOMAIN",
    "HOST",
    name="scan_target_type",
    native_enum=False,
    create_constraint=True,
    length=32,
)

finding_status_enum = sa.Enum(
    "OPEN",
    "CLOSED",
    "ACCEPTED_RISK",
    "FALSE_POSITIVE",
    name="finding_status",
    native_enum=False,
    create_constraint=True,
    length=32,
)


def upgrade():
    op.create_table(
        "scan_jobs",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("status", scan_status_enum, server_default="QUEUED", nullable=False),
        sa.Column("requested_by", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("selected_rule_ids", pg.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.create_index("ix_scan_jobs_status", "scan_jobs", ["status"])
    op.create_index("ix_scan_jobs_created_at", "scan_jobs", ["created_at"])

    op.create_table(
        "scan_job_targets",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_job_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", scan_target_type_enum, nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("domain_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("host_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("evidence", pg.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
    )
    op.create_index("ix_scan_job_targets_scan_job_id", "scan_job_targets", ["scan_job_id"])
    op.create_index("ix_scan_job_targets_target_type", "scan_job_targets", ["target_type"])

    op.create_table(
        "scan_runs",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_job_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("status", scan_status_enum, server_default="RUNNING", nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("summary", pg.JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
    )
    op.create_index("ix_scan_runs_scan_job_id", "scan_runs", ["scan_job_id"])
    op.create_index("ix_scan_runs_status", "scan_runs", ["status"])
    op.create_index("ix_scan_runs_started_at", "scan_runs", ["started_at"])

    op.create_table(
        "scan_findings",
        sa.Column("id", pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("scan_run_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_job_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_job_target_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("target_type", scan_target_type_enum, nullable=False),
        sa.Column("organization_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("domain_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("host_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("rule_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_version_id", pg.UUID(as_uuid=True), nullable=False),
        sa.Column("catalog_issue_type_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("catalog_issue_type_version_id", pg.UUID(as_uuid=True), nullable=True),
        sa.Column("status", finding_status_enum, server_default="OPEN", nullable=False),
        sa.Column("evidence", pg.JSONB(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["scan_run_id"], ["scan_runs.id"]),
        sa.ForeignKeyConstraint(["scan_job_id"], ["scan_jobs.id"]),
        sa.ForeignKeyConstraint(["scan_job_target_id"], ["scan_job_targets.id"]),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"]),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.ForeignKeyConstraint(["rule_id"], ["rule_engine_rules.id"]),
        sa.ForeignKeyConstraint(["rule_version_id"], ["rule_engine_rule_versions.id"]),
        sa.ForeignKeyConstraint(["catalog_issue_type_id"], ["catalog_issue_types.id"]),
        sa.ForeignKeyConstraint(["catalog_issue_type_version_id"], ["catalog_issue_type_versions.id"]),
        sa.UniqueConstraint(
            "scan_run_id",
            "scan_job_target_id",
            "rule_version_id",
            name="uq_scan_findings_run_target_rule_version",
        ),
    )
    op.create_index("ix_scan_findings_scan_run_id", "scan_findings", ["scan_run_id"])
    op.create_index("ix_scan_findings_rule_version_id", "scan_findings", ["rule_version_id"])
    op.create_index("ix_scan_findings_status", "scan_findings", ["status"])


def downgrade():
    op.drop_index("ix_scan_findings_status", table_name="scan_findings")
    op.drop_index("ix_scan_findings_rule_version_id", table_name="scan_findings")
    op.drop_index("ix_scan_findings_scan_run_id", table_name="scan_findings")
    op.drop_table("scan_findings")
    op.drop_index("ix_scan_runs_started_at", table_name="scan_runs")
    op.drop_index("ix_scan_runs_status", table_name="scan_runs")
    op.drop_index("ix_scan_runs_scan_job_id", table_name="scan_runs")
    op.drop_table("scan_runs")
    op.drop_index("ix_scan_job_targets_target_type", table_name="scan_job_targets")
    op.drop_index("ix_scan_job_targets_scan_job_id", table_name="scan_job_targets")
    op.drop_table("scan_job_targets")
    op.drop_index("ix_scan_jobs_created_at", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_status", table_name="scan_jobs")
    op.drop_table("scan_jobs")
