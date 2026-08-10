"""phase 2 asset inventory

Revision ID: 0003_phase2_asset_inventory
Revises: 0002_phase1a_catalog
Create Date: 2026-08-10 10:00:00.000000
"""
from alembic import op
import sqlalchemy as sa


revision = "0003_phase2_asset_inventory"
down_revision = "0002_phase1a_catalog"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("organizations", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("organizations", sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False))
    op.add_column("organizations", sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.add_column("organizations", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))

    op.add_column("domains", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("domains", sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.add_column("domains", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.alter_column("domains", "active", existing_type=sa.Boolean(), nullable=False, server_default=sa.text("true"))
    op.create_unique_constraint("uq_domains_org_name", "domains", ["organization_id", "name"])
    op.create_index("ix_domains_organization_id", "domains", ["organization_id"])

    op.add_column("hosts", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("hosts", sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.add_column("hosts", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.alter_column("hosts", "active", existing_type=sa.Boolean(), nullable=False, server_default=sa.text("true"))
    op.create_unique_constraint("uq_hosts_domain_hostname", "hosts", ["domain_id", "hostname"])
    op.create_index("ix_hosts_domain_id", "hosts", ["domain_id"])
    op.create_index("ix_hosts_ip", "hosts", ["ip"])

    op.add_column("host_groups", sa.Column("description", sa.Text(), nullable=True))
    op.add_column("host_groups", sa.Column("active", sa.Boolean(), server_default=sa.text("true"), nullable=False))
    op.add_column("host_groups", sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.add_column("host_groups", sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.create_unique_constraint("uq_host_groups_org_name", "host_groups", ["organization_id", "name"])
    op.create_index("ix_host_groups_organization_id", "host_groups", ["organization_id"])

    op.add_column("host_group_members", sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False))
    op.create_unique_constraint("uq_host_group_members_host_group", "host_group_members", ["host_id", "host_group_id"])
    op.create_index("ix_host_group_members_host_id", "host_group_members", ["host_id"])
    op.create_index("ix_host_group_members_host_group_id", "host_group_members", ["host_group_id"])


def downgrade():
    op.drop_index("ix_host_group_members_host_group_id", table_name="host_group_members")
    op.drop_index("ix_host_group_members_host_id", table_name="host_group_members")
    op.drop_constraint("uq_host_group_members_host_group", "host_group_members", type_="unique")
    op.drop_column("host_group_members", "created_at")

    op.drop_index("ix_host_groups_organization_id", table_name="host_groups")
    op.drop_constraint("uq_host_groups_org_name", "host_groups", type_="unique")
    op.drop_column("host_groups", "updated_at")
    op.drop_column("host_groups", "created_at")
    op.drop_column("host_groups", "active")
    op.drop_column("host_groups", "description")

    op.drop_index("ix_hosts_ip", table_name="hosts")
    op.drop_index("ix_hosts_domain_id", table_name="hosts")
    op.drop_constraint("uq_hosts_domain_hostname", "hosts", type_="unique")
    op.alter_column("hosts", "active", existing_type=sa.Boolean(), nullable=True, server_default=sa.text("true"))
    op.drop_column("hosts", "updated_at")
    op.drop_column("hosts", "created_at")
    op.drop_column("hosts", "description")

    op.drop_index("ix_domains_organization_id", table_name="domains")
    op.drop_constraint("uq_domains_org_name", "domains", type_="unique")
    op.alter_column("domains", "active", existing_type=sa.Boolean(), nullable=True, server_default=sa.text("true"))
    op.drop_column("domains", "updated_at")
    op.drop_column("domains", "created_at")
    op.drop_column("domains", "description")

    op.drop_column("organizations", "updated_at")
    op.drop_column("organizations", "created_at")
    op.drop_column("organizations", "active")
    op.drop_column("organizations", "description")
