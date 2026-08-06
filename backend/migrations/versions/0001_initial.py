"""initial migration

Revision ID: 0001_initial
Revises: 
Create Date: 2026-08-06 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
import sqlalchemy.dialects.postgresql as pg

revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('organizations',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False, unique=True),
    )
    op.create_table('domains',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('organization_id', pg.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=True, server_default=sa.text('true')),
    )
    op.create_table('hosts',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('domain_id', pg.UUID(as_uuid=True), sa.ForeignKey('domains.id'), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('ip', sa.String(length=64), nullable=True),
        sa.Column('active', sa.Boolean(), nullable=True, server_default=sa.text('true')),
    )
    op.create_table('host_groups',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('organization_id', pg.UUID(as_uuid=True), sa.ForeignKey('organizations.id'), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
    )
    op.create_table('host_group_members',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('host_id', pg.UUID(as_uuid=True), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('host_group_id', pg.UUID(as_uuid=True), sa.ForeignKey('host_groups.id'), nullable=False),
    )
    op.create_table('factors',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('key', sa.String(length=128), nullable=False, unique=True),
        sa.Column('name', sa.String(length=255), nullable=False),
    )
    op.create_table('issue_types',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('key', sa.String(length=128), nullable=False, unique=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('factor_id', pg.UUID(as_uuid=True), sa.ForeignKey('factors.id'), nullable=True),
    )
    op.create_table('issue_type_versions',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('issue_type_id', pg.UUID(as_uuid=True), sa.ForeignKey('issue_types.id'), nullable=False),
        sa.Column('version', sa.Integer(), nullable=False),
        sa.Column('payload', pg.JSONB(), nullable=False),
        sa.Column('effective_from', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )
    op.create_table('scoring_models',
        sa.Column('id', pg.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=64), nullable=False),
        sa.Column('weights', pg.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()')),
    )


def downgrade():
    op.drop_table('scoring_models')
    op.drop_table('issue_type_versions')
    op.drop_table('issue_types')
    op.drop_table('factors')
    op.drop_table('host_group_members')
    op.drop_table('host_groups')
    op.drop_table('hosts')
    op.drop_table('domains')
    op.drop_table('organizations')
