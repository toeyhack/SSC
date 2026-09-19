"""SSC API baseline acquisition provenance; no scanner or scoring changes."""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "0008_ssc_api_baseline"
down_revision = "0007_phase5_score_results"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("catalog_issue_type_versions", sa.Column("ssc_severity", sa.String(128), nullable=True))
    op.add_column("catalog_issue_type_versions", sa.Column("ssc_metadata", JSONB, nullable=True))
    op.add_column("catalog_snapshots", sa.Column("normalized_schema_version", sa.String(128), nullable=True))
    op.add_column("catalog_snapshots", sa.Column("normalized_payload", JSONB, nullable=True))
    op.add_column("catalog_snapshots", sa.Column("raw_source", JSONB, nullable=True))
    op.add_column("catalog_snapshots", sa.Column("is_real_baseline", sa.Boolean(), nullable=False, server_default=sa.text("false")))
    op.create_index("uq_catalog_snapshots_ssc_api_hash", "catalog_snapshots", ["content_hash"],
                    unique=True, postgresql_where=sa.text("source_type = 'SSC_API'"))
    op.execute("""
        CREATE FUNCTION protect_ssc_api_snapshot() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.raw_source IS NOT NULL THEN
                RAISE EXCEPTION 'SSC API snapshots are immutable';
            END IF;
            IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
            RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER immutable_ssc_api_snapshot BEFORE UPDATE OR DELETE ON catalog_snapshots
        FOR EACH ROW EXECUTE FUNCTION protect_ssc_api_snapshot()
    """)


def downgrade():
    op.execute("DROP TRIGGER immutable_ssc_api_snapshot ON catalog_snapshots")
    op.execute("DROP FUNCTION protect_ssc_api_snapshot()")
    op.drop_index("uq_catalog_snapshots_ssc_api_hash", table_name="catalog_snapshots")
    for column in ("is_real_baseline", "raw_source", "normalized_payload", "normalized_schema_version"):
        op.drop_column("catalog_snapshots", column)
    for column in ("ssc_metadata", "ssc_severity"):
        op.drop_column("catalog_issue_type_versions", column)
