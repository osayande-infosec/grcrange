"""
alembic/versions/0005_phases1_to_5_industry_expansion.py

Master migration — all new tables for phases 1 through 5.

Revision ID: 0005_phases1_to_5
Revises: 0004_batch2_reviews_caps_vendors
"""

from alembic import op
import sqlalchemy as sa

revision = "0005_phases1_to_5"
down_revision = "0004_batch2_reviews_caps_vendors"


def upgrade() -> None:

    # Phase 2 — Healthcare
    op.create_table(
        "assets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("asset_type", sa.String(64), nullable=False),
        sa.Column("data_classifications", sa.Text, default=""),
        sa.Column("highest_classification", sa.String(64), nullable=False),
        sa.Column("risk_multiplier", sa.Float, nullable=False, default=1.0),
        sa.Column("owner", sa.String(128), nullable=False),
        sa.Column("location", sa.String(256), default=""),
        sa.Column("description", sa.Text, default=""),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.String(10), nullable=False),
    )

    op.create_table(
        "breach_notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("incident_id", sa.String(64), nullable=False),
        sa.Column("discovery_date", sa.String(10), nullable=False),
        sa.Column("individuals_affected", sa.Integer, nullable=False),
        sa.Column("phi_types_involved", sa.Text, default=""),
        sa.Column("states_affected", sa.Text, default=""),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("hhs_notification_deadline", sa.String(10), nullable=False),
        sa.Column("individual_notification_deadline", sa.String(10), nullable=False),
        sa.Column("media_notification_required", sa.Boolean, default=False),
        sa.Column("hhs_notified", sa.Boolean, default=False),
        sa.Column("hhs_notified_at", sa.String(10), default=""),
        sa.Column("individuals_notified", sa.Boolean, default=False),
        sa.Column("individuals_notified_at", sa.String(10), default=""),
        sa.Column("media_notified", sa.Boolean, default=False),
        sa.Column("media_notified_at", sa.String(10), default=""),
        sa.Column("status", sa.String(16), default="Open"),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.String(10), nullable=False),
    )

    # Phase 4 — Government
    op.create_table(
        "ato_systems",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("description", sa.Text, default=""),
        sa.Column("impact_level", sa.String(16), nullable=False),
        sa.Column("system_owner", sa.String(128), nullable=False),
        sa.Column("authorising_official", sa.String(128), nullable=False),
        sa.Column("isso", sa.String(128), nullable=False),
        sa.Column("boundary_description", sa.Text, default=""),
        sa.Column("status", sa.String(32), default="Not Started"),
        sa.Column("ato_granted_at", sa.String(10), default=""),
        sa.Column("ato_expires_at", sa.String(10), default=""),
        sa.Column("open_poam_count", sa.Integer, default=0),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.String(10), nullable=False),
    )

    op.create_table(
        "poam_items",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("system_id", sa.String(36), nullable=False),
        sa.Column("control_id", sa.String(64), nullable=False),
        sa.Column("weakness_description", sa.Text, nullable=False),
        sa.Column("scheduled_completion", sa.String(10), nullable=False),
        sa.Column("responsible_party", sa.String(128), nullable=False),
        sa.Column("resources_required", sa.Text, default=""),
        sa.Column("milestones", sa.Text, default=""),
        sa.Column("status", sa.String(32), default="Open"),
        sa.Column("completion_date", sa.String(10), default=""),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.String(10), nullable=False),
    )

    # Phase 5 — Multi-tenant
    op.create_table(
        "tenants",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("org_name", sa.String(256), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False, unique=True),
        sa.Column("industry", sa.String(32), nullable=False),
        sa.Column("plan", sa.String(32), nullable=False, default="trial"),
        sa.Column("country", sa.String(4), default="US"),
        sa.Column("admin_email", sa.String(256), nullable=False),
        sa.Column("admin_name", sa.String(128), nullable=False),
        sa.Column("trial_ends_at", sa.String(10), default=""),
        sa.Column("active", sa.Boolean, nullable=False, default=True),
        sa.Column("created_at", sa.String(10), nullable=False),
    )

    op.create_table(
        "tenant_configs",
        sa.Column("tenant_id", sa.String(64), primary_key=True),
        sa.Column("industry_profile", sa.String(32), nullable=False),
        sa.Column("active_frameworks", sa.Text, default=""),
        sa.Column("risk_appetite_threshold", sa.Integer, default=12),
        sa.Column("currency", sa.String(8), default="USD"),
        sa.Column("breach_regulator_name", sa.String(128), default=""),
        sa.Column("breach_regulator_hours", sa.Integer, default=72),
    )


def downgrade() -> None:
    for table in [
        "tenant_configs", "tenants",
        "poam_items", "ato_systems",
        "breach_notifications", "assets",
    ]:
        op.drop_table(table)
