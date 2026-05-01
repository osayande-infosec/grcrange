"""
cyberresilient/models/db_models.py — Full additions across all phases.

Add these classes to your existing db_models.py.
Run: alembic upgrade head after placing the migration files.
"""

from sqlalchemy import Boolean, Column, Float, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


# ── Phase 2: Healthcare ──────────────────────────────────────

class AssetRow(Base):
    __tablename__ = "assets"
    id = Column(String(36), primary_key=True)
    name = Column(String(256), nullable=False)
    asset_type = Column(String(64), nullable=False)
    data_classifications = Column(Text, nullable=False)   # JSON list
    highest_classification = Column(String(64), nullable=False)
    risk_multiplier = Column(Float, nullable=False, default=1.0)
    owner = Column(String(128), nullable=False)
    location = Column(String(256), default="")
    description = Column(Text, default="")
    created_by = Column(String(128), nullable=False)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class BreachNotificationRow(Base):
    __tablename__ = "breach_notifications"
    id = Column(String(36), primary_key=True)
    incident_id = Column(String(64), nullable=False)
    discovery_date = Column(String(10), nullable=False)
    individuals_affected = Column(Integer, nullable=False)
    phi_types_involved = Column(Text, default="")         # JSON list
    states_affected = Column(Text, default="")            # JSON list
    description = Column(Text, nullable=False)
    severity = Column(String(16), nullable=False)
    hhs_notification_deadline = Column(String(10), nullable=False)
    individual_notification_deadline = Column(String(10), nullable=False)
    media_notification_required = Column(Boolean, default=False)
    hhs_notified = Column(Boolean, default=False)
    hhs_notified_at = Column(String(10), default="")
    individuals_notified = Column(Boolean, default=False)
    individuals_notified_at = Column(String(10), default="")
    media_notified = Column(Boolean, default=False)
    media_notified_at = Column(String(10), default="")
    status = Column(String(16), default="Open")
    created_by = Column(String(128), nullable=False)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# ── Phase 4: Government ──────────────────────────────────────

class ATOSystemRow(Base):
    __tablename__ = "ato_systems"
    id = Column(String(36), primary_key=True)
    name = Column(String(256), nullable=False)
    description = Column(Text, default="")
    impact_level = Column(String(16), nullable=False)
    system_owner = Column(String(128), nullable=False)
    authorising_official = Column(String(128), nullable=False)
    isso = Column(String(128), nullable=False)
    boundary_description = Column(Text, default="")
    status = Column(String(32), default="Not Started")
    ato_granted_at = Column(String(10), default="")
    ato_expires_at = Column(String(10), default="")
    open_poam_count = Column(Integer, default=0)
    created_by = Column(String(128), nullable=False)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class POAMRow(Base):
    __tablename__ = "poam_items"
    id = Column(String(36), primary_key=True)
    system_id = Column(String(36), nullable=False)
    control_id = Column(String(64), nullable=False)
    weakness_description = Column(Text, nullable=False)
    scheduled_completion = Column(String(10), nullable=False)
    responsible_party = Column(String(128), nullable=False)
    resources_required = Column(Text, default="")
    milestones = Column(Text, default="")
    status = Column(String(32), default="Open")
    completion_date = Column(String(10), default="")
    created_by = Column(String(128), nullable=False)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# ── Phase 5: Multi-tenant ────────────────────────────────────

class TenantRow(Base):
    __tablename__ = "tenants"
    id = Column(String(64), primary_key=True)
    org_name = Column(String(256), nullable=False)
    slug = Column(String(64), nullable=False, unique=True)
    industry = Column(String(32), nullable=False)
    plan = Column(String(32), nullable=False, default="trial")
    country = Column(String(4), default="US")
    admin_email = Column(String(256), nullable=False)
    admin_name = Column(String(128), nullable=False)
    trial_ends_at = Column(String(10), default="")
    active = Column(Boolean, nullable=False, default=True)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class TenantConfigRow(Base):
    __tablename__ = "tenant_configs"
    tenant_id = Column(String(64), primary_key=True)
    industry_profile = Column(String(32), nullable=False)
    active_frameworks = Column(Text, default="")          # comma-separated
    risk_appetite_threshold = Column(Integer, default=12)
    currency = Column(String(8), default="USD")
    breach_regulator_name = Column(String(128), default="")
    breach_regulator_hours = Column(Integer, default=72)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
