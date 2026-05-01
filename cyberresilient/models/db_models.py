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
    tenant_id = Column(String(64), default="")
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
    tenant_id = Column(String(64), default="")
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
    tenant_id = Column(String(64), default="")
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
    tenant_id = Column(String(64), default="")
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
    email_verified = Column(Boolean, default=False)
    email_verification_code = Column(String(64), default="")
    trial_ends_at = Column(String(10), default="")
    active = Column(Boolean, nullable=False, default=True)
    subdomain = Column(String(64), default="")
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


# ── 1st Line of Defence: Operational Security Modules ────────

class AccessReviewRow(Base):
    """Tracks user access reviews — evidence for AC-2, AC-6, HIPAA 164.312(a), PCI 7/8, SOX LA."""
    __tablename__ = "access_reviews"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), default="")
    system_name = Column(String(256), nullable=False)
    review_type = Column(String(32), nullable=False)      # periodic | onboarding | offboarding | privilege
    reviewer = Column(String(128), nullable=False)
    total_accounts = Column(Integer, nullable=False, default=0)
    accounts_appropriate = Column(Integer, nullable=False, default=0)
    accounts_revoked = Column(Integer, nullable=False, default=0)
    accounts_modified = Column(Integer, nullable=False, default=0)
    findings = Column(Text, default="")
    status = Column(String(32), default="Scheduled")      # Scheduled | In Progress | Completed | Overdue
    scheduled_date = Column(String(10), nullable=False)
    completed_date = Column(String(10), default="")
    next_review_date = Column(String(10), default="")
    evidence_ref = Column(String(256), default="")
    created_by = Column(String(128), nullable=False)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class ChangeRequestRow(Base):
    """Tracks IT change requests — evidence for CM-3, CM-5, SOX CC, PCI 6.5."""
    __tablename__ = "change_requests"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), default="")
    title = Column(String(256), nullable=False)
    description = Column(Text, nullable=False)
    change_type = Column(String(32), nullable=False)      # standard | normal | emergency | major
    system_affected = Column(String(256), nullable=False)
    risk_level = Column(String(16), default="Medium")     # Low | Medium | High | Critical
    requested_by = Column(String(128), nullable=False)
    approved_by = Column(String(128), default="")
    implemented_by = Column(String(128), default="")
    tested_by = Column(String(128), default="")
    rollback_plan = Column(Text, default="")
    test_evidence = Column(Text, default="")
    status = Column(String(32), default="Submitted")      # Submitted | Approved | Testing | Implemented | Rolled Back | Rejected
    submitted_at = Column(String(10), nullable=False)
    approved_at = Column(String(10), default="")
    implemented_at = Column(String(10), default="")
    evidence_ref = Column(String(256), default="")
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class VulnerabilityRow(Base):
    """Tracks vulnerabilities — evidence for SI-2, SI-5, RA-5, PCI 6.3/11.3, HIPAA risk analysis."""
    __tablename__ = "vulnerabilities"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), default="")
    title = Column(String(256), nullable=False)
    cve_id = Column(String(32), default="")
    source = Column(String(64), nullable=False)           # scan | pentest | bug_bounty | vendor_advisory | manual
    severity = Column(String(16), nullable=False)         # Critical | High | Medium | Low | Info
    cvss_score = Column(Float, default=0.0)
    affected_asset = Column(String(256), nullable=False)
    affected_component = Column(String(256), default="")
    description = Column(Text, nullable=False)
    remediation = Column(Text, default="")
    status = Column(String(32), default="Open")           # Open | In Progress | Remediated | Risk Accepted | False Positive
    sla_deadline = Column(String(10), default="")         # based on severity
    discovered_at = Column(String(10), nullable=False)
    remediated_at = Column(String(10), default="")
    verified_by = Column(String(128), default="")
    evidence_ref = Column(String(256), default="")
    created_by = Column(String(128), nullable=False)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


class SDLCActivityRow(Base):
    """Tracks SDLC security activities — evidence for SA-11, PCI 6.2, SOX CC-3."""
    __tablename__ = "sdlc_activities"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), default="")
    project_name = Column(String(256), nullable=False)
    activity_type = Column(String(32), nullable=False)    # threat_model | code_review | sast | dast | pentest | dependency_scan | security_signoff
    phase = Column(String(32), nullable=False)            # requirements | design | development | testing | deployment | maintenance
    description = Column(Text, default="")
    findings_count = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    findings_resolved = Column(Integer, default=0)
    conducted_by = Column(String(128), nullable=False)
    status = Column(String(32), default="Planned")        # Planned | In Progress | Completed | Blocked
    completed_date = Column(String(10), default="")
    evidence_ref = Column(String(256), default="")
    created_by = Column(String(128), nullable=False)
    created_at = Column(String(10), nullable=False)

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


# ── 3rd Line of Defence: Audit Trail ────────────────────────

class AuditLogRow(Base):
    """Immutable audit trail for all GRC actions — 3rd Line of Defence."""
    __tablename__ = "audit_log"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), default="")
    timestamp = Column(String(30), nullable=False)
    action = Column(String(64), nullable=False)
    entity_type = Column(String(64), nullable=False)
    entity_id = Column(String(64), nullable=False)
    user = Column(String(128), nullable=False)
    before_snapshot = Column(Text, default="")
    after_snapshot = Column(Text, default="")

    def to_dict(self) -> dict:
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
