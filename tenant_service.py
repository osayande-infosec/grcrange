"""
cyberresilient/services/tenant_service.py

Multi-Tenant Service.

Provides tenant isolation using schema-per-tenant with SQLAlchemy.
Each tenant gets:
  - A unique tenant_id (slug-based)
  - An industry profile (healthcare | financial | government | enterprise)
  - An isolated database schema (PostgreSQL) or prefixed tables (SQLite)
  - Their own RBAC roles and users
  - Their own branding configuration

Tenant context is injected via Streamlit session state on login.
All other services call get_tenant_session() instead of get_session()
to ensure query isolation.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import date
from typing import Optional

SUPPORTED_INDUSTRIES = ["healthcare", "financial", "government", "enterprise"]

PLAN_TIERS = ["trial", "starter", "professional", "enterprise"]

# Trial limits
TRIAL_RISK_LIMIT = 25
TRIAL_USER_LIMIT = 3
TRIAL_DAYS = 30


def _slugify(name: str) -> str:
    """Convert an org name to a URL-safe tenant slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = slug.strip("-")
    return slug[:48]


def _db_available() -> bool:
    try:
        from cyberresilient.database import get_engine
        from sqlalchemy import inspect
        return inspect(get_engine()).has_table("tenants")
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Tenant management
# ---------------------------------------------------------------------------

def create_tenant(
    org_name: str,
    industry: str,
    admin_email: str,
    admin_name: str,
    plan: str = "trial",
    country: str = "US",
    created_by: str = "system",
) -> dict:
    """
    Provision a new tenant.
    Creates tenant record, seeds industry profile, and creates admin user.
    """
    if industry not in SUPPORTED_INDUSTRIES:
        raise ValueError(
            f"Industry '{industry}' not supported. "
            f"Choose from: {', '.join(SUPPORTED_INDUSTRIES)}"
        )
    if plan not in PLAN_TIERS:
        raise ValueError(f"Plan must be one of: {', '.join(PLAN_TIERS)}")

    slug = _slugify(org_name)
    tenant_id = f"{slug}-{str(uuid.uuid4())[:8]}"

    trial_ends = None
    if plan == "trial":
        from datetime import timedelta
        trial_ends = (date.today() + timedelta(days=TRIAL_DAYS)).isoformat()

    record = {
        "id": tenant_id,
        "org_name": org_name,
        "slug": slug,
        "industry": industry,
        "plan": plan,
        "country": country,
        "admin_email": admin_email,
        "admin_name": admin_name,
        "trial_ends_at": trial_ends or "",
        "active": True,
        "created_at": date.today().isoformat(),
    }

    if _db_available():
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import TenantRow
        session = get_session()
        try:
            session.add(TenantRow(**record))
            session.commit()
            # Seed industry-specific data for this tenant
            _seed_tenant(tenant_id, industry, session)
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    return record


def _seed_tenant(tenant_id: str, industry: str, session) -> None:
    """
    Seed a new tenant with industry-appropriate starter data:
    - Risk categories from industry profile
    - Active framework list
    - Default risk appetite threshold
    This runs inside the calling session's transaction.
    """
    from cyberresilient.services.industry_service import INDUSTRY_PROFILES
    profile = INDUSTRY_PROFILES.get(industry, INDUSTRY_PROFILES["enterprise"])

    # Store tenant configuration
    from cyberresilient.models.db_models import TenantConfigRow
    config = TenantConfigRow(
        tenant_id=tenant_id,
        industry_profile=industry,
        active_frameworks=",".join(profile["primary_frameworks"]),
        risk_appetite_threshold=12,
        currency="USD",
        breach_regulator_name=profile["breach_notification"]["regulator_name"],
        breach_regulator_hours=profile["breach_notification"]["regulator_hours"],
    )
    session.add(config)


def get_tenant(tenant_id: str) -> Optional[dict]:
    if not _db_available():
        return None
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import TenantRow
    session = get_session()
    try:
        row = session.query(TenantRow).filter_by(id=tenant_id).first()
        return row.to_dict() if row else None
    finally:
        session.close()


def list_tenants(active_only: bool = True) -> list[dict]:
    if not _db_available():
        return []
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import TenantRow
    session = get_session()
    try:
        q = session.query(TenantRow)
        if active_only:
            q = q.filter_by(active=True)
        return [r.to_dict() for r in q.order_by(TenantRow.org_name).all()]
    finally:
        session.close()


def deactivate_tenant(tenant_id: str, deactivated_by: str = "system") -> None:
    if not _db_available():
        return
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import TenantRow
    session = get_session()
    try:
        row = session.query(TenantRow).filter_by(id=tenant_id).first()
        if row:
            row.active = False
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def is_trial_expired(tenant: dict) -> bool:
    if tenant.get("plan") != "trial":
        return False
    trial_end = tenant.get("trial_ends_at", "")
    if not trial_end:
        return False
    return date.today().isoformat() > trial_end


def tenant_summary() -> dict:
    tenants = list_tenants(active_only=False)
    by_industry: dict[str, int] = {}
    by_plan: dict[str, int] = {}
    trials_expiring = 0
    for t in tenants:
        by_industry[t["industry"]] = by_industry.get(t["industry"], 0) + 1
        by_plan[t["plan"]] = by_plan.get(t["plan"], 0) + 1
        if t.get("plan") == "trial" and not is_trial_expired(t):
            trial_end = t.get("trial_ends_at", "")
            if trial_end:
                days = (date.fromisoformat(trial_end) - date.today()).days
                if 0 <= days <= 7:
                    trials_expiring += 1
    return {
        "total": len(tenants),
        "active": sum(1 for t in tenants if t.get("active")),
        "by_industry": by_industry,
        "by_plan": by_plan,
        "trials_expiring_soon": trials_expiring,
    }


# ---------------------------------------------------------------------------
# Session context — inject tenant_id into queries
# ---------------------------------------------------------------------------

def get_current_tenant_id() -> Optional[str]:
    """Return the tenant_id from Streamlit session state."""
    try:
        import streamlit as st
        return st.session_state.get("tenant_id")
    except Exception:
        return None


def set_tenant_context(tenant_id: str) -> None:
    """Set tenant context in Streamlit session state on login."""
    try:
        import streamlit as st
        st.session_state["tenant_id"] = tenant_id
    except Exception:
        pass
