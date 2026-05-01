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

import hmac
import hashlib
import os
import re
import secrets
import uuid
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional

SUPPORTED_INDUSTRIES = ["healthcare", "financial", "government", "enterprise"]

PLAN_TIERS = ["trial", "starter", "professional", "enterprise"]

# Trial limits
TRIAL_RISK_LIMIT = 25
TRIAL_USER_LIMIT = 3
TRIAL_DAYS = 30
SESSION_TTL_MINUTES = int(os.getenv("CYBERRESILIENT_SESSION_TTL_MINUTES", "30"))
LOGIN_RATE_LIMIT_ATTEMPTS = int(os.getenv("CYBERRESILIENT_LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("CYBERRESILIENT_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300"))
VERIFY_RATE_LIMIT_ATTEMPTS = int(os.getenv("CYBERRESILIENT_VERIFY_RATE_LIMIT_ATTEMPTS", "8"))
VERIFY_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("CYBERRESILIENT_VERIFY_RATE_LIMIT_WINDOW_SECONDS", "600"))
RESEND_RATE_LIMIT_ATTEMPTS = int(os.getenv("CYBERRESILIENT_RESEND_RATE_LIMIT_ATTEMPTS", "3"))
RESEND_RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("CYBERRESILIENT_RESEND_RATE_LIMIT_WINDOW_SECONDS", "600"))
RATE_LIMIT_BACKEND = os.getenv("CYBERRESILIENT_RATE_LIMIT_BACKEND", "auto").strip().lower()
REDIS_URL = os.getenv("CYBERRESILIENT_REDIS_URL", "").strip()
REDIS_KEY_PREFIX = os.getenv("CYBERRESILIENT_REDIS_KEY_PREFIX", "cr:rate-limit").strip() or "cr:rate-limit"

_REDIS_CLIENT: Any = None
_REDIS_INIT_ATTEMPTED = False
_LOCAL_RATE_BUCKETS: dict[str, list[float]] = {}


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

    # Generate a 6-digit email verification code
    verification_code = f"{secrets.randbelow(900000) + 100000}"

    record = {
        "id": tenant_id,
        "org_name": org_name,
        "slug": slug,
        "industry": industry,
        "plan": plan,
        "country": country,
        "admin_email": admin_email,
        "admin_name": admin_name,
        "email_verified": False,
        "email_verification_code": verification_code,
        "trial_ends_at": trial_ends or "",
        "active": True,
        "subdomain": slug,
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

def _session_secret() -> str:
    return os.getenv("CYBERRESILIENT_SESSION_SECRET", "cyberresilient-dev-session-secret")


def _build_context_signature(tenant_id: str, issued_at: str) -> str:
    payload = f"{tenant_id}:{issued_at}".encode("utf-8")
    return hmac.new(_session_secret().encode("utf-8"), payload, hashlib.sha256).hexdigest()


def _clear_session_context(st_module) -> None:
    for key in ("tenant_id", "tenant_context_issued_at", "tenant_context_sig", "current_user"):
        st_module.session_state.pop(key, None)


def _rate_limiter_state(st_module) -> dict:
    state = st_module.session_state.get("rate_limiter_state")
    if not isinstance(state, dict):
        state = {}
        st_module.session_state["rate_limiter_state"] = state
    return state


def _rate_limiter_key(action: str, identifier: str) -> str:
    return f"{action}:{(identifier or 'unknown').strip().lower()}"


def _redis_key(action: str, identifier: str) -> str:
    return f"{REDIS_KEY_PREFIX}:{_rate_limiter_key(action, identifier)}"


def _resolve_redis_url() -> str:
    return REDIS_URL or os.getenv("REDIS_URL", "").strip()


def _init_redis_client() -> Any:
    global _REDIS_CLIENT, _REDIS_INIT_ATTEMPTED
    if _REDIS_INIT_ATTEMPTED:
        return _REDIS_CLIENT
    _REDIS_INIT_ATTEMPTED = True

    redis_url = _resolve_redis_url()
    if not redis_url:
        _REDIS_CLIENT = None
        return None

    try:
        import redis

        client = redis.Redis.from_url(
            redis_url,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        client.ping()
        _REDIS_CLIENT = client
    except Exception:
        _REDIS_CLIENT = None
    return _REDIS_CLIENT


def _rate_limit_backend() -> str:
    backend = RATE_LIMIT_BACKEND
    if backend == "redis":
        return "redis" if _init_redis_client() is not None else "memory"
    if backend == "memory":
        return "memory"
    return "redis" if _init_redis_client() is not None else "memory"


def _memory_bucket(action: str, identifier: str) -> list[float]:
    key = _rate_limiter_key(action, identifier)
    try:
        import streamlit as st
        state = _rate_limiter_state(st)
        attempts = state.get(key, [])
        if not isinstance(attempts, list):
            attempts = []
        return attempts
    except Exception:
        attempts = _LOCAL_RATE_BUCKETS.get(key, [])
        if not isinstance(attempts, list):
            attempts = []
        return attempts


def _set_memory_bucket(action: str, identifier: str, attempts: list[float]) -> None:
    key = _rate_limiter_key(action, identifier)
    try:
        import streamlit as st
        state = _rate_limiter_state(st)
        state[key] = attempts
    except Exception:
        _LOCAL_RATE_BUCKETS[key] = attempts


def rate_limit_backend_info() -> dict:
    """Expose effective rate-limit backend status for diagnostics."""
    redis_url = _resolve_redis_url()
    requested = RATE_LIMIT_BACKEND if RATE_LIMIT_BACKEND in ("auto", "redis", "memory") else "auto"
    redis_available = _init_redis_client() is not None if requested in ("auto", "redis") else False
    return {
        "requested_backend": requested,
        "effective_backend": _rate_limit_backend(),
        "redis_configured": bool(redis_url),
        "redis_available": bool(redis_available),
        "redis_key_prefix": REDIS_KEY_PREFIX,
    }


def _tenant_context_valid(st_module) -> bool:
    tenant_id = st_module.session_state.get("tenant_id", "")
    issued_at = st_module.session_state.get("tenant_context_issued_at", "")
    signature = st_module.session_state.get("tenant_context_sig", "")
    if not tenant_id or not issued_at or not signature:
        return False

    expected_sig = _build_context_signature(tenant_id, issued_at)
    if not hmac.compare_digest(str(signature), expected_sig):
        return False

    try:
        issued_dt = datetime.fromisoformat(str(issued_at))
    except ValueError:
        return False
    if issued_dt.tzinfo is None:
        issued_dt = issued_dt.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - issued_dt > timedelta(minutes=SESSION_TTL_MINUTES):
        return False

    tenant = get_tenant(tenant_id)
    return bool(tenant and tenant.get("active"))


def consume_rate_limit(
    action: str,
    identifier: str,
    max_attempts: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """
    Consume one attempt for a session-local rate limit bucket.
    Returns (allowed, retry_after_seconds).
    """
    now = datetime.now(timezone.utc).timestamp()
    window_seconds = max(int(window_seconds), 1)
    max_attempts = max(int(max_attempts), 1)

    if _rate_limit_backend() == "redis":
        client = _init_redis_client()
        if client is not None:
            key = _redis_key(action, identifier)
            try:
                current_count = int(client.incr(key))
                if current_count == 1:
                    client.expire(key, window_seconds)
                if current_count > max_attempts:
                    ttl = int(client.ttl(key))
                    retry_after = ttl if ttl > 0 else window_seconds
                    return False, retry_after
                return True, 0
            except Exception:
                pass

    attempts = _memory_bucket(action, identifier)
    cutoff = now - window_seconds
    attempts = [float(ts) for ts in attempts if float(ts) > cutoff]

    if len(attempts) >= max_attempts:
        retry_after = max(1, int(window_seconds - (now - attempts[0])))
        _set_memory_bucket(action, identifier, attempts)
        return False, retry_after

    attempts.append(now)
    _set_memory_bucket(action, identifier, attempts)
    return True, 0


def clear_rate_limit(action: str, identifier: str) -> None:
    """Clear rate-limit bucket after successful authentication/verification."""
    key = _rate_limiter_key(action, identifier)
    try:
        import streamlit as st
        state = _rate_limiter_state(st)
        state.pop(key, None)
    except Exception:
        _LOCAL_RATE_BUCKETS.pop(key, None)

    if _rate_limit_backend() == "redis":
        client = _init_redis_client()
        if client is not None:
            try:
                client.delete(_redis_key(action, identifier))
            except Exception:
                pass


def login_rate_limit(tenant_id: str) -> tuple[bool, int]:
    return consume_rate_limit(
        action="tenant_login",
        identifier=tenant_id,
        max_attempts=LOGIN_RATE_LIMIT_ATTEMPTS,
        window_seconds=LOGIN_RATE_LIMIT_WINDOW_SECONDS,
    )


def verify_rate_limit(tenant_id: str) -> tuple[bool, int]:
    return consume_rate_limit(
        action="tenant_verify",
        identifier=tenant_id,
        max_attempts=VERIFY_RATE_LIMIT_ATTEMPTS,
        window_seconds=VERIFY_RATE_LIMIT_WINDOW_SECONDS,
    )


def resend_rate_limit(tenant_id: str) -> tuple[bool, int]:
    return consume_rate_limit(
        action="tenant_resend",
        identifier=tenant_id,
        max_attempts=RESEND_RATE_LIMIT_ATTEMPTS,
        window_seconds=RESEND_RATE_LIMIT_WINDOW_SECONDS,
    )

def get_current_tenant_id() -> Optional[str]:
    """Return the tenant_id from Streamlit session state."""
    try:
        import streamlit as st
        if not _tenant_context_valid(st):
            _clear_session_context(st)
            return None
        return st.session_state.get("tenant_id")
    except Exception:
        return None


def set_tenant_context(tenant_id: str) -> None:
    """Set tenant context in Streamlit session state on login."""
    tenant = get_tenant(tenant_id)
    if not tenant or not tenant.get("active"):
        raise ValueError("Cannot set tenant context for an unknown or inactive tenant.")

    try:
        import streamlit as st
        issued_at = datetime.now(timezone.utc).isoformat()
        st.session_state["tenant_id"] = tenant_id
        st.session_state["tenant_context_issued_at"] = issued_at
        st.session_state["tenant_context_sig"] = _build_context_signature(tenant_id, issued_at)

        from cyberresilient.services.auth_service import User
        roles = ["admin", "editor", "viewer"] if tenant.get("email_verified") else ["viewer"]
        st.session_state["current_user"] = User(
            username=tenant.get("admin_email") or tenant_id,
            email=tenant.get("admin_email", ""),
            display_name=tenant.get("admin_name") or tenant.get("org_name") or "Tenant User",
            roles=roles,
            tenant_id=tenant_id,
            authenticated=True,
        )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Email verification
# ---------------------------------------------------------------------------

def verify_email(tenant_id: str, code: str) -> bool:
    """
    Verify the admin email with a 6-digit code.
    Returns True if verification succeeds.
    In production, the code is emailed to admin_email.
    Here we store it in DB and verify on input.
    """
    if not _db_available():
        return False
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import TenantRow
    session = get_session()
    try:
        row = session.query(TenantRow).filter_by(id=tenant_id).first()
        if not row:
            return False
        if row.email_verified:
            return True
        if secrets.compare_digest(str(row.email_verification_code), str(code)):
            row.email_verified = True
            row.email_verification_code = ""
            session.commit()
            return True
        return False
    except Exception:
        session.rollback()
        return False
    finally:
        session.close()


def resend_verification_code(tenant_id: str) -> Optional[str]:
    """
    Generate and store a new verification code.
    In production this would trigger an email send.
    Returns the new code (for dev/demo display).
    """
    if not _db_available():
        return None
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import TenantRow
    session = get_session()
    try:
        row = session.query(TenantRow).filter_by(id=tenant_id).first()
        if not row:
            return None
        new_code = f"{secrets.randbelow(900000) + 100000}"
        row.email_verification_code = new_code
        session.commit()
        return new_code
    except Exception:
        session.rollback()
        return None
    finally:
        session.close()


def is_email_verified(tenant_id: str) -> bool:
    """Check if the tenant's admin email is verified."""
    tenant = get_tenant(tenant_id)
    if not tenant:
        return False
    return tenant.get("email_verified", False)
