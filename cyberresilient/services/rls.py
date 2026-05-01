"""
cyberresilient/services/rls.py

Row-Level Security (RLS) utilities.

Every database query in the platform MUST go through these helpers
to ensure tenant isolation. A tenant can only see its own data.

Usage:
    from cyberresilient.services.rls import tenant_filter

    # In any query:
    q = session.query(SomeRow)
    q = tenant_filter(q, SomeRow)   # appends .filter_by(tenant_id=...)
"""

from __future__ import annotations
from typing import Optional


def get_tenant_id() -> str:
    """Return the active tenant_id from Streamlit session state."""
    try:
        from cyberresilient.services.tenant_service import get_current_tenant_id
        return get_current_tenant_id() or ""
    except Exception:
        return ""


def tenant_filter(query, model_class, tenant_id: Optional[str] = None):
    """
    Apply row-level security filter to a SQLAlchemy query.
    If no tenant_id is provided, reads from session state.
    Only filters if the model has a tenant_id column and the value is non-empty.
    """
    tid = tenant_id or get_tenant_id()
    if tid and hasattr(model_class, "tenant_id"):
        return query.filter_by(tenant_id=tid)
    return query


def require_tenant_id() -> str:
    """Return the active tenant_id or raise when no tenant context exists."""
    tenant_id = get_tenant_id()
    if not tenant_id:
        raise PermissionError("No active tenant context.")
    return tenant_id


def tenant_get_by_id(session, model_class, record_id: str, id_field: str = "id"):
    """Load a single row by id within the active tenant boundary."""
    query = session.query(model_class)
    query = tenant_filter(query, model_class, require_tenant_id())
    return query.filter(getattr(model_class, id_field) == record_id).first()


def inject_tenant_id(record: dict) -> dict:
    """Inject the current tenant_id into a record dict before insert."""
    tid = get_tenant_id()
    if tid:
        record["tenant_id"] = tid
    return record
