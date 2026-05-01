"""
cyberresilient/services/ato_service.py

FedRAMP / FISMA Authority to Operate (ATO) Workflow Service.

Manages the ATO lifecycle:
  System categorization → Security plan → Control assessment
  → Plan of Action & Milestones (POA&M) → ATO decision → Continuous monitoring

POA&M is the government equivalent of CAPs — every control weakness
identified during assessment gets a POA&M item with a scheduled
completion date that is reported to the authorising official.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Optional

# FISMA / FedRAMP impact levels
IMPACT_LEVELS = ["Low", "Moderate", "High"]

# ATO status lifecycle
ATO_STATUSES = [
    "Not Started",
    "Categorization",
    "Security Plan",
    "Assessment",
    "POA&M Development",
    "Authorization",
    "Active ATO",
    "ATO Expired",
    "Denied",
]

# POA&M item statuses
POAM_STATUSES = [
    "Open",
    "In Progress",
    "Completed",
    "Risk Accepted",
    "Vendor Dependency",
]

# ATO validity period by impact level (days)
ATO_VALIDITY: dict[str, int] = {
    "Low":      1095,   # 3 years
    "Moderate": 1095,   # 3 years
    "High":     365,    # 1 year
}


def _db_available() -> bool:
    try:
        from cyberresilient.database import get_engine
        from sqlalchemy import inspect
        return inspect(get_engine()).has_table("ato_systems")
    except Exception:
        return False


def _require_permission(permission: str) -> None:
    try:
        from cyberresilient.services.auth_service import has_permission
    except Exception:
        return
    if not has_permission(permission):
        raise PermissionError(f"Permission '{permission}' required.")


# ---------------------------------------------------------------------------
# ATO System management
# ---------------------------------------------------------------------------

def create_ato_system(
    name: str,
    description: str,
    impact_level: str,
    system_owner: str,
    authorising_official: str,
    isso: str,                  # Information System Security Officer
    boundary_description: str = "",
    created_by: str = "system",
) -> dict:
    """Register a system for ATO tracking."""
    _require_permission("admin")
    if impact_level not in IMPACT_LEVELS:
        raise ValueError(f"Impact level must be one of: {', '.join(IMPACT_LEVELS)}")

    record = {
        "id": str(uuid.uuid4()),
        "name": name,
        "description": description,
        "impact_level": impact_level,
        "system_owner": system_owner,
        "authorising_official": authorising_official,
        "isso": isso,
        "boundary_description": boundary_description,
        "status": "Not Started",
        "ato_granted_at": "",
        "ato_expires_at": "",
        "open_poam_count": 0,
        "created_by": created_by,
        "created_at": date.today().isoformat(),
    }
    # Row-level security: inject tenant_id
    from cyberresilient.services.rls import inject_tenant_id
    record = inject_tenant_id(record)

    if _db_available():
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import ATOSystemRow
        from cyberresilient.services.audit_service import log_action
        session = get_session()
        try:
            session.add(ATOSystemRow(**record))
            log_action(session, action="create_ato_system",
                       entity_type="ato_system", entity_id=record["id"],
                       user=created_by, after=record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return record


def grant_ato(
    system_id: str,
    granted_by: str,
    notes: str = "",
) -> dict:
    """Record an ATO grant and calculate expiry date."""
    _require_permission("admin")
    if not _db_available():
        raise RuntimeError("Database not available.")

    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import ATOSystemRow
    from cyberresilient.services.audit_service import log_action
    from cyberresilient.services.rls import tenant_get_by_id
    session = get_session()
    try:
        row = tenant_get_by_id(session, ATOSystemRow, system_id)
        if not row:
            raise ValueError(f"ATO system {system_id} not found.")
        before = row.to_dict()
        today = date.today()
        validity = ATO_VALIDITY.get(row.impact_level, 1095)
        row.status = "Active ATO"
        row.ato_granted_at = today.isoformat()
        row.ato_expires_at = (today + timedelta(days=validity)).isoformat()
        log_action(session, action="grant_ato",
                   entity_type="ato_system", entity_id=system_id,
                   user=granted_by, before=before, after=row.to_dict())
        session.commit()
        return row.to_dict()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def load_ato_systems() -> list[dict]:
    if not _db_available():
        return []
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import ATOSystemRow
    from cyberresilient.services.rls import tenant_filter
    session = get_session()
    try:
        q = tenant_filter(session.query(ATOSystemRow), ATOSystemRow)
        return [r.to_dict() for r in q.all()]
    finally:
        session.close()


def get_expiring_atos(days_ahead: int = 90) -> list[dict]:
    """Return ATOs expiring within the given number of days."""
    systems = load_ato_systems()
    threshold = (date.today() + timedelta(days=days_ahead)).isoformat()
    today = date.today().isoformat()
    return [
        s for s in systems
        if s["status"] == "Active ATO"
        and s.get("ato_expires_at")
        and today <= s["ato_expires_at"] <= threshold
    ]


# ---------------------------------------------------------------------------
# POA&M management
# ---------------------------------------------------------------------------

def create_poam(
    system_id: str,
    control_id: str,
    weakness_description: str,
    scheduled_completion: str,  # YYYY-MM-DD
    responsible_party: str,
    resources_required: str = "",
    milestones: str = "",
    created_by: str = "system",
) -> dict:
    """Create a Plan of Action & Milestones item."""
    _require_permission("edit_controls")
    record = {
        "id": f"POAM-{str(uuid.uuid4())[:8].upper()}",
        "system_id": system_id,
        "control_id": control_id,
        "weakness_description": weakness_description,
        "scheduled_completion": scheduled_completion,
        "responsible_party": responsible_party,
        "resources_required": resources_required,
        "milestones": milestones,
        "status": "Open",
        "completion_date": "",
        "created_by": created_by,
        "created_at": date.today().isoformat(),
    }
    # Row-level security: inject tenant_id
    from cyberresilient.services.rls import inject_tenant_id
    record = inject_tenant_id(record)

    if _db_available():
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import POAMRow, ATOSystemRow
        from cyberresilient.services.audit_service import log_action
        from cyberresilient.services.rls import tenant_get_by_id
        session = get_session()
        try:
            if not tenant_get_by_id(session, ATOSystemRow, system_id):
                raise ValueError("Target ATO system not found for current tenant.")
            session.add(POAMRow(**record))
            # Increment open POA&M count on system
            system = tenant_get_by_id(session, ATOSystemRow, system_id)
            if system:
                system.open_poam_count = (system.open_poam_count or 0) + 1
            log_action(session, action="create_poam",
                       entity_type="poam", entity_id=record["id"],
                       user=created_by, after=record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return record


def load_poams(system_id: Optional[str] = None) -> list[dict]:
    if not _db_available():
        return []
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import POAMRow
    from cyberresilient.services.rls import tenant_filter
    session = get_session()
    try:
        q = tenant_filter(session.query(POAMRow), POAMRow)
        if system_id:
            q = q.filter_by(system_id=system_id)
        return [r.to_dict() for r in q.order_by(POAMRow.scheduled_completion).all()]
    finally:
        session.close()


def get_overdue_poams() -> list[dict]:
    today = date.today().isoformat()
    return [
        p for p in load_poams()
        if p["status"] not in ("Completed", "Risk Accepted")
        and p["scheduled_completion"] < today
    ]


def poam_summary(system_id: Optional[str] = None) -> dict:
    poams = load_poams(system_id)
    by_status: dict[str, int] = {}
    for p in poams:
        by_status[p["status"]] = by_status.get(p["status"], 0) + 1
    overdue = len(get_overdue_poams())
    return {
        "total": len(poams),
        "open": by_status.get("Open", 0),
        "in_progress": by_status.get("In Progress", 0),
        "completed": by_status.get("Completed", 0),
        "overdue": overdue,
        "by_status": by_status,
    }


STATUS_COLORS = {
    "Not Started":       "#888888",
    "Categorization":    "#2196F3",
    "Security Plan":     "#2196F3",
    "Assessment":        "#FF9800",
    "POA&M Development": "#FFC107",
    "Authorization":     "#FF9800",
    "Active ATO":        "#4CAF50",
    "ATO Expired":       "#F44336",
    "Denied":            "#B71C1C",
}
