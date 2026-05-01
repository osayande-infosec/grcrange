"""
cyberresilient/services/audit_service.py

3rd Line of Defence — Audit & Assurance Service.

Records all significant actions (create, update, delete) with
before/after snapshots as immutable audit evidence.

The audit log is:
  - Append-only (no delete or update operations)
  - Tenant-isolated via RLS
  - Used by internal auditors for independent assurance
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Optional


def log_action(
    session,
    action: str,
    entity_type: str,
    entity_id: str,
    user: str = "system",
    before: Optional[dict] = None,
    after: Optional[dict] = None,
) -> None:
    """
    Write an audit log entry.
    Accepts an existing SQLAlchemy session so it runs inside
    the caller's transaction.
    """
    from cyberresilient.services.rls import get_tenant_id

    entry_id = str(uuid.uuid4())
    entry = {
        "id": entry_id,
        "tenant_id": get_tenant_id(),
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "user": user,
        "before_snapshot": _safe_serialize(before) if before else "",
        "after_snapshot": _safe_serialize(after) if after else "",
    }

    # Persist to DB if table exists
    try:
        from sqlalchemy import inspect
        if inspect(session.bind).has_table("audit_log"):
            from cyberresilient.models.db_models import AuditLogRow
            session.add(AuditLogRow(**entry))
    except Exception:
        pass


def load_audit_log(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
) -> list[dict]:
    """Query the audit trail with optional filters."""
    try:
        from cyberresilient.database import get_engine, get_session
        from sqlalchemy import inspect
        if not inspect(get_engine()).has_table("audit_log"):
            return []
    except Exception:
        return []

    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import AuditLogRow
    from cyberresilient.services.rls import tenant_filter
    session = get_session()
    try:
        q = tenant_filter(session.query(AuditLogRow), AuditLogRow)
        if entity_type:
            q = q.filter_by(entity_type=entity_type)
        if entity_id:
            q = q.filter_by(entity_id=entity_id)
        if action:
            q = q.filter_by(action=action)
        q = q.order_by(AuditLogRow.timestamp.desc()).limit(limit)
        return [r.to_dict() for r in q.all()]
    finally:
        session.close()


def audit_summary() -> dict:
    """Summary statistics for the audit dashboard."""
    entries = load_audit_log(limit=10000)
    by_action: dict[str, int] = {}
    by_entity: dict[str, int] = {}
    by_user: dict[str, int] = {}
    for e in entries:
        by_action[e["action"]] = by_action.get(e["action"], 0) + 1
        by_entity[e["entity_type"]] = by_entity.get(e["entity_type"], 0) + 1
        by_user[e["user"]] = by_user.get(e["user"], 0) + 1
    return {
        "total_entries": len(entries),
        "by_action": by_action,
        "by_entity_type": by_entity,
        "by_user": by_user,
    }


def _safe_serialize(obj: Any) -> str:
    """Serialize to JSON, handling non-serializable types."""
    try:
        return json.dumps(obj, default=str)
    except (TypeError, ValueError):
        return str(obj)
