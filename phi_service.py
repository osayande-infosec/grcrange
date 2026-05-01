"""
cyberresilient/services/phi_service.py

PHI / PII Asset Classification Engine (Healthcare Edition).

Manages asset tagging with data classification labels (PHI, PII, etc.)
and automatically escalates risk scores and breach notification
requirements when tagged assets are involved in incidents or
control failures.

Also provides the HIPAA breach notification workflow with
regulatory timeline enforcement.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Optional

# Data classification tiers and their risk multipliers
# When an asset tagged with a classification is involved in a risk,
# the risk's inherent score is multiplied by this factor.
CLASSIFICATION_MULTIPLIERS: dict[str, float] = {
    "PHI":              2.0,    # Protected Health Information — maximum escalation
    "PII":              1.75,   # Personally Identifiable Information
    "PCI Data":         2.0,    # Payment Card Data
    "Financial Records":1.5,
    "Protected B":      1.75,   # Government classification
    "Protected A":      1.25,
    "Confidential":     1.25,
    "Internal":         1.0,
    "Public":           0.75,
}

# HIPAA breach notification timelines
HIPAA_TIMELINES = {
    "hhs_days":         60,     # Notify HHS within 60 days of discovery
    "individual_days":  60,     # Notify individuals without unreasonable delay
    "media_threshold":  500,    # Notify media if >500 individuals affected in a state
    "annual_report_threshold": 500,  # <500 individuals — annual report to HHS
}

BREACH_SEVERITY_THRESHOLDS = {
    "minor":    {"individuals": 1,    "hhs_required": False, "media_required": False},
    "moderate": {"individuals": 100,  "hhs_required": True,  "media_required": False},
    "major":    {"individuals": 500,  "hhs_required": True,  "media_required": True},
    "critical": {"individuals": 5000, "hhs_required": True,  "media_required": True},
}


def _db_available() -> bool:
    try:
        from cyberresilient.database import get_engine
        from sqlalchemy import inspect
        return inspect(get_engine()).has_table("assets")
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Asset management
# ---------------------------------------------------------------------------

def register_asset(
    name: str,
    asset_type: str,            # Server | Application | Database | Device | Service
    data_classifications: list[str],
    owner: str,
    location: str = "",
    description: str = "",
    created_by: str = "system",
) -> dict:
    """Register a new asset with data classification tags."""
    record = {
        "id": str(uuid.uuid4()),
        "name": name,
        "asset_type": asset_type,
        "data_classifications": data_classifications,
        "highest_classification": _highest_classification(data_classifications),
        "risk_multiplier": _max_multiplier(data_classifications),
        "owner": owner,
        "location": location,
        "description": description,
        "created_by": created_by,
        "created_at": date.today().isoformat(),
    }
    if _db_available():
        import json
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import AssetRow
        from cyberresilient.services.audit_service import log_action
        session = get_session()
        try:
            row = AssetRow(
                **{k: (json.dumps(v) if isinstance(v, list) else v)
                   for k, v in record.items()}
            )
            session.add(row)
            log_action(session, action="register_asset",
                       entity_type="asset", entity_id=record["id"],
                       user=created_by, after=record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return record


def _highest_classification(classifications: list[str]) -> str:
    order = list(CLASSIFICATION_MULTIPLIERS.keys())
    ranked = sorted(
        classifications,
        key=lambda c: order.index(c) if c in order else len(order),
    )
    return ranked[0] if ranked else "Internal"


def _max_multiplier(classifications: list[str]) -> float:
    return max(
        (CLASSIFICATION_MULTIPLIERS.get(c, 1.0) for c in classifications),
        default=1.0,
    )


def get_escalated_score(base_score: int, asset_classifications: list[str]) -> int:
    """
    Apply classification multiplier to a risk score.
    Used when a risk is linked to a PHI/PII-bearing asset.
    Capped at 25 (maximum 5x5 matrix score).
    """
    multiplier = _max_multiplier(asset_classifications)
    return min(25, round(base_score * multiplier))


def load_assets() -> list[dict]:
    if not _db_available():
        return []
    import json
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import AssetRow
    session = get_session()
    try:
        rows = session.query(AssetRow).order_by(AssetRow.name).all()
        result = []
        for r in rows:
            d = r.to_dict()
            if isinstance(d.get("data_classifications"), str):
                d["data_classifications"] = json.loads(d["data_classifications"])
            result.append(d)
        return result
    finally:
        session.close()


def phi_asset_summary() -> dict:
    assets = load_assets()
    phi_count = sum(1 for a in assets if "PHI" in a.get("data_classifications", []))
    pii_count = sum(1 for a in assets if "PII" in a.get("data_classifications", []))
    return {
        "total": len(assets),
        "phi_assets": phi_count,
        "pii_assets": pii_count,
        "high_risk_assets": sum(
            1 for a in assets if a.get("risk_multiplier", 1.0) >= 1.75
        ),
    }


# ---------------------------------------------------------------------------
# HIPAA Breach Notification Workflow
# ---------------------------------------------------------------------------

def create_breach_notification(
    incident_id: str,
    discovery_date: str,            # YYYY-MM-DD
    individuals_affected: int,
    phi_types_involved: list[str],  # e.g. ["names", "SSN", "medical records"]
    states_affected: list[str],
    description: str,
    created_by: str = "system",
) -> dict:
    """
    Create a HIPAA breach notification record with all required
    regulatory deadlines calculated automatically.
    """
    disc = date.fromisoformat(discovery_date)

    hhs_deadline = (disc + timedelta(days=HIPAA_TIMELINES["hhs_days"])).isoformat()
    individual_deadline = (
        disc + timedelta(days=HIPAA_TIMELINES["individual_days"])
    ).isoformat()

    media_required = any(
        individuals_affected >= HIPAA_TIMELINES["media_threshold"]
        for _ in states_affected
    )

    severity = "minor"
    for level, threshold in sorted(
        BREACH_SEVERITY_THRESHOLDS.items(),
        key=lambda x: x[1]["individuals"],
        reverse=True,
    ):
        if individuals_affected >= threshold["individuals"]:
            severity = level
            break

    record = {
        "id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "discovery_date": discovery_date,
        "individuals_affected": individuals_affected,
        "phi_types_involved": phi_types_involved,
        "states_affected": states_affected,
        "description": description,
        "severity": severity,
        "hhs_notification_deadline": hhs_deadline,
        "individual_notification_deadline": individual_deadline,
        "media_notification_required": media_required,
        "hhs_notified": False,
        "hhs_notified_at": "",
        "individuals_notified": False,
        "individuals_notified_at": "",
        "media_notified": False,
        "media_notified_at": "",
        "status": "Open",
        "created_by": created_by,
        "created_at": date.today().isoformat(),
    }

    if _db_available():
        import json
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import BreachNotificationRow
        from cyberresilient.services.audit_service import log_action
        session = get_session()
        try:
            row = BreachNotificationRow(
                **{k: (json.dumps(v) if isinstance(v, list) else v)
                   for k, v in record.items()}
            )
            session.add(row)
            log_action(session, action="create_breach_notification",
                       entity_type="breach", entity_id=record["id"],
                       user=created_by, after=record)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    return record


def get_overdue_breach_notifications() -> list[dict]:
    """Return breach notifications with missed regulatory deadlines."""
    if not _db_available():
        return []
    import json
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import BreachNotificationRow
    today = date.today().isoformat()
    session = get_session()
    try:
        rows = session.query(BreachNotificationRow).filter_by(status="Open").all()
        overdue = []
        for r in rows:
            d = r.to_dict()
            if isinstance(d.get("phi_types_involved"), str):
                d["phi_types_involved"] = json.loads(d["phi_types_involved"])
            if isinstance(d.get("states_affected"), str):
                d["states_affected"] = json.loads(d["states_affected"])
            if (
                (not d["hhs_notified"] and d["hhs_notification_deadline"] < today) or
                (not d["individuals_notified"] and d["individual_notification_deadline"] < today)
            ):
                overdue.append(d)
        return overdue
    finally:
        session.close()


SEVERITY_COLORS = {
    "minor":    "#4CAF50",
    "moderate": "#FFC107",
    "major":    "#FF9800",
    "critical": "#F44336",
}
