"""
cyberresilient/services/secops_service.py

1st Line of Defence — Operational Security Modules.

Provides the day-to-day security operations that generate evidence
for compliance controls. Each module maps directly to framework
controls across all industry editions:

  Access Control   → NIST AC-2/AC-6, HIPAA 164.312(a), PCI 7/8, SOX LA
  Change Mgt       → NIST CM-3/CM-5, PCI 6.5, SOX CC
  Vuln Mgt         → NIST SI-2/RA-5, PCI 6.3/11.3, HIPAA Risk Analysis
  SDLC Security    → NIST SA-11, PCI 6.2, SOX CC-3

The compliance_service reads operational data from these modules
to calculate whether controls are actually implemented — not just
manually toggled.
"""

from __future__ import annotations

import uuid
from datetime import date, timedelta
from typing import Optional


# ─────────────────────────────────────────────────────────────
# Remediation SLA by vulnerability severity (calendar days)
# ─────────────────────────────────────────────────────────────
VULN_SLA_DAYS: dict[str, int] = {
    "Critical": 15,
    "High":     30,
    "Medium":   90,
    "Low":      180,
    "Info":     365,
}

ACCESS_REVIEW_TYPES = ["periodic", "onboarding", "offboarding", "privilege"]

CHANGE_TYPES = ["standard", "normal", "emergency", "major"]
CHANGE_STATUSES = ["Submitted", "Approved", "Testing", "Implemented", "Rolled Back", "Rejected"]

VULN_SOURCES = ["scan", "pentest", "bug_bounty", "vendor_advisory", "manual"]
VULN_SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

SDLC_ACTIVITY_TYPES = ["threat_model", "code_review", "sast", "dast", "pentest", "dependency_scan", "security_signoff"]
SDLC_PHASES = ["requirements", "design", "development", "testing", "deployment", "maintenance"]

# Maps operational modules to the compliance controls they provide evidence for
CONTROL_EVIDENCE_MAP = {
    "access_control": {
        "nist_800_53": ["AC-1", "AC-2", "AC-3", "AC-5", "AC-6", "AC-7", "AC-11", "AC-12", "AC-17"],
        "hipaa": ["164.312(a)(2)(i)", "164.312(a)(2)(ii)", "164.312(a)(2)(iii)", "164.312(d)",
                  "164.308(a)(3)(ii)(A)", "164.308(a)(3)(ii)(B)", "164.308(a)(3)(ii)(C)",
                  "164.308(a)(4)(ii)(B)", "164.308(a)(4)(ii)(C)"],
        "pci_dss": ["7.1", "7.2", "7.3", "8.1", "8.2", "8.3", "8.4", "8.5", "8.6"],
        "sox_itgc": ["LA-1", "LA-2", "LA-3", "LA-4", "LA-5", "LA-6"],
    },
    "change_management": {
        "nist_800_53": ["CM-1", "CM-2", "CM-3", "CM-4", "CM-5", "CM-6"],
        "hipaa": ["164.308(a)(1)(ii)(D)", "164.312(c)(2)", "164.312(e)(2)(i)"],
        "pci_dss": ["6.1", "6.2", "6.3", "6.4", "6.5"],
        "sox_itgc": ["CC-1", "CC-2", "CC-3", "CC-4", "CC-5"],
    },
    "vulnerability_management": {
        "nist_800_53": ["SI-2", "SI-3", "SI-4", "SI-5", "SI-7", "RA-5"],
        "hipaa": ["164.308(a)(1)(ii)(A)", "164.308(a)(1)(ii)(B)",
                  "164.308(a)(5)(ii)(B)", "164.308(a)(6)(ii)"],
        "pci_dss": ["5.1", "5.2", "5.3", "5.4", "6.3", "11.3", "11.4", "11.5"],
        "sox_itgc": ["OPS-2"],
    },
    "sdlc_security": {
        "nist_800_53": ["SA-11", "CM-4", "SI-10"],
        "hipaa": ["164.308(a)(1)(ii)(A)", "164.312(c)(2)"],
        "pci_dss": ["6.1", "6.2", "6.3", "6.4"],
        "sox_itgc": ["CC-3"],
    },
}


def _db_available(table: str = "access_reviews") -> bool:
    try:
        from cyberresilient.database import get_engine
        from sqlalchemy import inspect
        return inspect(get_engine()).has_table(table)
    except Exception:
        return False


def _get_tenant_id() -> str:
    try:
        from cyberresilient.services.tenant_service import get_current_tenant_id
        return get_current_tenant_id() or ""
    except Exception:
        return ""


def _require_tenant_context() -> str:
    tenant_id = _get_tenant_id()
    if not tenant_id:
        raise PermissionError("No active tenant context.")
    return tenant_id


def _require_permission(permission: str = "edit_controls") -> None:
    try:
        from cyberresilient.services.auth_service import has_permission
    except Exception:
        return
    if not has_permission(permission):
        raise PermissionError(f"Permission '{permission}' required.")


# ═══════════════════════════════════════════════════════════════
# MODULE 1: ACCESS CONTROL
# ═══════════════════════════════════════════════════════════════

def create_access_review(
    system_name: str,
    review_type: str,
    reviewer: str,
    total_accounts: int,
    scheduled_date: str,
    created_by: str = "system",
) -> dict:
    """Schedule or record an access review."""
    _require_permission("edit_controls")
    tenant_id = _require_tenant_context()
    record = {
        "id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "system_name": system_name,
        "review_type": review_type,
        "reviewer": reviewer,
        "total_accounts": total_accounts,
        "accounts_appropriate": 0,
        "accounts_revoked": 0,
        "accounts_modified": 0,
        "findings": "",
        "status": "Scheduled",
        "scheduled_date": scheduled_date,
        "completed_date": "",
        "next_review_date": "",
        "evidence_ref": "",
        "created_by": created_by,
        "created_at": date.today().isoformat(),
    }
    if _db_available("access_reviews"):
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import AccessReviewRow
        session = get_session()
        try:
            session.add(AccessReviewRow(**record))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return record


def complete_access_review(
    review_id: str,
    accounts_appropriate: int,
    accounts_revoked: int,
    accounts_modified: int,
    findings: str = "",
    completed_by: str = "system",
) -> Optional[dict]:
    """Mark an access review as completed with results."""
    _require_permission("edit_controls")
    if not _db_available("access_reviews"):
        return None
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import AccessReviewRow
    from cyberresilient.services.rls import tenant_get_by_id
    session = get_session()
    try:
        row = tenant_get_by_id(session, AccessReviewRow, review_id)
        if not row:
            return None
        row.accounts_appropriate = accounts_appropriate
        row.accounts_revoked = accounts_revoked
        row.accounts_modified = accounts_modified
        row.findings = findings
        row.status = "Completed"
        row.completed_date = date.today().isoformat()
        # Schedule next review in 90 days
        row.next_review_date = (date.today() + timedelta(days=90)).isoformat()
        session.commit()
        return row.to_dict()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def load_access_reviews(status_filter: Optional[str] = None) -> list[dict]:
    if not _db_available("access_reviews"):
        return []
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import AccessReviewRow
    session = get_session()
    try:
        q = session.query(AccessReviewRow)
        tid = _get_tenant_id()
        if tid:
            q = q.filter_by(tenant_id=tid)
        if status_filter:
            q = q.filter_by(status=status_filter)
        return [r.to_dict() for r in q.order_by(AccessReviewRow.scheduled_date.desc()).all()]
    finally:
        session.close()


def access_review_summary() -> dict:
    reviews = load_access_reviews()
    today = date.today().isoformat()
    total = len(reviews)
    completed = sum(1 for r in reviews if r["status"] == "Completed")
    overdue = sum(1 for r in reviews if r["status"] in ("Scheduled", "In Progress") and r["scheduled_date"] < today)
    total_revoked = sum(r.get("accounts_revoked", 0) for r in reviews)
    return {
        "total_reviews": total,
        "completed": completed,
        "overdue": overdue,
        "completion_rate": round((completed / total) * 100) if total else 0,
        "total_accounts_revoked": total_revoked,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE 2: CHANGE MANAGEMENT
# ═══════════════════════════════════════════════════════════════

def create_change_request(
    title: str,
    description: str,
    change_type: str,
    system_affected: str,
    risk_level: str,
    requested_by: str,
    rollback_plan: str = "",
    created_by: str = "system",
) -> dict:
    """Submit a new change request."""
    _require_permission("edit_controls")
    tenant_id = _require_tenant_context()
    record = {
        "id": f"CHG-{str(uuid.uuid4())[:8].upper()}",
        "tenant_id": tenant_id,
        "title": title,
        "description": description,
        "change_type": change_type,
        "system_affected": system_affected,
        "risk_level": risk_level,
        "requested_by": requested_by,
        "approved_by": "",
        "implemented_by": "",
        "tested_by": "",
        "rollback_plan": rollback_plan,
        "test_evidence": "",
        "status": "Submitted",
        "submitted_at": date.today().isoformat(),
        "approved_at": "",
        "implemented_at": "",
        "evidence_ref": "",
        "created_at": date.today().isoformat(),
    }
    if _db_available("change_requests"):
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import ChangeRequestRow
        session = get_session()
        try:
            session.add(ChangeRequestRow(**record))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return record


def approve_change(change_id: str, approved_by: str) -> Optional[dict]:
    _require_permission("edit_controls")
    if not _db_available("change_requests"):
        return None
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import ChangeRequestRow
    from cyberresilient.services.rls import tenant_get_by_id
    session = get_session()
    try:
        row = tenant_get_by_id(session, ChangeRequestRow, change_id)
        if not row:
            return None
        row.approved_by = approved_by
        row.approved_at = date.today().isoformat()
        row.status = "Approved"
        session.commit()
        return row.to_dict()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def implement_change(change_id: str, implemented_by: str, test_evidence: str = "") -> Optional[dict]:
    _require_permission("edit_controls")
    if not _db_available("change_requests"):
        return None
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import ChangeRequestRow
    from cyberresilient.services.rls import tenant_get_by_id
    session = get_session()
    try:
        row = tenant_get_by_id(session, ChangeRequestRow, change_id)
        if not row:
            return None
        row.implemented_by = implemented_by
        row.implemented_at = date.today().isoformat()
        row.test_evidence = test_evidence
        row.status = "Implemented"
        session.commit()
        return row.to_dict()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def load_change_requests(status_filter: Optional[str] = None) -> list[dict]:
    if not _db_available("change_requests"):
        return []
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import ChangeRequestRow
    session = get_session()
    try:
        q = session.query(ChangeRequestRow)
        tid = _get_tenant_id()
        if tid:
            q = q.filter_by(tenant_id=tid)
        if status_filter:
            q = q.filter_by(status=status_filter)
        return [r.to_dict() for r in q.order_by(ChangeRequestRow.created_at.desc()).all()]
    finally:
        session.close()


def change_management_summary() -> dict:
    changes = load_change_requests()
    total = len(changes)
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    unauthorized = 0
    for c in changes:
        by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        by_type[c["change_type"]] = by_type.get(c["change_type"], 0) + 1
        # Unauthorized = implemented without approval
        if c["status"] == "Implemented" and not c.get("approved_by"):
            unauthorized += 1
    return {
        "total_changes": total,
        "by_status": by_status,
        "by_type": by_type,
        "unauthorized_changes": unauthorized,
        "approval_rate": round(
            (by_status.get("Approved", 0) + by_status.get("Implemented", 0)) / total * 100
        ) if total else 0,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE 3: VULNERABILITY MANAGEMENT
# ═══════════════════════════════════════════════════════════════

def create_vulnerability(
    title: str,
    source: str,
    severity: str,
    affected_asset: str,
    description: str,
    cve_id: str = "",
    cvss_score: float = 0.0,
    affected_component: str = "",
    remediation: str = "",
    created_by: str = "system",
) -> dict:
    """Record a new vulnerability finding."""
    _require_permission("edit_controls")
    tenant_id = _require_tenant_context()
    disc = date.today()
    sla_days = VULN_SLA_DAYS.get(severity, 90)
    sla_deadline = (disc + timedelta(days=sla_days)).isoformat()

    record = {
        "id": f"VULN-{str(uuid.uuid4())[:8].upper()}",
        "tenant_id": tenant_id,
        "title": title,
        "cve_id": cve_id,
        "source": source,
        "severity": severity,
        "cvss_score": cvss_score,
        "affected_asset": affected_asset,
        "affected_component": affected_component,
        "description": description,
        "remediation": remediation,
        "status": "Open",
        "sla_deadline": sla_deadline,
        "discovered_at": disc.isoformat(),
        "remediated_at": "",
        "verified_by": "",
        "evidence_ref": "",
        "created_by": created_by,
        "created_at": disc.isoformat(),
    }
    if _db_available("vulnerabilities"):
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import VulnerabilityRow
        session = get_session()
        try:
            session.add(VulnerabilityRow(**record))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return record


def remediate_vulnerability(vuln_id: str, verified_by: str) -> Optional[dict]:
    _require_permission("edit_controls")
    if not _db_available("vulnerabilities"):
        return None
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import VulnerabilityRow
    from cyberresilient.services.rls import tenant_get_by_id
    session = get_session()
    try:
        row = tenant_get_by_id(session, VulnerabilityRow, vuln_id)
        if not row:
            return None
        row.status = "Remediated"
        row.remediated_at = date.today().isoformat()
        row.verified_by = verified_by
        session.commit()
        return row.to_dict()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def load_vulnerabilities(status_filter: Optional[str] = None) -> list[dict]:
    if not _db_available("vulnerabilities"):
        return []
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import VulnerabilityRow
    session = get_session()
    try:
        q = session.query(VulnerabilityRow)
        tid = _get_tenant_id()
        if tid:
            q = q.filter_by(tenant_id=tid)
        if status_filter:
            q = q.filter_by(status=status_filter)
        return [r.to_dict() for r in q.order_by(VulnerabilityRow.discovered_at.desc()).all()]
    finally:
        session.close()


def vulnerability_summary() -> dict:
    vulns = load_vulnerabilities()
    today = date.today().isoformat()
    total = len(vulns)
    open_vulns = [v for v in vulns if v["status"] in ("Open", "In Progress")]
    overdue = sum(1 for v in open_vulns if v.get("sla_deadline", "") < today)
    by_severity: dict[str, int] = {}
    for v in open_vulns:
        by_severity[v["severity"]] = by_severity.get(v["severity"], 0) + 1
    remediated = sum(1 for v in vulns if v["status"] == "Remediated")
    mttr_days = 0
    remediated_with_dates = [
        v for v in vulns
        if v["status"] == "Remediated" and v.get("remediated_at") and v.get("discovered_at")
    ]
    if remediated_with_dates:
        total_days = sum(
            (date.fromisoformat(v["remediated_at"]) - date.fromisoformat(v["discovered_at"])).days
            for v in remediated_with_dates
        )
        mttr_days = round(total_days / len(remediated_with_dates))
    return {
        "total_vulnerabilities": total,
        "open": len(open_vulns),
        "overdue_sla": overdue,
        "remediated": remediated,
        "by_severity": by_severity,
        "mttr_days": mttr_days,
        "remediation_rate": round((remediated / total) * 100) if total else 0,
    }


# ═══════════════════════════════════════════════════════════════
# MODULE 4: SDLC SECURITY
# ═══════════════════════════════════════════════════════════════

def create_sdlc_activity(
    project_name: str,
    activity_type: str,
    phase: str,
    conducted_by: str,
    description: str = "",
    created_by: str = "system",
) -> dict:
    """Record a security activity in the SDLC."""
    _require_permission("edit_controls")
    tenant_id = _require_tenant_context()
    record = {
        "id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "project_name": project_name,
        "activity_type": activity_type,
        "phase": phase,
        "description": description,
        "findings_count": 0,
        "critical_findings": 0,
        "findings_resolved": 0,
        "conducted_by": conducted_by,
        "status": "Planned",
        "completed_date": "",
        "evidence_ref": "",
        "created_by": created_by,
        "created_at": date.today().isoformat(),
    }
    if _db_available("sdlc_activities"):
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import SDLCActivityRow
        session = get_session()
        try:
            session.add(SDLCActivityRow(**record))
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    return record


def complete_sdlc_activity(
    activity_id: str,
    findings_count: int,
    critical_findings: int,
    findings_resolved: int,
) -> Optional[dict]:
    _require_permission("edit_controls")
    if not _db_available("sdlc_activities"):
        return None
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import SDLCActivityRow
    from cyberresilient.services.rls import tenant_get_by_id
    session = get_session()
    try:
        row = tenant_get_by_id(session, SDLCActivityRow, activity_id)
        if not row:
            return None
        row.findings_count = findings_count
        row.critical_findings = critical_findings
        row.findings_resolved = findings_resolved
        row.status = "Completed"
        row.completed_date = date.today().isoformat()
        session.commit()
        return row.to_dict()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def load_sdlc_activities(project_filter: Optional[str] = None) -> list[dict]:
    if not _db_available("sdlc_activities"):
        return []
    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import SDLCActivityRow
    session = get_session()
    try:
        q = session.query(SDLCActivityRow)
        tid = _get_tenant_id()
        if tid:
            q = q.filter_by(tenant_id=tid)
        if project_filter:
            q = q.filter_by(project_name=project_filter)
        return [r.to_dict() for r in q.order_by(SDLCActivityRow.created_at.desc()).all()]
    finally:
        session.close()


def sdlc_summary() -> dict:
    activities = load_sdlc_activities()
    total = len(activities)
    completed = sum(1 for a in activities if a["status"] == "Completed")
    total_findings = sum(a.get("findings_count", 0) for a in activities)
    total_critical = sum(a.get("critical_findings", 0) for a in activities)
    total_resolved = sum(a.get("findings_resolved", 0) for a in activities)
    by_type: dict[str, int] = {}
    by_phase: dict[str, int] = {}
    for a in activities:
        by_type[a["activity_type"]] = by_type.get(a["activity_type"], 0) + 1
        by_phase[a["phase"]] = by_phase.get(a["phase"], 0) + 1
    return {
        "total_activities": total,
        "completed": completed,
        "total_findings": total_findings,
        "critical_findings": total_critical,
        "findings_resolved": total_resolved,
        "resolution_rate": round((total_resolved / total_findings) * 100) if total_findings else 0,
        "by_type": by_type,
        "by_phase": by_phase,
    }


# ═══════════════════════════════════════════════════════════════
# CROSS-MODULE: Operational Health Score
# ═══════════════════════════════════════════════════════════════

def operational_health_score() -> dict:
    """
    Calculate an overall 1st Line operational health score.
    This feeds into the compliance scoring engine — the higher
    the operational health, the more controls are evidence-backed.

    Score is 0–100 based on weighted average of module metrics:
      Access Control:  25%  (review completion rate)
      Change Mgt:      25%  (approval rate, zero unauthorized)
      Vuln Mgt:        30%  (remediation rate, SLA compliance)
      SDLC Security:   20%  (activity completion, finding resolution)
    """
    ac = access_review_summary()
    cm = change_management_summary()
    vm = vulnerability_summary()
    sd = sdlc_summary()

    # Access Control score: % of reviews completed on time
    ac_score = ac["completion_rate"]

    # Change Mgt score: approval rate, penalised by unauthorized changes
    cm_score = cm["approval_rate"]
    if cm["unauthorized_changes"] > 0:
        cm_score = max(0, cm_score - (cm["unauthorized_changes"] * 10))

    # Vuln Mgt score: remediation rate, penalised by SLA breaches
    vm_score = vm["remediation_rate"]
    if vm["open"] > 0:
        sla_compliance = max(0, 100 - (vm["overdue_sla"] / vm["open"] * 100))
        vm_score = round((vm_score + sla_compliance) / 2)

    # SDLC score: finding resolution rate
    sd_score = sd["resolution_rate"]

    overall = round(
        ac_score * 0.25 +
        cm_score * 0.25 +
        vm_score * 0.30 +
        sd_score * 0.20
    )

    return {
        "overall": overall,
        "access_control": ac_score,
        "change_management": cm_score,
        "vulnerability_management": vm_score,
        "sdlc_security": sd_score,
        "tier": (
            "Excellent" if overall >= 80 else
            "Good" if overall >= 60 else
            "Needs Improvement" if overall >= 40 else
            "Critical"
        ),
        "details": {
            "access_reviews": ac,
            "change_management": cm,
            "vulnerability_management": vm,
            "sdlc_security": sd,
        },
    }
