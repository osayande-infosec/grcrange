"""
cyberresilient/services/compliance_service.py

Loads control catalogues from JSON files in data/ and merges
them into a single dict keyed by framework id.

3 Lines of Defence integration:
  - 1st Line (SecOps): operational evidence from access reviews,
    change requests, vulnerability remediation, SDLC activities
    automatically determines which controls are "evidence-backed"
  - 2nd Line (this service): aggregates manual attestation + operational
    evidence to calculate compliance scores
  - 3rd Line (audit): audit_service logs all changes for independent review
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from cyberresilient.config import DATA_DIR
from cyberresilient.services.industry_service import get_industry_profile


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


@lru_cache(maxsize=1)
def _load_all_catalogues() -> dict:
    """Load every JSON catalogue in data/ and merge into one dict."""
    merged: dict = {}
    for json_file in DATA_DIR.glob("controls_*.json"):
        data = _load_json(json_file)
        merged.update(data)
    return merged


def load_controls() -> dict:
    """
    Return the merged control catalogues.
    In a full implementation this would filter by active frameworks
    from the industry profile — for now it returns everything.
    """
    return _load_all_catalogues()


def _get_evidence_backed_controls() -> set[str]:
    """
    Query operational security modules (1st Line) to determine
    which controls have *actual* evidence backing them.

    Returns a set of control IDs (e.g. {"AC-2", "CM-3", ...})
    that are considered implemented based on operational data.

    Evidence rules:
      - Access Control: at least 1 completed review → AC-2, AC-6, etc.
      - Change Mgt: at least 1 approved change → CM-3, CM-5, etc.
      - Vuln Mgt: remediation rate >= 50% → SI-2, RA-5, etc.
      - SDLC: at least 1 completed activity → SA-11, etc.
    """
    from cyberresilient.services.secops_service import (
        CONTROL_EVIDENCE_MAP,
        access_review_summary,
        change_management_summary,
        vulnerability_summary,
        sdlc_summary,
    )

    backed: set[str] = set()

    # Access Control module provides evidence
    ac = access_review_summary()
    if ac["completed"] > 0:
        for fw_controls in CONTROL_EVIDENCE_MAP["access_control"].values():
            backed.update(fw_controls)

    # Change Management module provides evidence
    cm = change_management_summary()
    if cm["total_changes"] > 0 and cm["unauthorized_changes"] == 0:
        for fw_controls in CONTROL_EVIDENCE_MAP["change_management"].values():
            backed.update(fw_controls)

    # Vulnerability Management module provides evidence
    vm = vulnerability_summary()
    if vm["remediation_rate"] >= 50:
        for fw_controls in CONTROL_EVIDENCE_MAP["vulnerability_management"].values():
            backed.update(fw_controls)

    # SDLC Security module provides evidence
    sd = sdlc_summary()
    if sd["completed"] > 0:
        for fw_controls in CONTROL_EVIDENCE_MAP["sdlc_security"].values():
            backed.update(fw_controls)

    return backed


def get_compliance_score(framework_id: str) -> dict:
    """
    Calculate compliance percentage for a single framework.
    Returns dict with total, implemented, percentage, evidence_backed.

    A control counts as "implemented" if either:
      1. Manually marked "Implemented" in the JSON catalogue, OR
      2. Backed by operational evidence from 1st Line modules
    """
    controls_data = load_controls()
    fw_data = controls_data.get(framework_id, {})
    evidence_backed = _get_evidence_backed_controls()

    total = 0
    implemented = 0
    auto_implemented = 0

    # Handle different catalogue structures
    for section_key in ["families", "safeguards", "requirements", "domains",
                        "categories", "control_families"]:
        raw_sections = fw_data.get(section_key)
        if not raw_sections:
            continue

        # Normalise: new JSON files store sections as lists with pre-aggregated
        # totals/implemented counts; legacy files use dicts of control objects.
        if isinstance(raw_sections, list):
            for section in raw_sections:
                t = section.get("total", 0)
                imp = section.get("implemented", 0)
                total += t
                implemented += imp
            continue  # pre-aggregated — no deeper controls to inspect

        sections = raw_sections  # dict-based legacy format
        for section_id, section in sections.items():
            # NIST 800-53 style: families → controls
            if "controls" in section:
                for ctrl_id, ctrl in section["controls"].items():
                    total += 1
                    if ctrl.get("status") == "Implemented":
                        implemented += 1
                    elif ctrl_id in evidence_backed:
                        implemented += 1
                        auto_implemented += 1
            # HIPAA style: safeguards → standards → implementations
            if "standards" in section:
                for std_id, std in section["standards"].items():
                    for impl_id, impl in std.get("implementations", {}).items():
                        total += 1
                        if impl.get("status") == "Implemented":
                            implemented += 1
                        elif impl_id in evidence_backed:
                            implemented += 1
                            auto_implemented += 1

    pct = round((implemented / total) * 100) if total else 0
    return {
        "total": total,
        "implemented": implemented,
        "percentage": pct,
        "evidence_backed": auto_implemented,
        "manual": implemented - auto_implemented,
    }


def get_three_lines_summary() -> dict:
    """
    Return a summary across all three lines of defence for dashboard display.
    """
    from cyberresilient.services.secops_service import operational_health_score

    ops = operational_health_score()
    profile = get_industry_profile()
    frameworks = profile.get("frameworks", [])

    compliance_scores = {}
    total_controls = 0
    total_implemented = 0
    total_evidence = 0
    for fw_id in frameworks:
        score = get_compliance_score(fw_id)
        compliance_scores[fw_id] = score
        total_controls += score["total"]
        total_implemented += score["implemented"]
        total_evidence += score["evidence_backed"]

    overall_compliance = round((total_implemented / total_controls) * 100) if total_controls else 0

    return {
        "first_line": {
            "label": "1st Line — Operational Security",
            "score": ops["overall"],
            "tier": ops["tier"],
            "modules": {
                "Access Control": ops["access_control"],
                "Change Management": ops["change_management"],
                "Vulnerability Management": ops["vulnerability_management"],
                "SDLC Security": ops["sdlc_security"],
            },
        },
        "second_line": {
            "label": "2nd Line — Compliance & Risk",
            "score": overall_compliance,
            "total_controls": total_controls,
            "implemented": total_implemented,
            "evidence_backed": total_evidence,
            "manual_attestation": total_implemented - total_evidence,
            "frameworks": compliance_scores,
        },
        "third_line": {
            "label": "3rd Line — Audit & Assurance",
            "audit_trail_active": True,
            "last_assessment": "Pending",
        },
    }


# ---------------------------------------------------------------------------
# Phase 1-2: Multi-framework scoring (SOC 2, CMMC, FedRAMP, PCI DSS, NIST CSF, ISO 27001)
# Evidence staleness, dependency enforcement, compensating controls
# ---------------------------------------------------------------------------

from datetime import date, datetime, timedelta

EVIDENCE_EXPIRY_DAYS: int = 365
POLICY_ALERT_WINDOW_DAYS: int = 30

LIFECYCLE_WEIGHTS: dict[str, float] = {
    "Implemented": 1.0,
    "Compensating": 0.85,
    "Largely": 0.65,
    "Partial": 0.40,
    "Planned": 0.15,
    "Not Implemented": 0.0,
}

_STATUS_WEIGHTS_FALLBACK: dict[str, float] = {
    "Implemented": 1.0,
    "Partial": 0.5,
    "Gap": 0.0,
    "Not Implemented": 0.0,
}

CONTROL_DEPENDENCIES: dict[str, list[str]] = {
    "DE.CM-1": ["PR.AC-5"],
    "DE.CM-7": ["PR.AC-3"],
    "RS.CO-2": ["RS.RP-1"],
    "RC.CO-3": ["RC.RP-1"],
    "PR.DS-5": ["PR.AC-4"],
    "ID.RA-5": ["ID.RA-1", "ID.RA-2"],
}

COMPENSATING_CONTROLS: dict[str, list[str]] = {
    "PR.AC-1": ["PR.AC-3"],
    "DE.AE-1": ["DE.CM-1"],
    "RS.MI-1": ["RS.MI-2"],
}


def _db_available(table: str) -> bool:
    try:
        from sqlalchemy import inspect
        from cyberresilient.database import get_engine
        return inspect(get_engine()).has_table(table)
    except Exception:
        return False


def load_policies() -> list[dict]:
    if _db_available("policies"):
        from cyberresilient.database import get_session
        from cyberresilient.models.db_models import PolicyRow
        session = get_session()
        try:
            rows = session.query(PolicyRow).all()
            if rows:
                return [r.to_dict() for r in rows]
        finally:
            session.close()
    with open(DATA_DIR / "policies.json", encoding="utf-8") as f:
        return json.load(f)


def is_evidence_stale(evidence_date: str | None) -> bool:
    if not evidence_date:
        return True
    try:
        collected = datetime.strptime(evidence_date, "%Y-%m-%d").date()
        return (date.today() - collected).days > EVIDENCE_EXPIRY_DAYS
    except ValueError:
        return True


def evidence_expiry_status(evidence_date: str | None) -> dict:
    if not evidence_date:
        return {"stale": True, "days_remaining": None, "days_overdue": None}
    try:
        collected = datetime.strptime(evidence_date, "%Y-%m-%d").date()
        expires_on = collected + timedelta(days=EVIDENCE_EXPIRY_DAYS)
        delta = (expires_on - date.today()).days
        if delta > 0:
            return {"stale": False, "days_remaining": delta, "days_overdue": None}
        return {"stale": True, "days_remaining": None, "days_overdue": abs(delta)}
    except ValueError:
        return {"stale": True, "days_remaining": None, "days_overdue": None}


def _effective_weight(
    control_id: str,
    status: str,
    evidence_date: str | None,
    all_categories: dict,
) -> tuple[float, list[str]]:
    notes: list[str] = []
    weight = LIFECYCLE_WEIGHTS.get(status, _STATUS_WEIGHTS_FALLBACK.get(status, 0.0))

    if weight == 0.0:
        for comp_id in COMPENSATING_CONTROLS.get(control_id, []):
            comp = all_categories.get(comp_id, {})
            comp_weight = LIFECYCLE_WEIGHTS.get(comp.get("status", "Not Implemented"), 0.0)
            if comp_weight >= 0.5:
                weight = LIFECYCLE_WEIGHTS["Compensating"]
                notes.append(f"Compensated by {comp_id} ({comp.get('status')}); effective weight {weight:.2f}")
                break

    if is_evidence_stale(evidence_date) and weight > 0.5:
        exp = evidence_expiry_status(evidence_date)
        if exp["days_overdue"] is not None:
            notes.append(f"Evidence overdue by {exp['days_overdue']} days; weight capped at 0.50")
        else:
            notes.append("No evidence collected; weight capped at 0.50")
        weight = min(weight, 0.5)

    for prereq_id in CONTROL_DEPENDENCIES.get(control_id, []):
        prereq = all_categories.get(prereq_id, {})
        prereq_weight = LIFECYCLE_WEIGHTS.get(prereq.get("status", "Not Implemented"), 0.0)
        if prereq_weight < LIFECYCLE_WEIGHTS["Partial"] and weight > 0.5:
            notes.append(f"Prerequisite {prereq_id} is '{prereq.get('status')}'; effective weight capped at 0.50")
            weight = min(weight, 0.5)

    return weight, notes


def calc_nist_csf_scores(data: dict) -> dict:
    functions = data["nist_csf"]["functions"]
    all_categories: dict[str, dict] = {}
    for func_data in functions.values():
        for cat_id, cat in func_data["categories"].items():
            all_categories[cat_id] = cat

    scores: dict = {}
    total_score = 0.0
    total_controls = 0
    stale_evidence_count = 0
    dependency_breach_count = 0
    compensating_count = 0

    for func_name, func_data in functions.items():
        categories = func_data["categories"]
        func_total = len(categories)
        func_score = 0.0
        func_control_details = []

        for cat_id, cat in categories.items():
            status = cat.get("status", "Not Implemented")
            evidence_date = cat.get("evidence_date")
            weight, notes = _effective_weight(cat_id, status, evidence_date, all_categories)
            func_score += weight

            exp = evidence_expiry_status(evidence_date)
            if exp["stale"]:
                stale_evidence_count += 1
            if any("Prerequisite" in n for n in notes):
                dependency_breach_count += 1
            if any("Compensated" in n for n in notes):
                compensating_count += 1

            func_control_details.append({
                "id": cat_id,
                "name": cat.get("name", cat_id),
                "status": status,
                "effective_weight": round(weight, 2),
                "evidence_date": evidence_date,
                "evidence_status": exp,
                "notes": notes,
            })

        pct = round((func_score / func_total) * 100) if func_total > 0 else 0
        scores[func_name] = {
            "description": func_data["description"],
            "total_categories": func_total,
            "score": round(func_score, 1),
            "percentage": pct,
            "categories": dict(categories.items()),
            "control_details": func_control_details,
        }
        total_score += func_score
        total_controls += func_total

    overall_pct = round((total_score / total_controls) * 100) if total_controls > 0 else 0
    return {
        "functions": scores,
        "overall_percentage": overall_pct,
        "total_controls": total_controls,
        "stale_evidence_count": stale_evidence_count,
        "dependency_breach_count": dependency_breach_count,
        "compensating_count": compensating_count,
    }


def calc_iso27001_scores(data: dict) -> dict:
    domains = data["iso27001"]["domains"]
    results = []
    total_controls = 0
    total_implemented = 0
    total_partial = 0
    stale_evidence_domains = 0

    for d in domains:
        t = d["total"]
        imp = d["implemented"]
        par = d["partial"]
        evidence_date = d.get("evidence_date")
        score = imp + (par * 0.5)
        pct = round((score / t) * 100) if t > 0 else 0
        exp = evidence_expiry_status(evidence_date)
        if exp["stale"] and pct > 0:
            pct = min(pct, round(pct * 0.80))
            stale_evidence_domains += 1
        health = "Compliant" if pct >= 80 and not exp["stale"] else "At Risk" if pct >= 50 else "Non-Compliant"
        results.append({**d, "score": round(score, 1), "percentage": pct, "evidence_status": exp, "health": health})
        total_controls += t
        total_implemented += imp
        total_partial += par

    overall = total_implemented + (total_partial * 0.5)
    overall_pct = round((overall / total_controls) * 100) if total_controls > 0 else 0
    return {"domains": results, "overall_percentage": overall_pct, "total_controls": total_controls,
            "stale_evidence_domains": stale_evidence_domains}


def get_policy_summary(policies: list[dict]) -> dict:
    summary: dict[str, int] = {"Current": 0, "Under Review": 0, "Draft": 0, "Expired": 0}
    expiring_soon: list[dict] = []

    for p in policies:
        status = p.get("status", "Unknown")
        summary[status] = summary.get(status, 0) + 1
        review_date_str = p.get("next_review")
        if review_date_str and status != "Expired":
            try:
                review_date = datetime.strptime(review_date_str, "%Y-%m-%d").date()
                days_remaining = (review_date - date.today()).days
                if 0 <= days_remaining <= POLICY_ALERT_WINDOW_DAYS:
                    expiring_soon.append({"id": p.get("id"), "name": p.get("name", "Untitled"),
                                          "next_review": review_date_str, "days_remaining": days_remaining})
            except ValueError:
                pass

    return {"total": len(policies), "by_status": summary,
            "current_pct": round((summary.get("Current", 0) / len(policies)) * 100) if policies else 0,
            "expiring_soon": sorted(expiring_soon, key=lambda x: x["days_remaining"])}


def load_soc2_controls() -> dict:
    with open(DATA_DIR / "controls_soc2.json", encoding="utf-8") as f:
        return json.load(f)


def calc_soc2_scores(data: dict) -> dict:
    categories = data["soc2"]["categories"]
    results = []
    total_controls = total_implemented = total_partial = stale_categories = 0
    for cat in categories:
        t, imp, par = cat["total"], cat["implemented"], cat["partial"]
        evidence_date = cat.get("evidence_date")
        score = imp + (par * 0.5)
        pct = round((score / t) * 100) if t > 0 else 0
        exp = evidence_expiry_status(evidence_date)
        if exp["stale"] and pct > 0:
            pct = min(pct, round(pct * 0.80))
            stale_categories += 1
        health = "Compliant" if pct >= 80 and not exp["stale"] else "At Risk" if pct >= 50 else "Non-Compliant"
        results.append({**cat, "score": round(score, 1), "percentage": pct, "evidence_status": exp, "health": health})
        total_controls += t
        total_implemented += imp
        total_partial += par
    overall_pct = round(((total_implemented + total_partial * 0.5) / total_controls) * 100) if total_controls else 0
    return {"categories": results, "overall_percentage": overall_pct, "total_controls": total_controls,
            "stale_categories": stale_categories}


def load_cmmc_controls() -> dict:
    with open(DATA_DIR / "controls_cmmc.json", encoding="utf-8") as f:
        return json.load(f)


def calc_cmmc_scores(data: dict) -> dict:
    domains = data["cmmc"]["domains"]
    results = []
    total_controls = total_implemented = total_partial = stale_domains = 0
    for d in domains:
        t, imp, par = d["total"], d["implemented"], d["partial"]
        evidence_date = d.get("evidence_date")
        score = imp + (par * 0.5)
        pct = round((score / t) * 100) if t > 0 else 0
        exp = evidence_expiry_status(evidence_date)
        if exp["stale"] and pct > 0:
            pct = min(pct, round(pct * 0.80))
            stale_domains += 1
        health = "Compliant" if pct >= 80 and not exp["stale"] else "At Risk" if pct >= 50 else "Non-Compliant"
        results.append({**d, "score": round(score, 1), "percentage": pct, "evidence_status": exp, "health": health})
        total_controls += t
        total_implemented += imp
        total_partial += par
    overall_pct = round(((total_implemented + total_partial * 0.5) / total_controls) * 100) if total_controls else 0
    return {"domains": results, "overall_percentage": overall_pct, "total_controls": total_controls,
            "stale_domains": stale_domains}


def load_fedramp_controls() -> dict:
    with open(DATA_DIR / "controls_fedramp.json", encoding="utf-8") as f:
        return json.load(f)


def calc_fedramp_scores(data: dict) -> dict:
    families = data["fedramp"]["control_families"]
    results = []
    total_controls = total_implemented = total_partial = stale_families = 0
    for fam in families:
        t, imp, par = fam["total"], fam["implemented"], fam["partial"]
        evidence_date = fam.get("evidence_date")
        score = imp + (par * 0.5)
        pct = round((score / t) * 100) if t > 0 else 0
        exp = evidence_expiry_status(evidence_date)
        if exp["stale"] and pct > 0:
            pct = min(pct, round(pct * 0.80))
            stale_families += 1
        health = "Compliant" if pct >= 80 and not exp["stale"] else "At Risk" if pct >= 50 else "Non-Compliant"
        results.append({**fam, "score": round(score, 1), "percentage": pct, "evidence_status": exp, "health": health})
        total_controls += t
        total_implemented += imp
        total_partial += par
    overall_pct = round(((total_implemented + total_partial * 0.5) / total_controls) * 100) if total_controls else 0
    return {"families": results, "overall_percentage": overall_pct, "total_controls": total_controls,
            "stale_families": stale_families}


def load_pci_controls() -> dict:
    with open(DATA_DIR / "controls_pci_dss.json", encoding="utf-8") as f:
        return json.load(f)


def calc_pci_scores(data: dict) -> dict:
    requirements = data["pci_dss"]["requirements"]
    results = []
    total_controls = total_implemented = total_partial = stale_reqs = 0
    for req in requirements:
        t, imp, par = req["total"], req["implemented"], req["partial"]
        evidence_date = req.get("evidence_date")
        score = imp + (par * 0.5)
        pct = round((score / t) * 100) if t > 0 else 0
        exp = evidence_expiry_status(evidence_date)
        if exp["stale"] and pct > 0:
            pct = min(pct, round(pct * 0.80))
            stale_reqs += 1
        health = "Compliant" if pct >= 80 and not exp["stale"] else "At Risk" if pct >= 50 else "Non-Compliant"
        results.append({**req, "score": round(score, 1), "percentage": pct, "evidence_status": exp, "health": health})
        total_controls += t
        total_implemented += imp
        total_partial += par
    overall_pct = round(((total_implemented + total_partial * 0.5) / total_controls) * 100) if total_controls else 0
    return {"requirements": results, "overall_percentage": overall_pct, "total_controls": total_controls,
            "stale_requirements": stale_reqs}
