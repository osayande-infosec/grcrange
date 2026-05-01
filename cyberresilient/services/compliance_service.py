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
    for section_key in ["families", "safeguards", "requirements", "domains"]:
        sections = fw_data.get(section_key, {})
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
