"""
cyberresilient/services/industry_service.py

Industry Profile Service.

Loads the correct control catalogues, risk categories, regulatory
frameworks, breach notification SLAs, and report templates based
on the industry profile set in org_profile.yaml.

This is the central router that makes CyberResilient multi-sector.
All other services call get_active_frameworks() and get_risk_categories()
rather than hardcoding NIST CSF or healthcare-specific values.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from cyberresilient.config import get_config, DATA_DIR

# ---------------------------------------------------------------------------
# Profile definitions
# ---------------------------------------------------------------------------

INDUSTRY_PROFILES: dict[str, dict] = {
    "healthcare": {
        "label": "Healthcare",
        "icon": "🏥",
        "frameworks": ["nist_csf", "iso27001", "hipaa", "hitrust"],
        "primary_frameworks": ["hipaa", "nist_csf"],
        "risk_categories": [
            "PHI Data Breach", "Ransomware / Malware", "Medical Device Security",
            "Third-Party / BAA Compliance", "Insider Threat", "Identity & Access",
            "Cloud / EHR Security", "Regulatory Compliance", "Physical Security",
            "Business Continuity", "Vulnerability Management", "Other",
        ],
        "data_classifications": ["PHI", "PII", "Internal", "Public"],
        "breach_notification": {
            "regulator_hours": 1440,   # 60 days = HIPAA HHS notification
            "individual_hours": 1440,
            "regulator_name": "HHS Office for Civil Rights",
        },
        "kpis": [
            "PHI Breach Incidents", "BAA Coverage %",
            "EHR Access Reviews Completed", "HIPAA Training Completion %",
            "Medical Device Patch Compliance %",
        ],
        "catalogue_files": [
            "controls_nist_csf.json",
            "controls_iso27001.json",
            "controls_hipaa.json",
        ],
        "report_templates": [
            "executive_brief", "risk_register", "compliance_summary",
            "hipaa_risk_analysis", "breach_notification",
        ],
    },

    "financial": {
        "label": "Financial Services",
        "icon": "🏦",
        "frameworks": ["nist_csf", "iso27001", "pci_dss", "sox_itgc", "dora"],
        "primary_frameworks": ["pci_dss", "sox_itgc"],
        "risk_categories": [
            "Payment Card Data Breach", "Fraud & Financial Crime",
            "Third-Party / Vendor Risk", "Insider Threat", "Ransomware",
            "Regulatory Compliance", "Identity & Access", "Cloud Security",
            "Operational Resilience", "Cyber Insurance Gap",
            "Vulnerability Management", "Other",
        ],
        "data_classifications": ["PCI Data", "PII", "Financial Records", "Internal", "Public"],
        "breach_notification": {
            "regulator_hours": 72,
            "individual_hours": 168,   # 7 days
            "regulator_name": "OSFI / FINTRAC",
        },
        "kpis": [
            "PCI DSS Compliance %", "SOX Control Deficiencies",
            "Fraud Detection Rate", "Operational Loss Events",
            "Third-Party Risk Coverage %",
        ],
        "catalogue_files": [
            "controls_nist_csf.json",
            "controls_iso27001.json",
            "controls_pci_dss.json",
            "controls_sox_itgc.json",
        ],
        "scoring_model": "fair",       # Quantitative FAIR scoring
        "report_templates": [
            "executive_brief", "risk_register", "compliance_summary",
            "pci_saq", "fair_quantitative", "breach_notification",
        ],
    },

    "government": {
        "label": "Government",
        "icon": "🏛️",
        "frameworks": ["nist_csf", "nist_800_53", "fedramp", "fisma", "cmmc"],
        "primary_frameworks": ["nist_800_53", "fedramp"],
        "risk_categories": [
            "Nation-State Threat", "Insider Threat", "Critical Infrastructure",
            "Supply Chain / Third-Party", "Ransomware", "Data Classification Breach",
            "Identity & Privileged Access", "Cloud / FedRAMP Boundary",
            "Physical & Personnel Security", "Regulatory / ATIP Compliance",
            "Vulnerability Management", "Other",
        ],
        "data_classifications": [
            "Top Secret", "Secret", "Confidential",
            "Protected B", "Protected A", "Unclassified",
        ],
        "breach_notification": {
            "regulator_hours": 1,      # Immediate for government
            "individual_hours": 72,
            "regulator_name": "Treasury Board / CISA",
        },
        "kpis": [
            "ATO Coverage %", "FedRAMP Control Implementation %",
            "Continuous Monitoring Findings", "POA&M Items Open",
            "FISMA Compliance Score",
        ],
        "catalogue_files": [
            "controls_nist_csf.json",
            "controls_nist_800_53.json",
            "controls_fedramp.json",
        ],
        "report_templates": [
            "executive_brief", "risk_register", "compliance_summary",
            "fedramp_ssp", "poam_report", "audit_readiness",
        ],
    },

    "enterprise": {
        "label": "Enterprise",
        "icon": "🏢",
        "frameworks": ["nist_csf", "iso27001"],
        "primary_frameworks": ["nist_csf", "iso27001"],
        "risk_categories": [
            "Malware / Ransomware", "Vulnerability Management",
            "Third-Party / Supply Chain", "Insider Threat",
            "Cloud Security", "Compliance / Regulatory",
            "Physical Security", "Data Loss", "Other",
        ],
        "data_classifications": ["Confidential", "Internal", "Public"],
        "breach_notification": {
            "regulator_hours": 72,
            "individual_hours": 720,
            "regulator_name": "Privacy Commissioner",
        },
        "kpis": [
            "MTTD (hrs)", "MTTR (hrs)", "Patch Compliance %",
            "Open Critical Vulnerabilities", "Phishing Click Rate %",
        ],
        "catalogue_files": [
            "controls_nist_csf.json",
            "controls_iso27001.json",
        ],
        "report_templates": [
            "executive_brief", "risk_register",
            "compliance_summary", "audit_readiness",
        ],
    },
}


# ---------------------------------------------------------------------------
# Profile loader
# ---------------------------------------------------------------------------

@lru_cache(maxsize=1)
def get_industry_profile() -> dict:
    """Return the active industry profile based on org_profile.yaml."""
    cfg = get_config()
    profile_key = getattr(
        getattr(cfg, "industry", None), "profile", "enterprise"
    ) or "enterprise"
    return INDUSTRY_PROFILES.get(profile_key, INDUSTRY_PROFILES["enterprise"])


def get_active_frameworks() -> list[str]:
    return get_industry_profile()["primary_frameworks"]


def get_risk_categories() -> list[str]:
    return get_industry_profile()["risk_categories"]


def get_data_classifications() -> list[str]:
    return get_industry_profile()["data_classifications"]


def get_breach_notification_config() -> dict:
    return get_industry_profile()["breach_notification"]


def get_industry_kpis() -> list[str]:
    return get_industry_profile()["kpis"]


def get_catalogue_files() -> list[str]:
    return get_industry_profile()["catalogue_files"]


def get_report_templates() -> list[str]:
    return get_industry_profile()["report_templates"]


def get_scoring_model() -> str:
    """Returns 'matrix' for most sectors, 'fair' for financial."""
    return get_industry_profile().get("scoring_model", "matrix")


def is_framework_active(framework_id: str) -> bool:
    """Check if a specific framework is active for the current profile."""
    cfg = get_config()
    frameworks = getattr(getattr(cfg, "compliance", None), "frameworks", [])
    for fw in frameworks:
        fwid = getattr(fw, "id", None) or fw.get("id", "")
        enabled = getattr(fw, "enabled", False) or fw.get("enabled", False)
        if fwid == framework_id:
            return enabled
    # Fall back to profile default
    return framework_id in get_industry_profile()["frameworks"]


def load_industry_controls() -> dict:
    """
    Load all active control catalogues for the current industry profile
    and merge them into a single dict keyed by framework id.
    """
    import json
    result = {}
    for fname in get_catalogue_files():
        path = DATA_DIR / fname
        if path.exists():
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            # Each file is keyed by its framework id at the top level
            result.update(data)
    return result


def profile_summary() -> dict:
    """Return a display-ready summary of the active profile."""
    profile = get_industry_profile()
    cfg = get_config()
    return {
        "label": profile["label"],
        "icon": profile["icon"],
        "organization": getattr(cfg.organization, "name", "Your Organization"),
        "sector": getattr(cfg.organization, "sector", ""),
        "active_frameworks": get_active_frameworks(),
        "scoring_model": get_scoring_model(),
        "data_classifications": get_data_classifications(),
    }
