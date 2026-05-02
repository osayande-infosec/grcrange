"""
AI Gap Analysis service.

Uses the OpenAI API when a key is configured; otherwise falls back to a
deterministic rule-based engine so the page is always functional.

Configuration
-------------
Set the OPENAI_API_KEY environment variable (or add to .env) and optionally:
  OPENAI_MODEL   (default: gpt-4o-mini)
  OPENAI_ORG     (optional organisation ID)
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Optional OpenAI import
# ---------------------------------------------------------------------------
try:
    import openai as _openai_lib

    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

_OPENAI_KEY: str | None = os.getenv("OPENAI_API_KEY")
_OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

# Cache directory — avoids repeat API calls for identical inputs
_CACHE_DIR = Path(__file__).resolve().parents[2] / "instance" / "ai_cache"
_CACHE_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# Severity thresholds
# ---------------------------------------------------------------------------
_GAP_THRESHOLDS = {
    "critical": 40,   # < 40 %
    "high": 60,       # 40–59 %
    "medium": 80,     # 60–79 %
    "low": 100,       # 80–99 %
}


def _severity(pct: int) -> str:
    if pct < _GAP_THRESHOLDS["critical"]:
        return "Critical"
    if pct < _GAP_THRESHOLDS["high"]:
        return "High"
    if pct < _GAP_THRESHOLDS["medium"]:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Rule-based fallback engine
# ---------------------------------------------------------------------------
_RULE_LIBRARY: dict[str, dict] = {
    # NIST CSF functions
    "Govern": {
        "description": "Governance function establishes organisational context, risk strategy, and oversight.",
        "quick_wins": [
            "Document and board-approve a cybersecurity policy referencing NIST CSF.",
            "Assign named CISO or security lead with board-level reporting line.",
            "Complete an annual cyber risk appetite statement.",
        ],
        "strategic": [
            "Integrate cybersecurity KPIs into executive dashboards.",
            "Establish a cybersecurity steering committee with quarterly meetings.",
        ],
    },
    "Identify": {
        "description": "Asset management, risk assessment, and supply chain risk.",
        "quick_wins": [
            "Deploy an automated asset discovery tool (e.g., Nmap, Rumble).",
            "Complete a formal risk assessment using NIST SP 800-30 methodology.",
            "Build a software bill of materials (SBOM) for all critical applications.",
        ],
        "strategic": [
            "Integrate asset inventory with CMDB and patch management tooling.",
            "Establish third-party risk scoring in vendor procurement process.",
        ],
    },
    "Protect": {
        "description": "Safeguards to limit impact of cybersecurity events.",
        "quick_wins": [
            "Enforce MFA on all privileged and remote access accounts.",
            "Implement endpoint detection and response (EDR) on all managed endpoints.",
            "Deploy email filtering with anti-phishing and attachment sandboxing.",
        ],
        "strategic": [
            "Adopt Zero Trust network architecture for internal segmentation.",
            "Implement data loss prevention (DLP) controls for sensitive data.",
        ],
    },
    "Detect": {
        "description": "Continuous monitoring and anomaly detection capabilities.",
        "quick_wins": [
            "Enable centralised log aggregation (SIEM) for all critical systems.",
            "Configure alerts for failed login attempts and privilege escalation.",
            "Establish 24/7 alert triage process (internal SOC or MSSP).",
        ],
        "strategic": [
            "Deploy user and entity behaviour analytics (UEBA).",
            "Establish threat hunting programme with quarterly exercises.",
        ],
    },
    "Respond": {
        "description": "Incident response plans, communications, and mitigation.",
        "quick_wins": [
            "Document and test an incident response plan (IRP) within 90 days.",
            "Conduct a tabletop exercise simulating a ransomware scenario.",
            "Define clear escalation paths and external contacts (legal, PR, regulator).",
        ],
        "strategic": [
            "Retain a cyber incident response retainer with a specialist firm.",
            "Automate playbooks for common incident types using SOAR tooling.",
        ],
    },
    "Recover": {
        "description": "Recovery planning and post-incident improvements.",
        "quick_wins": [
            "Test backup restoration at least quarterly with documented RTO/RPO targets.",
            "Create a business continuity plan covering top 5 critical services.",
            "Conduct post-incident reviews and track lessons learned.",
        ],
        "strategic": [
            "Implement immutable backups (air-gapped or cloud-based write-once storage).",
            "Integrate recovery metrics into executive security reporting.",
        ],
    },
    # ISO domains
    "Information Security Policies": {
        "description": "Governance policies directing information security management.",
        "quick_wins": [
            "Review and board-approve the Information Security Policy.",
            "Ensure policy versioning and annual review cycle is documented.",
        ],
        "strategic": ["Integrate policy lifecycle into GRC platform with automated reminders."],
    },
    "Organisation of Information Security": {
        "description": "Roles, responsibilities and coordination for information security.",
        "quick_wins": [
            "Define information security roles in all job descriptions.",
            "Establish information security contacts with relevant authorities.",
        ],
        "strategic": ["Create a formal security function with board-level visibility."],
    },
    # Generic fallback
    "_default": {
        "description": "Control area requires attention based on current implementation scores.",
        "quick_wins": [
            "Assign a named owner responsible for this control domain.",
            "Conduct a gap assessment to identify specific unimplemented controls.",
            "Define a 90-day remediation roadmap with measurable milestones.",
        ],
        "strategic": [
            "Integrate this control domain into the annual risk assessment process.",
            "Establish quarterly evidence collection cycles to maintain compliance.",
        ],
    },
}


def _rule_based_recommendations(gaps: list[dict]) -> list[dict]:
    """Generate structured recommendations from the rule library for each gap."""
    results = []
    for gap in gaps:
        name = gap["name"]
        rules = _RULE_LIBRARY.get(name, _RULE_LIBRARY["_default"])
        results.append(
            {
                "control": name,
                "framework": gap["framework"],
                "score": gap["score"],
                "severity": gap["severity"],
                "description": rules["description"],
                "quick_wins": rules["quick_wins"],
                "strategic_actions": rules["strategic"],
                "source": "rule-based",
            }
        )
    return results


# ---------------------------------------------------------------------------
# OpenAI-powered recommendations
# ---------------------------------------------------------------------------
def _cache_key(gaps: list[dict]) -> str:
    payload = json.dumps(gaps, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _load_cache(key: str) -> list[dict] | None:
    path = _CACHE_DIR / f"{key}.json"
    if path.exists():
        try:
            with open(path, encoding="utf-8") as f:
                cached = json.load(f)
            # Expire cache after 7 days
            if (datetime.now() - datetime.fromisoformat(cached["cached_at"])).days < 7:
                return cached["data"]
        except Exception:
            pass
    return None


def _save_cache(key: str, data: list[dict]) -> None:
    path = _CACHE_DIR / f"{key}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"cached_at": datetime.now().isoformat(), "data": data}, f)


def _openai_recommendations(gaps: list[dict]) -> list[dict]:
    """Call OpenAI to generate gap recommendations. Falls back to rule-based on error."""
    if not _OPENAI_AVAILABLE or not _OPENAI_KEY:
        return _rule_based_recommendations(gaps)

    key = _cache_key(gaps)
    cached = _load_cache(key)
    if cached:
        return cached

    prompt_gaps = "\n".join(
        f"- {g['framework']} | {g['name']} | Score: {g['score']}% | Severity: {g['severity']}"
        for g in gaps
    )

    system_prompt = (
        "You are a GRC (Governance, Risk & Compliance) expert specialising in cybersecurity frameworks "
        "(NIST CSF 2.0, ISO 27001:2022, SOC 2, CMMC 2.0, FedRAMP, PCI DSS). "
        "Your job is to analyse compliance gaps and provide practical, prioritised remediation guidance. "
        "Be specific, concise, and actionable. Avoid generic advice."
    )

    user_prompt = f"""Analyse these compliance gaps and provide remediation recommendations:

{prompt_gaps}

For each gap, respond with a JSON array where each item has:
- "control": the control/domain name
- "framework": the framework name
- "score": the score percentage (number)
- "severity": Critical/High/Medium/Low
- "description": one sentence explaining why this gap matters
- "quick_wins": list of 3 specific actions achievable within 30 days
- "strategic_actions": list of 2 longer-term improvements (3-6 months)
- "source": "openai"

Return ONLY the JSON array, no other text."""

    try:
        client = _openai_lib.OpenAI(api_key=_OPENAI_KEY)
        response = client.chat.completions.create(
            model=_OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
            response_format={"type": "json_object"},
        )
        raw = response.choices[0].message.content
        # The model may return {"recommendations": [...]} or just [...]
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            recs = next(iter(parsed.values()))
        else:
            recs = parsed
        _save_cache(key, recs)
        return recs
    except Exception:
        # Silently fall back — never crash the UI
        return _rule_based_recommendations(gaps)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def identify_gaps(
    nist_scores: dict | None = None,
    iso_scores: dict | None = None,
    soc2_scores: dict | None = None,
    cmmc_scores: dict | None = None,
    fedramp_scores: dict | None = None,
    pci_scores: dict | None = None,
    threshold: int = 80,
) -> list[dict]:
    """
    Collect all control areas below *threshold* percent from any provided
    framework score dict and return a sorted list of gap records.
    """
    gaps: list[dict] = []

    if nist_scores:
        for fname, fdata in nist_scores.get("functions", {}).items():
            pct = fdata["percentage"]
            if pct < threshold:
                gaps.append(
                    {
                        "framework": "NIST CSF 2.0",
                        "name": fname,
                        "score": pct,
                        "severity": _severity(pct),
                    }
                )

    if iso_scores:
        for d in iso_scores.get("domains", []):
            pct = d["percentage"]
            if pct < threshold:
                gaps.append(
                    {
                        "framework": "ISO 27001:2022",
                        "name": d["name"],
                        "score": pct,
                        "severity": _severity(pct),
                    }
                )

    if soc2_scores:
        for c in soc2_scores.get("categories", []):
            pct = c["percentage"]
            if pct < threshold:
                gaps.append(
                    {
                        "framework": "SOC 2 Type II",
                        "name": f"{c['id']} - {c['name']}",
                        "score": pct,
                        "severity": _severity(pct),
                    }
                )

    if cmmc_scores:
        for d in cmmc_scores.get("domains", []):
            pct = d["percentage"]
            if pct < threshold:
                gaps.append(
                    {
                        "framework": "CMMC 2.0",
                        "name": f"{d['id']} - {d['name']}",
                        "score": pct,
                        "severity": _severity(pct),
                    }
                )

    if fedramp_scores:
        for fam in fedramp_scores.get("families", []):
            pct = fam["percentage"]
            if pct < threshold:
                gaps.append(
                    {
                        "framework": "FedRAMP Moderate",
                        "name": f"{fam['id']} - {fam['name']}",
                        "score": pct,
                        "severity": _severity(pct),
                    }
                )

    if pci_scores:
        for req in pci_scores.get("requirements", []):
            pct = req["percentage"]
            if pct < threshold:
                gaps.append(
                    {
                        "framework": "PCI DSS v4.0",
                        "name": f"{req['id']} - {req['name']}",
                        "score": pct,
                        "severity": _severity(pct),
                    }
                )

    # Sort: Critical first, then by score ascending
    _order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    gaps.sort(key=lambda g: (_order.get(g["severity"], 9), g["score"]))
    return gaps


def get_gap_recommendations(gaps: list[dict], use_ai: bool = True) -> list[dict]:
    """
    Return remediation recommendations for the provided gaps list.

    If *use_ai* is True and OPENAI_API_KEY is set, uses the OpenAI API.
    Otherwise uses the built-in rule-based engine.
    """
    if not gaps:
        return []
    if use_ai and _OPENAI_AVAILABLE and _OPENAI_KEY:
        return _openai_recommendations(gaps)
    return _rule_based_recommendations(gaps)


def is_ai_available() -> bool:
    """Returns True if the OpenAI key is configured and the library is installed."""
    return _OPENAI_AVAILABLE and bool(_OPENAI_KEY)
