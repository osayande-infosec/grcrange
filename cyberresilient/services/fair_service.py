"""
cyberresilient/services/fair_service.py

FAIR (Factor Analysis of Information Risk) Quantitative Risk Scoring.

Replaces or augments the 5x5 matrix for financial sector clients who
need risk expressed in monetary terms (Annualised Loss Expectancy).

FAIR model:
  Risk = Loss Event Frequency × Loss Magnitude

  Loss Event Frequency (LEF) = Threat Event Frequency × Vulnerability
  Loss Magnitude = Primary Loss + Secondary Loss

  Output: Annualised Loss Expectancy (ALE) in currency units
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

from cyberresilient.config import get_config


def _get_currency() -> str:
    cfg = get_config()
    return getattr(getattr(cfg, "risk", None), "currency", "USD") or "USD"


# ---------------------------------------------------------------------------
# FAIR input model
# ---------------------------------------------------------------------------

@dataclass
class FAIRInput:
    """
    Inputs for a FAIR risk calculation.
    All frequency values are per-year estimates.
    All magnitude values are in currency units.
    """
    # Threat Event Frequency
    tef_low: float          # Minimum threat events per year
    tef_likely: float       # Most likely threat events per year
    tef_high: float         # Maximum threat events per year

    # Vulnerability (probability 0.0–1.0)
    vuln_low: float
    vuln_likely: float
    vuln_high: float

    # Primary Loss Magnitude (direct financial impact per event)
    plm_low: float
    plm_likely: float
    plm_high: float

    # Secondary Loss Magnitude (regulatory, reputational, legal)
    slm_low: float = 0.0
    slm_likely: float = 0.0
    slm_high: float = 0.0

    # Metadata
    risk_id: str = ""
    scenario: str = ""
    currency: str = field(default_factory=_get_currency)


# ---------------------------------------------------------------------------
# PERT distribution helper
# ---------------------------------------------------------------------------

def _pert_mean(low: float, likely: float, high: float) -> float:
    """Calculate PERT weighted mean: (low + 4*likely + high) / 6"""
    return (low + 4 * likely + high) / 6


def _pert_stddev(low: float, likely: float, high: float) -> float:
    """Calculate PERT standard deviation: (high - low) / 6"""
    return (high - low) / 6


# ---------------------------------------------------------------------------
# FAIR calculation
# ---------------------------------------------------------------------------

def calculate_fair(inputs: FAIRInput) -> dict:
    """
    Perform a FAIR risk calculation and return a structured result.

    Returns ALE (Annualised Loss Expectancy) with confidence intervals
    and a qualitative risk tier mapped to the result.
    """
    # Loss Event Frequency
    tef_mean = _pert_mean(inputs.tef_low, inputs.tef_likely, inputs.tef_high)
    vuln_mean = _pert_mean(inputs.vuln_low, inputs.vuln_likely, inputs.vuln_high)
    lef_mean = tef_mean * vuln_mean

    tef_sd = _pert_stddev(inputs.tef_low, inputs.tef_likely, inputs.tef_high)
    vuln_sd = _pert_stddev(inputs.vuln_low, inputs.vuln_likely, inputs.vuln_high)

    # Loss Magnitude (primary + secondary)
    plm_mean = _pert_mean(inputs.plm_low, inputs.plm_likely, inputs.plm_high)
    slm_mean = _pert_mean(inputs.slm_low, inputs.slm_likely, inputs.slm_high)
    lm_mean = plm_mean + slm_mean

    plm_sd = _pert_stddev(inputs.plm_low, inputs.plm_likely, inputs.plm_high)
    slm_sd = _pert_stddev(inputs.slm_low, inputs.slm_likely, inputs.slm_high)
    lm_sd = math.sqrt(plm_sd ** 2 + slm_sd ** 2)

    # Annualised Loss Expectancy
    ale = lef_mean * lm_mean

    # Confidence interval (±1 standard deviation)
    ale_low = max(0, (lef_mean - tef_sd * vuln_mean) * max(0, lm_mean - lm_sd))
    ale_high = (lef_mean + tef_sd * vuln_mean) * (lm_mean + lm_sd)

    # Risk tier based on ALE
    tier = _ale_to_tier(ale)

    # Map to 1–25 matrix equivalent for compatibility with existing risk register
    matrix_equivalent = _ale_to_matrix(ale)

    return {
        "risk_id": inputs.risk_id,
        "scenario": inputs.scenario,
        "currency": inputs.currency,
        "tef_mean": round(tef_mean, 2),
        "vulnerability_mean": round(vuln_mean, 3),
        "lef_mean": round(lef_mean, 2),
        "primary_loss_mean": round(plm_mean, 2),
        "secondary_loss_mean": round(slm_mean, 2),
        "total_loss_mean": round(lm_mean, 2),
        "ale": round(ale, 2),
        "ale_low": round(ale_low, 2),
        "ale_high": round(ale_high, 2),
        "risk_tier": tier,
        "matrix_equivalent": matrix_equivalent,
        "formatted_ale": _format_currency(ale, inputs.currency),
        "formatted_ale_range": (
            f"{_format_currency(ale_low, inputs.currency)} – "
            f"{_format_currency(ale_high, inputs.currency)}"
        ),
    }


def _ale_to_tier(ale: float) -> str:
    if ale >= 5_000_000:
        return "Very High"
    if ale >= 1_000_000:
        return "High"
    if ale >= 250_000:
        return "Medium"
    return "Low"


def _ale_to_matrix(ale: float) -> int:
    """Map ALE to a 1–25 matrix score for cross-sector compatibility."""
    if ale >= 5_000_000:
        return 20
    if ale >= 1_000_000:
        return 15
    if ale >= 500_000:
        return 12
    if ale >= 250_000:
        return 9
    if ale >= 100_000:
        return 6
    return 3


def _format_currency(amount: float, currency: str = "USD") -> str:
    symbols = {"USD": "$", "CAD": "CA$", "GBP": "£", "EUR": "€"}
    symbol = symbols.get(currency, currency + " ")
    if amount >= 1_000_000:
        return f"{symbol}{amount / 1_000_000:.1f}M"
    if amount >= 1_000:
        return f"{symbol}{amount / 1_000:.0f}K"
    return f"{symbol}{amount:.0f}"


# ---------------------------------------------------------------------------
# Scenario library — pre-built FAIR scenarios per sector
# ---------------------------------------------------------------------------

FINANCIAL_SCENARIOS = [
    {
        "id": "FS-001",
        "name": "Payment Card Data Breach",
        "description": "Unauthorised exfiltration of PCI cardholder data",
        "defaults": {
            "tef_low": 0.1, "tef_likely": 0.5, "tef_high": 2.0,
            "vuln_low": 0.1, "vuln_likely": 0.3, "vuln_high": 0.6,
            "plm_low": 500_000, "plm_likely": 2_000_000, "plm_high": 10_000_000,
            "slm_low": 100_000, "slm_likely": 500_000, "slm_high": 3_000_000,
        },
    },
    {
        "id": "FS-002",
        "name": "Ransomware — Core Banking System",
        "description": "Ransomware encrypting core banking infrastructure",
        "defaults": {
            "tef_low": 0.05, "tef_likely": 0.2, "tef_high": 1.0,
            "vuln_low": 0.05, "vuln_likely": 0.2, "vuln_high": 0.5,
            "plm_low": 1_000_000, "plm_likely": 5_000_000, "plm_high": 20_000_000,
            "slm_low": 500_000, "slm_likely": 2_000_000, "slm_high": 8_000_000,
        },
    },
    {
        "id": "FS-003",
        "name": "Insider Trading — Data Leak",
        "description": "Privileged user leaking market-sensitive data",
        "defaults": {
            "tef_low": 0.02, "tef_likely": 0.1, "tef_high": 0.5,
            "vuln_low": 0.1, "vuln_likely": 0.25, "vuln_high": 0.5,
            "plm_low": 200_000, "plm_likely": 1_000_000, "plm_high": 5_000_000,
            "slm_low": 1_000_000, "slm_likely": 5_000_000, "slm_high": 20_000_000,
        },
    },
]

HEALTHCARE_SCENARIOS = [
    {
        "id": "HC-001",
        "name": "PHI Data Breach — EHR System",
        "description": "Unauthorised access to electronic health records",
        "defaults": {
            "tef_low": 0.1, "tef_likely": 0.5, "tef_high": 2.0,
            "vuln_low": 0.1, "vuln_likely": 0.3, "vuln_high": 0.6,
            "plm_low": 100_000, "plm_likely": 500_000, "plm_high": 3_000_000,
            "slm_low": 200_000, "slm_likely": 1_000_000, "slm_high": 5_000_000,
        },
    },
    {
        "id": "HC-002",
        "name": "Ransomware — Clinical Systems",
        "description": "Ransomware disrupting patient care systems",
        "defaults": {
            "tef_low": 0.1, "tef_likely": 0.3, "tef_high": 1.0,
            "vuln_low": 0.1, "vuln_likely": 0.3, "vuln_high": 0.6,
            "plm_low": 500_000, "plm_likely": 3_000_000, "plm_high": 15_000_000,
            "slm_low": 100_000, "slm_likely": 500_000, "slm_high": 2_000_000,
        },
    },
]
