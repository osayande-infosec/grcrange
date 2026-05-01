"""
cyberresilient/config.py

Loads org_profile.yaml and exposes configuration as a nested object.
All services import get_config() to read organisation settings.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

# Data directory — where control catalogue JSON files live
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Config file path — can be overridden via env var
_CONFIG_PATH = os.environ.get(
    "CYBERRESILIENT_CONFIG",
    str(Path(__file__).resolve().parent.parent / "config" / "org_profile.yaml"),
)


def _dict_to_namespace(d: Any) -> Any:
    """Recursively convert dict to SimpleNamespace for dot-access."""
    if isinstance(d, dict):
        return SimpleNamespace(**{k: _dict_to_namespace(v) for k, v in d.items()})
    if isinstance(d, list):
        return [_dict_to_namespace(i) for i in d]
    return d


@lru_cache(maxsize=1)
def get_config() -> SimpleNamespace:
    """Load and return the org profile configuration."""
    config_path = Path(_CONFIG_PATH)
    if not config_path.exists():
        # Return minimal defaults if no config file
        return _dict_to_namespace({
            "organization": {"name": "CyberResilient", "sector": "Enterprise"},
            "industry": {"profile": "enterprise", "sub_sector": "tech"},
            "risk": {"scoring_model": "matrix", "currency": "USD", "appetite_threshold": 12},
            "breach_notification": {"regulator_hours": 72, "individual_hours": 720},
        })
    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return _dict_to_namespace(data or {})
