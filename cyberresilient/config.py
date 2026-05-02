"""
cyberresilient/config.py

Loads org_profile.yaml and exposes configuration as a nested object.
All services import get_config() to read organisation settings.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

try:
    import streamlit as st
except ImportError:
    st = None  # type: ignore

# Data directory — where control catalogue JSON files live
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Config directories
_ROOT = Path(__file__).resolve().parent.parent
_CONFIG_DIR = _ROOT / "config"
_ORGS_DIR = _CONFIG_DIR / "orgs"

# Config file path — can be overridden via env var
_CONFIG_PATH = os.environ.get(
    "CYBERRESILIENT_CONFIG",
    str(_CONFIG_DIR / "org_profile.yaml"),
)


def _dict_to_namespace(d: Any) -> Any:
    """Recursively convert dict to SimpleNamespace for dot-access."""
    if isinstance(d, dict):
        return SimpleNamespace(**{k: _dict_to_namespace(v) for k, v in d.items()})
    if isinstance(d, list):
        return [_dict_to_namespace(i) for i in d]
    return d


_DEFAULTS: dict[str, Any] = {
    "organization": {"name": "CyberResilient", "sector": "Enterprise"},
    "industry": {"profile": "enterprise", "sub_sector": "tech"},
    "risk": {"scoring_model": "matrix", "currency": "USD", "appetite_threshold": 12},
    "breach_notification": {"regulator_hours": 72, "individual_hours": 720},
    "compliance": {"custom_frameworks": []},
}


def _load_yaml_config(path: Path) -> SimpleNamespace:
    """Load a YAML config file or return defaults."""
    if not path.exists():
        return _dict_to_namespace(_DEFAULTS)
    with open(path, encoding="utf-8") as f:
        data: dict[str, Any] = yaml.safe_load(f) or {}
    return _dict_to_namespace(data)


def get_config() -> SimpleNamespace:
    """Load and return the org profile for the active org.

    Reads ``active_org_key`` from ``st.session_state`` when Streamlit is
    available, falling back to the default org profile.
    """
    org_key: str = "default"
    if st is not None:
        try:
            org_key = st.session_state.get("active_org_key", "default")
        except Exception:
            pass
    return load_config_for_org(org_key)


def list_orgs() -> dict[str, str]:
    """Return {org_key: display_name} for all YAML files in config/orgs/.

    The default org (org_profile.yaml) is always included as key ``"default"``.
    """
    result: dict[str, str] = {}
    default_path = _CONFIG_DIR / "org_profile.yaml"
    if default_path.exists():
        with open(default_path, encoding="utf-8") as f:
            raw: dict[str, Any] = yaml.safe_load(f) or {}
        result["default"] = raw.get("organization", {}).get("name", "Default Organization")

    if _ORGS_DIR.exists():
        for yaml_file in sorted(_ORGS_DIR.glob("*.yaml")):
            key = yaml_file.stem
            with open(yaml_file, encoding="utf-8") as f:
                raw = yaml.safe_load(f) or {}
            result[key] = raw.get("organization", {}).get("name", key.replace("_", " ").title())

    return result


def load_config_for_org(org_key: str) -> SimpleNamespace:
    """Load the config for a named org key."""
    if org_key == "default" or not org_key:
        return _load_yaml_config(Path(_CONFIG_PATH))
    yaml_path = _ORGS_DIR / f"{org_key}.yaml"
    return _load_yaml_config(yaml_path)
