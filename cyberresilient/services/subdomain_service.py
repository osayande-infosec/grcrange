"""
cyberresilient/services/subdomain_service.py

Subdomain Routing for Multi-Tenant Deployment.

In production, each tenant gets a subdomain:
    acme-health.cyberresilient.io → tenant_id="acme-health-a1b2c3d4"
    finserv-corp.cyberresilient.io → tenant_id="finserv-corp-e5f6g7h8"

This module:
  1. Extracts the subdomain from the HTTP Host header
  2. Resolves it to a tenant_id via the tenants table (slug match)
  3. Automatically sets the tenant context on page load

In local development (localhost:8501), subdomain routing is skipped
and manual tenant login via onboarding page is used instead.
"""

from __future__ import annotations
import re
from typing import Optional

# Base domain — tenants get <slug>.BASE_DOMAIN
BASE_DOMAIN = "cyberresilient.io"

# Domains that should NOT trigger subdomain resolution
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}
RESERVED_SUBDOMAINS = {"www", "app", "api"}
HOST_PATTERN = re.compile(r"^[a-z0-9.-]{1,253}$")
SUBDOMAIN_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def extract_subdomain(host: str) -> Optional[str]:
    """
    Extract the tenant subdomain from a Host header value.

    Examples:
        "acme-health.cyberresilient.io"     → "acme-health"
        "acme-health.cyberresilient.io:443"  → "acme-health"
        "localhost:8501"                     → None
        "cyberresilient.io"                  → None (apex domain)
    """
    if not host:
        return None

    # Prefer the first host value if a malformed comma-delimited header is provided.
    hostname = host.split(",", 1)[0].split(":", 1)[0].strip().lower()
    if not HOST_PATTERN.fullmatch(hostname):
        return None

    # Skip local development
    if hostname in LOCAL_HOSTS:
        return None

    # Must end with base domain
    if not hostname.endswith(f".{BASE_DOMAIN}"):
        return None

    # Extract the subdomain prefix
    subdomain = hostname[: -(len(BASE_DOMAIN) + 1)]
    if not subdomain or subdomain in RESERVED_SUBDOMAINS:
        return None
    if "." in subdomain:
        return None
    if not SUBDOMAIN_PATTERN.fullmatch(subdomain):
        return None

    return subdomain


def resolve_tenant_from_subdomain(subdomain: str) -> Optional[dict]:
    """
    Look up a tenant by their slug (subdomain).
    Returns the tenant dict or None if not found.
    """
    subdomain = (subdomain or "").strip().lower()
    if not SUBDOMAIN_PATTERN.fullmatch(subdomain):
        return None

    try:
        from cyberresilient.database import get_engine
        from sqlalchemy import inspect
        if not inspect(get_engine()).has_table("tenants"):
            return None
    except Exception:
        return None

    from cyberresilient.database import get_session
    from cyberresilient.models.db_models import TenantRow
    session = get_session()
    try:
        row = session.query(TenantRow).filter_by(slug=subdomain, active=True).first()
        return row.to_dict() if row else None
    finally:
        session.close()


def auto_set_tenant_from_host() -> Optional[str]:
    """
    Auto-detect tenant from the current HTTP Host header and
    set the tenant context. Called on app startup.

    Returns the tenant_id if resolved, None otherwise.
    """
    try:
        import streamlit as st
    except ImportError:
        return None

    # Already in a tenant context — don't override
    if st.session_state.get("tenant_id"):
        return st.session_state["tenant_id"]

    # Try to get Host header
    host = _get_host_header()
    if not host:
        return None

    subdomain = extract_subdomain(host)
    if not subdomain:
        return None

    tenant = resolve_tenant_from_subdomain(subdomain)
    if not tenant:
        return None

    from cyberresilient.services.tenant_service import set_tenant_context
    set_tenant_context(tenant["id"])
    return tenant["id"]


def get_tenant_url(slug: str) -> str:
    """Return the full tenant URL for a given slug."""
    return f"https://{slug}.{BASE_DOMAIN}"


def _get_host_header() -> Optional[str]:
    """
    Extract Host header from Streamlit's internal server context.
    Returns None in local development or if unavailable.
    """
    try:
        from streamlit.web.server.websocket_headers import _get_websocket_headers
        headers = _get_websocket_headers()
        if headers:
            return headers.get("Host") or headers.get("host")
    except Exception:
        pass

    # Fallback: check query parameters (for reverse-proxy setups)
    try:
        import streamlit as st
        host = st.query_params.get("host")
        if host:
            return host
    except Exception:
        pass

    return None
