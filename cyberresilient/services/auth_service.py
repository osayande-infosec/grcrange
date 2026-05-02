"""
cyberresilient/services/auth_service.py

Authentication and RBAC service.
Provides get_current_user() and has_permission() used by all pages.

In production this integrates with your identity provider.
For local development, returns a default admin user.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import streamlit as st


@dataclass
class User:
    username: str = "guest"
    email: str = ""
    display_name: str = "Guest"
    roles: list[str] = field(default_factory=list)
    tenant_id: str = ""
    authenticated: bool = False


# Permission map — which roles can do what
_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin":  ["admin", "edit_risks", "edit_controls", "edit_vendors", "view"],
    "editor": ["edit_risks", "edit_controls", "edit_vendors", "view"],
    "viewer": ["view"],
}


def _guest_user() -> User:
    return User(roles=["viewer"])


def _build_tenant_user(tenant: dict) -> User:
    roles = ["admin", "editor", "viewer"] if tenant.get("email_verified") else ["viewer"]
    email = tenant.get("admin_email", "")
    return User(
        username=email or tenant.get("id", "tenant-user"),
        email=email,
        display_name=tenant.get("admin_name") or tenant.get("org_name") or "Tenant User",
        roles=roles,
        tenant_id=tenant.get("id", ""),
        authenticated=bool(tenant.get("active")),
    )


def get_current_user() -> User:
    """Return the current authenticated user from session state."""
    from cyberresilient.services.tenant_service import get_current_tenant_id, get_tenant

    tenant_id = get_current_tenant_id() or ""
    session_user = st.session_state.get("current_user")
    if isinstance(session_user, User) and session_user.tenant_id == tenant_id:
        return session_user

    if not tenant_id:
        guest = _guest_user()
        st.session_state["current_user"] = guest
        return guest

    tenant = get_tenant(tenant_id)
    if not tenant or not tenant.get("active"):
        guest = _guest_user()
        st.session_state["current_user"] = guest
        return guest

    user = _build_tenant_user(tenant)
    st.session_state["current_user"] = user
    return user


def has_permission(permission: str) -> bool:
    """Check if the current user has a specific permission."""
    user = get_current_user()
    if permission != "view" and not user.authenticated:
        return False
    for role in user.roles:
        if permission in _ROLE_PERMISSIONS.get(role, []):
            return True
    return False


def is_learning_mode() -> bool:
    """Check if learning mode is currently active."""
    return st.session_state.get("learning_mode", False)


def learning_callout(title: str, content: str, icon: str = "💡") -> None:
    """Show an educational callout if learning mode is on."""
    if is_learning_mode():
        st.info(f"{icon} **{title}**\n\n{content}")
