"""
pages/0_Onboarding.py

Tenant Onboarding — self-service signup flow.
Sets up a new organisation with industry profile selection,
admin user creation, and trial activation.
"""

import streamlit as st
import plotly.express as px

from cyberresilient.services.tenant_service import (
    create_tenant, list_tenants, tenant_summary,
    is_trial_expired, SUPPORTED_INDUSTRIES, PLAN_TIERS,
    set_tenant_context,
)
from cyberresilient.services.industry_service import INDUSTRY_PROFILES
from cyberresilient.theme import get_theme_colors

colors = get_theme_colors()
GOLD = colors["accent"]

# ── Check if already in a tenant context ────────────────────
if st.session_state.get("tenant_id"):
    st.success(f"Already onboarded — Tenant: `{st.session_state['tenant_id']}`")
    if st.button("Switch / Reset Tenant Context"):
        del st.session_state["tenant_id"]
        st.rerun()
    st.stop()

st.markdown("# 🛡️ Welcome to CyberResilient")
st.markdown("Set up your organisation to get started.")
st.markdown("---")

mode = st.radio(
    "What would you like to do?",
    ["Start a new organisation", "Log in to an existing organisation"],
    horizontal=True,
)

if mode == "Start a new organisation":
    st.markdown("### New Organisation Setup")

    with st.form("onboarding"):
        c1, c2 = st.columns(2)
        with c1:
            org_name = st.text_input("Organisation Name *", placeholder="Acme Health Systems")
            industry = st.selectbox(
                "Industry *",
                SUPPORTED_INDUSTRIES,
                format_func=lambda x: INDUSTRY_PROFILES[x]["label"],
            )
            country = st.selectbox(
                "Country",
                ["US", "CA", "GB", "AU", "NZ", "IE", "SG", "Other"],
            )
        with c2:
            admin_name = st.text_input("Your Name *")
            admin_email = st.text_input("Your Email *", placeholder="admin@example.com")

        # Show what comes with the selected industry
        profile = INDUSTRY_PROFILES[industry]
        st.info(
            f"**{profile['icon']} {profile['label']} Edition** includes: "
            f"{', '.join(profile['primary_frameworks']).upper()} compliance, "
            f"{len(profile['risk_categories'])} risk categories, "
            f"and {len(profile['report_templates'])} report templates."
        )

        submitted = st.form_submit_button("🚀 Create Organisation (30-day free trial)", type="primary")

    if submitted:
        if not org_name or not admin_name or not admin_email:
            st.error("Organisation name, your name, and email are required.")
        elif "@" not in admin_email:
            st.error("Please enter a valid email address.")
        else:
            try:
                tenant = create_tenant(
                    org_name=org_name,
                    industry=industry,
                    admin_email=admin_email,
                    admin_name=admin_name,
                    plan="trial",
                    country=country,
                )
                set_tenant_context(tenant["id"])
                st.success(
                    f"Organisation '{org_name}' created! "
                    f"Your tenant ID is `{tenant['id']}`. "
                    f"Trial expires: {tenant['trial_ends_at']}."
                )
                st.balloons()
                st.info("Navigate to any page in the sidebar to begin.")
            except ValueError as e:
                st.error(str(e))

else:
    st.markdown("### Log In to Existing Organisation")
    with st.form("login_tenant"):
        tenant_id = st.text_input(
            "Tenant ID",
            placeholder="acme-health-systems-a1b2c3d4",
            help="Your tenant ID was provided when you signed up.",
        )
        submitted = st.form_submit_button("Log In", type="primary")

    if submitted:
        if not tenant_id:
            st.error("Please enter your tenant ID.")
        else:
            from cyberresilient.services.tenant_service import get_tenant
            tenant = get_tenant(tenant_id.strip())
            if not tenant:
                st.error("Tenant not found. Check your tenant ID.")
            elif not tenant.get("active"):
                st.error("This organisation account is inactive. Contact support.")
            elif is_trial_expired(tenant):
                st.error(
                    "Your trial has expired. "
                    "Contact support to upgrade to a paid plan."
                )
            else:
                set_tenant_context(tenant["id"])
                profile = INDUSTRY_PROFILES.get(tenant["industry"], {})
                st.success(
                    f"Welcome back, {tenant['org_name']}! "
                    f"Industry: {profile.get('label', tenant['industry'])}. "
                    f"Plan: {tenant['plan'].title()}."
                )
                st.rerun()
