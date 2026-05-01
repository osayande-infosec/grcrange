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
    set_tenant_context, verify_email, resend_verification_code,
    is_email_verified, login_rate_limit, verify_rate_limit,
    resend_rate_limit, clear_rate_limit,
)
from cyberresilient.services.industry_service import INDUSTRY_PROFILES
from cyberresilient.theme import (
    get_theme_colors, inject_platform_css, page_header, footer,
)

colors = get_theme_colors()
GOLD = colors["accent"]
inject_platform_css()


def _rate_limit_message(seconds: int) -> str:
    minutes = seconds // 60
    rem = seconds % 60
    if minutes > 0:
        return f"Too many attempts. Try again in {minutes}m {rem}s."
    return f"Too many attempts. Try again in {seconds}s."

# ── Check if already in a tenant context ────────────────────
if st.session_state.get("tenant_id"):
    tid = st.session_state["tenant_id"]
    # Check email verification status
    if not is_email_verified(tid):
        page_header("Email Verification Required", "Verify your email to unlock all features", icon="📧")
        with st.form("verify_email"):
            code_input = st.text_input("Enter 6-digit verification code")
            col_v, col_r = st.columns(2)
            with col_v:
                verify_btn = st.form_submit_button("Verify", type="primary")
            with col_r:
                resend_btn = st.form_submit_button("Resend Code")
        if verify_btn:
            allowed, retry_after = verify_rate_limit(tid)
            if not allowed:
                st.error(_rate_limit_message(retry_after))
            elif verify_email(tid, code_input):
                clear_rate_limit("tenant_verify", tid)
                st.success("Email verified successfully!")
                st.rerun()
            else:
                st.error("Invalid verification code. Please try again.")
        if resend_btn:
            allowed, retry_after = resend_rate_limit(tid)
            if not allowed:
                st.error(_rate_limit_message(retry_after))
            else:
                new_code = resend_verification_code(tid)
                if new_code:
                    st.info(f"In production, a new code is emailed. For demo: **{new_code}**")
        st.stop()

    page_header("Welcome Back", f"Tenant: {tid} — Email verified", icon="✅")
    if st.button("Switch / Reset Tenant Context"):
        del st.session_state["tenant_id"]
        st.rerun()
    st.stop()

page_header("Welcome to CyberResilient GRC Range", "Set up your organisation to get started", icon="🛡️")

mode = st.radio(
    "What would you like to do?",
    ["Start a new organisation", "Log in to an existing organisation"],
    horizontal=True,
)

if mode == "Start a new organisation":
    from cyberresilient.theme import section_header
    section_header("New Organisation Setup")

    # Industry picker outside the form so it reacts to changes immediately
    industry = st.selectbox(
        "Industry *",
        SUPPORTED_INDUSTRIES,
        format_func=lambda x: INDUSTRY_PROFILES[x]["label"],
        key="new_org_industry",
    )
    _profile_preview = INDUSTRY_PROFILES[industry]
    st.info(
        f"**{_profile_preview['icon']} {_profile_preview['label']} Edition** includes: "
        f"{', '.join(_profile_preview['primary_frameworks']).upper()} compliance, "
        f"{len(_profile_preview['risk_categories'])} risk categories, "
        f"and {len(_profile_preview['report_templates'])} report templates."
    )

    with st.form("onboarding"):
        c1, c2 = st.columns(2)
        with c1:
            org_name = st.text_input("Organisation Name *", placeholder="Acme Health Systems")
            country = st.selectbox(
                "Country",
                ["US", "CA", "GB", "AU", "NZ", "IE", "SG", "Other"],
            )
        with c2:
            admin_name = st.text_input("Your Name *")
            admin_email = st.text_input("Your Email *", placeholder="admin@example.com")

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
                st.info(
                    f"📧 Verification code sent to **{admin_email}**. "
                    f"For demo: **{tenant.get('email_verification_code', 'N/A')}**"
                )
                st.balloons()
                st.info("Navigate to any page in the sidebar to begin.")
            except ValueError as e:
                st.error(str(e))

else:
    section_header("Log In to Existing Organisation")
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
            tenant_id_norm = tenant_id.strip()
            allowed, retry_after = login_rate_limit(tenant_id_norm)
            if not allowed:
                st.error(_rate_limit_message(retry_after))
                st.stop()
            from cyberresilient.services.tenant_service import get_tenant
            tenant = get_tenant(tenant_id_norm)
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
                clear_rate_limit("tenant_login", tenant_id_norm)
                set_tenant_context(tenant["id"])
                profile = INDUSTRY_PROFILES.get(tenant["industry"], {})
                st.success(
                    f"Welcome back, {tenant['org_name']}! "
                    f"Industry: {profile.get('label', tenant['industry'])}. "
                    f"Plan: {tenant['plan'].title()}."
                )
                st.rerun()

footer()
