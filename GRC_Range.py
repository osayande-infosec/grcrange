"""
CyberResilient — Multi-Industry GRC Platform
Main Streamlit application entry point.

Run: streamlit run app.py
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import streamlit as st

st.set_page_config(
    page_title="CyberResilient GRC Range",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from cyberresilient.config import get_config
from cyberresilient.database import init_db
from cyberresilient.theme import (
    get_theme_colors, inject_platform_css,
    page_header, kpi_card, section_header, footer,
)
from cyberresilient.services.industry_service import (
    get_industry_profile,
    get_active_frameworks,
    get_risk_categories,
    get_industry_kpis,
    get_breach_notification_config,
)
from cyberresilient.services.compliance_service import load_controls, get_compliance_score

# ── Initialise ────────────────────────────────────────────────
init_db()

colors = get_theme_colors()
GOLD = colors["accent"]
cfg = get_config()
profile = get_industry_profile()

inject_platform_css()

# ── Sidebar ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        f"""<div style="text-align:center; padding: 1rem 0 0.5rem 0;">
            <div style="font-size: 2.5rem; margin-bottom: 0.25rem;">🛡️</div>
            <div style="font-size: 1.2rem; font-weight: 700; color: #D4AF37;
                        letter-spacing: -0.02em;">CyberResilient GRC Range</div>
        </div>""",
        unsafe_allow_html=True,
    )
    st.markdown("---")
    st.markdown(f"**{profile['icon']} {profile['label']} Edition**")
    st.caption(f"Frameworks: {', '.join(profile['primary_frameworks']).upper()}")
    tenant_id = st.session_state.get("tenant_id")
    if tenant_id:
        st.success(f"Tenant: {tenant_id}")
    st.markdown("---")

# ── Main dashboard ────────────────────────────────────────────
page_header(
    f"CyberResilient — {profile['icon']} {profile['label']} Edition",
    "Governance, Risk & Compliance Platform",
    icon="🛡️",
)

# ── Compliance Scores (top KPIs) ─────────────────────────────
controls = load_controls()
framework_ids = list(controls.keys())

score_cols = st.columns(min(len(framework_ids), 4))

for idx, fw_id in enumerate(framework_ids):
    fw_data = controls[fw_id]
    score = get_compliance_score(fw_id)
    fw_name = fw_data.get("framework", fw_id.upper())
    pct = score["percentage"]
    color = "#3FB950" if pct >= 80 else "#D29922" if pct >= 50 else "#F85149"

    with score_cols[idx % len(score_cols)]:
        st.markdown(
            kpi_card(fw_name, f"{pct}%", f"{score['implemented']}/{score['total']} controls", color),
            unsafe_allow_html=True,
        )

st.markdown("")

# ── Industry Overview ─────────────────────────────────────────
section_header("Active Industry Profile")

col1, col2, col3 = st.columns(3)

with col1:
    frameworks_html = "".join(f"<li style='color:#EAEAEA; margin-bottom:0.25rem;'>{fw.upper()}</li>" for fw in profile["frameworks"])
    st.markdown(
        f"""<div style="background:#161B22; border:1px solid #30363D; border-radius:12px; padding:1.25rem;">
            <div style="color:#D4AF37; font-weight:600; font-size:0.85rem; text-transform:uppercase;
                        letter-spacing:0.05em; margin-bottom:0.75rem;">Frameworks</div>
            <ul style="margin:0; padding-left:1.25rem; list-style-type:'› ';">{frameworks_html}</ul>
        </div>""",
        unsafe_allow_html=True,
    )

with col2:
    cats = profile["risk_categories"][:6]
    remaining = len(profile["risk_categories"]) - 6
    cats_html = "".join(f"<li style='color:#EAEAEA; margin-bottom:0.25rem;'>{cat}</li>" for cat in cats)
    extra = f"<div style='color:#8B949E; font-size:0.8rem; margin-top:0.5rem;'>+ {remaining} more</div>" if remaining > 0 else ""
    st.markdown(
        f"""<div style="background:#161B22; border:1px solid #30363D; border-radius:12px; padding:1.25rem;">
            <div style="color:#D4AF37; font-weight:600; font-size:0.85rem; text-transform:uppercase;
                        letter-spacing:0.05em; margin-bottom:0.75rem;">Risk Categories</div>
            <ul style="margin:0; padding-left:1.25rem; list-style-type:'› ';">{cats_html}</ul>
            {extra}
        </div>""",
        unsafe_allow_html=True,
    )

with col3:
    kpis_html = "".join(f"<li style='color:#EAEAEA; margin-bottom:0.25rem;'>{kpi}</li>" for kpi in get_industry_kpis())
    st.markdown(
        f"""<div style="background:#161B22; border:1px solid #30363D; border-radius:12px; padding:1.25rem;">
            <div style="color:#D4AF37; font-weight:600; font-size:0.85rem; text-transform:uppercase;
                        letter-spacing:0.05em; margin-bottom:0.75rem;">KPIs</div>
            <ul style="margin:0; padding-left:1.25rem; list-style-type:'› ';">{kpis_html}</ul>
        </div>""",
        unsafe_allow_html=True,
    )

# ── Breach Notification Config ────────────────────────────────
breach_cfg = get_breach_notification_config()
section_header("Breach Notification SLAs")

bc1, bc2, bc3 = st.columns(3)
bc1.metric("Regulator", breach_cfg["regulator_name"])

reg_hours = breach_cfg["regulator_hours"]
if reg_hours >= 24:
    bc2.metric("Regulator Deadline", f"{reg_hours // 24} days")
else:
    bc2.metric("Regulator Deadline", f"{reg_hours} hours")

bc3.metric("Data Classifications", ", ".join(profile.get("data_classifications", [])[:3]))

# ── Navigation guide ──────────────────────────────────────────
section_header("Quick Navigation")

nav_items = [
    ("🏢", "Onboarding", "Set up or switch organisations"),
    ("🛡️", "Security Operations", "1st Line: Access Control, Change Mgt, Vuln Mgt, SDLC"),
    ("🏥", "Healthcare Compliance", "HIPAA Security Rule, PHI assets, breach notifications"),
    ("🏦", "Financial Compliance", "PCI DSS, SOX ITGC, FAIR quantitative risk"),
    ("🏛️", "Government Compliance", "NIST 800-53, FedRAMP ATO, POA&M tracker"),
    ("📋", "Audit & Assurance", "3rd Line: audit trail, gap analysis, evidence review"),
]

cols = st.columns(3)
for idx, (icon, name, desc) in enumerate(nav_items):
    with cols[idx % 3]:
        st.markdown(
            f"""<div style="
                background: #161B22; border: 1px solid #30363D; border-radius: 12px;
                padding: 1.25rem; margin-bottom: 0.75rem; min-height: 100px;
                transition: all 0.2s ease;
            ">
                <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">{icon}</div>
                <div style="color: #EAEAEA; font-weight: 600; font-size: 0.95rem;">{name}</div>
                <div style="color: #8B949E; font-size: 0.8rem; margin-top: 0.25rem;">{desc}</div>
            </div>""",
            unsafe_allow_html=True,
        )

footer()
