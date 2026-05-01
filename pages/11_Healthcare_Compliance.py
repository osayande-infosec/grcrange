"""
pages/11_Healthcare_Compliance.py

Healthcare Edition — HIPAA Security Rule, PHI Asset Management,
and Breach Notification Workflow.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import date

from cyberresilient.services.phi_service import (
    register_asset, load_assets, phi_asset_summary,
    create_breach_notification, get_overdue_breach_notifications,
    get_escalated_score, SEVERITY_COLORS, HIPAA_TIMELINES,
    CLASSIFICATION_MULTIPLIERS,
)
from cyberresilient.services.compliance_service import load_controls
from cyberresilient.services.auth_service import get_current_user, has_permission
from cyberresilient.theme import (
    get_theme_colors, inject_platform_css,
    page_header, section_header, kpi_card, footer,
)

colors = get_theme_colors()
GOLD = colors["accent"]
inject_platform_css()

page_header(
    "Healthcare Compliance — HIPAA & PHI Management",
    "HIPAA Security Rule compliance, PHI asset classification, and breach notification",
    icon="🏥",
)

# ── Alert strip ──────────────────────────────────────────────
overdue_breaches = get_overdue_breach_notifications()
if overdue_breaches:
    st.error(
        f"🚨 {len(overdue_breaches)} breach notification(s) have missed regulatory deadlines. "
        "Review immediately in the Breach Notifications tab."
    )

asset_summary = phi_asset_summary()
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Assets", asset_summary["total"])
m2.metric("PHI Assets", asset_summary["phi_assets"])
m3.metric("PII Assets", asset_summary["pii_assets"])
m4.metric("High-Risk Assets", asset_summary["high_risk_assets"])

st.markdown("---")

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🏛️ HIPAA Security Rule",
    "🗄️ PHI Asset Register",
    "🚨 Breach Notifications",
    "➕ Register Asset",
    "🌍 GDPR & PIPEDA",
])


# ── Tab 1: HIPAA Security Rule ───────────────────────────────
with tab1:
    st.markdown("### HIPAA Security Rule — Safeguard Compliance")

    controls_data = load_controls()
    hipaa_data = controls_data.get("hipaa", {})
    safeguards = hipaa_data.get("safeguards", {})

    if not safeguards:
        st.warning("HIPAA control catalogue not loaded. Ensure controls_hipaa.json is in your data/ directory.")
    else:
        # Summary scores per safeguard
        for safeguard_name, safeguard_data in safeguards.items():
            standards = safeguard_data.get("standards", {})
            total_impl = 0
            implemented = 0

            for std_id, std_data in standards.items():
                for impl_id, impl in std_data.get("implementations", {}).items():
                    total_impl += 1
                    if impl["status"] == "Implemented":
                        implemented += 1

            pct = round((implemented / total_impl) * 100) if total_impl else 0
            health_color = "#4CAF50" if pct >= 80 else "#FF9800" if pct >= 50 else "#F44336"

            with st.expander(
                f"**{safeguard_name} Safeguards** — {pct}% ({implemented}/{total_impl} implemented)"
            ):
                for std_id, std_data in standards.items():
                    st.markdown(f"**{std_id} — {std_data['name']}** *(Type: {std_data['type']})*")
                    for impl_id, impl in std_data.get("implementations", {}).items():
                        status = impl["status"]
                        icon = "✅" if status == "Implemented" else "⚠️" if status == "Partial" else "❌"
                        req_type = impl.get("type", "")
                        req_badge = "🔴 Required" if req_type == "Required" else "🔵 Addressable"
                        st.markdown(
                            f"   {icon} `{impl_id}` — {impl['name']} | {req_badge} | **{status}**"
                        )
                        if impl.get("evidence_date"):
                            st.caption(f"   Evidence: {impl['evidence_date']}")
                    st.divider()

    # HIPAA Risk Analysis reminder
    st.info(
        "💡 **HIPAA requires a formal Risk Analysis** (164.308(a)(1)(ii)(A)) covering "
        "all ePHI. Use the Risk Register with PHI asset tagging to satisfy this requirement. "
        "Export the HIPAA Risk Analysis report from the Reports section."
    )


# ── Tab 2: PHI Asset Register ────────────────────────────────
with tab2:
    st.markdown("### PHI & PII Asset Register")
    st.markdown(
        "All assets that create, receive, maintain, or transmit ePHI must be "
        "inventoried per HIPAA 164.310(d)(1)."
    )

    assets = load_assets()
    if not assets:
        st.info("No assets registered. Use the 'Register Asset' tab to add assets.")
    else:
        # Classification distribution
        classification_counts: dict[str, int] = {}
        for a in assets:
            for c in a.get("data_classifications", []):
                classification_counts[c] = classification_counts.get(c, 0) + 1

        if classification_counts:
            fig = px.bar(
                x=list(classification_counts.keys()),
                y=list(classification_counts.values()),
                color=list(classification_counts.keys()),
                labels={"x": "Classification", "y": "Asset Count"},
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#EAEAEA", showlegend=False, height=280,
                xaxis=dict(gridcolor="#222"), yaxis=dict(gridcolor="#222"),
            )
            st.plotly_chart(fig, use_container_width=True)

        for asset in assets:
            classifications = asset.get("data_classifications", [])
            has_phi = "PHI" in classifications
            has_pii = "PII" in classifications
            risk_mult = asset.get("risk_multiplier", 1.0)

            phi_flag = " 🔴 PHI" if has_phi else ""
            pii_flag = " 🟠 PII" if has_pii else ""

            with st.expander(
                f"**{asset['name']}** ({asset['asset_type']}){phi_flag}{pii_flag}"
            ):
                ac1, ac2 = st.columns(2)
                with ac1:
                    st.markdown(f"**Owner:** {asset['owner']}")
                    st.markdown(f"**Location:** {asset.get('location', '—')}")
                    st.markdown(f"**Classifications:** {', '.join(classifications)}")
                with ac2:
                    st.markdown(f"**Highest Classification:** {asset['highest_classification']}")
                    mult_color = "#F44336" if risk_mult >= 2.0 else "#FF9800" if risk_mult >= 1.5 else "#4CAF50"
                    st.markdown(
                        f"**Risk Multiplier:** "
                        f"<span style='color:{mult_color};font-weight:600'>{risk_mult}×</span>",
                        unsafe_allow_html=True,
                    )
                    st.caption("Risk scores for risks linked to this asset are multiplied by this factor.")
                if asset.get("description"):
                    st.markdown(f"**Description:** {asset['description']}")


# ── Tab 3: Breach Notifications ──────────────────────────────
with tab3:
    st.markdown("### HIPAA Breach Notification Workflow")
    st.markdown(
        f"HHS notification required within **{HIPAA_TIMELINES['hhs_days']} days** of discovery. "
        f"Individual notification required within **{HIPAA_TIMELINES['individual_days']} days**. "
        f"Media notification required when **{HIPAA_TIMELINES['media_threshold']}+** individuals affected in a single state."
    )

    if overdue_breaches:
        st.error(f"🚨 {len(overdue_breaches)} breach notification(s) are overdue")
        for b in overdue_breaches:
            st.markdown(f"- **{b['id']}** — {b['description']} | Severity: {b['severity']}")

    st.markdown("---")
    st.markdown("#### Create Breach Notification Record")

    with st.form("breach_notification"):
        c1, c2 = st.columns(2)
        with c1:
            incident_id = st.text_input("Incident ID", placeholder="INC-2024-001")
            discovery_date = st.date_input("Discovery Date", value=date.today())
            individuals = st.number_input("Individuals Affected", min_value=1, value=1)
        with c2:
            phi_types = st.multiselect(
                "PHI Types Involved",
                ["Names", "SSN", "Dates", "Phone", "Address", "Email",
                 "Medical Record Numbers", "Health Plan Numbers", "Diagnoses",
                 "Treatment Information", "Financial Information"],
            )
            states = st.multiselect(
                "States / Provinces Affected",
                ["AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA",
                 "HI","ID","IL","IN","IA","KS","KY","LA","ME","MD",
                 "MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ",
                 "NM","NY","NC","ND","OH","OK","OR","PA","RI","SC",
                 "SD","TN","TX","UT","VT","VA","WA","WV","WI","WY",
                 "ON","BC","AB","QC"],
            )
        description = st.text_area("Breach Description *")
        submitted = st.form_submit_button("📋 Create Notification Record", type="primary")

    if submitted:
        if not description or not incident_id:
            st.error("Incident ID and Description are required.")
        else:
            record = create_breach_notification(
                incident_id=incident_id,
                discovery_date=str(discovery_date),
                individuals_affected=int(individuals),
                phi_types_involved=phi_types,
                states_affected=states,
                description=description,
                created_by=get_current_user().username,
            )
            sev_color = SEVERITY_COLORS.get(record["severity"], "#888")
            st.success(
                f"Breach notification created — "
                f"Severity: **{record['severity'].upper()}** | "
                f"HHS deadline: **{record['hhs_notification_deadline']}** | "
                f"Individual deadline: **{record['individual_notification_deadline']}**"
                + (" | ⚠️ Media notification required" if record["media_notification_required"] else "")
            )
            st.rerun()


# ── Tab 4: Register Asset ────────────────────────────────────
with tab4:
    if not has_permission("edit_risks"):
        st.warning("You do not have permission to register assets.")
    else:
        st.markdown("### Register New Asset")
        with st.form("register_asset"):
            c1, c2 = st.columns(2)
            with c1:
                asset_name = st.text_input("Asset Name *")
                asset_type = st.selectbox(
                    "Asset Type",
                    ["Server", "Application", "Database", "Medical Device",
                     "Workstation", "Network Device", "Cloud Service", "Other"],
                )
                owner = st.text_input("Owner *")
            with c2:
                data_class = st.multiselect(
                    "Data Classifications *",
                    list(CLASSIFICATION_MULTIPLIERS.keys()),
                    help="Select all data types this asset handles",
                )
                location = st.text_input("Location / Environment", placeholder="e.g., AWS us-east-1")
            description = st.text_area("Description")
            submitted = st.form_submit_button("➕ Register Asset", type="primary")

        if submitted:
            if not asset_name or not owner or not data_class:
                st.error("Name, Owner, and at least one Data Classification are required.")
            else:
                asset = register_asset(
                    name=asset_name,
                    asset_type=asset_type,
                    data_classifications=data_class,
                    owner=owner,
                    location=location,
                    description=description,
                    created_by=get_current_user().username,
                )
                st.success(
                    f"Asset '{asset_name}' registered — "
                    f"Risk multiplier: **{asset['risk_multiplier']}×**"
                )
                st.rerun()


# ── Tab 5: GDPR & PIPEDA ────────────────────────────────────
with tab5:
    st.markdown("### Privacy Regulations for Global Healthcare")
    st.caption(
        "MVP privacy coverage for organisations operating across US, EU, and Canada. "
        "This complements HIPAA with GDPR and PIPEDA requirements."
    )

    controls_data = load_controls()
    gdpr_data = controls_data.get("gdpr", {})
    pipeda_data = controls_data.get("pipeda", {})

    def _score_framework(framework_data: dict) -> tuple[int, int, int]:
        domains = framework_data.get("domains", {})
        total = 0
        implemented = 0
        for domain in domains.values():
            for ctrl in domain.get("controls", {}).values():
                total += 1
                if ctrl.get("status") == "Implemented":
                    implemented += 1
        pct = round((implemented / total) * 100) if total else 0
        return total, implemented, pct

    g_total, g_impl, g_pct = _score_framework(gdpr_data)
    p_total, p_impl, p_pct = _score_framework(pipeda_data)

    g_col, p_col = st.columns(2)
    with g_col:
        st.metric("GDPR Readiness", f"{g_pct}%", f"{g_impl}/{g_total} controls")
    with p_col:
        st.metric("PIPEDA Readiness", f"{p_pct}%", f"{p_impl}/{p_total} controls")

    st.markdown("---")
    st.markdown("#### Control Domains")

    left, right = st.columns(2)
    with left:
        st.markdown("**GDPR (EU)**")
        g_domains = gdpr_data.get("domains", {})
        if not g_domains:
            st.warning("GDPR catalogue not loaded.")
        else:
            for domain_id, domain in g_domains.items():
                controls = domain.get("controls", {})
                total = len(controls)
                impl = sum(1 for c in controls.values() if c.get("status") == "Implemented")
                pct = round((impl / total) * 100) if total else 0
                with st.expander(f"{domain_id} — {domain.get('name', 'Domain')} ({pct}%)"):
                    for ctrl_id, ctrl in controls.items():
                        status = ctrl.get("status", "Not Implemented")
                        icon = "✅" if status == "Implemented" else "⚠️" if status == "Partial" else "❌"
                        st.markdown(f"{icon} **{ctrl_id}** — {ctrl.get('name', 'Control')} | {status}")

    with right:
        st.markdown("**PIPEDA (Canada)**")
        p_domains = pipeda_data.get("domains", {})
        if not p_domains:
            st.warning("PIPEDA catalogue not loaded.")
        else:
            for domain_id, domain in p_domains.items():
                controls = domain.get("controls", {})
                total = len(controls)
                impl = sum(1 for c in controls.values() if c.get("status") == "Implemented")
                pct = round((impl / total) * 100) if total else 0
                with st.expander(f"{domain_id} — {domain.get('name', 'Domain')} ({pct}%)"):
                    for ctrl_id, ctrl in controls.items():
                        status = ctrl.get("status", "Not Implemented")
                        icon = "✅" if status == "Implemented" else "⚠️" if status == "Partial" else "❌"
                        st.markdown(f"{icon} **{ctrl_id}** — {ctrl.get('name', 'Control')} | {status}")

    st.info(
        "Next step for production: map shared evidence between HIPAA, GDPR, and PIPEDA so one operational control "
        "can satisfy multiple obligations and reduce audit overhead."
    )

footer()
