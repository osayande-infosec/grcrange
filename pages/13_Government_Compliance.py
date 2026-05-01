"""
pages/13_Government_Compliance.py

Government Edition — NIST SP 800-53, FedRAMP ATO Workflow,
POA&M Tracker, and Continuous Monitoring Dashboard.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import date

from cyberresilient.services.ato_service import (
    create_ato_system, grant_ato, load_ato_systems,
    create_poam, load_poams, get_overdue_poams,
    get_expiring_atos, poam_summary,
    IMPACT_LEVELS, ATO_STATUSES, POAM_STATUSES,
    STATUS_COLORS,
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


def _render_action_result(fn, success_message: str) -> None:
    try:
        fn()
        st.success(success_message)
        st.rerun()
    except PermissionError as exc:
        st.error(str(exc))
    except Exception as exc:
        st.error(f"Action failed: {exc}")

page_header(
    "Government Compliance — NIST 800-53, FedRAMP & ATO",
    "NIST SP 800-53 Rev 5 compliance, FedRAMP ATO lifecycle, and POA&M tracking",
    icon="🏛️",
)

overdue_poams = get_overdue_poams()
expiring_atos = get_expiring_atos(days_ahead=90)

if overdue_poams:
    st.error(f"🚨 {len(overdue_poams)} POA&M item(s) are past their scheduled completion date.")
if expiring_atos:
    names = ", ".join(s["name"] for s in expiring_atos[:3])
    st.warning(f"⚠️ {len(expiring_atos)} ATO(s) expiring within 90 days: {names}")

systems = load_ato_systems()
psum = poam_summary()

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.markdown(kpi_card("Registered Systems", str(len(systems))), unsafe_allow_html=True)
with m2:
    active_count = sum(1 for s in systems if s["status"] == "Active ATO")
    st.markdown(kpi_card("Active ATOs", str(active_count), color="#3FB950"), unsafe_allow_html=True)
with m3:
    st.markdown(kpi_card("Open POA&Ms", str(psum["open"]), color="#D29922"), unsafe_allow_html=True)
with m4:
    od_color = "#F85149" if psum["overdue"] > 0 else "#3FB950"
    st.markdown(kpi_card("Overdue POA&Ms", str(psum["overdue"]), color=od_color), unsafe_allow_html=True)

st.markdown("")

tab1, tab2, tab3, tab4 = st.tabs([
    "📋 NIST 800-53",
    "🔐 ATO Systems",
    "📝 POA&M Tracker",
    "➕ Register System",
])


# ── Tab 1: NIST 800-53 ───────────────────────────────────────
with tab1:
    st.markdown("### NIST SP 800-53 Rev 5 — Control Families")

    controls_data = load_controls()
    n800_data = controls_data.get("nist_800_53", {})
    families = n800_data.get("families", {})

    baseline_filter = st.selectbox(
        "Filter by Baseline", ["All", "Low", "Moderate", "High"], index=0,
    )

    if not families:
        st.warning("NIST 800-53 catalogue not loaded. Ensure controls_nist_800_53.json is in data/.")
    else:
        family_summary_data = []
        for fam_id, fam in families.items():
            controls = fam["controls"]
            if baseline_filter != "All":
                controls = {
                    k: v for k, v in controls.items()
                    if baseline_filter in v.get("baseline", [])
                }
            if not controls:
                continue
            total = len(controls)
            impl = sum(1 for c in controls.values() if c["status"] == "Implemented")
            pct = round((impl / total) * 100) if total else 0
            family_summary_data.append({
                "family": fam_id,
                "name": fam["name"],
                "total": total,
                "implemented": impl,
                "pct": pct,
            })

        if family_summary_data:
            fdf = pd.DataFrame(family_summary_data)
            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=fdf["family"], y=fdf["pct"],
                marker_color=[
                    "#4CAF50" if p >= 80 else "#FF9800" if p >= 50 else "#F44336"
                    for p in fdf["pct"]
                ],
                text=[f"{p}%" for p in fdf["pct"]],
                textposition="outside",
                hovertext=fdf["name"],
            ))
            fig.add_hline(y=80, line_dash="dash", line_color=GOLD, annotation_text="Target: 80%")
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font_color="#EAEAEA",
                yaxis=dict(range=[0, 115], gridcolor="#222"),
                xaxis=dict(gridcolor="#222"),
                height=400, margin=dict(t=30),
            )
            st.plotly_chart(fig, use_container_width=True)

        for row in family_summary_data:
            fam = families[row["family"]]
            controls = fam["controls"]
            if baseline_filter != "All":
                controls = {k: v for k, v in controls.items() if baseline_filter in v.get("baseline", [])}
            with st.expander(
                f"**{row['family']} — {row['name']}** ({row['pct']}% | {row['implemented']}/{row['total']})"
            ):
                for ctrl_id, ctrl in controls.items():
                    status = ctrl["status"]
                    icon = "✅" if status == "Implemented" else "⚠️" if status == "Partial" else "❌"
                    baselines = ", ".join(ctrl.get("baseline", []))
                    st.markdown(f"{icon} `{ctrl_id}` — {ctrl['name']} | Baseline: {baselines} | **{status}**")


# ── Tab 2: ATO Systems ────────────────────────────────────────
with tab2:
    st.markdown("### ATO System Registry")

    if not systems:
        st.info("No systems registered. Use the 'Register System' tab.")
    else:
        for s in systems:
            status_color = STATUS_COLORS.get(s["status"], "#888")
            expiry = s.get("ato_expires_at", "")
            expiry_flag = ""
            if expiry:
                days_left = (date.fromisoformat(expiry) - date.today()).days
                if days_left <= 0:
                    expiry_flag = " 🔴 EXPIRED"
                elif days_left <= 90:
                    expiry_flag = f" 🟡 {days_left}d remaining"

            with st.expander(
                f"**{s['name']}** — "
                f"<span style='color:{status_color}'>{s['status']}</span>"
                f"{expiry_flag} | Impact: {s['impact_level']}",
                unsafe_allow_html=True,
            ):
                sc1, sc2, sc3 = st.columns(3)
                sc1.markdown(f"**System Owner:** {s['system_owner']}")
                sc1.markdown(f"**ISSO:** {s['isso']}")
                sc2.markdown(f"**AO:** {s['authorising_official']}")
                sc2.markdown(f"**Impact Level:** {s['impact_level']}")
                sc3.markdown(f"**ATO Granted:** {s.get('ato_granted_at') or 'Not yet'}")
                sc3.markdown(f"**ATO Expires:** {expiry or 'N/A'}")
                sc3.markdown(f"**Open POA&Ms:** {s.get('open_poam_count', 0)}")

                if s["description"]:
                    st.markdown(f"**Description:** {s['description']}")

                if has_permission("admin") and s["status"] != "Active ATO":
                    if st.button(f"Grant ATO — {s['name']}", key=f"ato_{s['id']}"):
                        _render_action_result(
                            lambda: grant_ato(s["id"], granted_by=get_current_user().username),
                            "ATO granted!",
                        )


# ── Tab 3: POA&M Tracker ──────────────────────────────────────
with tab3:
    st.markdown("### Plan of Action & Milestones (POA&M)")

    system_filter = st.selectbox(
        "Filter by System",
        ["All Systems"] + [s["name"] for s in systems],
        key="poam_system_filter",
    )
    system_id_filter = None
    if system_filter != "All Systems":
        system_id_filter = next(
            (s["id"] for s in systems if s["name"] == system_filter), None
        )

    poams = load_poams(system_id=system_id_filter)
    today = date.today().isoformat()

    if not poams:
        st.info("No POA&M items found.")
    else:
        for p in poams:
            is_overdue = (
                p["status"] not in ("Completed", "Risk Accepted")
                and p["scheduled_completion"] < today
            )
            status_icon = {
                "Open": "🔴", "In Progress": "🟡",
                "Completed": "✅", "Risk Accepted": "🔵",
                "Vendor Dependency": "🟠",
            }.get(p["status"], "❓")
            overdue_flag = " ⏰ OVERDUE" if is_overdue else ""

            with st.expander(
                f"{status_icon} **{p['id']}** — `{p['control_id']}` | {p['status']}{overdue_flag}"
            ):
                pc1, pc2 = st.columns(2)
                with pc1:
                    st.markdown(f"**Weakness:** {p['weakness_description']}")
                    st.markdown(f"**Responsible Party:** {p['responsible_party']}")
                with pc2:
                    st.markdown(f"**Scheduled Completion:** {p['scheduled_completion']}")
                    if p.get("completion_date"):
                        st.markdown(f"**Completed:** {p['completion_date']}")
                if p.get("milestones"):
                    st.markdown(f"**Milestones:** {p['milestones']}")
                if p.get("resources_required"):
                    st.markdown(f"**Resources Required:** {p['resources_required']}")

    st.markdown("---")
    st.markdown("#### Create New POA&M Item")
    if systems:
        with st.form("new_poam"):
            pc1, pc2 = st.columns(2)
            with pc1:
                poam_system = st.selectbox("System", [s["name"] for s in systems])
                control_id = st.text_input("Control ID", placeholder="e.g., AC-2")
                responsible = st.text_input("Responsible Party")
            with pc2:
                scheduled = st.date_input("Scheduled Completion")
                resources = st.text_input("Resources Required")
            weakness = st.text_area("Weakness Description *")
            milestones = st.text_area("Milestones")
            p_submitted = st.form_submit_button("➕ Create POA&M", type="primary")

        if p_submitted:
            if not weakness or not control_id or not responsible:
                st.error("Weakness, Control ID, and Responsible Party are required.")
            else:
                system_id = next(s["id"] for s in systems if s["name"] == poam_system)
                _render_action_result(
                    lambda: create_poam(
                        system_id=system_id,
                        control_id=control_id,
                        weakness_description=weakness,
                        scheduled_completion=str(scheduled),
                        responsible_party=responsible,
                        resources_required=resources,
                        milestones=milestones,
                        created_by=get_current_user().username,
                    ),
                    "POA&M item created.",
                )
    else:
        st.info("Register a system first before creating POA&M items.")


# ── Tab 4: Register System ────────────────────────────────────
with tab4:
    if not has_permission("admin"):
        st.warning("Admin permission required to register ATO systems.")
    else:
        st.markdown("### Register System for ATO Tracking")
        with st.form("register_system"):
            c1, c2 = st.columns(2)
            with c1:
                sys_name = st.text_input("System Name *")
                impact = st.selectbox("FIPS 199 Impact Level", IMPACT_LEVELS)
                owner = st.text_input("System Owner *")
                isso = st.text_input("ISSO *")
            with c2:
                ao = st.text_input("Authorising Official (AO) *")
                boundary = st.text_area("System Boundary Description")
            description = st.text_area("System Description")
            submitted = st.form_submit_button("➕ Register System", type="primary")

        if submitted:
            if not sys_name or not owner or not isso or not ao:
                st.error("Name, System Owner, ISSO, and AO are required.")
            else:
                _render_action_result(
                    lambda: create_ato_system(
                        name=sys_name,
                        description=description,
                        impact_level=impact,
                        system_owner=owner,
                        authorising_official=ao,
                        isso=isso,
                        boundary_description=boundary,
                        created_by=get_current_user().username,
                    ),
                    f"System '{sys_name}' registered for {impact}-baseline ATO tracking.",
                )

footer()
