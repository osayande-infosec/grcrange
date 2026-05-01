"""
pages/10_Security_Operations.py

1st Line of Defence — Operational Security Modules.

Four tabs:
  1. Access Control Reviews
  2. Change Management
  3. Vulnerability Management
  4. SDLC Security

Plus a Three Lines of Defence dashboard summary.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from datetime import date, timedelta

from cyberresilient.services.secops_service import (
    create_access_review, complete_access_review, load_access_reviews,
    access_review_summary, ACCESS_REVIEW_TYPES,
    create_change_request, approve_change, implement_change,
    load_change_requests, change_management_summary,
    CHANGE_TYPES, CHANGE_STATUSES,
    create_vulnerability, remediate_vulnerability,
    load_vulnerabilities, vulnerability_summary,
    VULN_SOURCES, VULN_SEVERITIES, VULN_SLA_DAYS,
    create_sdlc_activity, complete_sdlc_activity,
    load_sdlc_activities, sdlc_summary,
    SDLC_ACTIVITY_TYPES, SDLC_PHASES,
    operational_health_score,
)
from cyberresilient.services.compliance_service import get_three_lines_summary
from cyberresilient.services.auth_service import get_current_user, has_permission
from cyberresilient.theme import (
    get_theme_colors, inject_platform_css,
    page_header, section_header, kpi_card, footer,
)

colors = get_theme_colors()
GOLD = colors["accent"]
user = get_current_user()
user_name = user.display_name
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
    "Security Operations Centre",
    "1st Line of Defence — operational security modules that generate compliance evidence automatically",
    icon="🛡️",
)

# ── Three Lines of Defence Overview ──────────────────────────
three_lines = get_three_lines_summary()
first = three_lines["first_line"]
second = three_lines["second_line"]
third = three_lines["third_line"]

tier_color_map = {"Excellent": "#3FB950", "Good": "#D29922", "Needs Improvement": "#F0883E", "Critical": "#F85149"}

c1, c2, c3 = st.columns(3)
with c1:
    tier_c = tier_color_map.get(first["tier"], "#8B949E")
    st.markdown(
        kpi_card("1st Line — SecOps", f"{first['score']}%", first["tier"], tier_c),
        unsafe_allow_html=True,
    )
with c2:
    sc_color = "#3FB950" if second["score"] >= 80 else "#D29922" if second["score"] >= 50 else "#F85149"
    st.markdown(
        kpi_card("2nd Line — Compliance", f"{second['score']}%",
                 f"{second['implemented']}/{second['total_controls']} controls ({second['evidence_backed']} auto-evidenced)", sc_color),
        unsafe_allow_html=True,
    )
with c3:
    audit_status = "Active" if third["audit_trail_active"] else "Inactive"
    audit_color = "#3FB950" if third["audit_trail_active"] else "#F85149"
    st.markdown(
        kpi_card("3rd Line — Audit", audit_status, f"Last: {third['last_assessment']}", audit_color),
        unsafe_allow_html=True,
    )

st.markdown("")

# Module health gauges
section_header("Module Health")
mod_cols = st.columns(4)
module_names = ["Access Control", "Change Management", "Vulnerability Management", "SDLC Security"]
module_icons = ["🔐", "🔄", "🐛", "⚙️"]
for col, name, icon in zip(mod_cols, module_names, module_icons):
    score = first["modules"].get(name, 0)
    mod_color = "#3FB950" if score >= 80 else "#D29922" if score >= 50 else "#F85149"
    col.markdown(
        kpi_card(f"{icon} {name}", f"{score}%", color=mod_color),
        unsafe_allow_html=True,
    )

st.markdown("")

# ── Tabs ─────────────────────────────────────────────────────
tab_ac, tab_cm, tab_vm, tab_sdlc = st.tabs([
    "🔐 Access Control",
    "🔄 Change Management",
    "🐛 Vulnerability Mgt",
    "⚙️ SDLC Security",
])


# ═══════════════════════════════════════════════════════════════
# TAB 1: ACCESS CONTROL REVIEWS
# ═══════════════════════════════════════════════════════════════
with tab_ac:
    st.subheader("Access Control Reviews")
    st.caption("Controls: NIST AC-2/AC-6, HIPAA §164.312(a), PCI DSS 7/8, SOX LA")

    ac_sum = access_review_summary()
    a1, a2, a3, a4 = st.columns(4)
    a1.metric("Total Reviews", ac_sum["total_reviews"])
    a2.metric("Completed", ac_sum["completed"])
    a3.metric("Overdue", ac_sum["overdue"])
    a4.metric("Accounts Revoked", ac_sum["total_accounts_revoked"])

    # Schedule new review
    with st.expander("➕ Schedule New Access Review"):
        with st.form("new_access_review"):
            ar_system = st.text_input("System Name", placeholder="e.g. Active Directory, EHR Portal")
            ar_type = st.selectbox("Review Type", ACCESS_REVIEW_TYPES)
            ar_reviewer = st.text_input("Reviewer", value=user_name)
            ar_accounts = st.number_input("Total Accounts", min_value=1, value=50)
            ar_date = st.date_input("Scheduled Date", value=date.today() + timedelta(days=7))
            if st.form_submit_button("Schedule Review"):
                _render_action_result(
                    lambda: create_access_review(
                        system_name=ar_system,
                        review_type=ar_type,
                        reviewer=ar_reviewer,
                        total_accounts=ar_accounts,
                        scheduled_date=ar_date.isoformat(),
                        created_by=user_name,
                    ),
                    f"Access review scheduled for {ar_system}",
                )

    # Complete existing review
    reviews = load_access_reviews()
    pending = [r for r in reviews if r["status"] in ("Scheduled", "In Progress")]
    if pending:
        with st.expander("✅ Complete a Review"):
            selected_review = st.selectbox(
                "Select Review",
                pending,
                format_func=lambda r: f"{r['system_name']} — {r['review_type']} ({r['scheduled_date']})",
            )
            if selected_review:
                with st.form("complete_review"):
                    cr_appropriate = st.number_input("Appropriate Accounts", 0, value=selected_review["total_accounts"] - 5)
                    cr_revoked = st.number_input("Revoked", 0, value=3)
                    cr_modified = st.number_input("Modified", 0, value=2)
                    cr_findings = st.text_area("Findings", placeholder="Describe any issues found...")
                    if st.form_submit_button("Mark Complete"):
                        _render_action_result(
                            lambda: complete_access_review(
                                review_id=selected_review["id"],
                                accounts_appropriate=cr_appropriate,
                                accounts_revoked=cr_revoked,
                                accounts_modified=cr_modified,
                                findings=cr_findings,
                                completed_by=user_name,
                            ),
                            "Review completed — compliance evidence generated.",
                        )

    # Review history table
    if reviews:
        st.subheader("Review History")
        df = pd.DataFrame(reviews)
        display_cols = ["system_name", "review_type", "reviewer", "status", "scheduled_date", "completed_date", "accounts_revoked"]
        st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No access reviews yet. Schedule one above to start generating compliance evidence.")


# ═══════════════════════════════════════════════════════════════
# TAB 2: CHANGE MANAGEMENT
# ═══════════════════════════════════════════════════════════════
with tab_cm:
    st.subheader("Change Management")
    st.caption("Controls: NIST CM-3/CM-5, PCI DSS 6.5, SOX CC")

    cm_sum = change_management_summary()
    cm1, cm2, cm3, cm4 = st.columns(4)
    cm1.metric("Total Changes", cm_sum["total_changes"])
    cm2.metric("Approval Rate", f"{cm_sum['approval_rate']}%")
    cm3.metric("Unauthorized", cm_sum["unauthorized_changes"])
    cm4.metric("Pending Approval", cm_sum["by_status"].get("Submitted", 0))

    # Submit new change
    with st.expander("➕ Submit Change Request"):
        with st.form("new_change"):
            chg_title = st.text_input("Title", placeholder="e.g. Update firewall rules for new VLAN")
            chg_desc = st.text_area("Description")
            chg_type = st.selectbox("Change Type", CHANGE_TYPES)
            chg_system = st.text_input("System Affected", placeholder="e.g. Firewall, EHR, Database")
            chg_risk = st.selectbox("Risk Level", ["Low", "Medium", "High", "Critical"])
            chg_rollback = st.text_area("Rollback Plan")
            if st.form_submit_button("Submit Change"):
                _render_action_result(
                    lambda: create_change_request(
                        title=chg_title,
                        description=chg_desc,
                        change_type=chg_type,
                        system_affected=chg_system,
                        risk_level=chg_risk,
                        requested_by=user_name,
                        rollback_plan=chg_rollback,
                        created_by=user_name,
                    ),
                    "Change request submitted for approval",
                )

    # Approve / implement changes
    changes = load_change_requests()
    submitted = [c for c in changes if c["status"] == "Submitted"]
    approved = [c for c in changes if c["status"] == "Approved"]

    if submitted:
        with st.expander("✅ Approve a Change"):
            sel_change = st.selectbox(
                "Select Change",
                submitted,
                format_func=lambda c: f"{c['id']} — {c['title']} ({c['risk_level']})",
                key="approve_select",
            )
            if sel_change:
                st.write(f"**Description:** {sel_change['description']}")
                st.write(f"**Rollback:** {sel_change['rollback_plan']}")
                if st.button("Approve Change"):
                    _render_action_result(
                        lambda: approve_change(sel_change["id"], approved_by=user_name),
                        "Change approved",
                    )

    if approved:
        with st.expander("🚀 Implement a Change"):
            sel_impl = st.selectbox(
                "Select Approved Change",
                approved,
                format_func=lambda c: f"{c['id']} — {c['title']}",
                key="impl_select",
            )
            if sel_impl:
                impl_evidence = st.text_area("Test Evidence", placeholder="Describe testing performed...")
                if st.button("Mark Implemented"):
                    _render_action_result(
                        lambda: implement_change(sel_impl["id"], implemented_by=user_name, test_evidence=impl_evidence),
                        "Change implemented — compliance evidence generated.",
                    )

    if changes:
        st.subheader("Change Log")
        df = pd.DataFrame(changes)
        display_cols = ["id", "title", "change_type", "risk_level", "status", "requested_by", "approved_by", "submitted_at"]
        st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No change requests yet. Submit one above to start the change management workflow.")


# ═══════════════════════════════════════════════════════════════
# TAB 3: VULNERABILITY MANAGEMENT
# ═══════════════════════════════════════════════════════════════
with tab_vm:
    st.subheader("Vulnerability Management")
    st.caption("Controls: NIST SI-2/RA-5, PCI DSS 6.3/11.3, HIPAA Risk Analysis")

    vm_sum = vulnerability_summary()
    v1, v2, v3, v4 = st.columns(4)
    v1.metric("Total Vulns", vm_sum["total_vulnerabilities"])
    v2.metric("Open", vm_sum["open"])
    v3.metric("Overdue SLA", vm_sum["overdue_sla"])
    v4.metric("MTTR (days)", vm_sum["mttr_days"])

    # SLA reference
    with st.expander("📋 Remediation SLA Policy"):
        sla_df = pd.DataFrame(
            [{"Severity": k, "SLA (days)": v} for k, v in VULN_SLA_DAYS.items()]
        )
        st.table(sla_df)

    # Record new vulnerability
    with st.expander("➕ Record Vulnerability"):
        with st.form("new_vuln"):
            vuln_title = st.text_input("Title", placeholder="e.g. SQL Injection in Patient Portal")
            vuln_cve = st.text_input("CVE ID", placeholder="CVE-2024-XXXX (optional)")
            vuln_source = st.selectbox("Source", VULN_SOURCES)
            vuln_severity = st.selectbox("Severity", VULN_SEVERITIES)
            vuln_cvss = st.number_input("CVSS Score", 0.0, 10.0, value=7.5, step=0.1)
            vuln_asset = st.text_input("Affected Asset", placeholder="e.g. patient-portal.example.com")
            vuln_component = st.text_input("Affected Component", placeholder="e.g. login form (optional)")
            vuln_desc = st.text_area("Description")
            vuln_fix = st.text_area("Remediation Step", placeholder="Recommended fix")
            if st.form_submit_button("Record Vulnerability"):
                _render_action_result(
                    lambda: create_vulnerability(
                        title=vuln_title, source=vuln_source, severity=vuln_severity,
                        affected_asset=vuln_asset, description=vuln_desc,
                        cve_id=vuln_cve, cvss_score=vuln_cvss,
                        affected_component=vuln_component, remediation=vuln_fix,
                        created_by=user_name,
                    ),
                    f"Vulnerability recorded — SLA: {VULN_SLA_DAYS.get(vuln_severity)} days",
                )

    # Remediate
    vulns = load_vulnerabilities()
    open_vulns = [v for v in vulns if v["status"] in ("Open", "In Progress")]
    if open_vulns:
        with st.expander("✅ Remediate Vulnerability"):
            sel_vuln = st.selectbox(
                "Select Vulnerability",
                open_vulns,
                format_func=lambda v: f"{v['id']} [{v['severity']}] {v['title']} (SLA: {v.get('sla_deadline', 'N/A')})",
            )
            if sel_vuln:
                st.write(f"**Asset:** {sel_vuln['affected_asset']}")
                st.write(f"**Description:** {sel_vuln['description']}")
                if st.button("Mark Remediated"):
                    _render_action_result(
                        lambda: remediate_vulnerability(sel_vuln["id"], verified_by=user_name),
                        "Vulnerability remediated — compliance evidence generated.",
                    )

    # Severity distribution chart
    if vulns:
        st.subheader("Vulnerability Register")
        severity_counts = vm_sum.get("by_severity", {})
        if severity_counts:
            fig = go.Figure(data=[go.Bar(
                x=list(severity_counts.keys()),
                y=list(severity_counts.values()),
                marker_color=["#ff4444", "#ff8800", "#ffcc00", "#44bb44", "#8888ff"],
            )])
            fig.update_layout(title="Open Vulnerabilities by Severity", height=300)
            st.plotly_chart(fig, use_container_width=True)

        df = pd.DataFrame(vulns)
        display_cols = ["id", "title", "severity", "cvss_score", "affected_asset", "status", "sla_deadline", "discovered_at"]
        st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No vulnerabilities recorded yet. Record one above to start tracking.")


# ═══════════════════════════════════════════════════════════════
# TAB 4: SDLC SECURITY
# ═══════════════════════════════════════════════════════════════
with tab_sdlc:
    st.subheader("SDLC Security Activities")
    st.caption("Controls: NIST SA-11, PCI DSS 6.2, SOX CC-3")

    sd_sum = sdlc_summary()
    s1, s2, s3, s4 = st.columns(4)
    s1.metric("Total Activities", sd_sum["total_activities"])
    s2.metric("Completed", sd_sum["completed"])
    s3.metric("Total Findings", sd_sum["total_findings"])
    s4.metric("Resolution Rate", f"{sd_sum['resolution_rate']}%")

    # Record SDLC activity
    with st.expander("➕ Record Security Activity"):
        with st.form("new_sdlc"):
            sdlc_project = st.text_input("Project Name", placeholder="e.g. Patient Portal v2.0")
            sdlc_type = st.selectbox("Activity Type", SDLC_ACTIVITY_TYPES)
            sdlc_phase = st.selectbox("SDLC Phase", SDLC_PHASES)
            sdlc_by = st.text_input("Conducted By", value=user_name)
            sdlc_desc = st.text_area("Description")
            if st.form_submit_button("Record Activity"):
                _render_action_result(
                    lambda: create_sdlc_activity(
                        project_name=sdlc_project,
                        activity_type=sdlc_type,
                        phase=sdlc_phase,
                        conducted_by=sdlc_by,
                        description=sdlc_desc,
                        created_by=user_name,
                    ),
                    f"SDLC activity recorded for {sdlc_project}",
                )

    # Complete activity
    activities = load_sdlc_activities()
    planned = [a for a in activities if a["status"] in ("Planned", "In Progress")]
    if planned:
        with st.expander("✅ Complete Activity"):
            sel_act = st.selectbox(
                "Select Activity",
                planned,
                format_func=lambda a: f"{a['project_name']} — {a['activity_type']} ({a['phase']})",
            )
            if sel_act:
                with st.form("complete_sdlc"):
                    f_count = st.number_input("Findings Count", 0, value=5)
                    f_critical = st.number_input("Critical Findings", 0, value=1)
                    f_resolved = st.number_input("Findings Resolved", 0, value=4)
                    if st.form_submit_button("Mark Complete"):
                        _render_action_result(
                            lambda: complete_sdlc_activity(
                                activity_id=sel_act["id"],
                                findings_count=f_count,
                                critical_findings=f_critical,
                                findings_resolved=f_resolved,
                            ),
                            "Activity completed — compliance evidence generated.",
                        )

    # Activity coverage heatmap
    if activities:
        st.subheader("Activity Register")
        # Coverage matrix: phase × type
        phase_type: dict[str, dict[str, int]] = {}
        for a in activities:
            if a["phase"] not in phase_type:
                phase_type[a["phase"]] = {}
            phase_type[a["phase"]][a["activity_type"]] = (
                phase_type[a["phase"]].get(a["activity_type"], 0) + 1
            )
        if phase_type:
            phases_order = [p for p in SDLC_PHASES if p in phase_type]
            types_order = sorted({t for d in phase_type.values() for t in d})
            z = [[phase_type.get(p, {}).get(t, 0) for t in types_order] for p in phases_order]
            fig = go.Figure(data=go.Heatmap(
                z=z, x=types_order, y=phases_order,
                colorscale="YlGn", showscale=True,
            ))
            fig.update_layout(title="Security Activity Coverage (Phase × Type)", height=300)
            st.plotly_chart(fig, use_container_width=True)

        df = pd.DataFrame(activities)
        display_cols = ["project_name", "activity_type", "phase", "conducted_by", "status", "findings_count", "critical_findings", "findings_resolved"]
        st.dataframe(df[display_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No SDLC activities yet. Record one above to start tracking software security.")

footer()
