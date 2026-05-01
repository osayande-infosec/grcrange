"""
pages/15_Audit_Assurance.py

3rd Line of Defence — Audit & Assurance.

Provides independent oversight of the GRC platform:
  - Immutable audit trail of all actions
  - Three Lines of Defence dashboard
  - Evidence completeness assessment
  - Compliance gap analysis
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

from cyberresilient.services.audit_service import load_audit_log, audit_summary
from cyberresilient.services.compliance_service import get_three_lines_summary
from cyberresilient.services.auth_service import get_current_user
from cyberresilient.theme import (
    get_theme_colors, inject_platform_css,
    page_header, section_header, kpi_card, footer,
)

colors = get_theme_colors()
user = get_current_user()
inject_platform_css()

page_header(
    "Audit & Assurance",
    "3rd Line of Defence — independent oversight and evidence review",
    icon="📋",
)

st.markdown("")

# ── Three Lines of Defence Summary ────────────────────────────
three_lines = get_three_lines_summary()

section_header("Three Lines of Defence Overview")

# Gauge chart for each line
fig = go.Figure()

first = three_lines["first_line"]
second = three_lines["second_line"]

fig.add_trace(go.Indicator(
    mode="gauge+number",
    value=first["score"],
    title={"text": "1st Line<br>Operational Security"},
    gauge={
        "axis": {"range": [0, 100]},
        "bar": {"color": "#1f77b4"},
        "steps": [
            {"range": [0, 40], "color": "#ffcccc"},
            {"range": [40, 60], "color": "#ffe0b2"},
            {"range": [60, 80], "color": "#fff9c4"},
            {"range": [80, 100], "color": "#c8e6c9"},
        ],
    },
    domain={"row": 0, "column": 0},
))

fig.add_trace(go.Indicator(
    mode="gauge+number",
    value=second["score"],
    title={"text": "2nd Line<br>Compliance & Risk"},
    gauge={
        "axis": {"range": [0, 100]},
        "bar": {"color": "#ff7f0e"},
        "steps": [
            {"range": [0, 40], "color": "#ffcccc"},
            {"range": [40, 60], "color": "#ffe0b2"},
            {"range": [60, 80], "color": "#fff9c4"},
            {"range": [80, 100], "color": "#c8e6c9"},
        ],
    },
    domain={"row": 0, "column": 1},
))

fig.update_layout(
    grid={"rows": 1, "columns": 2, "pattern": "independent"},
    height=300,
    margin=dict(l=30, r=30, t=60, b=30),
)
st.plotly_chart(fig, use_container_width=True)

# Evidence breakdown
section_header("Evidence Analysis")
ev1, ev2, ev3 = st.columns(3)
ev1.metric("Total Controls", second["total_controls"])
ev2.metric("Auto-Evidenced (1st Line)", second["evidence_backed"])
ev3.metric("Manual Attestation", second["manual_attestation"])

if second["total_controls"] > 0:
    auto_pct = round(second["evidence_backed"] / second["total_controls"] * 100)
    st.progress(auto_pct / 100, text=f"Evidence automation: {auto_pct}%")

st.markdown("---")

# ── Tabs ─────────────────────────────────────────────────────
tab_trail, tab_analysis, tab_frameworks = st.tabs([
    "📜 Audit Trail",
    "🔍 Gap Analysis",
    "📊 Framework Detail",
])

# ═══════════════════════════════════════════════════════════════
# TAB 1: AUDIT TRAIL
# ═══════════════════════════════════════════════════════════════
with tab_trail:
    st.subheader("Audit Log")

    # Filters
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        entity_filter = st.text_input("Entity Type", placeholder="e.g. asset, breach, change_request")
    with fc2:
        action_filter = st.text_input("Action", placeholder="e.g. create, approve, remediate")
    with fc3:
        limit = st.number_input("Max Results", 10, 1000, 100)

    entries = load_audit_log(
        entity_type=entity_filter or None,
        action=action_filter or None,
        limit=limit,
    )

    if entries:
        df = pd.DataFrame(entries)
        display_cols = ["timestamp", "action", "entity_type", "entity_id", "user"]
        st.dataframe(df[display_cols], use_container_width=True, hide_index=True)

        # Summary charts
        summary = audit_summary()
        if summary["by_action"]:
            a1, a2 = st.columns(2)
            with a1:
                fig_action = px.pie(
                    names=list(summary["by_action"].keys()),
                    values=list(summary["by_action"].values()),
                    title="Actions by Type",
                )
                fig_action.update_layout(height=300)
                st.plotly_chart(fig_action, use_container_width=True)
            with a2:
                fig_entity = px.pie(
                    names=list(summary["by_entity_type"].keys()),
                    values=list(summary["by_entity_type"].values()),
                    title="Actions by Entity",
                )
                fig_entity.update_layout(height=300)
                st.plotly_chart(fig_entity, use_container_width=True)
    else:
        st.info("No audit log entries yet. Actions will appear here as you use the platform.")


# ═══════════════════════════════════════════════════════════════
# TAB 2: GAP ANALYSIS
# ═══════════════════════════════════════════════════════════════
with tab_analysis:
    st.subheader("Compliance Gap Analysis")
    st.caption("Controls NOT yet implemented or evidence-backed, sorted by priority.")

    for fw_id, fw_score in second["frameworks"].items():
        with st.expander(f"**{fw_id.upper()}** — {fw_score['percentage']}% complete ({fw_score['implemented']}/{fw_score['total']})", expanded=fw_score["percentage"] < 80):
            gap_count = fw_score["total"] - fw_score["implemented"]
            if gap_count == 0:
                st.success("All controls implemented or evidence-backed!")
            else:
                st.warning(f"{gap_count} controls still need implementation or evidence")
                col_impl, col_ev, col_manual = st.columns(3)
                col_impl.metric("Implemented", fw_score["implemented"])
                col_ev.metric("Auto-Evidenced", fw_score["evidence_backed"])
                col_manual.metric("Manual", fw_score["manual"])


# ═══════════════════════════════════════════════════════════════
# TAB 3: FRAMEWORK DETAIL
# ═══════════════════════════════════════════════════════════════
with tab_frameworks:
    st.subheader("Per-Framework Compliance Detail")

    fw_names = list(second["frameworks"].keys())
    if fw_names:
        fw_scores = second["frameworks"]
        chart_data = []
        for fw_id, score in fw_scores.items():
            chart_data.append({
                "Framework": fw_id.upper(),
                "Implementation %": score["percentage"],
                "Total Controls": score["total"],
                "Implemented": score["implemented"],
                "Evidence-Backed": score["evidence_backed"],
            })
        df = pd.DataFrame(chart_data)
        fig = px.bar(
            df, x="Framework", y="Implementation %",
            color="Implementation %",
            color_continuous_scale=["#F44336", "#FF9800", "#4CAF50"],
            range_color=[0, 100],
            text="Implementation %",
        )
        fig.update_layout(height=400, yaxis_range=[0, 100])
        st.plotly_chart(fig, use_container_width=True)

        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No framework data available.")

footer()
