"""
Page 5 — Compliance & Policy Tracker
NIST CSF 2.0 mapping, ISO 27001 Annex A,
policy lifecycle management, and audit readiness score.

v2: Surfaces evidence staleness, dependency breaches, compensating controls,
7-level lifecycle states, and policy expiry proximity alerts.
"""

import json as _json

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from cyberresilient.config import get_config
from cyberresilient.services.auth_service import learning_callout
from cyberresilient.services.cap_service import create_cap
from cyberresilient.services.ai_service import (
    get_gap_recommendations,
    identify_gaps,
    is_ai_available,
)
from cyberresilient.services.compliance_service import (
    LIFECYCLE_WEIGHTS,
    calc_cmmc_scores,
    calc_fedramp_scores,
    calc_iso27001_scores,
    calc_nist_csf_scores,
    calc_pci_scores,
    calc_soc2_scores,
    get_policy_summary,
    load_cmmc_controls,
    load_controls,
    load_fedramp_controls,
    load_pci_controls,
    load_policies,
    load_soc2_controls,
)
from cyberresilient.services.learning_service import (
    auditor_questions_panel,
    chart_navigation_guide,
    compliance_comparison_table,
    compliance_pipeline_panel,
    evidence_types_panel,
    get_content,
    grc_insight,
    how_to_use_panel,
    learning_section,
    nist_function_detail,
    try_this_panel,
)
from cyberresilient.theme import get_theme_colors

cfg = get_config()
colors = get_theme_colors()
GOLD = colors["accent"]

FUNC_COLORS = {
    "Govern": "#9C27B0",
    "Identify": "#2196F3",
    "Protect": "#4CAF50",
    "Detect": "#FF9800",
    "Respond": "#F44336",
    "Recover": GOLD,
}

# 7-level lifecycle → icon + colour
LIFECYCLE_META = {
    "Implemented": {"icon": "✅", "color": "#4CAF50"},
    "Compensating": {"icon": "🔄", "color": "#8BC34A"},
    "Largely": {"icon": "⚡", "color": "#CDDC39"},
    "Partial": {"icon": "⚠️", "color": "#FFC107"},
    "Planned": {"icon": "📅", "color": "#2196F3"},
    "Not Implemented": {"icon": "❌", "color": "#F44336"},
    "Gap": {"icon": "❌", "color": "#F44336"},  # legacy alias
}

# ── Header ──────────────────────────────────────────────────
st.markdown("# ✅ Compliance & Policy Tracker")
st.markdown("NIST CSF 2.0, ISO 27001:2022 compliance mapping and policy lifecycle management.")
st.markdown("---")

lc = get_content("compliance")

learning_callout(
    "Why Compliance Frameworks Matter",
    "Compliance frameworks like **NIST CSF** and **ISO 27001** provide structured "
    "approaches to managing cybersecurity risk. They are not checkbox exercises — "
    "they are engineering blueprints for building a defensible security program. "
    "Scores here reflect evidence quality and control dependencies, not just status.",
)

if lc.get("how_to_use"):
    hu = lc["how_to_use"]
    how_to_use_panel(hu["title"], hu["steps"])

if lc.get("grc_engineering"):
    ge = lc["grc_engineering"]
    grc_insight(ge["title"].replace("The ", ""), ge["content"])
    compliance_comparison_table(ge.get("comparison", []))

if lc.get("evidence_collection"):
    ec = lc["evidence_collection"]
    learning_section(ec["title"], ec["content"], icon="🗂️")
    evidence_types_panel(ec.get("evidence_types", []))

if lc.get("compliance_tracking"):
    ct = lc["compliance_tracking"]
    learning_section(ct["title"], ct["content"], icon="🔄")
    compliance_pipeline_panel(ct.get("pipeline_stages", []))

if lc.get("audit_readiness"):
    ar = lc["audit_readiness"]
    learning_section(ar["title"], ar["content"], icon="🔍")
    auditor_questions_panel(ar.get("auditor_questions", []))

if lc.get("navigating_charts"):
    nc = lc["navigating_charts"]
    learning_section(nc["title"], nc["content"], icon="📊")
    chart_navigation_guide(nc.get("charts", []))

if lc.get("try_this"):
    try_this_panel(lc["try_this"]["exercises"])

# ── Load & Score ─────────────────────────────────────────────
controls_data = load_controls()
policies = load_policies()
nist_scores = calc_nist_csf_scores(controls_data)
iso_scores = calc_iso27001_scores(controls_data)
policy_summary = get_policy_summary(policies)
soc2_data = load_soc2_controls()
soc2_scores = calc_soc2_scores(soc2_data)
cmmc_data = load_cmmc_controls()
cmmc_scores = calc_cmmc_scores(cmmc_data)
fedramp_data = load_fedramp_controls()
fedramp_scores = calc_fedramp_scores(fedramp_data)
pci_data = load_pci_controls()
pci_scores = calc_pci_scores(pci_data)

# ── Platform-wide alert strip ───────────────────────────────
total_stale = nist_scores.get("stale_evidence_count", 0)
dep_breaches = nist_scores.get("dependency_breach_count", 0)
compensating = nist_scores.get("compensating_count", 0)
expiring_soon = policy_summary.get("expiring_soon", [])

if total_stale or dep_breaches or expiring_soon:
    with st.container():
        if total_stale:
            st.warning(
                f"🗂️ **{total_stale} NIST CSF control(s)** have stale or missing evidence "
                f"(>365 days). Effective scores are capped at 50% until evidence is refreshed."
            )
        if dep_breaches:
            st.warning(
                f"🔗 **{dep_breaches} control(s)** are capped by unmet prerequisite controls. "
                "Expand the Category Detail below to see which prerequisites are blocking."
            )
        if compensating:
            st.info(
                f"🔄 **{compensating} control(s)** are currently satisfied by compensating "
                "controls. These are credited at 85% — verify with your auditor."
            )
        if expiring_soon:
            names = ", ".join(p["name"] for p in expiring_soon[:3])
            more = f" (+{len(expiring_soon) - 3} more)" if len(expiring_soon) > 3 else ""
            st.error(
                f"📋 **{len(expiring_soon)} policy/policies expiring within 30 days:** "
                f"{names}{more}. Review the Policy Lifecycle tab."
            )

# ── Overall Metrics ─────────────────────────────────────────
st.markdown("### Compliance Overview")
ov1, ov2, ov3, ov4, ov5, ov6, ov7 = st.columns(7)
ov1.metric("NIST CSF 2.0", f"{nist_scores['overall_percentage']}%")
ov2.metric("ISO 27001:2022", f"{iso_scores['overall_percentage']}%")
ov3.metric("SOC 2 Type II", f"{soc2_scores['overall_percentage']}%")
ov4.metric("CMMC 2.0 L2", f"{cmmc_scores['overall_percentage']}%")
ov5.metric("FedRAMP Mod", f"{fedramp_scores['overall_percentage']}%")
ov6.metric("PCI DSS v4.0", f"{pci_scores['overall_percentage']}%")
ov7.metric("Policies Current", f"{policy_summary['current_pct']}%")

st.markdown("---")

tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs(
    [
        "🏛️ NIST CSF 2.0",
        "📋 ISO 27001 & MFIPPA",
        "🔒 SOC 2 Type II",
        "🛡️ CMMC 2.0",
        "🌐 FedRAMP",
        "💳 PCI DSS",
        "🤖 AI Gap Analysis",
        "📄 Policy Lifecycle",
    ]
)


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 1 — NIST CSF 2.0                                       ║
# ╚══════════════════════════════════════════════════════════════╝
with tab1:
    st.markdown("### NIST Cybersecurity Framework v2.0 — Compliance Map")

    func_names = list(nist_scores["functions"].keys())
    func_pcts = [nist_scores["functions"][f]["percentage"] for f in func_names]
    func_colors_list = [FUNC_COLORS.get(f, "#888") for f in func_names]

    fig_func = go.Figure()
    fig_func.add_trace(
        go.Bar(
            x=func_names,
            y=func_pcts,
            marker_color=func_colors_list,
            text=[f"{p}%" for p in func_pcts],
            textposition="outside",
        )
    )
    fig_func.add_hline(
        y=80,
        line_dash="dash",
        line_color=GOLD,
        annotation_text="Target: 80%",
    )
    fig_func.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        yaxis_title="Compliance %",
        yaxis={"range": [0, 115], "gridcolor": "#222"},
        xaxis={"gridcolor": "#222"},
        height=400,
        margin={"t": 30},
    )
    st.plotly_chart(fig_func, use_container_width=True)

    # ── 7-level lifecycle legend ─────────────────────────────
    st.markdown("#### Control Status Legend")
    leg_cols = st.columns(len(LIFECYCLE_WEIGHTS))
    for idx, (status, weight) in enumerate(LIFECYCLE_WEIGHTS.items()):
        meta = LIFECYCLE_META.get(status, {"icon": "❓", "color": "#888"})
        with leg_cols[idx]:
            st.markdown(
                f"<div style='text-align:center;background:{meta['color']}22;"
                f"border:1px solid {meta['color']};border-radius:6px;padding:6px 2px'>"
                f"<span style='font-size:18px'>{meta['icon']}</span><br>"
                f"<span style='font-size:11px;color:{meta['color']};font-weight:600'>"
                f"{status}</span><br>"
                f"<span style='font-size:10px;color:#aaa'>{int(weight * 100)}% weight</span>"
                f"</div>",
                unsafe_allow_html=True,
            )

    st.markdown("---")
    st.markdown("### Category-Level Detail")

    nist_deep = lc.get("nist_csf_deep_dive", {})
    nist_functions = nist_deep.get("functions", {})

    for func_name, func_data in nist_scores["functions"].items():
        func_color = FUNC_COLORS.get(func_name, "#888")
        stale_in_func = sum(1 for cd in func_data.get("control_details", []) if cd["evidence_status"]["stale"])
        dep_in_func = sum(
            1 for cd in func_data.get("control_details", []) if any("Prerequisite" in n for n in cd.get("notes", []))
        )

        func_label = (
            f"{func_name} — {func_data['description']} "
            f"({func_data['percentage']}%)"
            + (f" 🗂️ {stale_in_func} stale" if stale_in_func else "")
            + (f" 🔗 {dep_in_func} capped" if dep_in_func else "")
        )

        with st.expander(func_label):
            control_details = func_data.get("control_details", [])

            if control_details:
                for cd in control_details:
                    status = cd["status"]
                    meta = LIFECYCLE_META.get(status, {"icon": "❓", "color": "#888"})
                    eff_weight = cd["effective_weight"]
                    ev_status = cd["evidence_status"]
                    notes = cd.get("notes", [])

                    # Control header row
                    c_col1, c_col2, c_col3 = st.columns([3, 1, 1])
                    with c_col1:
                        st.markdown(f"{meta['icon']} **{cd['id']}** — {cd['name']}")
                    with c_col2:
                        st.markdown(
                            f"<span style='color:{meta['color']};font-weight:600'>{status}</span>",
                            unsafe_allow_html=True,
                        )
                    with c_col3:
                        weight_color = "#4CAF50" if eff_weight >= 0.8 else "#FFC107" if eff_weight >= 0.4 else "#F44336"
                        st.markdown(
                            f"<span style='color:{weight_color};font-size:12px'>"
                            f"Effective: {int(eff_weight * 100)}%</span>",
                            unsafe_allow_html=True,
                        )

                    # Evidence status
                    if ev_status["stale"]:
                        if ev_status.get("days_overdue"):
                            st.caption(
                                f"   🗂️ Evidence overdue by {ev_status['days_overdue']} days"
                                f" — collected {cd.get('evidence_date', 'never')}"
                            )
                        else:
                            st.caption("   🗂️ No evidence date recorded")
                    elif ev_status.get("days_remaining") and ev_status["days_remaining"] <= 90:
                        st.caption(f"   🗂️ Evidence expires in {ev_status['days_remaining']} days")

                    # Advisory notes (dependency caps, compensating uplifts)
                    for note in notes:
                        if "Prerequisite" in note:
                            st.caption(f"   🔗 {note}")
                        elif "Compensated" in note:
                            st.caption(f"   🔄 {note}")
                        else:
                            st.caption(f"   ℹ️ {note}")

                    st.divider()
            else:
                # Fallback to legacy category dict rendering
                for cat_name, cat_data in func_data["categories"].items():
                    status = cat_data.get("status", "Not Implemented")
                    meta = LIFECYCLE_META.get(status, {"icon": "❓", "color": "#888"})
                    st.markdown(
                        f"{meta['icon']} **{cat_name}** — {cat_data.get('name', '')}  "
                        f"| Status: **{status}** | Evidence: {cat_data.get('evidence', 'N/A')}"
                    )

            if func_name in nist_functions:
                nist_function_detail(func_name, nist_functions[func_name])

    # ── Sunburst (coloured by effective weight tier) ─────────
    st.markdown("### NIST CSF Sunburst View")
    sunburst_data = {
        "ids": [],
        "labels": [],
        "parents": [],
        "values": [],
        "colors": [],
    }
    sunburst_data["ids"].append("NIST CSF")
    sunburst_data["labels"].append("NIST CSF 2.0")
    sunburst_data["parents"].append("")
    sunburst_data["values"].append(nist_scores["total_controls"])
    sunburst_data["colors"].append("#333")

    for func_name, func_data in nist_scores["functions"].items():
        sunburst_data["ids"].append(func_name)
        sunburst_data["labels"].append(f"{func_name}\n{func_data['percentage']}%")
        sunburst_data["parents"].append("NIST CSF")
        sunburst_data["values"].append(func_data["total_categories"])
        sunburst_data["colors"].append(FUNC_COLORS.get(func_name, "#888"))

        for cd in func_data.get("control_details", []):
            cat_id = f"{func_name}/{cd['id']}"
            # Colour by effective weight, not raw status
            w = cd["effective_weight"]
            if w >= 0.8:
                cell_color = "#4CAF50"
            elif w >= 0.6:
                cell_color = "#8BC34A"
            elif w >= 0.4:
                cell_color = "#FFC107"
            elif w >= 0.1:
                cell_color = "#FF9800"
            else:
                cell_color = "#F44336"
            sunburst_data["ids"].append(cat_id)
            sunburst_data["labels"].append(cd["id"])
            sunburst_data["parents"].append(func_name)
            sunburst_data["values"].append(1)
            sunburst_data["colors"].append(cell_color)

    fig_sun = go.Figure(
        go.Sunburst(
            ids=sunburst_data["ids"],
            labels=sunburst_data["labels"],
            parents=sunburst_data["parents"],
            values=sunburst_data["values"],
            marker={"colors": sunburst_data["colors"]},
            branchvalues="total",
        )
    )
    fig_sun.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        height=600,
        margin={"t": 20, "b": 20, "l": 20, "r": 20},
    )
    st.plotly_chart(fig_sun, use_container_width=True)
    st.caption(
        "Sunburst colour reflects **effective weight** after evidence staleness "
        "and dependency penalties — not raw status."
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 2 — ISO 27001 & MFIPPA                                 ║
# ╚══════════════════════════════════════════════════════════════╝
with tab2:
    st.markdown("### ISO 27001:2022 Annex A — Control Implementation")

    iso_df = pd.DataFrame(iso_scores["domains"])

    fig_iso = go.Figure()
    fig_iso.add_trace(
        go.Bar(
            name="Implemented",
            x=iso_df["name"],
            y=iso_df["implemented"],
            marker_color="#4CAF50",
        )
    )
    fig_iso.add_trace(
        go.Bar(
            name="Partial",
            x=iso_df["name"],
            y=iso_df["partial"],
            marker_color="#FFC107",
        )
    )
    fig_iso.add_trace(
        go.Bar(
            name="Gap",
            x=iso_df["name"],
            y=iso_df["total"] - iso_df["implemented"] - iso_df["partial"],
            marker_color="#F44336",
        )
    )
    fig_iso.update_layout(
        barmode="stack",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        yaxis_title="Controls",
        xaxis_title="",
        height=400,
        xaxis={"gridcolor": "#222"},
        yaxis={"gridcolor": "#222"},
        legend={"bgcolor": "rgba(0,0,0,0)"},
    )
    st.plotly_chart(fig_iso, use_container_width=True)

    # ── ISO domain table with health + staleness ─────────────
    st.markdown("#### Domain Detail")
    for domain in iso_scores["domains"]:
        ev = domain.get("evidence_status", {})
        health = domain.get("health", "Unknown")
        health_icon = {"Compliant": "✅", "At Risk": "⚠️", "Non-Compliant": "❌"}.get(health, "❓")
        stale_flag = " 🗂️ stale evidence" if ev.get("stale") else ""

        with st.expander(f"{health_icon} **{domain['name']}** — {domain['percentage']}% ({health}){stale_flag}"):
            dc1, dc2, dc3 = st.columns(3)
            dc1.metric("Total Controls", domain["total"])
            dc2.metric("Implemented", domain["implemented"])
            dc3.metric("Partial", domain["partial"])

            if ev.get("stale"):
                if ev.get("days_overdue"):
                    st.error(
                        f"🗂️ Domain evidence overdue by {ev['days_overdue']} days. "
                        "Score penalised to 80% of calculated until refreshed."
                    )
                else:
                    st.error("🗂️ No evidence date recorded for this domain. Score penalised to 80% of calculated.")
            elif ev.get("days_remaining") and ev["days_remaining"] <= 90:
                st.warning(f"🗂️ Evidence expires in {ev['days_remaining']} days — schedule refresh before it lapses.")

    st.markdown("---")

    # MFIPPA / custom frameworks (unchanged)
    custom_fws = [fw for fw in cfg.compliance.custom_frameworks if fw.enabled]
    if custom_fws:
        for fw in custom_fws:
            st.markdown(f"### 🏛️ {fw.name} — {fw.full_name}")
    else:
        st.markdown("### 🏛️ Additional Regulatory Frameworks")

    mfippa_items = [
        {
            "requirement": "Privacy Impact Assessments (PIAs)",
            "status": "Implemented",
            "detail": "PIAs required for all new systems processing personal information",
        },
        {
            "requirement": "Access to Information Requests",
            "status": "Implemented",
            "detail": "30-day response window; tracked in FOIP management system",
        },
        {
            "requirement": "Privacy Breach Protocol",
            "status": "Implemented",
            "detail": "IPC notification at earliest opportunity; target < 72 hours",
        },
        {
            "requirement": "Data Minimization",
            "status": "Partial",
            "detail": "Policy in place; enforcement gaps in legacy systems",
        },
        {
            "requirement": "Retention & Disposal Schedules",
            "status": "Partial",
            "detail": "Schedules exist for most record types; OT data retention under review",
        },
        {
            "requirement": "Staff Privacy Training",
            "status": "Implemented",
            "detail": "Annual mandatory training with completion tracking",
        },
        {
            "requirement": "Third-Party Data Sharing Agreements",
            "status": "Partial",
            "detail": "Template agreements exist; not all vendors have current DSAs",
        },
    ]
    for item in mfippa_items:
        icon = {"Implemented": "✅", "Partial": "⚠️", "Gap": "❌"}.get(item["status"], "❓")
        st.markdown(f"{icon} **{item['requirement']}** — *{item['status']}*")
        st.caption(item["detail"])


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 3 — SOC 2 Type II                                      ║
# ╚══════════════════════════════════════════════════════════════╝
with tab3:
    st.markdown("### 🔒 SOC 2 Type II — Trust Services Criteria")
    st.markdown(
        "AICPA SOC 2 Type II assesses controls over a review period (typically 6–12 months). "
        "Scores reflect implementation status and evidence currency."
    )

    soc2_cats = soc2_scores["categories"]
    soc2_names = [c["name"] for c in soc2_cats]
    soc2_pcts = [c["percentage"] for c in soc2_cats]
    soc2_ids = [c["id"] for c in soc2_cats]

    cat_colors = []
    for p in soc2_pcts:
        if p >= 80:
            cat_colors.append("#4CAF50")
        elif p >= 50:
            cat_colors.append("#FFC107")
        else:
            cat_colors.append("#F44336")

    fig_soc2 = go.Figure()
    fig_soc2.add_trace(
        go.Bar(
            x=soc2_ids,
            y=soc2_pcts,
            marker_color=cat_colors,
            text=[f"{p}%" for p in soc2_pcts],
            textposition="outside",
            hovertext=soc2_names,
            hoverinfo="text+y",
        )
    )
    fig_soc2.add_hline(y=80, line_dash="dash", line_color=GOLD, annotation_text="Target: 80%")
    fig_soc2.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        yaxis_title="Implementation %",
        yaxis={"range": [0, 115], "gridcolor": "#222"},
        xaxis={"gridcolor": "#222"},
        height=380,
        margin={"t": 30},
    )
    st.plotly_chart(fig_soc2, use_container_width=True)

    s1, s2, s3 = st.columns(3)
    s1.metric("Overall Score", f"{soc2_scores['overall_percentage']}%")
    s2.metric("Total Criteria", soc2_scores["total_controls"])
    s3.metric("Stale Evidence", soc2_scores.get("stale_categories", 0))

    st.markdown("---")
    st.markdown("#### Category Detail")

    for cat in soc2_cats:
        ev = cat.get("evidence_status", {})
        health = cat.get("health", "Unknown")
        health_icon = {"Compliant": "✅", "At Risk": "⚠️", "Non-Compliant": "❌"}.get(health, "❓")
        stale_flag = " 🗂️ stale" if ev.get("stale") else ""

        with st.expander(
            f"{health_icon} **{cat['id']} — {cat['name']}** — {cat['percentage']}% ({health}){stale_flag}"
        ):
            sc1, sc2, sc3, sc4 = st.columns(4)
            sc1.metric("Total Criteria", cat["total"])
            sc2.metric("Implemented", cat["implemented"])
            sc3.metric("Partial", cat["partial"])
            sc4.metric("Gap", cat["gap"])
            st.markdown(f"*{cat.get('description', '')}*")
            if ev.get("stale"):
                if ev.get("days_overdue"):
                    st.error(f"🗂️ Evidence overdue by {ev['days_overdue']} days. Score penalised to 80%.")
                else:
                    st.error("🗂️ No evidence date recorded. Score penalised to 80%.")
            elif ev.get("days_remaining") and ev["days_remaining"] <= 90:
                st.warning(f"🗂️ Evidence expires in {ev['days_remaining']} days.")

    st.markdown("---")
    st.info(
        "**Note:** SOC 2 Type II requires an independent auditor to assess whether controls operated effectively "
        "over the audit period. These scores represent your internal implementation readiness — not a substitute "
        "for a formal Type II audit. Engage a licensed CPA firm for formal attestation."
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 4 — CMMC 2.0                                           ║
# ╚══════════════════════════════════════════════════════════════╝
with tab4:
    st.markdown("### 🛡️ CMMC 2.0 Level 2 — 110 NIST SP 800-171 Practices")
    st.markdown(
        "Cybersecurity Maturity Model Certification (CMMC) Level 2 applies to contractors and subcontractors "
        "handling **Controlled Unclassified Information (CUI)** for the US Department of Defense."
    )

    cmmc_doms = cmmc_scores["domains"]
    cmmc_names = [f"{d['id']}" for d in cmmc_doms]
    cmmc_pcts = [d["percentage"] for d in cmmc_doms]

    domain_colors = []
    for p in cmmc_pcts:
        if p >= 80:
            domain_colors.append("#4CAF50")
        elif p >= 50:
            domain_colors.append("#FFC107")
        else:
            domain_colors.append("#F44336")

    fig_cmmc = go.Figure()
    fig_cmmc.add_trace(
        go.Bar(
            x=cmmc_names,
            y=cmmc_pcts,
            marker_color=domain_colors,
            text=[f"{p}%" for p in cmmc_pcts],
            textposition="outside",
            hovertext=[d["name"] for d in cmmc_doms],
            hoverinfo="text+y",
        )
    )
    fig_cmmc.add_hline(y=80, line_dash="dash", line_color=GOLD, annotation_text="Target: 80%")
    fig_cmmc.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        yaxis_title="Practice Implementation %",
        yaxis={"range": [0, 115], "gridcolor": "#222"},
        xaxis={"gridcolor": "#222"},
        height=380,
        margin={"t": 30},
    )
    st.plotly_chart(fig_cmmc, use_container_width=True)

    cm1, cm2, cm3, cm4 = st.columns(4)
    cm1.metric("Overall Score", f"{cmmc_scores['overall_percentage']}%")
    cm2.metric("Total Practices", cmmc_scores["total_controls"])
    cm3.metric("Domains", len(cmmc_doms))
    cm4.metric("Stale Evidence", cmmc_scores.get("stale_domains", 0))

    st.markdown("---")
    st.markdown("#### Domain Detail")

    for dom in cmmc_doms:
        ev = dom.get("evidence_status", {})
        health = dom.get("health", "Unknown")
        health_icon = {"Compliant": "✅", "At Risk": "⚠️", "Non-Compliant": "❌"}.get(health, "❓")
        stale_flag = " 🗂️ stale" if ev.get("stale") else ""

        with st.expander(
            f"{health_icon} **{dom['id']} — {dom['name']}** — {dom['percentage']}% ({dom['implemented']}/{dom['total']} practices){stale_flag}"
        ):
            dm1, dm2, dm3, dm4 = st.columns(4)
            dm1.metric("Total Practices", dom["total"])
            dm2.metric("Implemented", dom["implemented"])
            dm3.metric("Partial", dom["partial"])
            dm4.metric("Gap", dom["gap"])
            st.markdown(f"*{dom.get('description', '')}*")
            if ev.get("stale"):
                if ev.get("days_overdue"):
                    st.error(f"🗂️ Evidence overdue by {ev['days_overdue']} days. Score penalised to 80%.")
                else:
                    st.error("🗂️ No evidence date recorded. Score penalised to 80%.")
            elif ev.get("days_remaining") and ev["days_remaining"] <= 90:
                st.warning(f"🗂️ Evidence expires in {ev['days_remaining']} days.")

    st.markdown("---")
    st.info(
        "**Note:** CMMC 2.0 Level 2 certification requires a triennial third-party assessment (C3PAO) "
        "or annual self-assessment depending on CUI sensitivity. These scores represent implementation readiness — "
        "engage a CMMC Third-Party Assessment Organization (C3PAO) for formal certification."
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 5 — FedRAMP Moderate                                   ║
# ╚══════════════════════════════════════════════════════════════╝
with tab5:
    st.markdown("### 🌐 FedRAMP Moderate Baseline — NIST SP 800-53 Rev 5")
    st.markdown(
        "FedRAMP (Federal Risk and Authorization Management Program) provides a standardised approach "
        "to security assessment for cloud services used by US federal agencies. "
        "Moderate baseline applies to systems handling sensitive but unclassified data."
    )

    framp_fams = fedramp_scores["families"]
    framp_ids = [f["id"] for f in framp_fams]
    framp_pcts = [f["percentage"] for f in framp_fams]
    framp_colors = ["#4CAF50" if p >= 80 else "#FFC107" if p >= 50 else "#F44336" for p in framp_pcts]

    fig_fr = go.Figure()
    fig_fr.add_trace(
        go.Bar(
            x=framp_ids,
            y=framp_pcts,
            marker_color=framp_colors,
            text=[f"{p}%" for p in framp_pcts],
            textposition="outside",
            hovertext=[f["name"] for f in framp_fams],
            hoverinfo="text+y",
        )
    )
    fig_fr.add_hline(y=80, line_dash="dash", line_color=GOLD, annotation_text="Target: 80%")
    fig_fr.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        yaxis_title="Implementation %",
        yaxis={"range": [0, 115], "gridcolor": "#222"},
        xaxis={"gridcolor": "#222"},
        height=380,
        margin={"t": 30},
    )
    st.plotly_chart(fig_fr, use_container_width=True)

    fr1, fr2, fr3, fr4 = st.columns(4)
    fr1.metric("Overall Score", f"{fedramp_scores['overall_percentage']}%")
    fr2.metric("Total Controls", fedramp_scores["total_controls"])
    fr3.metric("Control Families", len(framp_fams))
    fr4.metric("Stale Evidence", fedramp_scores.get("stale_families", 0))

    st.markdown("---")
    st.markdown("#### Control Family Detail")
    for fam in framp_fams:
        ev = fam.get("evidence_status", {})
        health = fam.get("health", "Unknown")
        health_icon = {"Compliant": "✅", "At Risk": "⚠️", "Non-Compliant": "❌"}.get(health, "❓")
        stale_flag = " 🗂️ stale" if ev.get("stale") else ""
        with st.expander(
            f"{health_icon} **{fam['id']} — {fam['name']}** — {fam['percentage']}% "
            f"({fam['implemented']}/{fam['total']} controls){stale_flag}"
        ):
            frc1, frc2, frc3, frc4 = st.columns(4)
            frc1.metric("Total", fam["total"])
            frc2.metric("Implemented", fam["implemented"])
            frc3.metric("Partial", fam["partial"])
            frc4.metric("Gap", fam["gap"])
            st.markdown(f"*{fam.get('description', '')}*")
            if ev.get("stale"):
                if ev.get("days_overdue"):
                    st.error(f"🗂️ Evidence overdue by {ev['days_overdue']} days. Score penalised to 80%.")
                else:
                    st.error("🗂️ No evidence date recorded. Score penalised to 80%.")
            elif ev.get("days_remaining") and ev["days_remaining"] <= 90:
                st.warning(f"🗂️ Evidence expires in {ev['days_remaining']} days.")

    st.markdown("---")
    st.info(
        "**Note:** FedRAMP authorisation requires a Third Party Assessment Organization (3PAO) assessment "
        "and authorisation by a federal agency AO. These scores reflect internal implementation readiness. "
        "Contact the FedRAMP PMO or a certified 3PAO for formal authorisation guidance."
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 6 — PCI DSS v4.0                                       ║
# ╚══════════════════════════════════════════════════════════════╝
with tab6:
    st.markdown("### 💳 PCI DSS v4.0 — Payment Card Industry Data Security Standard")
    st.markdown(
        "PCI DSS applies to all entities that store, process, or transmit cardholder data. "
        "Version 4.0 introduces new requirements around targeted risk analysis, "
        "authentication, and customised implementation approaches."
    )

    pci_reqs = pci_scores["requirements"]
    pci_ids = [r["id"] for r in pci_reqs]
    pci_pcts = [r["percentage"] for r in pci_reqs]
    pci_colors = ["#4CAF50" if p >= 80 else "#FFC107" if p >= 50 else "#F44336" for p in pci_pcts]

    fig_pci = go.Figure()
    fig_pci.add_trace(
        go.Bar(
            x=pci_ids,
            y=pci_pcts,
            marker_color=pci_colors,
            text=[f"{p}%" for p in pci_pcts],
            textposition="outside",
            hovertext=[r["name"] for r in pci_reqs],
            hoverinfo="text+y",
        )
    )
    fig_pci.add_hline(y=80, line_dash="dash", line_color=GOLD, annotation_text="Target: 80%")
    fig_pci.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        yaxis_title="Implementation %",
        yaxis={"range": [0, 115], "gridcolor": "#222"},
        xaxis={"gridcolor": "#222"},
        height=380,
        margin={"t": 30},
    )
    st.plotly_chart(fig_pci, use_container_width=True)

    pc1, pc2, pc3, pc4 = st.columns(4)
    pc1.metric("Overall Score", f"{pci_scores['overall_percentage']}%")
    pc2.metric("Total Sub-Requirements", pci_scores["total_controls"])
    pc3.metric("Requirements", len(pci_reqs))
    pc4.metric("Stale Evidence", pci_scores.get("stale_requirements", 0))

    st.markdown("---")
    st.markdown("#### Requirement Detail")
    for req in pci_reqs:
        ev = req.get("evidence_status", {})
        health = req.get("health", "Unknown")
        health_icon = {"Compliant": "✅", "At Risk": "⚠️", "Non-Compliant": "❌"}.get(health, "❓")
        stale_flag = " 🗂️ stale" if ev.get("stale") else ""
        with st.expander(
            f"{health_icon} **{req['id']} — {req['name']}** — {req['percentage']}% "
            f"({req['implemented']}/{req['total']} sub-requirements){stale_flag}"
        ):
            prc1, prc2, prc3, prc4 = st.columns(4)
            prc1.metric("Total", req["total"])
            prc2.metric("Implemented", req["implemented"])
            prc3.metric("Partial", req["partial"])
            prc4.metric("Gap", req["gap"])
            st.markdown(f"*{req.get('description', '')}*")
            if ev.get("stale"):
                if ev.get("days_overdue"):
                    st.error(f"🗂️ Evidence overdue by {ev['days_overdue']} days. Score penalised to 80%.")
                else:
                    st.error("🗂️ No evidence date recorded. Score penalised to 80%.")
            elif ev.get("days_remaining") and ev["days_remaining"] <= 90:
                st.warning(f"🗂️ Evidence expires in {ev['days_remaining']} days.")

    st.markdown("---")
    st.info(
        "**Note:** PCI DSS compliance must be validated annually by a Qualified Security Assessor (QSA) "
        "or via a Self-Assessment Questionnaire (SAQ) depending on transaction volume and processing method. "
        "These scores reflect internal implementation readiness — not formal QSA validation."
    )


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 7 — AI Gap Analysis                                    ║
# ╚══════════════════════════════════════════════════════════════╝
with tab7:
    st.markdown("### 🤖 AI-Powered Gap Analysis & Remediation Planner")
    ai_available = is_ai_available()
    if ai_available:
        st.success("✅ OpenAI integration active — recommendations are AI-generated.")
    else:
        st.info(
            "OpenAI API key not configured. Showing rule-based recommendations. "
            "Set `OPENAI_API_KEY` in your environment to enable AI-powered analysis."
        )

    # ── Controls ─────────────────────────────────────────────
    ga_col1, ga_col2 = st.columns([2, 1])
    with ga_col1:
        gap_threshold = st.slider(
            "Include controls scoring below:",
            min_value=50, max_value=100, value=80, step=5,
            format="%d%%",
            key="gap_threshold",
        )
    with ga_col2:
        selected_frameworks = st.multiselect(
            "Frameworks to analyse:",
            ["NIST CSF 2.0", "ISO 27001", "SOC 2", "CMMC 2.0", "FedRAMP", "PCI DSS"],
            default=["NIST CSF 2.0", "ISO 27001"],
            key="gap_frameworks",
        )

    if st.button("🔍 Run Gap Analysis", type="primary", key="run_gap"):
        with st.spinner("Identifying gaps and generating recommendations..."):
            gaps = identify_gaps(
                nist_scores=nist_scores if "NIST CSF 2.0" in selected_frameworks else None,
                iso_scores=iso_scores if "ISO 27001" in selected_frameworks else None,
                soc2_scores=soc2_scores if "SOC 2" in selected_frameworks else None,
                cmmc_scores=cmmc_scores if "CMMC 2.0" in selected_frameworks else None,
                fedramp_scores=fedramp_scores if "FedRAMP" in selected_frameworks else None,
                pci_scores=pci_scores if "PCI DSS" in selected_frameworks else None,
                threshold=gap_threshold,
            )

        if not gaps:
            st.success(f"No control areas below {gap_threshold}% across selected frameworks.")
        else:
            # Summary bar
            sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
            for g in gaps:
                sev_counts[g["severity"]] = sev_counts.get(g["severity"], 0) + 1

            gs1, gs2, gs3, gs4 = st.columns(4)
            gs1.metric("Critical Gaps", sev_counts["Critical"], delta_color="inverse")
            gs2.metric("High Gaps", sev_counts["High"], delta_color="inverse")
            gs3.metric("Medium Gaps", sev_counts["Medium"], delta_color="inverse")
            gs4.metric("Low Gaps", sev_counts["Low"])

            st.markdown("---")

            with st.spinner("Generating remediation recommendations..."):
                recs = get_gap_recommendations(gaps, use_ai=ai_available)

            _sev_colors = {"Critical": "#F44336", "High": "#FF9800", "Medium": "#FFC107", "Low": "#4CAF50"}
            for rec in recs:
                sev = rec.get("severity", "Medium")
                sev_color = _sev_colors.get(sev, "#888")
                src_badge = "🤖 AI" if rec.get("source") == "openai" else "📋 Rule"
                with st.expander(
                    f"{src_badge} [{rec['framework']}] **{rec['control']}** — "
                    f"{rec['score']}% "
                    f"| Severity: {sev}"
                ):
                    st.markdown(
                        f"<span style='background:{sev_color};color:#fff;padding:2px 10px;"
                        f"border-radius:12px;font-size:12px;font-weight:700'>{sev}</span>",
                        unsafe_allow_html=True,
                    )
                    st.markdown(f"\n*{rec.get('description', '')}*")

                    st.markdown("**Quick Wins (0–30 days)**")
                    for qw in rec.get("quick_wins", []):
                        st.markdown(f"- {qw}")

                    st.markdown("**Strategic Actions (3–6 months)**")
                    for sa in rec.get("strategic_actions", []):
                        st.markdown(f"- {sa}")

                    st.markdown("---")
                    cap_key = f"cap_{rec['framework']}_{rec['control']}".replace(" ", "_")
                    if st.button(
                        "🛠️ Create CAP from this gap",
                        key=cap_key,
                        help="Auto-create a Corrective Action Plan pre-filled from this gap recommendation",
                    ):
                        import datetime as _dt
                        target = (_dt.date.today() + _dt.timedelta(days=90)).isoformat()
                        priority_map = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}
                        try:
                            new_cap = create_cap(
                                title=f"[{rec['framework']}] {rec['control']} – Gap Remediation",
                                description=(
                                    rec.get("description", "") + " Quick wins: "
                                    + "; ".join(rec.get("quick_wins", [])[:2])
                                ),
                                owner=cfg.organization.name + " Security Team",
                                target_date=target,
                                priority=priority_map.get(sev, "High"),
                                linked_control_id=rec.get("control", ""),
                                created_by="AI Gap Analysis",
                            )
                            st.success(
                                f"CAP created: **{new_cap['title']}** "
                                f"(ID: {new_cap['id'][:8]}...) — target {target}. "
                                "View in the CAP Tracker page."
                            )
                        except Exception as _cap_err:
                            st.error(f"CAP creation failed: {_cap_err}")

            # Export gap report
            st.markdown("---")
            import json as _gap_json
            gap_report = _gap_json.dumps(
                {"generated": str(__import__('datetime').datetime.now())[:19],
                 "threshold": gap_threshold,
                 "gap_count": len(gaps),
                 "recommendations": recs},
                indent=2,
            )
            st.download_button(
                "⬇️ Export Gap Report (JSON)",
                data=gap_report,
                file_name="gap_analysis_report.json",
                mime="application/json",
                use_container_width=True,
            )


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 8 — Policy Lifecycle                                   ║
# ╚══════════════════════════════════════════════════════════════╝
with tab8:
    st.markdown("### 📄 Security Policy Lifecycle Management")

    # ── Expiry proximity alert ───────────────────────────────
    if expiring_soon:
        st.error(f"🚨 **{len(expiring_soon)} policy/policies expiring within 30 days**")
        for p in expiring_soon:
            days = p["days_remaining"]
            urgency = "🔴" if days <= 7 else "🟠" if days <= 14 else "🟡"
            st.markdown(
                f"{urgency} **{p['name']}** — "
                f"review due **{p['next_review']}** ({days} day{'s' if days != 1 else ''} remaining)"
            )
        st.markdown("---")

    # Summary metrics
    ps1, ps2, ps3, ps4 = st.columns(4)
    ps1.metric("Current", policy_summary["by_status"].get("Current", 0))
    ps2.metric("Under Review", policy_summary["by_status"].get("Under Review", 0))
    ps3.metric("Draft", policy_summary["by_status"].get("Draft", 0))
    ps4.metric("Expired", policy_summary["by_status"].get("Expired", 0))

    # Donut
    status_counts = {k: v for k, v in policy_summary["by_status"].items() if v > 0}
    fig_pol = px.pie(
        names=list(status_counts.keys()),
        values=list(status_counts.values()),
        color=list(status_counts.keys()),
        color_discrete_map={
            "Current": "#4CAF50",
            "Under Review": "#FFC107",
            "Draft": "#2196F3",
            "Expired": "#F44336",
        },
        hole=0.4,
    )
    fig_pol.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        height=300,
    )
    st.plotly_chart(fig_pol, use_container_width=True)

    st.markdown("---")
    st.markdown("### Policy Details")

    filter_status = st.multiselect(
        "Filter by Status",
        ["Current", "Under Review", "Draft", "Expired"],
        default=["Current", "Under Review", "Draft", "Expired"],
        key="policy_filter",
    )
    filtered_policies = [p for p in policies if p["status"] in filter_status]

    # Sort: expiring soonest first, then alphabetical
    expiring_names = {p["name"] for p in expiring_soon}

    def _policy_sort_key(p):
        if p.get("name") in expiring_names:
            days = next((ep["days_remaining"] for ep in expiring_soon if ep["name"] == p.get("name")), 999)
            return (0, days)
        status_order = {"Expired": 1, "Under Review": 2, "Draft": 3, "Current": 4}
        return (status_order.get(p["status"], 5), 999)

    filtered_policies.sort(key=_policy_sort_key)

    for p in filtered_policies:
        icon = {
            "Current": "✅",
            "Under Review": "🔄",
            "Draft": "📝",
            "Expired": "⛔",
        }.get(p["status"], "❓")

        is_expiring = p.get("name") in expiring_names
        expiry_flag = " 🔴 EXPIRING SOON" if is_expiring else ""

        with st.expander(f"{icon} {p['name']} — v{p['version']} ({p['status']}){expiry_flag}"):
            pc1, pc2 = st.columns(2)
            with pc1:
                st.markdown(f"**Owner:** {p['owner']}")
                st.markdown(f"**Approver:** {p['approved_by']}")
                st.markdown(f"**Version:** {p['version']}")
            with pc2:
                st.markdown(f"**Status:** {p['status']}")
                st.markdown(f"**Last Reviewed:** {p['last_reviewed']}")
                st.markdown(f"**Next Review:** {p['next_review']}")

            if is_expiring:
                days_rem = next((ep["days_remaining"] for ep in expiring_soon if ep["name"] == p.get("name")), None)
                if days_rem is not None:
                    st.error(
                        f"⏰ Review due in **{days_rem} day{'s' if days_rem != 1 else ''}**. "
                        "Assign a reviewer immediately."
                    )

            st.markdown(f"**Description:** {p['description']}")

    st.markdown("---")

    # ── Audit Readiness Score ────────────────────────────────
    st.markdown("### 🎯 Audit Readiness Score")

    nist_pct = nist_scores["overall_percentage"]
    iso_pct = iso_scores["overall_percentage"]
    policy_pct = policy_summary["current_pct"]

    # Evidence quality penalty: deduct proportionally for stale evidence
    stale_ratio = total_stale / max(nist_scores["total_controls"], 1)
    evidence_penalty = round(stale_ratio * 10)  # up to -10 pts for fully stale

    audit_score = max(
        0,
        round(nist_pct * 0.4 + iso_pct * 0.35 + policy_pct * 0.25) - evidence_penalty,
    )

    fig_audit = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=audit_score,
            title={"text": "Audit Readiness", "font": {"color": "#EAEAEA", "size": 18}},
            number={"suffix": "%", "font": {"color": GOLD, "size": 48}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": GOLD},
                "bgcolor": "#1A1A1A",
                "steps": [
                    {"range": [0, 40], "color": "#3a1010"},
                    {"range": [40, 70], "color": "#3a3010"},
                    {"range": [70, 100], "color": "#103a10"},
                ],
                "threshold": {"line": {"color": "#F44336", "width": 2}, "value": 70},
            },
        )
    )
    fig_audit.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        height=300,
        margin={"t": 80, "b": 10},
    )
    st.plotly_chart(fig_audit, use_container_width=True)

    st.markdown(f"""
| Component | Weight | Score |
|---|---|---|
| NIST CSF 2.0 | 40% | {nist_pct}% |
| ISO 27001:2022 | 35% | {iso_pct}% |
| Policy Currency | 25% | {policy_pct}% |
| Evidence penalty | — | -{evidence_penalty}% |
| **Composite** | **100%** | **{audit_score}%** |
""")

    if audit_score >= 80:
        st.success("✅ Strong audit readiness. Maintain current trajectory.")
    elif audit_score >= 60:
        st.warning("⚠️ Moderate readiness. Address stale evidence and NIST CSF gaps before the next audit cycle.")
    else:
        st.error(
            "❌ Significant gaps. Prioritize compliance remediation, "
            "evidence refresh, and expired policy reviews immediately."
        )

# ── Export ───────────────────────────────────────────────────
st.markdown("---")
st.markdown("### 📥 Export Compliance Data")
ce1, ce2, ce3 = st.columns(3)
with ce1:
    policy_json = _json.dumps(
        [p.__dict__ if hasattr(p, "__dict__") else p for p in policies],
        indent=2,
        default=str,
    )
    st.download_button(
        "📋 Policies JSON",
        data=policy_json,
        file_name="policies_export.json",
        mime="application/json",
        use_container_width=True,
    )
with ce2:
    nist_json = _json.dumps(controls_data, indent=2, default=str)
    st.download_button(
        "📋 NIST CSF Controls JSON",
        data=nist_json,
        file_name="nist_csf_controls.json",
        mime="application/json",
        use_container_width=True,
    )
with ce3:
    if st.button("📄 Board Report (PDF)", use_container_width=True, type="primary"):
        from cyberresilient.services.report_service import generate_compliance_board_report

        # Recalculate audit score for the report
        _nist_pct = nist_scores["overall_percentage"]
        _iso_pct = iso_scores["overall_percentage"]
        _pol_pct = policy_summary["current_pct"]
        _stale_ratio = total_stale / max(nist_scores["total_controls"], 1)
        _evidence_penalty = round(_stale_ratio * 10)
        _audit_score = max(0, round(_nist_pct * 0.4 + _iso_pct * 0.35 + _pol_pct * 0.25) - _evidence_penalty)

        with st.spinner("Generating board report PDF..."):
            pdf_path = generate_compliance_board_report(
                nist_scores=nist_scores,
                iso_scores=iso_scores,
                policy_summary=policy_summary,
                audit_score=_audit_score,
            )
        with open(pdf_path, "rb") as _f:
            st.download_button(
                "⬇️ Download Board Report",
                data=_f.read(),
                file_name="Compliance_Board_Report.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
