"""
pages/12_Financial_Compliance.py

Financial Edition — PCI DSS v4.0, SOX ITGC,
and FAIR Quantitative Risk Calculator.
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

from cyberresilient.services.fair_service import (
    calculate_fair, FAIRInput,
    FINANCIAL_SCENARIOS, HEALTHCARE_SCENARIOS,
    _format_currency,
)
from cyberresilient.services.compliance_service import load_controls
from cyberresilient.services.industry_service import get_industry_profile
from cyberresilient.theme import get_theme_colors

colors = get_theme_colors()
GOLD = colors["accent"]

st.markdown("# 🏦 Financial Compliance — PCI DSS, SOX ITGC & FAIR Risk")
st.markdown("PCI DSS v4.0, SOX IT General Controls compliance and quantitative risk analysis.")
st.markdown("---")

tab1, tab2, tab3 = st.tabs([
    "💳 PCI DSS v4.0",
    "📊 SOX IT General Controls",
    "📐 FAIR Quantitative Risk",
])


# ── Tab 1: PCI DSS ───────────────────────────────────────────
with tab1:
    st.markdown("### PCI DSS v4.0 — Requirement Compliance")

    controls_data = load_controls()
    pci_data = controls_data.get("pci_dss", {})
    requirements = pci_data.get("requirements", {})

    if not requirements:
        st.warning("PCI DSS catalogue not loaded. Ensure controls_pci_dss_sox.json is in your data/ directory.")
    else:
        # Overall score
        total = sum(len(r["controls"]) for r in requirements.values())
        implemented = sum(
            sum(1 for c in r["controls"].values() if c["status"] == "Implemented")
            for r in requirements.values()
        )
        pct = round((implemented / total) * 100) if total else 0

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=pct,
            title={"text": "PCI DSS Compliance", "font": {"color": "#EAEAEA"}},
            number={"suffix": "%", "font": {"color": GOLD}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": GOLD},
                "bgcolor": "#1A1A1A",
                "steps": [
                    {"range": [0, 50], "color": "#3a1010"},
                    {"range": [50, 80], "color": "#3a3010"},
                    {"range": [80, 100], "color": "#103a10"},
                ],
                "threshold": {"line": {"color": "#F44336", "width": 2}, "value": 80},
            },
        ))
        fig_gauge.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", height=250, margin=dict(t=60, b=10),
        )
        st.plotly_chart(fig_gauge, use_container_width=True)

        for req_id, req_data in requirements.items():
            req_total = len(req_data["controls"])
            req_impl = sum(1 for c in req_data["controls"].values() if c["status"] == "Implemented")
            req_pct = round((req_impl / req_total) * 100) if req_total else 0
            health = "✅" if req_pct == 100 else "⚠️" if req_pct >= 50 else "❌"

            with st.expander(f"{health} **{req_id}** — {req_data['name']} ({req_pct}%)"):
                for ctrl_id, ctrl in req_data["controls"].items():
                    status = ctrl["status"]
                    icon = "✅" if status == "Implemented" else "⚠️" if status == "Partial" else "❌"
                    st.markdown(f"{icon} `{ctrl_id}` — {ctrl['name']} | **{status}**")
                    if ctrl.get("evidence_date"):
                        st.caption(f"Evidence: {ctrl['evidence_date']}")


# ── Tab 2: SOX ITGC ──────────────────────────────────────────
with tab2:
    st.markdown("### SOX IT General Controls")

    sox_data = controls_data.get("sox_itgc", {})
    domains = sox_data.get("domains", {})

    if not domains:
        st.warning("SOX ITGC catalogue not loaded.")
    else:
        domain_names, domain_pcts, domain_colors_list = [], [], []

        for domain_id, domain in domains.items():
            total = len(domain["controls"])
            impl = sum(1 for c in domain["controls"].values() if c["status"] == "Implemented")
            pct = round((impl / total) * 100) if total else 0
            domain_names.append(domain["name"])
            domain_pcts.append(pct)
            domain_colors_list.append(
                "#4CAF50" if pct >= 80 else "#FF9800" if pct >= 50 else "#F44336"
            )

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=domain_names, y=domain_pcts,
            marker_color=domain_colors_list,
            text=[f"{p}%" for p in domain_pcts],
            textposition="outside",
        ))
        fig.add_hline(y=100, line_dash="dash", line_color=GOLD, annotation_text="Target: 100%")
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            font_color="#EAEAEA", yaxis=dict(range=[0, 115], gridcolor="#222"),
            height=350, margin=dict(t=30),
        )
        st.plotly_chart(fig, use_container_width=True)

        for domain_id, domain in domains.items():
            with st.expander(f"**{domain['name']}**"):
                for ctrl_id, ctrl in domain["controls"].items():
                    status = ctrl["status"]
                    icon = "✅" if status == "Implemented" else "⚠️" if status == "Partial" else "❌"
                    st.markdown(f"{icon} `{ctrl_id}` — {ctrl['name']} | **{status}**")


# ── Tab 3: FAIR Quantitative Risk ────────────────────────────
with tab3:
    st.markdown("### FAIR Quantitative Risk Calculator")
    st.markdown(
        "Express risk in monetary terms using the Factor Analysis of Information Risk (FAIR) model. "
        "Annualised Loss Expectancy (ALE) = Loss Event Frequency × Loss Magnitude."
    )

    profile = get_industry_profile()
    scenarios = FINANCIAL_SCENARIOS if "financial" in profile["label"].lower() else HEALTHCARE_SCENARIOS

    mode = st.radio("Input Mode", ["Use Pre-Built Scenario", "Custom Inputs"], horizontal=True)

    if mode == "Use Pre-Built Scenario":
        scenario_map = {s["name"]: s for s in scenarios}
        selected = st.selectbox("Select Scenario", list(scenario_map.keys()))
        scenario = scenario_map[selected]
        st.info(scenario["description"])
        defaults = scenario["defaults"]
    else:
        defaults = {
            "tef_low": 0.1, "tef_likely": 0.5, "tef_high": 2.0,
            "vuln_low": 0.1, "vuln_likely": 0.3, "vuln_high": 0.6,
            "plm_low": 100_000, "plm_likely": 500_000, "plm_high": 2_000_000,
            "slm_low": 0, "slm_likely": 50_000, "slm_high": 200_000,
        }
        scenario = {"id": "CUSTOM", "name": "Custom Scenario"}

    with st.form("fair_calculator"):
        st.markdown("#### Threat Event Frequency (per year)")
        tc1, tc2, tc3 = st.columns(3)
        tef_low    = tc1.number_input("Low",    value=float(defaults["tef_low"]),    step=0.1, key="tl")
        tef_likely = tc2.number_input("Likely", value=float(defaults["tef_likely"]), step=0.1, key="tm")
        tef_high   = tc3.number_input("High",   value=float(defaults["tef_high"]),   step=0.1, key="th")

        st.markdown("#### Vulnerability (0.0 – 1.0 probability)")
        vc1, vc2, vc3 = st.columns(3)
        vuln_low    = vc1.number_input("Low",    value=float(defaults["vuln_low"]),    min_value=0.0, max_value=1.0, step=0.05, key="vl")
        vuln_likely = vc2.number_input("Likely", value=float(defaults["vuln_likely"]), min_value=0.0, max_value=1.0, step=0.05, key="vm")
        vuln_high   = vc3.number_input("High",   value=float(defaults["vuln_high"]),   min_value=0.0, max_value=1.0, step=0.05, key="vh")

        st.markdown("#### Primary Loss Magnitude (per event, $)")
        pc1, pc2, pc3 = st.columns(3)
        plm_low    = pc1.number_input("Low",    value=float(defaults["plm_low"]),    step=10_000.0, key="pl")
        plm_likely = pc2.number_input("Likely", value=float(defaults["plm_likely"]), step=10_000.0, key="pm")
        plm_high   = pc3.number_input("High",   value=float(defaults["plm_high"]),   step=10_000.0, key="ph")

        st.markdown("#### Secondary Loss Magnitude (regulatory, reputational, $)")
        sc1, sc2, sc3 = st.columns(3)
        slm_low    = sc1.number_input("Low",    value=float(defaults["slm_low"]),    step=10_000.0, key="sl")
        slm_likely = sc2.number_input("Likely", value=float(defaults["slm_likely"]), step=10_000.0, key="sm")
        slm_high   = sc3.number_input("High",   value=float(defaults["slm_high"]),   step=10_000.0, key="sh")

        calc_submitted = st.form_submit_button("📐 Calculate FAIR ALE", type="primary")

    if calc_submitted:
        inputs = FAIRInput(
            tef_low=tef_low, tef_likely=tef_likely, tef_high=tef_high,
            vuln_low=vuln_low, vuln_likely=vuln_likely, vuln_high=vuln_high,
            plm_low=plm_low, plm_likely=plm_likely, plm_high=plm_high,
            slm_low=slm_low, slm_likely=slm_likely, slm_high=slm_high,
            scenario=scenario["name"],
        )
        result = calculate_fair(inputs)

        st.markdown("---")
        st.markdown(f"### Results: {scenario['name']}")

        r1, r2, r3 = st.columns(3)
        r1.metric("Annualised Loss Expectancy", result["formatted_ale"])
        r2.metric("ALE Range", result["formatted_ale_range"])
        r3.metric("Risk Tier", result["risk_tier"])

        r4, r5, r6 = st.columns(3)
        r4.metric("Loss Event Frequency", f"{result['lef_mean']} / yr")
        r5.metric("Total Loss (mean)", result["formatted_ale"].replace(result["formatted_ale"].split()[0], "")[1:] if " " in result["formatted_ale"] else result["formatted_ale"])
        r6.metric("Matrix Equivalent", f"{result['matrix_equivalent']}/25")

        # Waterfall chart: TEF → Vuln → LEF → Loss → ALE
        tier_color = {
            "Very High": "#F44336", "High": "#FF9800",
            "Medium": "#FFC107", "Low": "#4CAF50",
        }.get(result["risk_tier"], GOLD)

        fig_ale = go.Figure(go.Indicator(
            mode="number+delta",
            value=result["ale"],
            number={"prefix": "$", "valueformat": ",.0f", "font": {"color": tier_color}},
            delta={"reference": result["ale_low"], "relative": False,
                   "valueformat": ",.0f", "prefix": "Range low: $"},
            title={"text": "Annualised Loss Expectancy (ALE)", "font": {"color": "#EAEAEA"}},
        ))
        fig_ale.update_layout(paper_bgcolor="rgba(0,0,0,0)", height=200)
        st.plotly_chart(fig_ale, use_container_width=True)

        st.caption(
            f"Matrix equivalent score {result['matrix_equivalent']}/25 is available "
            "for cross-sector risk register comparison."
        )
