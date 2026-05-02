"""
Page 12 — Executive Security Dashboard (C-Suite View)
Single-page board-level summary: KRI gauges, compliance trajectory,
open CAPAs, risk heat, policy health, and top AI-identified gaps.
"""

from __future__ import annotations

import datetime
import json

import plotly.graph_objects as go
import streamlit as st

from cyberresilient.config import get_config
from cyberresilient.services.ai_service import identify_gaps
from cyberresilient.services.cap_service import cap_summary
from cyberresilient.services.compliance_service import (
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
from cyberresilient.services.report_service import generate_compliance_board_report
from cyberresilient.services.risk_service import get_risk_summary, load_risks
from cyberresilient.theme import get_theme_colors

cfg = get_config()
colors = get_theme_colors()
GOLD = colors["accent"]

st.markdown("# 🏛️ Executive Security Dashboard")
st.markdown(
    f"**{cfg.organization.name}** | Board & C-Suite View | {datetime.date.today().strftime('%B %d, %Y')}"
)
st.markdown("---")


# ── Load all data (cached) ───────────────────────────────────
@st.cache_data(ttl=300)
def _load_all():
    controls = load_controls()
    nist = calc_nist_csf_scores(controls)
    iso = calc_iso27001_scores(controls)
    soc2 = calc_soc2_scores(load_soc2_controls())
    cmmc = calc_cmmc_scores(load_cmmc_controls())
    fedramp = calc_fedramp_scores(load_fedramp_controls())
    pci = calc_pci_scores(load_pci_controls())
    policies = load_policies()
    policy_sum = get_policy_summary(policies)
    risks = load_risks()
    risk_sum = get_risk_summary(risks)
    cap_sum = cap_summary()
    top_gaps = identify_gaps(
        nist_scores=nist,
        iso_scores=iso,
        soc2_scores=soc2,
        cmmc_scores=cmmc,
        fedramp_scores=fedramp,
        pci_scores=pci,
        threshold=80,
    )[:5]
    return nist, iso, soc2, cmmc, fedramp, pci, policy_sum, risk_sum, cap_sum, top_gaps


nist_s, iso_s, soc2_s, cmmc_s, fedramp_s, pci_s, pol_sum, risk_sum, caps, top_gaps = _load_all()


# ── Section: Multi-Framework Compliance Gauges ───────────────
st.markdown("### 📊 Compliance Posture — All Frameworks")

frameworks = [
    ("NIST CSF 2.0", nist_s["overall_percentage"], "#2196F3"),
    ("ISO 27001:2022", iso_s["overall_percentage"], "#9C27B0"),
    ("SOC 2 Type II", soc2_s["overall_percentage"], "#4CAF50"),
    ("CMMC 2.0 L2", cmmc_s["overall_percentage"], "#FF9800"),
    ("FedRAMP Mod", fedramp_s["overall_percentage"], "#00BCD4"),
    ("PCI DSS v4.0", pci_s["overall_percentage"], "#F44336"),
]

gauge_cols = st.columns(6)
for col, (fw_name, fw_pct, fw_color) in zip(gauge_cols, frameworks):
    with col:
        fig = go.Figure(
            go.Indicator(
                mode="gauge+number",
                value=fw_pct,
                title={"text": fw_name, "font": {"color": "#EAEAEA", "size": 11}},
                number={"suffix": "%", "font": {"color": fw_color, "size": 22}},
                gauge={
                    "axis": {"range": [0, 100], "tickfont": {"color": "#888", "size": 9}},
                    "bar": {"color": fw_color},
                    "bgcolor": "#1A1A1A",
                    "steps": [
                        {"range": [0, 50], "color": "#2a1010"},
                        {"range": [50, 75], "color": "#2a2010"},
                        {"range": [75, 100], "color": "#102a10"},
                    ],
                    "threshold": {
                        "line": {"color": GOLD, "width": 2},
                        "value": 80,
                    },
                },
            )
        )
        fig.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            height=160,
            margin={"t": 50, "b": 0, "l": 10, "r": 10},
        )
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ── Section: KRI Cards (Risk + CAP + Policy) ─────────────────
st.markdown("### 🔑 Key Risk Indicators")

k1, k2, k3, k4, k5, k6 = st.columns(6)

appetite_breaches = risk_sum.get("appetite_breaches", 0)
open_caps = caps.get("by_status", {}).get("Open", 0) + caps.get("by_status", {}).get("In Progress", 0)
overdue_caps = caps.get("overdue", 0)
critical_risks = sum(1 for r in risk_sum.get("by_category", {}).values() if isinstance(r, dict) and r.get("max_score", 0) >= 16)
expired_policies = pol_sum["by_status"].get("Expired", 0)
stale_controls = nist_s.get("stale_evidence_count", 0)


def _kri_card(col, label, value, subtitle, alert: bool = False):
    color = "#F44336" if alert and value > 0 else "#4CAF50" if value == 0 else "#FFC107"
    col.markdown(
        f"<div style='background:{color}22;border:1px solid {color};border-radius:10px;"
        f"padding:16px;text-align:center'>"
        f"<div style='font-size:32px;font-weight:700;color:{color}'>{value}</div>"
        f"<div style='font-size:13px;color:#ddd;font-weight:600'>{label}</div>"
        f"<div style='font-size:10px;color:#888;margin-top:4px'>{subtitle}</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


_kri_card(k1, "Appetite Breaches", appetite_breaches, "Residual > threshold", alert=True)
_kri_card(k2, "Open / In-Progress CAPAs", open_caps, "Corrective action plans", alert=True)
_kri_card(k3, "Overdue CAPAs", overdue_caps, "Past target date", alert=True)
_kri_card(k4, "Expired Policies", expired_policies, "Require immediate review", alert=True)
_kri_card(k5, "Stale NIST Controls", stale_controls, "Evidence > 365 days", alert=True)
_kri_card(k6, "Policies Current", pol_sum["by_status"].get("Current", 0), "Up to date", alert=False)

st.markdown("---")

# ── Section: Risk Heat Summary ────────────────────────────────
st.markdown("### 🔥 Risk Category Heat Summary")

risk_by_cat = risk_sum.get("by_category", {})
if risk_by_cat:
    cats = list(risk_by_cat.keys())
    counts = [risk_by_cat[c] if isinstance(risk_by_cat[c], int) else risk_by_cat[c].get("count", 0) for c in cats]
    cat_colors = []
    for c in cats:
        val = risk_by_cat[c]
        n = val if isinstance(val, int) else val.get("count", 0)
        cat_colors.append("#F44336" if n >= 5 else "#FFC107" if n >= 3 else "#4CAF50")

    fig_risk = go.Figure(
        go.Bar(
            x=cats,
            y=counts,
            marker_color=cat_colors,
            text=counts,
            textposition="outside",
        )
    )
    fig_risk.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#EAEAEA",
        yaxis={"gridcolor": "#333", "title": "Risk Count"},
        xaxis={"gridcolor": "#333"},
        height=300,
        margin={"t": 20, "b": 10},
        showlegend=False,
    )
    st.plotly_chart(fig_risk, use_container_width=True)
else:
    st.info("Risk category data not available.")

st.markdown("---")

# ── Section: Top Compliance Gaps ─────────────────────────────
st.markdown("### ⚠️ Top Compliance Gaps Requiring Attention")

if top_gaps:
    _sev_colors = {"Critical": "#F44336", "High": "#FF9800", "Medium": "#FFC107", "Low": "#4CAF50"}
    for gap in top_gaps:
        sev = gap.get("severity", "Medium")
        col = _sev_colors.get(sev, "#888")
        st.markdown(
            f"<div style='background:{col}11;border-left:4px solid {col};"
            f"border-radius:4px;padding:8px 14px;margin-bottom:6px'>"
            f"<span style='color:{col};font-weight:700;font-size:12px'>{sev.upper()}</span>"
            f" &nbsp;|&nbsp; <strong>[{gap['framework']}]</strong> {gap['control']}"
            f" &nbsp; <span style='color:#aaa;font-size:12px'>{gap['score']}%</span>"
            f"</div>",
            unsafe_allow_html=True,
        )
    st.caption("Run the full AI Gap Analysis from the Compliance page for detailed remediation plans.")
else:
    st.success("No critical compliance gaps detected at the 80% threshold.")

st.markdown("---")

# ── Section: Policy Health ────────────────────────────────────
st.markdown("### 📋 Policy Health")
ph1, ph2, ph3, ph4, ph5 = st.columns(5)
ph1.metric("Total Policies", pol_sum.get("total", 0))
ph2.metric("Current", pol_sum["by_status"].get("Current", 0))
ph3.metric("Under Review", pol_sum["by_status"].get("Under Review", 0))
ph4.metric("Draft", pol_sum["by_status"].get("Draft", 0))
ph5.metric("Expired", pol_sum["by_status"].get("Expired", 0), delta_color="inverse")

if pol_sum.get("expiring_soon"):
    expiring = pol_sum["expiring_soon"]
    names = ", ".join(p["name"] for p in expiring[:3])
    more = f" (+{len(expiring) - 3} more)" if len(expiring) > 3 else ""
    st.warning(f"⏰ **{len(expiring)} policy/policies expiring within 30 days:** {names}{more}")

st.markdown("---")

# ── Section: CAPA Summary ─────────────────────────────────────
st.markdown("### 🛠️ Corrective Action Plan (CAPA) Summary")
ca1, ca2, ca3, ca4 = st.columns(4)
ca1.metric("Total CAPAs", caps.get("total", 0))
ca2.metric("Open / In Progress", open_caps, delta_color="inverse")
ca3.metric("Overdue", overdue_caps, delta_color="inverse")
ca4.metric("Closed", caps.get("by_status", {}).get("Closed", 0))

by_priority = caps.get("by_priority", {})
if by_priority:
    prio_cols = st.columns(4)
    for col, prio in zip(prio_cols, ["Critical", "High", "Medium", "Low"]):
        col.metric(f"{prio} CAPAs", by_priority.get(prio, 0))

st.markdown("---")

# ── Section: Board PDF Export ─────────────────────────────────
st.markdown("### 📥 Export Board Report")
exp_col1, exp_col2 = st.columns([2, 3])

with exp_col1:
    if st.button("📄 Generate Board PDF Report", type="primary", use_container_width=True):
        with st.spinner("Generating PDF..."):
            try:
                audit_score = max(
                    0,
                    round(
                        nist_s["overall_percentage"] * 0.4
                        + iso_s["overall_percentage"] * 0.35
                        + pol_sum["current_pct"] * 0.25
                    ) - round(nist_s.get("stale_evidence_count", 0) / max(nist_s["total_controls"], 1) * 10),
                )
                pdf_path = generate_compliance_board_report(
                    nist_scores=nist_s,
                    iso_scores=iso_s,
                    policy_summary=pol_sum,
                    audit_score=audit_score,
                )
                with open(pdf_path, "rb") as f:
                    st.download_button(
                        "⬇️ Download PDF",
                        data=f.read(),
                        file_name="Executive_Board_Report.pdf",
                        mime="application/pdf",
                        use_container_width=True,
                    )
                st.success(f"PDF ready: {pdf_path}")
            except Exception as e:
                st.error(f"PDF generation failed: {e}")

with exp_col2:
    summary_data = {
        "generated": datetime.datetime.now().isoformat()[:19],
        "frameworks": {fw: pct for fw, pct, _ in frameworks},
        "kri": {
            "appetite_breaches": appetite_breaches,
            "open_caps": open_caps,
            "overdue_caps": overdue_caps,
            "expired_policies": expired_policies,
            "stale_controls": stale_controls,
        },
        "top_gaps": [
            {"framework": g["framework"], "control": g["control"], "score": g["score"], "severity": g["severity"]}
            for g in top_gaps
        ],
    }
    st.download_button(
        "⬇️ Export Summary JSON",
        data=json.dumps(summary_data, indent=2),
        file_name="executive_summary.json",
        mime="application/json",
        use_container_width=True,
    )
