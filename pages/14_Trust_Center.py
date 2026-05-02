"""
Page 11 — Trust Center

Public-facing security posture page. Shows framework scores, certifications,
policies, and security commitments in a customer-readable format.
No authentication required for read access (controlled by Streamlit sharing).
"""

import plotly.graph_objects as go
import streamlit as st

from cyberresilient.config import get_config
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
from cyberresilient.theme import get_theme_colors

cfg = get_config()
colors = get_theme_colors()
GOLD = colors["accent"]

# ── Page config ──────────────────────────────────────────────
st.set_page_config(page_title="Trust Center", page_icon="🔐", layout="wide")

# ── Header ───────────────────────────────────────────────────
st.markdown(
    f"""
<div style='text-align:center;padding:40px 0 20px 0'>
  <h1 style='font-size:48px;color:{GOLD};margin-bottom:4px'>🔐 Trust Center</h1>
  <h3 style='color:#EAEAEA;font-weight:300'>{cfg.branding.app_title}</h3>
  <p style='color:#aaa;font-size:16px;max-width:700px;margin:12px auto 0'>
    Our commitment to security, privacy, and compliance — publicly verifiable
    and continuously updated from our live compliance programme.
  </p>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown("---")

# ── Load scores ───────────────────────────────────────────────
controls_data = load_controls()
policies = load_policies()
nist_scores = calc_nist_csf_scores(controls_data)
iso_scores = calc_iso27001_scores(controls_data)
policy_summary = get_policy_summary(policies)
soc2_scores = calc_soc2_scores(load_soc2_controls())
cmmc_scores = calc_cmmc_scores(load_cmmc_controls())
fedramp_scores = calc_fedramp_scores(load_fedramp_controls())
pci_scores = calc_pci_scores(load_pci_controls())

# Compute audit readiness
total_stale = nist_scores.get("stale_evidence_count", 0)
stale_ratio = total_stale / max(nist_scores["total_controls"], 1)
evidence_penalty = round(stale_ratio * 10)
audit_score = max(
    0,
    round(
        nist_scores["overall_percentage"] * 0.4
        + iso_scores["overall_percentage"] * 0.35
        + policy_summary["current_pct"] * 0.25
    ) - evidence_penalty,
)

# ── Scorecard strip ───────────────────────────────────────────
st.markdown("### Security Posture at a Glance")
_cols = st.columns(7)
_frameworks = [
    ("NIST CSF 2.0", nist_scores["overall_percentage"]),
    ("ISO 27001", iso_scores["overall_percentage"]),
    ("SOC 2 Type II", soc2_scores["overall_percentage"]),
    ("CMMC 2.0 L2", cmmc_scores["overall_percentage"]),
    ("FedRAMP Mod", fedramp_scores["overall_percentage"]),
    ("PCI DSS v4", pci_scores["overall_percentage"]),
    ("Audit Ready", audit_score),
]
for col, (label, pct) in zip(_cols, _frameworks):
    color = "#4CAF50" if pct >= 80 else "#FFC107" if pct >= 60 else "#F44336"
    col.markdown(
        f"""<div style='text-align:center;background:{color}18;border:1px solid {color};
border-radius:10px;padding:14px 4px'>
<div style='font-size:28px;font-weight:700;color:{color}'>{pct}%</div>
<div style='font-size:11px;color:#ccc;margin-top:4px'>{label}</div>
</div>""",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# ── Radar chart — overall posture ─────────────────────────────
fw_labels = ["NIST CSF", "ISO 27001", "SOC 2", "CMMC 2.0", "FedRAMP", "PCI DSS"]
fw_values = [
    nist_scores["overall_percentage"],
    iso_scores["overall_percentage"],
    soc2_scores["overall_percentage"],
    cmmc_scores["overall_percentage"],
    fedramp_scores["overall_percentage"],
    pci_scores["overall_percentage"],
]
# Close the polygon
fw_labels_r = fw_labels + [fw_labels[0]]
fw_values_r = fw_values + [fw_values[0]]

fig_radar = go.Figure()
fig_radar.add_trace(
    go.Scatterpolar(
        r=fw_values_r,
        theta=fw_labels_r,
        fill="toself",
        line_color=GOLD,
        fillcolor=f"{GOLD}33",
        name="Compliance Score",
    )
)
fig_radar.add_trace(
    go.Scatterpolar(
        r=[80] * (len(fw_labels) + 1),
        theta=fw_labels_r,
        line={"color": "#4CAF50", "dash": "dash"},
        mode="lines",
        name="Target (80%)",
    )
)
fig_radar.update_layout(
    polar={
        "radialaxis": {"visible": True, "range": [0, 100], "ticksuffix": "%"},
        "bgcolor": "rgba(0,0,0,0)",
    },
    paper_bgcolor="rgba(0,0,0,0)",
    font_color="#EAEAEA",
    height=420,
    legend={"bgcolor": "rgba(0,0,0,0)"},
    margin={"t": 40, "b": 40},
)
st.plotly_chart(fig_radar, use_container_width=True)

st.markdown("---")

# ── Certifications & Frameworks ────────────────────────────────
st.markdown("### Frameworks & Standards We Align To")

cert_items = [
    {
        "name": "NIST Cybersecurity Framework 2.0",
        "icon": "🏛️",
        "status": "Active",
        "score": nist_scores["overall_percentage"],
        "description": (
            "We align all security controls to NIST CSF 2.0 across six functions: "
            "Govern, Identify, Protect, Detect, Respond, and Recover."
        ),
    },
    {
        "name": "ISO/IEC 27001:2022",
        "icon": "📋",
        "status": "Active",
        "score": iso_scores["overall_percentage"],
        "description": (
            "ISO 27001 Information Security Management System controls are implemented "
            "across all 11 Annex A domains with evidence-tracked controls."
        ),
    },
    {
        "name": "SOC 2 Type II",
        "icon": "🔒",
        "status": "Readiness",
        "score": soc2_scores["overall_percentage"],
        "description": (
            "SOC 2 Trust Services Criteria (Security, Availability, Confidentiality, "
            "Processing Integrity, Privacy) are in active implementation. "
            "Formal Type II attestation planned."
        ),
    },
    {
        "name": "CMMC 2.0 Level 2",
        "icon": "🛡️",
        "status": "Readiness",
        "score": cmmc_scores["overall_percentage"],
        "description": (
            "CMMC 2.0 Level 2 (110 NIST SP 800-171 practices) implemented for "
            "Controlled Unclassified Information (CUI) handling readiness."
        ),
    },
    {
        "name": "FedRAMP Moderate Baseline",
        "icon": "🌐",
        "status": "Readiness",
        "score": fedramp_scores["overall_percentage"],
        "description": (
            "FedRAMP Moderate Baseline controls (NIST SP 800-53 Rev 5) implemented "
            "to support federal cloud service procurement requirements."
        ),
    },
    {
        "name": "PCI DSS v4.0",
        "icon": "💳",
        "status": "Active",
        "score": pci_scores["overall_percentage"],
        "description": (
            "All 12 PCI DSS v4.0 requirements actively implemented to protect "
            "payment card data and maintain cardholder data environment security."
        ),
    },
]

cert_col1, cert_col2 = st.columns(2)
for i, cert in enumerate(cert_items):
    col = cert_col1 if i % 2 == 0 else cert_col2
    with col:
        status_color = "#4CAF50" if cert["status"] == "Active" else "#2196F3"
        score_color = "#4CAF50" if cert["score"] >= 80 else "#FFC107" if cert["score"] >= 60 else "#F44336"
        st.markdown(
            f"""<div style='background:#1a1a2e;border:1px solid #333;border-radius:12px;
padding:20px;margin-bottom:16px'>
<div style='display:flex;justify-content:space-between;align-items:flex-start'>
  <div>
    <span style='font-size:22px'>{cert['icon']}</span>
    <span style='font-size:16px;font-weight:700;color:#EAEAEA;margin-left:8px'>{cert['name']}</span>
  </div>
  <div>
    <span style='background:{status_color}22;color:{status_color};font-size:11px;
    padding:3px 10px;border-radius:12px;border:1px solid {status_color};font-weight:600'>
    {cert['status']}</span>
    <span style='background:{score_color}22;color:{score_color};font-size:11px;
    padding:3px 10px;border-radius:12px;border:1px solid {score_color};font-weight:700;margin-left:6px'>
    {cert['score']}%</span>
  </div>
</div>
<p style='color:#bbb;font-size:13px;margin-top:10px;margin-bottom:0'>{cert['description']}</p>
</div>""",
            unsafe_allow_html=True,
        )

st.markdown("---")

# ── Policy Commitments ─────────────────────────────────────────
st.markdown("### Policy Commitments")
pol_col1, pol_col2 = st.columns(2)
with pol_col1:
    st.metric("Policies in Force", policy_summary.get("total", 0))
    st.metric("Policies Current", policy_summary["by_status"].get("Current", 0))
with pol_col2:
    st.metric("Annual Review Cycle", "All policies")
    st.metric("Policy Currency Rate", f"{policy_summary['current_pct']}%")

policy_commitments = [
    ("Acceptable Use Policy", "Governs appropriate use of information assets by all personnel."),
    ("Information Security Policy", "Top-level commitment to protecting confidentiality, integrity, and availability."),
    ("Incident Response Policy", "Defined procedures for detecting, reporting, and responding to security incidents."),
    ("Access Control Policy", "Least-privilege access model with mandatory MFA for privileged accounts."),
    ("Data Classification Policy", "Four-tier classification: Public, Internal, Confidential, Restricted."),
    ("Business Continuity Policy", "RTO/RPO targets defined; tested annually via DR simulation."),
    ("Vendor Management Policy", "Third-party risk scoring and annual questionnaire assessments."),
    ("Vulnerability Management Policy", "Critical patches applied within 72 hours; high within 14 days."),
]

pc1, pc2 = st.columns(2)
for i, (name, desc) in enumerate(policy_commitments):
    col = pc1 if i % 2 == 0 else pc2
    with col:
        st.markdown(f"**✅ {name}**")
        st.caption(desc)

st.markdown("---")

# ── Security Practices ─────────────────────────────────────────
st.markdown("### Security Practices")

practices = {
    "Data Protection": [
        "AES-256 encryption at rest for all sensitive data stores",
        "TLS 1.3 for all data in transit",
        "Data retention schedules aligned to regulatory requirements",
        "Annual data classification reviews",
    ],
    "Access Control": [
        "Multi-factor authentication enforced for all privileged access",
        "Role-based access control (RBAC) with least privilege",
        "Quarterly access reviews and certification",
        "Privileged access workstations (PAWs) for administrative tasks",
    ],
    "Vulnerability Management": [
        "Weekly automated vulnerability scans across all systems",
        "Annual third-party penetration testing",
        "Critical vulnerabilities patched within 72 hours",
        "Software composition analysis (SCA) in CI/CD pipeline",
    ],
    "Incident Response": [
        "24/7 security monitoring with SIEM correlation",
        "Defined incident response plan with escalation procedures",
        "Quarterly tabletop exercises simulating realistic scenarios",
        "Cyber incident response retainer with specialist firm",
    ],
    "Business Continuity": [
        "Recovery Time Objective (RTO): 4 hours for critical systems",
        "Recovery Point Objective (RPO): 1 hour for critical data",
        "Immutable offsite backups tested quarterly",
        "Annual disaster recovery simulation with documented results",
    ],
    "Supply Chain Security": [
        "All third-party vendors subject to risk scoring assessment",
        "Annual SIG Lite or CAIQ questionnaire for critical vendors",
        "Software Bill of Materials (SBOM) for all critical applications",
        "Contractual security requirements in all vendor agreements",
    ],
}

prac_col1, prac_col2 = st.columns(2)
for i, (category, items) in enumerate(practices.items()):
    col = prac_col1 if i % 2 == 0 else prac_col2
    with col:
        with st.expander(f"**{category}**", expanded=False):
            for item in items:
                st.markdown(f"- {item}")

st.markdown("---")

# ── Contact ────────────────────────────────────────────────────
st.markdown("### Contact Our Security Team")
ct1, ct2, ct3 = st.columns(3)
with ct1:
    st.markdown(
        """<div style='background:#1a1a2e;border:1px solid #333;border-radius:10px;padding:20px;text-align:center'>
<div style='font-size:28px'>🔒</div>
<div style='font-weight:700;margin:8px 0'>Security Issues</div>
<div style='color:#aaa;font-size:13px'>Report vulnerabilities or security concerns</div>
<div style='color:#E2B94C;margin-top:10px;font-size:13px'>security@example.com</div>
</div>""",
        unsafe_allow_html=True,
    )
with ct2:
    st.markdown(
        """<div style='background:#1a1a2e;border:1px solid #333;border-radius:10px;padding:20px;text-align:center'>
<div style='font-size:28px'>📋</div>
<div style='font-weight:700;margin:8px 0'>Compliance Inquiries</div>
<div style='color:#aaa;font-size:13px'>Framework certifications and audit requests</div>
<div style='color:#E2B94C;margin-top:10px;font-size:13px'>compliance@example.com</div>
</div>""",
        unsafe_allow_html=True,
    )
with ct3:
    st.markdown(
        """<div style='background:#1a1a2e;border:1px solid #333;border-radius:10px;padding:20px;text-align:center'>
<div style='font-size:28px'>🔏</div>
<div style='font-weight:700;margin:8px 0'>Privacy Requests</div>
<div style='color:#aaa;font-size:13px'>Data subject rights and privacy questions</div>
<div style='color:#E2B94C;margin-top:10px;font-size:13px'>privacy@example.com</div>
</div>""",
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)
st.caption(
    f"Security posture data is pulled live from the {cfg.branding.app_title} compliance programme. "
    "Scores reflect internal implementation readiness and are updated continuously."
)
