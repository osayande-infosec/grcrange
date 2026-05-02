"""
pages/9_Vendor_Registry.py

Third-Party / Vendor Risk Registry
"""

import html as _html
from datetime import date

import pandas as pd
import plotly.express as px
import streamlit as st

from cyberresilient.services.auth_service import get_current_user, has_permission, learning_callout
from cyberresilient.services.learning_service import (
    case_study_panel,
    chart_navigation_guide,
    get_content,
    grc_insight,
    how_to_use_panel,
    learning_section,
    try_this_panel,
)
from cyberresilient.services.risk_service import (
    ARCHITECTURE_CHECKS,
    run_architecture_assessment,
)
from cyberresilient.services.vendor_service import (
    CRITICALITY_COLORS,
    DATA_CLASSIFICATIONS,
    TIER_COLORS,
    VENDOR_CATEGORIES,
    VENDOR_CRITICALITIES,
    create_vendor,
    get_assessment_history,
    get_overdue_vendors,
    get_questionnaire,
    get_questionnaire_templates,
    load_questionnaire_responses,
    load_vendors,
    record_assessment,
    save_questionnaire_response,
    score_questionnaire,
    vendor_summary,
)
from cyberresilient.theme import get_theme_colors

colors = get_theme_colors()
GOLD = colors["accent"]

st.markdown("# 🤝 Vendor Risk Registry")
st.markdown("Third-party risk management — vendor profiles, assessment history, and re-assessment scheduling.")
st.markdown("---")

lc = get_content("vendor_risk")

learning_callout(
    "Why Third-Party Risk Matters",
    "Your security posture is only as strong as your weakest vendor. NIST CSF 2.0 "
    "added **GV.SC (Supply Chain Risk Management)** as a dedicated category. "
    "ISO 27001 A.5.19–A.5.23 covers Supplier Relationships. You are accountable "
    "for risks introduced by your vendors, even if you don't control their systems.",
)

if lc.get("how_to_use"):
    hu = lc["how_to_use"]
    how_to_use_panel(hu["title"], hu["steps"])

if lc.get("case_studies"):
    case_study_panel(lc["case_studies"]["cases"])

if lc.get("grc_connection"):
    gc = lc["grc_connection"]
    grc_insight(gc["title"].replace("GRC Engineering: ", ""), gc["content"])

if lc.get("vendor_assessment_guide"):
    vg = lc["vendor_assessment_guide"]
    learning_section(vg["title"], vg["content"], icon="📋")

if lc.get("try_this"):
    try_this_panel(lc["try_this"]["exercises"])

if lc.get("navigating_charts"):
    nc = lc["navigating_charts"]
    learning_section(nc["title"], nc["content"], icon="📊")
    chart_navigation_guide(nc["charts"])

summary = vendor_summary()
overdue = get_overdue_vendors()

m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Vendors", summary["total"])
m2.metric("Not Assessed", summary["not_assessed"])
m3.metric("Overdue Assessment", summary["overdue_assessment"])
m4.metric("Critical Vendors", summary["by_criticality"].get("Critical", 0))

if overdue:
    st.error(
        f"🚨 {len(overdue)} vendor(s) are overdue for reassessment: "
        + ", ".join(v["name"] for v in overdue[:5])
        + ("..." if len(overdue) > 5 else "")
    )

st.markdown("---")

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "📋 Vendor Register",
        "🔍 Assess a Vendor",
        "📝 Questionnaire",
        "➕ Add Vendor",
    ]
)

with tab1:
    vendors = load_vendors()
    if not vendors:
        st.info("No vendors registered yet. Add one in the 'Add Vendor' tab.")
    else:
        # Risk tier distribution chart
        tier_counts = summary.get("by_tier", {})
        if tier_counts:
            fig = px.pie(
                names=list(tier_counts.keys()),
                values=list(tier_counts.values()),
                color=list(tier_counts.keys()),
                color_discrete_map=TIER_COLORS,
                hole=0.45,
                title="Vendor Risk Tier Distribution",
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font_color="#EAEAEA",
                height=280,
            )
            st.plotly_chart(fig, use_container_width=True)

        today = date.today().isoformat()
        for v in sorted(vendors, key=lambda x: x["criticality"]):
            tier_color = TIER_COLORS.get(v["current_risk_tier"], "#888")
            crit_color = CRITICALITY_COLORS.get(v["criticality"], "#888")
            overdue_flag = " ⏰ REASSESSMENT OVERDUE" if v["reassessment_due"] < today else ""

            with st.expander(
                f"**{v['name']}** — {v['current_risk_tier']}{overdue_flag} | Criticality: {v['criticality']}"
            ):
                vc1, vc2, vc3 = st.columns(3)
                with vc1:
                    st.markdown(f"**Category:** {v['category']}")
                    st.markdown(
                        f"**Criticality:** <span style='color:{crit_color}'>{v['criticality']}</span>",
                        unsafe_allow_html=True,
                    )
                    st.markdown(f"**Data Classification:** {v['data_classification']}")
                with vc2:
                    st.markdown(
                        f"**Risk Tier:** "
                        f"<span style='color:{tier_color}'>{_html.escape(v['current_risk_tier'])}</span>",
                        unsafe_allow_html=True,
                    )
                    if v.get("last_assessment_score") is not None:
                        st.markdown(f"**Last Score:** {v['last_assessment_score']}%")
                    st.markdown(f"**Last Assessed:** {v.get('last_assessed_at') or 'Never'}")
                    st.markdown(f"**Next Due:** {v['reassessment_due']}")
                with vc3:
                    if v.get("contact_name"):
                        st.markdown(f"**Contact:** {v['contact_name']}")
                    if v.get("contact_email"):
                        st.markdown(f"**Email:** {v['contact_email']}")
                    if v.get("contract_reference"):
                        st.markdown(f"**Contract:** {v['contract_reference']}")
                    if v.get("contract_expiry"):
                        st.markdown(f"**Contract Expiry:** {v['contract_expiry']}")

                # Assessment history
                history = get_assessment_history(v["id"])
                if history:
                    st.markdown("**Assessment History**")
                    hist_df = pd.DataFrame(history)[
                        ["assessed_at", "score_pct", "risk_tier", "passed", "failed", "assessed_by"]
                    ]
                    hist_df.columns = ["Date", "Score %", "Tier", "Passed", "Failed", "Assessed By"]
                    st.dataframe(hist_df, use_container_width=True, hide_index=True)


with tab2:
    vendors = load_vendors()
    if not vendors:
        st.info("Add a vendor first before running an assessment.")
    else:
        vendor_map = {v["name"]: v["id"] for v in vendors}
        selected_name = st.selectbox("Select Vendor to Assess", list(vendor_map.keys()))
        selected_id = vendor_map[selected_name]

        with st.form("vendor_assessment"):
            st.markdown("#### Security Control Checklist")
            answers = {}
            for check in ARCHITECTURE_CHECKS:
                answers[check["id"]] = st.checkbox(
                    f"**{check['control']}** — {check['question']}",
                    key=f"va_{check['id']}",
                )
                st.caption(f"Framework: {check['framework']}")
            submitted = st.form_submit_button("🔍 Run Assessment", type="primary")

        if submitted:
            result = run_architecture_assessment(answers)
            record_assessment(
                vendor_id=selected_id,
                score_pct=result["score_pct"],
                assessment_detail=result,
                assessed_by=get_current_user().username,
            )
            st.success(
                f"Assessment recorded — {selected_name} scored **{result['score_pct']}%** ({result['overall_risk']})"
            )
            for r in result["results"]:
                if not r["passed"]:
                    st.warning(f"❌ {r['control']}: {r['risk_if_missing']}")
            st.rerun()


with tab3:
    st.markdown("### 📝 Vendor Risk Questionnaire")
    st.markdown("Send a SIG Lite or CAIQ questionnaire to a vendor and record their responses to generate a scored risk profile.")

    vendors_q = load_vendors()
    if not vendors_q:
        st.info("No vendors registered yet. Add one in the 'Add Vendor' tab.")
    else:
        templates_meta = get_questionnaire_templates()
        template_options = {v["name"]: k for k, v in templates_meta.items()}

        qc1, qc2 = st.columns(2)
        with qc1:
            q_vendor_name = st.selectbox("Select Vendor", [v["name"] for v in vendors_q], key="q_vendor")
            q_vendor = next(v for v in vendors_q if v["name"] == q_vendor_name)
        with qc2:
            q_template_label = st.selectbox("Questionnaire Template", list(template_options.keys()), key="q_template")
            q_template_key = template_options[q_template_label]

        selected_tmpl = templates_meta[q_template_key]
        st.caption(f"**{selected_tmpl['full_name']}** — {selected_tmpl['description']}")

        questions = get_questionnaire(q_template_key)
        if not questions:
            st.error("Questionnaire template not found.")
        else:
            # Group by domain
            domains_order = []
            by_domain: dict[str, list] = {}
            for q in questions:
                d = q["domain"]
                if d not in by_domain:
                    by_domain[d] = []
                    domains_order.append(d)
                by_domain[d].append(q)

            st.markdown("---")
            st.markdown(f"#### {q_template_label} — {len(questions)} Questions")

            answers: dict[str, bool] = {}
            with st.form(f"questionnaire_{q_template_key}"):
                for domain in domains_order:
                    st.markdown(f"**{domain}**")
                    for q in by_domain[domain]:
                        answers[q["id"]] = st.checkbox(
                            q["question"],
                            key=f"q_{q['id']}",
                            help=q.get("guidance", ""),
                        )
                    st.markdown("")

                q_submitted = st.form_submit_button("📊 Score & Save Response", type="primary")

            if q_submitted:
                result = score_questionnaire(answers, questions)
                st.markdown("---")
                st.markdown("### Results")

                rc1, rc2, rc3, rc4 = st.columns(4)
                rc1.metric("Overall Score", f"{result['score_pct']}%")
                rc2.metric("Questions Passed", result["passed"])
                rc3.metric("Questions Failed", result["failed"])
                risk_tier = (
                    "Low Risk" if result["score_pct"] >= 80
                    else "Medium Risk" if result["score_pct"] >= 60
                    else "High Risk" if result["score_pct"] >= 40
                    else "Critical Risk"
                )
                rc4.metric("Risk Rating", risk_tier)

                # Domain breakdown
                st.markdown("#### Domain Scores")
                for domain, ds in result["domain_scores"].items():
                    pct = ds["percentage"]
                    bar_color = "#4CAF50" if pct >= 80 else "#FFC107" if pct >= 50 else "#F44336"
                    st.markdown(
                        f"<div style='margin-bottom:4px'>"
                        f"<span style='font-size:13px'><b>{domain}</b> — {pct}%</span>"
                        f"<div style='background:#333;border-radius:4px;height:8px;width:100%'>"
                        f"<div style='background:{bar_color};border-radius:4px;height:8px;width:{pct}%'></div>"
                        f"</div></div>",
                        unsafe_allow_html=True,
                    )

                # Save
                save_questionnaire_response(
                    vendor_id=q_vendor["id"],
                    vendor_name=q_vendor_name,
                    template=q_template_key,
                    answers=answers,
                    score_result=result,
                    completed_by=get_current_user().username,
                )
                st.success(f"Response saved. {q_vendor_name} scored **{result['score_pct']}%** on {q_template_label}.")

        # ── Previous responses ─────────────────────────────
        st.markdown("---")
        st.markdown("#### Previous Questionnaire Responses")
        if vendors_q:
            prev_vendor_name = st.selectbox(
                "View responses for vendor:",
                [v["name"] for v in vendors_q],
                key="q_history_vendor",
            )
            prev_vendor = next(v for v in vendors_q if v["name"] == prev_vendor_name)
            responses = load_questionnaire_responses(prev_vendor["id"])
            if not responses:
                st.info("No questionnaire responses recorded yet for this vendor.")
            else:
                for r in responses:
                    tmpl_label = templates_meta.get(r["template"], {}).get("name", r["template"])
                    sc = r["score"]["score_pct"]
                    passed = r["score"]["passed"]
                    failed = r["score"]["failed"]
                    with st.expander(
                        f"**{tmpl_label}** — {sc}% — completed {r['completed_at'][:10]} by {r.get('completed_by', '—')}"
                    ):
                        h1, h2, h3 = st.columns(3)
                        h1.metric("Score", f"{sc}%")
                        h2.metric("Passed", passed)
                        h3.metric("Failed", failed)
                        if r["score"].get("domain_scores"):
                            for domain, ds in r["score"]["domain_scores"].items():
                                st.caption(f"  {domain}: {ds['percentage']}%")


with tab4:
    if not has_permission("edit_risks"):
        st.warning("You do not have permission to add vendors.")
    else:
        with st.form("add_vendor"):
            c1, c2 = st.columns(2)
            with c1:
                name = st.text_input("Vendor Name *")
                category = st.selectbox("Category", VENDOR_CATEGORIES)
                criticality = st.selectbox("Criticality", VENDOR_CRITICALITIES)
                data_class = st.selectbox("Data Classification", DATA_CLASSIFICATIONS)
            with c2:
                contact_name = st.text_input("Contact Name")
                contact_email = st.text_input("Contact Email")
                contract_ref = st.text_input("Contract Reference")
                contract_expiry = st.date_input("Contract Expiry", value=None)
            notes = st.text_area("Notes")
            submitted = st.form_submit_button("➕ Add Vendor", type="primary")

        if submitted:
            if not name:
                st.error("Vendor name is required.")
            else:
                create_vendor(
                    name=name,
                    category=category,
                    criticality=criticality,
                    data_classification=data_class,
                    contact_name=contact_name,
                    contact_email=contact_email,
                    contract_reference=contract_ref,
                    contract_expiry=str(contract_expiry) if contract_expiry else "",
                    notes=notes,
                    created_by=get_current_user().username,
                )
                st.success(f"Vendor '{name}' added.")
                st.rerun()
