"""
Page 13 — Evidence Library
Upload, browse, and manage compliance evidence files linked to
frameworks and controls. Org-scoped via multi-tenancy session state.
"""

import json
from datetime import date
from pathlib import Path

import streamlit as st

from cyberresilient.config import get_config
from cyberresilient.services.compliance_service import (
    load_cmmc_controls,
    load_controls,
    load_fedramp_controls,
    load_pci_controls,
    load_soc2_controls,
)
from cyberresilient.services.evidence_service import (
    delete_evidence,
    format_size,
    get_evidence_summary,
    list_evidence,
    save_evidence,
)
from cyberresilient.theme import get_theme_colors

cfg = get_config()
colors = get_theme_colors()
GOLD = colors["accent"]

# ── Page header ──────────────────────────────────────────────
st.markdown("# 🗂️ Evidence Library")
st.markdown(
    f"Upload and manage compliance evidence for **{cfg.organization.name}**. "
    "Evidence is linked to framework controls and tracked for freshness."
)
st.markdown("---")

org_key = st.session_state.get("active_org_key", "default")

# ── Summary strip ────────────────────────────────────────────
summary = get_evidence_summary(org_key)
es1, es2, es3, es4 = st.columns(4)
es1.metric("Total Evidence Items", summary["total"])
es2.metric("Fresh (< 365 days)", summary["fresh"], delta_color="normal")
es3.metric("Stale (> 365 days)", summary["stale"], delta_color="inverse")
es4.metric(
    "Frameworks Covered",
    len(summary["frameworks"]) if summary["frameworks"] else 0,
)

if summary["stale"]:
    st.warning(
        f"🗂️ **{summary['stale']} evidence item(s)** are older than 365 days. "
        "Re-collect or re-upload to maintain audit currency."
    )

st.markdown("---")

upload_tab, library_tab = st.tabs(["⬆️ Upload Evidence", "📚 Evidence Library"])


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 1 — Upload                                             ║
# ╚══════════════════════════════════════════════════════════════╝
with upload_tab:
    st.markdown("### Upload New Evidence")
    st.markdown(
        "Attach evidence files (PDFs, screenshots, exports, logs) to a specific "
        "framework control. Files are stored per-org and tracked for staleness."
    )

    # ── Framework + control selectors ────────────────────────
    FRAMEWORK_OPTIONS = [
        "NIST CSF 2.0",
        "ISO 27001",
        "SOC 2 Type II",
        "CMMC 2.0",
        "FedRAMP",
        "PCI DSS",
    ]

    up_col1, up_col2 = st.columns(2)
    with up_col1:
        selected_framework = st.selectbox(
            "Framework",
            FRAMEWORK_OPTIONS,
            key="ev_upload_framework",
        )
    with up_col2:
        uploader_name = st.text_input(
            "Your name / team",
            value=cfg.organization.name + " Security Team",
            key="ev_upload_uploader",
        )

    # Build control list from the selected framework
    @st.cache_data(show_spinner=False)
    def _get_controls_for_framework(fw: str) -> list[str]:
        try:
            if fw == "NIST CSF 2.0":
                data = load_controls()
                controls = []
                for func_data in data.get("functions", {}).values():
                    for cat_id, cat in func_data.get("categories", {}).items():
                        controls.append(f"{cat_id} — {cat.get('name', cat_id)}")
                return sorted(controls) or ["(no controls found)"]

            if fw == "ISO 27001":
                data = load_controls()
                controls = []
                for domain in data.get("iso27001_domains", {}).values():
                    for ctrl in domain.get("controls", []):
                        cid = ctrl.get("id", "")
                        cname = ctrl.get("name", cid)
                        controls.append(f"{cid} — {cname}")
                return sorted(controls) or ["(no controls found)"]

            if fw == "SOC 2 Type II":
                data = load_soc2_controls()
                controls = []
                for cat in data.get("categories", []):
                    for crit in cat.get("criteria", []):
                        cid = crit.get("id", "")
                        cname = crit.get("name", cid)
                        controls.append(f"{cid} — {cname}")
                return sorted(controls) or ["(no controls found)"]

            if fw == "CMMC 2.0":
                data = load_cmmc_controls()
                controls = []
                for domain in data.get("domains", []):
                    for practice in domain.get("practices", []):
                        pid = practice.get("id", "")
                        pname = practice.get("name", pid)
                        controls.append(f"{pid} — {pname}")
                return sorted(controls) or ["(no controls found)"]

            if fw == "FedRAMP":
                data = load_fedramp_controls()
                controls = []
                for family in data.get("families", []):
                    for ctrl in family.get("controls", []):
                        cid = ctrl.get("id", "")
                        cname = ctrl.get("name", cid)
                        controls.append(f"{cid} — {cname}")
                return sorted(controls) or ["(no controls found)"]

            if fw == "PCI DSS":
                data = load_pci_controls()
                controls = []
                for req in data.get("requirements", []):
                    for sub in req.get("sub_requirements", []):
                        sid = sub.get("id", "")
                        sname = sub.get("name", sid)
                        controls.append(f"{sid} — {sname}")
                return sorted(controls) or ["(no controls found)"]

        except Exception:
            pass
        return ["(no controls found)"]

    control_list = _get_controls_for_framework(selected_framework)
    selected_control_label = st.selectbox(
        "Control",
        control_list,
        key="ev_upload_control",
    )
    # Extract the control ID (everything before " — ")
    selected_control_id = selected_control_label.split(" — ")[0].strip()

    # ── File uploader ─────────────────────────────────────────
    uploaded_file = st.file_uploader(
        "Evidence file",
        type=["pdf", "png", "jpg", "jpeg", "xlsx", "docx", "csv", "txt", "eml", "zip"],
        help="Max 25 MB. Accepted: PDF, PNG, JPG, XLSX, DOCX, CSV, TXT, EML, ZIP",
        key="ev_file_uploader",
    )

    description = st.text_area(
        "Description (optional)",
        placeholder="e.g. Screenshot of MFA enforcement policy in Azure AD — captured 2026-05-01",
        key="ev_upload_description",
        height=80,
    )

    if uploaded_file:
        size_mb = uploaded_file.size / (1024 * 1024)
        st.caption(
            f"File: **{uploaded_file.name}** | Size: {size_mb:.2f} MB | "
            f"Control: **{selected_control_id}** | Framework: **{selected_framework}**"
        )

    if st.button("💾 Save Evidence", type="primary", key="ev_save_btn", disabled=uploaded_file is None):
        if uploaded_file is None:
            st.error("Please select a file to upload.")
        elif not selected_control_id or selected_control_id == "(no controls found)":
            st.error("Please select a valid control.")
        else:
            with st.spinner("Saving evidence..."):
                try:
                    file_bytes = uploaded_file.read()
                    meta = save_evidence(
                        org_key=org_key,
                        control_id=selected_control_id,
                        framework=selected_framework,
                        file_bytes=file_bytes,
                        filename=uploaded_file.name,
                        uploader=uploader_name or "system",
                    )
                    st.success(
                        f"Evidence saved: **{uploaded_file.name}** "
                        f"linked to **{selected_control_id}** ({selected_framework}). "
                        f"SHA-256: `{meta['sha256'][:16]}...`"
                    )
                    # Bust the summary cache so the strip updates
                    st.cache_data.clear()
                    st.rerun()
                except ValueError as err:
                    st.error(f"Upload rejected: {err}")
                except Exception as err:
                    st.error(f"Unexpected error saving file: {err}")


# ╔══════════════════════════════════════════════════════════════╗
# ║  TAB 2 — Library                                            ║
# ╚══════════════════════════════════════════════════════════════╝
with library_tab:
    st.markdown("### Evidence Library")

    # Filter controls
    lib_col1, lib_col2, lib_col3 = st.columns(3)
    with lib_col1:
        lib_framework = st.selectbox(
            "Filter by framework",
            ["All"] + [
                "NIST CSF 2.0", "ISO 27001", "SOC 2 Type II",
                "CMMC 2.0", "FedRAMP", "PCI DSS",
            ],
            key="lib_fw_filter",
        )
    with lib_col2:
        lib_staleness = st.selectbox(
            "Staleness",
            ["All", "Fresh only", "Stale only"],
            key="lib_stale_filter",
        )
    with lib_col3:
        lib_search = st.text_input(
            "Search by control ID or filename",
            key="lib_search",
            placeholder="e.g. AC-2 or policy.pdf",
        )

    fw_filter = None if lib_framework == "All" else lib_framework
    items = list_evidence(org_key, framework=fw_filter)

    # Apply staleness filter
    if lib_staleness == "Fresh only":
        items = [m for m in items if not m["stale"]]
    elif lib_staleness == "Stale only":
        items = [m for m in items if m["stale"]]

    # Apply search
    if lib_search:
        q = lib_search.lower()
        items = [
            m for m in items
            if q in m.get("control_id", "").lower()
            or q in m.get("original_filename", "").lower()
        ]

    if not items:
        st.info("No evidence items found. Upload files in the Upload tab.")
    else:
        st.markdown(f"**{len(items)} item(s)**")
        st.markdown("---")

        for m in items:
            stale_flag = " 🗂️ STALE" if m["stale"] else ""
            days_old = m.get("days_old", 0)
            staleness_color = "#F44336" if m["stale"] else "#4CAF50"
            staleness_label = f"{days_old}d old — STALE" if m["stale"] else f"{days_old}d old — Fresh"

            with st.expander(
                f"[{m.get('framework', '?')}] **{m.get('control_id', '?')}** — "
                f"{m.get('original_filename', '?')} ({m.get('collected_date', '?')}){stale_flag}"
            ):
                ec1, ec2 = st.columns([3, 1])
                with ec1:
                    st.markdown(f"**Framework:** {m.get('framework', '—')}")
                    st.markdown(f"**Control:** {m.get('control_id', '—')}")
                    st.markdown(f"**Uploaded by:** {m.get('uploader', '—')}")
                    st.markdown(f"**Collected:** {m.get('collected_date', '—')}")
                    st.markdown(
                        f"**Staleness:** "
                        f"<span style='color:{staleness_color};font-weight:600'>{staleness_label}</span>",
                        unsafe_allow_html=True,
                    )
                    st.caption(
                        f"Size: {format_size(m.get('file_size_bytes', 0))} | "
                        f"SHA-256: {m.get('sha256', '')[:20]}..."
                    )

                with ec2:
                    # Download button
                    file_path = Path(m.get("download_path", ""))
                    if file_path.exists():
                        file_bytes = file_path.read_bytes()
                        st.download_button(
                            "⬇️ Download",
                            data=file_bytes,
                            file_name=m.get("original_filename", "evidence"),
                            use_container_width=True,
                            key=f"dl_{m['evidence_id']}",
                        )
                    else:
                        st.caption("File not found on disk")

                    # Delete
                    if st.button(
                        "🗑️ Delete",
                        key=f"del_{m['evidence_id']}",
                        use_container_width=True,
                        help="Permanently delete this evidence item",
                    ):
                        if delete_evidence(org_key, m["evidence_id"]):
                            st.success("Evidence deleted.")
                            st.cache_data.clear()
                            st.rerun()
                        else:
                            st.error("Could not delete evidence.")

    st.markdown("---")

    # ── Export evidence manifest ──────────────────────────────
    all_items = list_evidence(org_key)
    if all_items:
        manifest = {
            "org_key": org_key,
            "exported_at": date.today().isoformat(),
            "total_items": len(all_items),
            "items": all_items,
        }
        st.download_button(
            "⬇️ Export Evidence Manifest (JSON)",
            data=json.dumps(manifest, indent=2, default=str),
            file_name=f"evidence_manifest_{org_key}_{date.today().isoformat()}.json",
            mime="application/json",
            use_container_width=False,
        )
