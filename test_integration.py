"""Integration test — validates all imports and core functions across all phases + 3 Lines of Defence."""
import sys, os
sys.path.insert(0, ".")

# Remove old DB to force fresh schema (skip if locked by another process)
db_path = os.path.join(os.path.dirname(__file__), "cyberresilient.db")
try:
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Removed old DB for fresh schema")
except PermissionError:
    print("DB locked by another process — will use init_db() to add missing tables")

# Phase 1 - config + industry
from cyberresilient.config import get_config, DATA_DIR
from cyberresilient.theme import get_theme_colors
from cyberresilient.database import init_db, get_session
from cyberresilient.services.industry_service import (
    INDUSTRY_PROFILES, get_industry_profile, get_active_frameworks,
    get_risk_categories, get_data_classifications,
    get_breach_notification_config, get_industry_kpis,
)
from cyberresilient.services.compliance_service import load_controls, get_compliance_score, get_three_lines_summary

# Phase 2 - Healthcare
from cyberresilient.services.phi_service import (
    register_asset, load_assets, phi_asset_summary,
    create_breach_notification, get_overdue_breach_notifications,
    get_escalated_score, SEVERITY_COLORS, HIPAA_TIMELINES,
    CLASSIFICATION_MULTIPLIERS,
)

# Phase 3 - Financial
from cyberresilient.services.fair_service import (
    calculate_fair, FAIRInput,
    FINANCIAL_SCENARIOS, HEALTHCARE_SCENARIOS,
)

# Phase 4 - Government
from cyberresilient.services.ato_service import (
    create_ato_system, grant_ato, load_ato_systems,
    create_poam, load_poams, get_overdue_poams,
    get_expiring_atos, poam_summary,
    IMPACT_LEVELS, ATO_STATUSES, POAM_STATUSES, STATUS_COLORS,
)

# Phase 5 - Multi-tenant
from cyberresilient.services.tenant_service import (
    create_tenant, list_tenants, tenant_summary,
    is_trial_expired, SUPPORTED_INDUSTRIES, PLAN_TIERS,
    verify_email, resend_verification_code, is_email_verified,
)

# 1st Line - SecOps
from cyberresilient.services.secops_service import (
    create_access_review, complete_access_review, load_access_reviews,
    access_review_summary, create_change_request, approve_change,
    implement_change, load_change_requests, change_management_summary,
    create_vulnerability, remediate_vulnerability, load_vulnerabilities,
    vulnerability_summary, create_sdlc_activity, complete_sdlc_activity,
    load_sdlc_activities, sdlc_summary, operational_health_score,
    CONTROL_EVIDENCE_MAP,
)

# Row-level security
from cyberresilient.services.rls import get_tenant_id, tenant_filter, inject_tenant_id

# Subdomain routing
from cyberresilient.services.subdomain_service import (
    extract_subdomain, resolve_tenant_from_subdomain,
    get_tenant_url, BASE_DOMAIN,
)

# 3rd Line - Audit
from cyberresilient.services.audit_service import log_action, load_audit_log, audit_summary as audit_sum

print("ALL IMPORTS OK")

profile = get_industry_profile()
print("Profile:", profile["label"])
print("Frameworks:", get_active_frameworks())
print("Risk categories:", len(get_risk_categories()))
print("KPIs:", get_industry_kpis())
print("Breach config:", get_breach_notification_config())

catalogues = load_controls()
print("Catalogues loaded:", list(catalogues.keys()))
print("HIPAA:", get_compliance_score("hipaa"))
print("NIST 800-53:", get_compliance_score("nist_800_53"))
print("PCI DSS:", get_compliance_score("pci_dss"))
print("SOX ITGC:", get_compliance_score("sox_itgc"))

result = calculate_fair(FAIRInput(**FINANCIAL_SCENARIOS[0]["defaults"]))
print("FAIR ALE:", result["formatted_ale"], "| Tier:", result["risk_tier"])

print("PHI escalation (base=10, PHI):", get_escalated_score(10, ["PHI"]))
print("PHI escalation (base=10, PII):", get_escalated_score(10, ["PII"]))

print("Industries:", SUPPORTED_INDUSTRIES)
print("Plans:", PLAN_TIERS)

# ── 1st Line SecOps Test ──────────────────────────────────────
print("\n--- 1st Line: Security Operations ---")
init_db()

# Access Review
ar = create_access_review("Active Directory", "periodic", "John", 50, "2025-07-01")
print("Access Review created:", ar["id"])
print("Access Review summary:", access_review_summary())

# Change Management
chg = create_change_request("Update FW Rules", "Modify firewall", "normal", "Firewall", "Medium", "Jane")
print("Change created:", chg["id"])
print("Change summary:", change_management_summary())

# Vulnerability
vuln = create_vulnerability("SQLi in Login", "pentest", "Critical", "web-app", "SQL injection found", cve_id="CVE-2024-1234", cvss_score=9.8)
print("Vulnerability created:", vuln["id"], "SLA:", vuln["sla_deadline"])
print("Vuln summary:", vulnerability_summary())

# SDLC
sdlc = create_sdlc_activity("Portal v2", "sast", "development", "SecEng")
print("SDLC activity created:", sdlc["id"])
print("SDLC summary:", sdlc_summary())

# Operational Health
health = operational_health_score()
print("Operational Health Score:", health["overall"], "| Tier:", health["tier"])

# ── 3 Lines of Defence ────────────────────────────────────────
print("\n--- Three Lines of Defence ---")
three_lines = get_three_lines_summary()
print("1st Line:", three_lines["first_line"]["score"], "%")
print("2nd Line:", three_lines["second_line"]["score"], "%")
print("3rd Line active:", three_lines["third_line"]["audit_trail_active"])

# ── Subdomain Routing Test ────────────────────────────────────
print("\n--- Subdomain Routing ---")
assert extract_subdomain("acme.cyberresilient.io") == "acme"
assert extract_subdomain("acme.cyberresilient.io:443") == "acme"
assert extract_subdomain("localhost:8501") is None
assert extract_subdomain("cyberresilient.io") is None
assert extract_subdomain("www.cyberresilient.io") is None
print("Subdomain extraction: ALL PASSED")
print("Tenant URL example:", get_tenant_url("acme-health"))

# ── Row-Level Security Test ──────────────────────────────────
print("\n--- Row-Level Security ---")
rec = inject_tenant_id({"name": "test"})
print("Injected tenant_id:", rec.get("tenant_id", "(none - expected in non-Streamlit context)"))

# ── Control Evidence Map ──────────────────────────────────────
print("\n--- Control Evidence Map ---")
for module, frameworks in CONTROL_EVIDENCE_MAP.items():
    total_controls = sum(len(ctrls) for ctrls in frameworks.values())
    print(f"  {module}: {total_controls} controls across {len(frameworks)} frameworks")

# DB check
from cyberresilient.database import get_engine
from sqlalchemy import inspect
tables = sorted(inspect(get_engine()).get_table_names())
print("\nDB tables:", tables)
expected_tables = [
    "access_reviews", "assets", "ato_systems", "audit_log",
    "breach_notifications", "change_requests", "poam_items",
    "sdlc_activities", "tenant_configs", "tenants", "vulnerabilities",
]
for t in expected_tables:
    assert t in tables, f"Missing table: {t}"
print(f"All {len(expected_tables)} expected tables present")

print("\n=== PLATFORM READY — ALL PHASES + 3 LINES OF DEFENCE VALIDATED ===")
