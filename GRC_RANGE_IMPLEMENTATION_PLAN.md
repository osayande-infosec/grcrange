# CyberResilient — Multi-Industry GRC Range Platform
## Implementation Plan & Architecture Guide


## Executive Summary

CyberResilient is being expanded from a framework-agnostic GRC platform (NIST CSF + ISO 27001) into an **industry-configurable product** — same engine, different compliance profiles loaded per sector. The platform supports four editions:

| Edition | Primary Frameworks | Key Differentiator |
|---|---|---|
| **Healthcare** | HIPAA, HITRUST, NIST CSF | PHI data classification + breach notification workflows |
| **Financial** | PCI DSS v4.0, SOX ITGC, DORA | FAIR quantitative risk scoring (risk in dollar terms) |
| **Government** | NIST 800-53, FedRAMP, FISMA, CMMC | ATO lifecycle + continuous monitoring + POA&M tracking |
| **Enterprise** | NIST CSF, ISO 27001 | Base tier — general-purpose GRC |

**Platform reuse: ~70%.** The existing Risk Register, Compliance Scoring Engine, Evidence Service, Control Testing, CAP Tracker, Vendor Registry, Audit Log, Treatment Workflow, Notification Service, and RBAC all transfer directly. The 30% that needs building is mostly data (control catalogues) and configuration (industry profiles), not new engineering.

---

## What Already Exists (Leverageable As-Is)

| Existing Component | Reuse Level | Notes |
|---|---|---|
| Risk Register + CRUD | Full reuse | Add sector risk categories to seed data |
| Compliance Scoring Engine | Full reuse | Swap control catalogues per industry |
| Evidence Artifact Service | Full reuse | No changes needed |
| Control Testing Service | Full reuse | No changes needed |
| CAP Tracker | Full reuse | No changes needed |
| Vendor Registry | Full reuse | Add sector-specific vendor tiers |
| Audit Log | Full reuse | No changes needed |
| Treatment Workflow | Full reuse | No changes needed |
| Notification Service | Full reuse | Add sector breach timelines |
| Dashboard | Partial reuse | Add sector KPIs |
| RBAC | Full reuse | Extend roles per sector |

---

## Project Directory Structure

```
GRC Range/
├── config/
│   └── org_profile.yaml                    # Industry profile configuration
├── cyberresilient/
│   ├── services/
│   │   ├── industry_service.py             # Central industry profile router
│   │   ├── phi_service.py                  # PHI/PII asset classification engine
│   │   ├── fair_service.py                 # FAIR quantitative risk calculator
│   │   ├── ato_service.py                  # FedRAMP/FISMA ATO workflow
│   │   └── tenant_service.py              # Multi-tenant provisioning
│   └── models/
│       └── db_models.py                    # SQLAlchemy models (all phases)
├── data/
│   ├── controls_nist_800_53.json          # 100+ controls, 8 families
│   ├── controls_hipaa.json                # HIPAA Security Rule (3 safeguards)
│   └── controls_pci_dss_sox.json          # PCI DSS v4.0 + SOX ITGC
├── pages/
│   ├── 0_Onboarding.py                    # Multi-tenant onboarding flow
│   ├── 11_Healthcare_Compliance.py        # HIPAA + PHI management UI
│   ├── 12_Financial_Compliance.py         # PCI DSS + SOX + FAIR calculator UI
│   └── 13_Government_Compliance.py        # NIST 800-53 + ATO + POA&M UI
├── alembic/
│   └── versions/
│       └── 0005_phases1_to_5_industry_expansion.py  # Master migration
├── INDUSTRY_EXPANSION_GUIDE.txt            # File placement reference
└── GRC_RANGE_IMPLEMENTATION_PLAN.md        # This document
```

---

## Phased Delivery Plan

### Phase 1 — Industry Profile Architecture (Foundation)

**Goal:** Build the config-driven layer that makes the entire platform industry-aware.

#### What Gets Built

1. **`config/org_profile.yaml`** — Extended industry profile schema
   - Organisation metadata (sector, country, region, employee count)
   - Industry profile selection (`healthcare | financial | government | enterprise`)
   - Sub-sector options (e.g., hospital, banking, federal)
   - Data classification configuration (PHI, PII, PCI Data, etc.)
   - Active compliance framework toggles
   - Risk scoring model selection (`matrix` vs `fair`)
   - Breach notification SLAs (sector-specific defaults)
   - Report template activation

2. **`cyberresilient/services/industry_service.py`** — Central industry router
   - `INDUSTRY_PROFILES` dictionary with full profiles for all 4 sectors
   - Each profile defines: frameworks, risk categories, data classifications, breach notification config, KPIs, catalogue files, report templates
   - `get_industry_profile()` — reads org_profile.yaml, returns active profile
   - `get_active_frameworks()` — returns framework list for current sector
   - `get_risk_categories()` — returns sector-specific risk categories
   - `get_data_classifications()` — returns classification labels
   - `get_breach_notification_config()` — returns sector breach SLAs
   - `get_industry_kpis()` — returns sector dashboard KPIs
   - All other services call these functions instead of hardcoding values

3. **Three new control catalogues:**
   - `data/controls_nist_800_53.json` — NIST SP 800-53 Rev 5 (8 families: AC, AU, CA, CM, IA, IR, SI, SC; 100+ controls with Low/Moderate/High baseline tagging)
   - `data/controls_hipaa.json` — HIPAA Security Rule (3 safeguards: Administrative, Physical, Technical; Required vs Addressable implementation tracking)
   - `data/controls_pci_dss_sox.json` — PCI DSS v4.0 (12 requirements, 60+ controls) + SOX ITGC (4 domains: Change Management, Logical Access, Computer Operations, DR/BCP)

#### Architecture Decision: Config-Driven Sector Selection

```yaml
# config/org_profile.yaml — just change these two lines to switch editions
industry:
  profile: "healthcare"    # financial | government | healthcare | enterprise
```

The `industry_service.py` reads this and returns the correct:
- Control catalogues to load
- Risk categories for the risk register
- Breach notification timelines
- Dashboard KPIs
- Report templates

**Zero code changes required in the existing scoring engine, evidence service, or control testing service.** They just get different data.

---

### Phase 2 — Healthcare Edition

**Goal:** HIPAA compliance, PHI asset management, breach notification workflow.

#### What Gets Built

1. **`cyberresilient/services/phi_service.py`** — PHI/PII Asset Classification Engine
   - **Asset Registration:** Name, type (Server/Application/Database/Medical Device/etc.), data classification tags, owner, location
   - **Risk Multipliers:** Automatic risk score escalation based on data classification:
     - PHI → 2.0× multiplier
     - PII → 1.75× multiplier
     - PCI Data → 2.0× multiplier
     - Financial Records → 1.5× multiplier
     - Protected B → 1.75× (government)
     - Confidential → 1.25×
     - Internal → 1.0× (no change)
     - Public → 0.75× (risk reduction)
   - `get_escalated_score(base_score, classifications)` — applies multiplier, caps at 25
   - Stored in `assets` table with highest classification tracking

2. **HIPAA Breach Notification Workflow**
   - `create_breach_notification()` — calculates all regulatory deadlines automatically:
     - HHS: 60 days from discovery
     - Individuals: 60 days (without unreasonable delay)
     - Media: required when 500+ individuals affected in a single state
   - Severity auto-classification: minor (<100), moderate (100-499), major (500-4999), critical (5000+)
   - Tracks notification status: HHS notified? Individuals notified? Media notified?
   - `get_overdue_breach_notifications()` — flags missed deadlines
   - Stored in `breach_notifications` table

3. **`pages/11_Healthcare_Compliance.py`** — Streamlit UI with 4 tabs:
   - **HIPAA Security Rule:** All 3 safeguards (Administrative, Physical, Technical) with Required vs Addressable tracking, per-standard implementation percentages
   - **PHI Asset Register:** Classification distribution chart, per-asset detail with risk multiplier display
   - **Breach Notifications:** Overdue alerts, notification record creation with auto-calculated deadlines
   - **Register Asset:** Form with multi-select data classifications

#### HIPAA Controls Coverage

| Safeguard | Standards | Implementation Specs |
|---|---|---|
| Administrative | 9 standards (164.308) | Risk Analysis, Workforce Security, Contingency Plan, BAA Contracts, etc. |
| Physical | 4 standards (164.310) | Facility Access, Workstation Use/Security, Device & Media Controls |
| Technical | 5 standards (164.312) | Access Control, Audit Controls, Integrity, Authentication, Transmission Security |

---

### Phase 3 — Financial Edition

**Goal:** Quantitative risk scoring, PCI DSS/SOX compliance tracking.

#### What Gets Built

1. **`cyberresilient/services/fair_service.py`** — FAIR Quantitative Risk Calculator
   - **FAIR Model:** Risk = Loss Event Frequency × Loss Magnitude
   - **Three-point PERT estimates** for each input:
     - Threat Event Frequency (per year): low, likely, high
     - Vulnerability (probability 0.0–1.0): low, likely, high
     - Primary Loss Magnitude (direct $ per event): low, likely, high
     - Secondary Loss Magnitude (regulatory/reputational $): low, likely, high
   - **Output:**
     - Annualised Loss Expectancy (ALE) in dollar terms
     - ALE confidence interval (±1σ)
     - Risk tier: Very High (≥$5M), High (≥$1M), Medium (≥$250K), Low (<$250K)
     - Matrix equivalent (1-25 scale) for cross-sector compatibility
   - **Pre-built scenarios:**
     - FS-001: Payment Card Data Breach
     - FS-002: Ransomware — Core Banking System
     - FS-003: Insider Trading — Data Leak
     - HC-001: PHI Data Breach — EHR System
     - HC-002: Ransomware — Clinical Systems
   - Multi-currency support: USD, CAD, GBP, EUR

2. **`pages/12_Financial_Compliance.py`** — Streamlit UI with 3 tabs:
   - **PCI DSS v4.0:** Gauge chart for overall compliance, per-requirement expandable details (12 requirements, 60+ controls)
   - **SOX ITGC:** Bar chart by domain (Change Management, Logical Access, Computer Operations, DR/BCP), per-control drill-down
   - **FAIR Quantitative Risk Calculator:** Pre-built scenario or custom inputs, full result display with ALE in currency, confidence range, risk tier, matrix equivalent

#### PCI DSS v4.0 Coverage (All 12 Requirements)

| Req | Name | Controls |
|---|---|---|
| 1 | Network Security Controls | 5 |
| 2 | Secure Configurations | 3 |
| 3 | Protect Stored Account Data | 7 |
| 4 | Cryptography During Transmission | 2 |
| 5 | Malicious Software Protection | 4 |
| 6 | Secure Systems and Software | 5 |
| 7 | Restrict Access by Need to Know | 3 |
| 8 | Identify and Authenticate | 6 |
| 9 | Restrict Physical Access | 5 |
| 10 | Log and Monitor Access | 7 |
| 11 | Test Security Regularly | 6 |
| 12 | Organizational Policies | 10 |

#### SOX ITGC Coverage (4 Domains)

| Domain | Controls |
|---|---|
| Change Management (ITGC-CC) | 5 controls |
| Logical Access (ITGC-LA) | 6 controls |
| Computer Operations (ITGC-OPS) | 4 controls |
| Disaster Recovery (ITGC-DR) | 4 controls |

---

### Phase 4 — Government Edition

**Goal:** NIST 800-53 full catalogue, FedRAMP ATO lifecycle, POA&M tracking.

#### What Gets Built

1. **`cyberresilient/services/ato_service.py`** — ATO Workflow Service
   - **ATO Lifecycle:**
     ```
     Not Started → Categorization → Security Plan → Assessment
     → POA&M Development → Authorization → Active ATO → ATO Expired
     ```
   - **ATO Validity by Impact Level:**
     - Low: 3 years (1,095 days)
     - Moderate: 3 years (1,095 days)
     - High: 1 year (365 days)
   - `create_ato_system()` — register system with FIPS 199 impact level, system owner, ISSO, authorising official
   - `grant_ato()` — records grant date, auto-calculates expiry
   - `get_expiring_atos(days_ahead=90)` — early warning for upcoming expirations

2. **POA&M (Plan of Action & Milestones) Tracker**
   - Government equivalent of CAPs — every control weakness gets a scheduled completion date
   - `create_poam()` — links to system, control ID, responsible party, milestones
   - `get_overdue_poams()` — flags items past scheduled completion
   - `poam_summary()` — counts by status (Open, In Progress, Completed, Risk Accepted, Vendor Dependency)
   - Auto-increments open POA&M count on the parent ATO system

3. **`pages/13_Government_Compliance.py`** — Streamlit UI with 4 tabs:
   - **NIST 800-53:** Bar chart by control family, baseline filter (Low/Moderate/High), per-control drill-down with baseline tags
   - **ATO Systems:** System cards with status color-coding, expiry countdown, one-click ATO grant for admins
   - **POA&M Tracker:** System filter, status icons, overdue flags, inline creation form
   - **Register System:** Form for new ATO system registration with impact level, ISSO, AO

#### NIST SP 800-53 Rev 5 Coverage (8 Families)

| Family | Name | Controls |
|---|---|---|
| AC | Access Control | 16 |
| AU | Audit and Accountability | 11 |
| CA | Assessment, Authorization, Monitoring | 7 |
| CM | Configuration Management | 10 |
| IA | Identification and Authentication | 10 |
| IR | Incident Response | 8 |
| SI | System and Information Integrity | 9 |
| SC | System and Communications Protection | 12 |

---

### Phase 5 — Multi-Tenant + Commercial Launch

**Goal:** Tenant isolation, onboarding flow, trial management.

#### What Gets Built

1. **`cyberresilient/services/tenant_service.py`** — Multi-Tenant Service
   - `create_tenant()` — provisions org with slug-based ID, industry profile, 30-day trial
   - `_seed_tenant()` — auto-configures industry-specific frameworks, risk categories, breach SLAs
   - `get_tenant()` / `list_tenants()` / `deactivate_tenant()`
   - `is_trial_expired()` — checks trial end date
   - `tenant_summary()` — cross-tenant stats (by industry, by plan, expiring trials)
   - `set_tenant_context()` / `get_current_tenant_id()` — session state injection

2. **`pages/0_Onboarding.py`** — Self-service signup flow
   - **New Organisation:** org name, industry selection (shows edition features), country, admin credentials
   - **Login:** tenant ID lookup with trial/active validation
   - Industry profile preview before signup ("Healthcare Edition includes: HIPAA, NIST CSF compliance, 12 risk categories, 5 report templates")

3. **Plan Tiers:** trial → starter → professional → enterprise

4. **Trial Limits:** 25 risks, 3 users, 30 days

#### Database Tables (Migration 0005)

| Table | Phase | Purpose |
|---|---|---|
| `assets` | 2 | PHI/PII asset register |
| `breach_notifications` | 2 | HIPAA breach notification tracking |
| `ato_systems` | 4 | FedRAMP/FISMA ATO system registry |
| `poam_items` | 4 | Plan of Action & Milestones |
| `tenants` | 5 | Tenant records |
| `tenant_configs` | 5 | Per-tenant industry configuration |

---

## Breach Notification Timelines by Sector

| Regulation | Regulator Deadline | Individual Deadline | Media Requirement |
|---|---|---|---|
| HIPAA | 60 days to HHS | 60 days | >500 individuals in a state |
| GDPR | 72 hours to supervisory authority | Without undue delay | Case-by-case |
| PIPEDA/PHIPA | As soon as feasible | As soon as feasible | If significant risk |
| PCI DSS | Immediate to card brands | Per card brand rules | N/A |
| Government | Immediate (1 hour) to Treasury Board/CISA | 72 hours | Mandatory for federal |

---

## Risk Scoring: Matrix vs FAIR

### Standard 5×5 Matrix (All Sectors)
- Likelihood (1-5) × Impact (1-5) = Risk Score (1-25)
- Risk appetite threshold configurable per tenant (default: 12)

### FAIR Quantitative (Financial Sector)
- ALE = Loss Event Frequency × Loss Magnitude
- Expressed in dollar terms with confidence intervals
- Maps back to 1-25 matrix for cross-sector compatibility:

| ALE | Matrix Equivalent | Tier |
|---|---|---|
| ≥ $5M | 20/25 | Very High |
| ≥ $1M | 15/25 | High |
| ≥ $500K | 12/25 | Medium-High |
| ≥ $250K | 9/25 | Medium |
| ≥ $100K | 6/25 | Low-Medium |
| < $100K | 3/25 | Low |

---

## Sector-Specific KPIs

### Healthcare
- PHI Breach Incidents
- BAA Coverage %
- EHR Access Reviews Completed
- HIPAA Training Completion %
- Medical Device Patch Compliance %

### Financial
- PCI DSS Compliance %
- SOX Control Deficiencies
- Fraud Detection Rate
- Operational Loss Events
- Third-Party Risk Coverage %

### Government
- ATO Coverage %
- FedRAMP Control Implementation %
- Continuous Monitoring Findings
- POA&M Items Open
- FISMA Compliance Score

### Enterprise (Base)
- MTTD (hrs)
- MTTR (hrs)
- Patch Compliance %
- Open Critical Vulnerabilities
- Phishing Click Rate %

---

## How to Activate an Industry Edition

Edit `config/org_profile.yaml`:

### Healthcare
```yaml
industry:
  profile: "healthcare"
  sub_sector: "hospital"    # hospital | clinic | health_tech | pharma | insurer
compliance:
  frameworks:
    - id: "hipaa"
      enabled: true
    - id: "hitrust"
      enabled: true          # optional
```

### Financial
```yaml
industry:
  profile: "financial"
  sub_sector: "banking"     # banking | insurance | investment | fintech | credit_union
risk:
  scoring_model: "fair"     # enables FAIR quantitative scoring
compliance:
  frameworks:
    - id: "pci_dss"
      enabled: true
    - id: "sox_itgc"
      enabled: true
```

### Government
```yaml
industry:
  profile: "government"
  sub_sector: "federal"     # federal | provincial | municipal | defence | crown_corp
compliance:
  frameworks:
    - id: "nist_800_53"
      enabled: true
    - id: "fedramp"
      enabled: true
```

---

## Remaining Work for Full Commercial Launch

| Item | Complexity | Priority |
|---|---|---|
| Billing integration (Stripe) — plan upgrades, usage limits | High | P1 |
| Row-level security — prefix all queries with tenant_id filter | High | P1 |
| Email verification on onboarding | Medium | P1 |
| Subdomain routing — tenant.cyberresilient.io per org | Medium | P2 |
| Admin super-dashboard — cross-tenant health monitoring | Medium | P2 |
| HITRUST CSF catalogue (healthcare enterprise tier) | Medium | P2 |
| DORA (EU) catalogue (financial EU clients) | Medium | P3 |
| CMMC Level 2 catalogue (defence contractors) | Medium | P3 |
| NIST 800-53 expansion to all 20 families (currently 8) | High | P3 |
| FedRAMP SSP auto-generation (System Security Plan) | High | P3 |
| SOC 2 Type II catalogue (health tech vendors) | Medium | P4 |

---

## Go-To-Market Recommendation

**Start with Healthcare.** Healthcare buyers have:
1. **Budget** — HIPAA compliance is non-negotiable
2. **Regulatory urgency** — breach notification penalties are severe ($100-$50K per violation)
3. **Well-defined compliance surface** — HIPAA Security Rule is finite and mappable
4. **Expensive alternatives** — existing HIPAA compliance tools are overpriced

A working Healthcare edition validates the commercial model before investing in the broader Financial and Government expansions.

**Recommended launch sequence:**
1. Phase 1 (Industry Profile Architecture) + Phase 2 (Healthcare) — **first product launch**
2. Phase 3 (Financial) — **second product launch**
3. Phase 4 (Government) — **third product launch**
4. Phase 5 (Multi-Tenant) — runs alongside or after Phase 2 depending on GTM strategy
