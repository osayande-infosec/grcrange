# Tenant Isolation Analysis: GRC Range SaaS Platform

**Analysis Date**: April 22, 2026  
**Analyzed Files**: tenant_service.py, database.py, rls.py, auth_service.py, subdomain_service.py, secops_service.py, ato_service.py, phi_service.py, audit_service.py, db_models.py  
**Risk Level**: **HIGH** ⚠️ Critical vulnerabilities found

---

## Executive Summary

The GRC Range platform implements multi-tenant isolation using **row-level security (RLS) filters** combined with Streamlit session state management. While the architecture is sound in principle, **critical vulnerabilities exist** in record-level update operations where tenant_id validation is missing. This creates a cross-tenant data access risk if an attacker knows record IDs from other tenants.

**Overall Grade: C+** — Strong foundation with dangerous gaps.

---

## 1. Database Query Enforcement (ROW-LEVEL SECURITY)

### ✅ STRENGTHS

**RLS Helper Service** (`cyberresilient/services/rls.py`):
- Provides centralized `tenant_filter()` function that appends `filter_by(tenant_id=...)` to queries
- `inject_tenant_id()` ensures all new records are tagged with current tenant_id
- Both helpers read from Streamlit session state via `get_current_tenant_id()`

**Database Schema**:
- Every data table includes `tenant_id` column:
  - AccessReviewRow, ChangeRequestRow, VulnerabilityRow, SDLCActivityRow
  - ATOSystemRow, POAMRow, AssetRow, BreachNotificationRow
  - AuditLogRow
- No foreign key constraints defined (SQLite limitation), but tenant_id is indexed

**List Operations Are Protected**:
```python
# secops_service.py - load_access_reviews()
tid = _get_tenant_id()
if tid:
    q = q.filter_by(tenant_id=tid)  ✅ Tenant filtering applied
```

---

### 🔴 CRITICAL VULNERABILITIES

**Missing Tenant Validation on Record Updates**

The following functions query by ID only, WITHOUT validating tenant_id:

#### secops_service.py:

| Function | Line | Query | Risk |
|----------|------|-------|------|
| `complete_access_review()` | 160 | `session.query(AccessReviewRow).filter_by(id=review_id).first()` | 🔴 CRITICAL |
| `approve_change()` | 272 | `session.query(ChangeRequestRow).filter_by(id=change_id).first()` | 🔴 CRITICAL |
| `implement_change()` | 294 | `session.query(ChangeRequestRow).filter_by(id=change_id).first()` | 🔴 CRITICAL |
| `remediate_vulnerability()` | 415 | `session.query(VulnerabilityRow).filter_by(id=vuln_id).first()` | 🔴 CRITICAL |
| `complete_sdlc_activity()` | 537 | `session.query(SDLCActivityRow).filter_by(id=activity_id).first()` | 🔴 CRITICAL |

#### ato_service.py:

| Function | Line | Query | Risk |
|----------|------|-------|------|
| `grant_ato()` | 134 | `session.query(ATOSystemRow).filter_by(id=system_id).first()` | 🔴 CRITICAL |

**Attack Scenario**:
```python
# Attacker is logged into Tenant A
# Discovers a change request ID from Tenant B: "CHG-12345678"
# Calls this in their Streamlit app:
from cyberresilient.services.secops_service import approve_change

# This succeeds without tenant checking!
approve_change("CHG-12345678", "attacker@tenant-a.com")

# Result: Tenant A user approved Tenant B's change request
```

---

## 2. Authentication & Authorization Flow

### ✅ STRENGTHS

**Tenant Context Injection** (`cyberresilient/services/tenant_service.py`):
```python
def set_tenant_context(tenant_id: str) -> None:
    """Set tenant context in Streamlit session state on login."""
    st.session_state["tenant_id"] = tenant_id
```
- Called during onboarding or login
- Persists for session lifetime

**Email Verification Gate** (`pages/0_Onboarding.py`):
```python
if not is_email_verified(tid):
    # Display verification form
    # Only proceed after 6-digit code matches
```
- Prevents unverified tenants from accessing platform
- Uses `secrets.compare_digest()` for timing-safe comparison ✅

**Tenant Existence Check** (`pages/0_Onboarding.py`):
```python
tenant = get_tenant(tenant_id.strip())
if not tenant:
    st.error("Tenant not found...")
elif not tenant.get("active"):
    st.error("This organisation account is inactive...")
```
- Validates tenant exists and is active before login

---

### 🟡 MEDIUM RISKS

**No Login Required Before Setting Tenant Context**:
- `set_tenant_context()` can be called from any page without authentication
- If XSS exists in Streamlit pages, attacker could directly set `st.session_state["tenant_id"]`
- No explicit session timeout enforcement
- Streamlit sessions persist until browser closes (no TTL)

**Weak Auth Service** (`cyberresilient/services/auth_service.py`):
```python
def get_current_user() -> User:
    """Return the current authenticated user from session state."""
    if "current_user" not in st.session_state:
        st.session_state["current_user"] = User()  # Default admin!
    return st.session_state["current_user"]
```
- Returns default admin user if none set
- No actual authentication (OAuth, SAML, etc.)
- Dev-only placeholder, but dangerous in production

---

## 3. Session State Management

### ✅ STRENGTHS

**Tenant ID Storage**:
```python
# tenant_service.py
def get_current_tenant_id() -> Optional[str]:
    """Return the tenant_id from Streamlit session state."""
    try:
        import streamlit as st
        return st.session_state.get("tenant_id")
    except Exception:
        return None
```
- Centralized accessor with exception handling
- Returns None if not set (safe default)

**Session Validation**:
```python
# pages/0_Onboarding.py
if st.session_state.get("tenant_id"):
    tid = st.session_state["tenant_id"]
    # Check email verification
    if not is_email_verified(tid):
        # Require verification before proceeding
```

---

### 🔴 CRITICAL ISSUES

**Session State Not Cryptographically Signed**:
- Streamlit session state is stored in browser memory/cookies
- No HMAC signature or encryption
- Attacker with XSS can modify: `st.session_state["tenant_id"] = "competitor-tenant-id"`

**No Session Invalidation on Logout**:
- No logout function defined
- Session persists until browser tab is closed

**RLS Filters Depend on Session State**:
```python
# rls.py
def get_tenant_id() -> str:
    """Return the active tenant_id from Streamlit session state."""
    try:
        from cyberresilient.services.tenant_service import get_current_tenant_id
        return get_current_tenant_id() or ""  # Trusts session state!
    except Exception:
        return ""
```
- If session state is compromised, all queries leak to wrong tenant

---

## 4. Multi-Tenant URL Routing (Subdomain Isolation)

### ✅ STRENGTHS

**Subdomain Resolution** (`cyberresilient/services/subdomain_service.py`):
```python
def extract_subdomain(host: str) -> Optional[str]:
    """Extract tenant subdomain from Host header."""
    hostname = host.split(":")[0].strip().lower()
    
    if hostname in {"localhost", "127.0.0.1"}:
        return None  # Skip local dev
    
    if not hostname.endswith(f".{BASE_DOMAIN}"):
        return None  # Not our domain
    
    subdomain = hostname[: -(len(BASE_DOMAIN) + 1)]
    # ... validation ...
    return subdomain
```
- Properly strips port numbers
- Skips reserved hosts (www, app, api)
- Validates domain suffix

**Tenant Lookup via Slug**:
```python
def resolve_tenant_from_subdomain(subdomain: str) -> Optional[dict]:
    row = session.query(TenantRow).filter_by(
        slug=subdomain,  # Unique constraint
        active=True      # Only active tenants
    ).first()
    return row.to_dict() if row else None
```
- ✅ Enforces `slug` is unique
- ✅ Only resolves active tenants
- ✅ Uses exact match (no wildcard injection)

**Auto-Set on Page Load**:
```python
def auto_set_tenant_from_host() -> Optional[str]:
    if st.session_state.get("tenant_id"):
        return st.session_state["tenant_id"]  # Already set, don't override
    
    subdomain = extract_subdomain(_get_host_header())
    if not subdomain:
        return None
    
    tenant = resolve_tenant_from_subdomain(subdomain)
    if tenant:
        set_tenant_context(tenant["id"])
```
- ✅ Won't override existing session
- ✅ Safe to call multiple times

---

### 🟡 MEDIUM RISKS

**Host Header Injection**:
- `_get_host_header()` reads from HTTP `Host` header
- Attacker can send custom `Host: competitor.cyberresilient.io`
- However, since DNS must resolve to your IP first, limited risk
- **Mitigation**: Streamlit should validate Host matches expected domain

**Local Development Doesn't Use Subdomains**:
```python
# pages/0_Onboarding.py - manual tenant selection required
with st.form("login_tenant"):
    tenant_id = st.text_input("Tenant ID", placeholder="acme-health-systems-a1b2c3d4")
```
- In dev/localhost, users manually enter tenant_id
- If dev environment exposed, trivial to login as any tenant

---

## 5. Permission & Role-Based Access Control (RBAC)

### ✅ STRENGTHS

**Permission Map Defined** (`cyberresilient/services/auth_service.py`):
```python
_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "admin":  ["admin", "edit_risks", "edit_controls", "edit_vendors", "view"],
    "editor": ["edit_risks", "edit_controls", "edit_vendors", "view"],
    "viewer": ["view"],
}

def has_permission(permission: str) -> bool:
    user = get_current_user()
    for role in user.roles:
        if permission in _ROLE_PERMISSIONS.get(role, []):
            return True
    return False
```
- ✅ Clear permission hierarchy
- ✅ Multiple roles per user supported

**Permission Checks in UI**:
```python
# pages/10_Security_Operations.py
from cyberresilient.services.auth_service import has_permission

if has_permission("edit_controls"):
    # Show edit button
```

---

### 🔴 CRITICAL ISSUES

**No Per-Tenant RBAC**:
- User roles are global (in session state) not per-tenant
- No way to assign different roles to same user in different tenants
- Example: Alice is admin@tenant-a.com AND user@tenant-b.com → Same roles in both

**Permission Checks Not Enforced on All Operations**:
- UI checks `has_permission()` but backend functions don't validate
- If permission check removed from UI, backend allows operation
- Example: `secops_service.complete_access_review()` doesn't verify caller's permission

**No Audit Trail of Permission Grants**:
- No record of who assigned which role to which user
- `audit_service.py` logs data changes but not permission changes

---

## 6. Database Schema Design

### ✅ STRENGTHS

**Tenant Partitioning**:
```sql
-- All data tables have tenant_id:
CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,           -- ✅ Indexed for filtering
    name TEXT,
    ...
);

CREATE TABLE access_reviews (
    id TEXT PRIMARY KEY,
    tenant_id TEXT,           -- ✅ Partition key
    system_name TEXT,
    ...
);
```
- Logical partitioning per table (not schema-per-tenant)
- Simpler migration than schema-per-tenant
- Supports multi-tenancy without database-level isolation

**Tenant Configuration Isolation**:
```python
class TenantConfigRow(Base):
    __tablename__ = "tenant_configs"
    tenant_id = Column(String(64), primary_key=True)  # ✅ Part of PK
    industry_profile = Column(String(32), nullable=False)
    active_frameworks = Column(Text, default="")
    # ...
```
- tenant_id is PRIMARY KEY (strongest guarantee)
- Only one config per tenant

**Audit Log Immutability**:
```python
class AuditLogRow(Base):
    __tablename__ = "audit_log"
    id = Column(String(36), primary_key=True)
    tenant_id = Column(String(64), default="")
    timestamp = Column(String(30), nullable=False)
    action = Column(String(64), nullable=False)
    entity_type = Column(String(64), nullable=False)
    before_snapshot = Column(Text, default="")
    after_snapshot = Column(Text, default="")
```
- ✅ Immutable once written (no update/delete)
- ✅ Tenant-isolated
- ✅ Before/after snapshots for accountability

---

### 🟡 MEDIUM RISKS

**No Foreign Key Constraints**:
- SQLite used in dev; lacks deferred constraint checking
- In production (PostgreSQL), should add:
```sql
ALTER TABLE change_requests 
ADD CONSTRAINT fk_change_requests_tenant 
FOREIGN KEY (tenant_id) REFERENCES tenants(id);
```

**No Unique Index on (tenant_id, entity_id)**:
- Could add secondary uniqueness for extra safety:
```sql
CREATE UNIQUE INDEX uk_access_reviews_tenant_id 
ON access_reviews (tenant_id, id);
```

**Trial Expiration Not Enforced at DB Level**:
```python
# tenant_service.py
if is_trial_expired(tenant):
    st.error("Your trial has expired...")
```
- Only checked in UI, not database constraints
- Could manually query database to access expired tenants

---

## 7. Identified Gaps & Risks

### 🔴 CRITICAL (Fix Immediately)

| Risk | Impact | Location | Fix |
|------|--------|----------|-----|
| **Missing tenant_id in record updates** | Cross-tenant data modification | secops_service.py (5 functions), ato_service.py (1 function) | Add `filter_by(tenant_id=...)` to every `session.query().filter_by(id=...)` |
| **No permission validation on backend** | Unauthorized operations | All service functions | Check `has_permission()` before modifying data |
| **Session state not signed** | Tenant ID forgery | Streamlit core | Implement server-side session storage with HMAC |

### 🟡 HIGH (Fix Soon)

| Risk | Impact | Location | Fix |
|------|--------|----------|-----|
| **No actual login mechanism** | Default admin user always active | auth_service.py | Implement OAuth 2.0 or SSO integration |
| **Session timeout not enforced** | Unlimited session lifetime | Streamlit app | Add TTL checks to every page |
| **Default user fallback** | Anyone can access if current_user not set | auth_service.py | Fail-closed instead of default to admin |

### 🟠 MEDIUM (Fix Before Production)

| Risk | Impact | Location | Fix |
|------|--------|----------|-----|
| **Trial enforcement only in UI** | Expired tenants can query database directly | tenant_service.py | Add check in every query function |
| **No per-tenant RBAC** | Same user can't have different roles per tenant | auth_service.py | Redesign to store (user_id, tenant_id, role) |
| **No API rate limiting** | Brute force attacks on record lookups | N/A | Implement rate limiter at endpoint level |

---

## 8. Cross-Tenant Data Leakage Scenarios

### Scenario A: Guessing Record IDs

**Attacker**:
1. Logs into Tenant A (acme-health-systems)
2. Knows Tenant B uses sequential UUIDs: `review_id = "550e8400-e29b-41d4-a716-446655440000"`
3. Calls:
```python
from cyberresilient.services.secops_service import complete_access_review

# No tenant_id validation in this function!
result = complete_access_review(
    "550e8400-e29b-41d4-a716-446655440001",  # Tenant B's review
    accounts_appropriate=50,
    accounts_revoked=0,
    accounts_modified=0,
)
# ✅ Success! Tenant A just modified Tenant B's access review
```

**Likelihood**: Medium (UUIDs are hard to guess, but sequential ones are predictable)  
**Impact**: HIGH (data integrity compromise)

---

### Scenario B: Session State Hijacking

**Attacker**:
1. Injects XSS into a Streamlit text_input field
2. Streamlit renders: `st.text_input("Asset Name")` → XSS payload
3. Payload executes: 
```javascript
// Streamlit WebSocket intercept
ws.send(JSON.stringify({
  "type": "session_state_update",
  "state": {"tenant_id": "competitor-corp-x1y2z3"}
}));
```
4. Now attacker's Streamlit client sees competitor's data

**Likelihood**: Low (XSS in Streamlit framework)  
**Impact**: CRITICAL (full data access)

---

### Scenario C: Subdomain Takeover + Tenant Context

**Attacker**:
1. Compromises DNS for `phishing-corp.cyberresilient.io` → Points to attacker's IP
2. Attacker's server receives request with custom `Host: phishing-corp.cyberresilient.io`
3. If application doesn't validate Host header:
```python
# subdomain_service.py
subdomain = extract_subdomain(host)  # Returns "phishing-corp"
tenant = resolve_tenant_from_subdomain(subdomain)
# Lookup fails (no such tenant)
# But if someone manually creates phishing-corp tenant earlier...
```

**Likelihood**: Very Low (DNS must be compromised, and requires pre-registration)  
**Impact**: HIGH (if successful, full access to fake tenant's data)

---

## 9. Compliance & Best Practices

### ISO 27001 / SOC 2 Gaps

| Control | Requirement | Status |
|---------|-------------|--------|
| AC-3 (Access Enforcement) | Role-based access control with positive allow lists | 🟡 PARTIAL — roles defined but not enforced |
| AC-4 (Information Flow) | Prevent unauthorized data flow between tenants | 🔴 FAIL — record update gap |
| AU-2 (Audit Logging) | Log all security-relevant events | ✅ PASS — audit_service.py comprehensive |
| SC-7 (Boundary Protection) | Multi-tenancy isolation at system boundary | 🟡 PARTIAL — subdomain ok, but session weak |

### OWASP Top 10 Risks

| Risk | Evidence |
|------|----------|
| **A01: Broken Access Control** | 🔴 Missing tenant_id in update operations |
| **A04: Insecure Design** | 🟡 Session state design is client-side |
| **A05: Security Misconfiguration** | ✅ Email verification in place |
| **A07: Cross-Site Scripting** | 🟡 No input sanitization visible |
| **A09: Broken Authentication** | 🔴 Default admin user with no real auth |

---

## 10. Recommendations (Priority Order)

### IMMEDIATE (Do This Week)

1. **Add tenant_id validation to all record updates**:
```python
# secops_service.py - BEFORE
row = session.query(AccessReviewRow).filter_by(id=review_id).first()

# AFTER
from cyberresilient.services.rls import get_tenant_id
row = session.query(AccessReviewRow).filter_by(
    id=review_id,
    tenant_id=get_tenant_id()  # ✅ ADD THIS
).first()
if not row:
    raise PermissionError(f"Access review {review_id} not found or not yours")
```

2. **Implement backend permission validation**:
```python
def complete_access_review(...):
    from cyberresilient.services.auth_service import has_permission
    if not has_permission("edit_risks"):  # ✅ ADD THIS
        raise PermissionError("You don't have permission to complete reviews")
    # ... rest of function
```

3. **Add tenant_id verification to subdomain resolution**:
```python
# Ensure resolved tenant matches session tenant
if tenant["id"] != st.session_state.get("tenant_id"):
    raise PermissionError("Subdomain does not match your tenant context")
```

---

### SHORT TERM (Do This Month)

4. **Implement server-side session storage**:
- Move `tenant_id` from client-side Streamlit session to server-side database
- Store session tokens with HMAC signature
- Implement 30-minute TTL

5. **Add per-tenant role assignment**:
```python
class UserTenantRole(Base):
    __tablename__ = "user_tenant_roles"
    user_id = Column(String, primary_key=True)
    tenant_id = Column(String, primary_key=True)
    role = Column(String, nullable=False)  # admin, editor, viewer
    assigned_at = Column(String)
```

6. **Replace default user with actual OAuth 2.0**:
- Remove `User()` default fallback
- Integrate with Auth0, Okta, or Google Workspace
- Fail-closed if no valid token

---

### LONG TERM (Before Production)

7. **Foreign key constraints at database level**:
```sql
ALTER TABLE access_reviews 
ADD CONSTRAINT fk_access_reviews_tenant 
FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT;
```

8. **API rate limiting**:
- Add fail2ban or rate-limit middleware
- 1000 requests per hour per tenant
- 10 failed auth attempts = 1 hour lockout

9. **Implement audit trail signing**:
- Sign audit log entries with private key
- Allow verification by external auditors
- Hash chain (each entry includes previous entry's hash)

10. **Multi-region failover**:
- Replicate tenant data with read-only secondary databases
- Implement data residency rules (GDPR, HIPAA)
- Add encryption at rest

---

## 11. Deployment Hardening Checklist

- [ ] Set `DATABASE_URL` to PostgreSQL with SSL in production (not SQLite)
- [ ] Enable row-level security (RLS) at PostgreSQL level:
  ```sql
  CREATE POLICY tenant_isolation ON access_reviews
    FOR ALL TO app_user
    USING (tenant_id = current_user_id::tenant_id);
  ```
- [ ] Use HTTPS only; set `Secure` cookie flag
- [ ] Implement HSTS header: `Strict-Transport-Security: max-age=31536000`
- [ ] Add `X-Frame-Options: DENY` to prevent clickjacking
- [ ] Enable CSRF protection on all state-changing operations
- [ ] Rotate database credentials monthly
- [ ] Enable audit logging in PostgreSQL:
  ```sql
  SET log_statement = 'all';
  SET log_error_verbosity = 'verbose';
  ```

---

## 12. Summary Table

| Mechanism | Grade | Status |
|-----------|-------|--------|
| **Database Query Filtering** | C | ✅ List queries filtered; ❌ Update queries not filtered |
| **Authentication** | F | ❌ No real auth, default admin user |
| **Authorization (RBAC)** | C+ | ✅ Roles defined; ❌ Not enforced in backend |
| **Session State** | D | ❌ Client-side, no signing, no timeout |
| **Subdomain Routing** | A | ✅ Properly implemented |
| **Email Verification** | B+ | ✅ 6-digit code, timing-safe comparison; ❌ No email delivery |
| **Database Schema** | B | ✅ Tenant_id in all tables; ❌ No foreign keys, no constraints |
| **Audit Logging** | A | ✅ Comprehensive, immutable, tenant-isolated |
| **Error Handling** | C | 🟡 Generic error messages (good for security, but hard to debug) |
| **Rate Limiting** | F | ❌ None present |

**Overall Score: C** (Dangerous for production)

---

## Contact & Questions

For detailed implementation guidance on any of these items, refer to:
- [OWASP Multi-Tenant SaaS Design](https://owasp.org/www-community/attacks/Multi-Tenant_Saas_Design_Flaws)
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Streamlit Security Guide](https://docs.streamlit.io/library/advanced-features/session-state#session-state-best-practices)

---

**Generated by Tenant Isolation Analysis Tool**  
**Platform**: GRC Range CyberResilient  
**Version**: Phase 5 (Multi-Tenant Edition)
