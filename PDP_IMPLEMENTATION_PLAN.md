# PDP Implementation Plan v2 — Complete Admin-Configurable Resource Access Flow

## Based on: *Soluție securizată de acces distant la resurse cu autentificare multifactor*
## Scope: Full functional resource access flow WITHOUT MFA (MFA defined but inactive)

---

## Strategic Reordering

Previous plan (v1) prioritized MFA step-up, HRD, and CAEP propagation. Per Laura's directive, this revised plan focuses first on making **every entity configurable from the PA admin dashboard** and **persisted in SQLite**, enabling a complete end-to-end access flow: tenant → IdP → Gateway enrollment → resource definition → policy → device → session → audit. MFA structures are defined in the data model and UI but kept **inactive** (no enforcement) until a later phase.

### Hierarchical Creation Flow

The UI enforces a natural parent-child creation hierarchy:
- **Tenant page** → "Create Gateway" button pre-selects the current tenant
- **Gateway page** → "Create Resource" button pre-selects the current gateway and its tenant
- This ensures data integrity and guides the admin through the correct provisioning sequence

Each child entity automatically inherits the parent's `tenant_id`. Resources are always scoped to a Gateway, which is scoped to a Tenant.

### Policy Scoping Levels

Policies operate at three hierarchical levels:
- **Global (Tenant-wide)**: Applies to all gateways and resources within a tenant — `scope = "global"`, no specific gateway/resource ID
- **Gateway-level**: Applies to a specific gateway and all its resources — `scope = "gateway"`, `gateway_id` set
- **Resource-level (local)**: Applies to a single resource — `scope = "resource"`, `resource_id` set (and implicitly its parent gateway)

The Policy Engine evaluates rules with the most specific scope first (resource > gateway > global), respecting the priority field within each scope level. Policy CRUD in the dashboard always requires selecting a scope level, and the gateway/resource selectors are conditionally shown.

---

## Phase 1: Tenant / Multi-Organization Model

### Business Rationale
The solution document (lines 259, 305-316) requires "Modelarea unui mediu multi-organizațional" with complete identity, Gateway, resource, and policy isolation per tenant. Currently, there is no `Tenant` model — all data is global.

### Data Model

#### 1.1 Add `Tenant` struct to [`models.go`](pdp/models/models.go)
```go
type Tenant struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`        // e.g. "Company HQ"
    Domain      string    `json:"domain"`      // e.g. "company.com" (used for HRD later)
    Description string    `json:"description,omitempty"`
    Enabled     bool      `json:"enabled"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

#### 1.2 Add `TenantID` foreign key to existing models
Add `TenantID string \`json:"tenant_id,omitempty"\`` to:
- [`User`](pdp/models/models.go:10)
- [`Resource`](pdp/models/models.go:335)
- [`Gateway`](pdp/models/models.go:516)
- [`PolicyRule`](pdp/models/models.go:131)
- [`DeviceEnrollment`](pdp/models/models.go:441)
- [`DeviceHealthReport`](pdp/models/models.go:100)
- [`Session`](pdp/models/models.go:291)

#### 1.3 SQLite Schema
- New table: `tenants(id, name, domain, description, enabled, created_at, updated_at)`
- `ALTER TABLE users ADD COLUMN tenant_id TEXT DEFAULT ''`
- `ALTER TABLE resources ADD COLUMN tenant_id TEXT DEFAULT ''`
- `ALTER TABLE gateways ADD COLUMN tenant_id TEXT DEFAULT ''`
- `ALTER TABLE policy_rules ADD COLUMN tenant_id TEXT DEFAULT ''`
- `ALTER TABLE device_enrollments ADD COLUMN tenant_id TEXT DEFAULT ''`
- `ALTER TABLE device_health ADD COLUMN tenant_id TEXT DEFAULT ''`
- `ALTER TABLE sessions ADD COLUMN tenant_id TEXT DEFAULT ''`

#### 1.4 Store Operations ([`store.go`](pdp/store/store.go))
- `CreateTenant(t *models.Tenant)`, `GetTenant(id string)`, `ListTenants()`, `UpdateTenant()`, `DeleteTenant(id string)`
- Add `WHERE tenant_id = ?` filters to all list/query operations (with admin override that returns all tenants)

#### 1.5 API Endpoints ([`router.go`](pdp/pa/transport/router.go))
- `GET /admin/tenants` — list all tenants (admin)
- `POST /admin/tenants` — create tenant
- `GET /admin/tenants/{id}` — get tenant
- `PUT /admin/tenants/{id}` — update tenant
- `DELETE /admin/tenants/{id}` — delete tenant

#### 1.6 Dashboard
- **New page**: [`Tenants.jsx`](pdp/pa/dashboard/src/pages/Tenants.jsx) — CRUD table with name, domain, enabled, created_at
- **Add to nav**: "Tenants" item in [`Layout.jsx`](pdp/pa/dashboard/src/components/Layout.jsx:15) sidebar
- **Add to routes**: `/dashboard/tenants` in [`App.jsx`](pdp/pa/dashboard/src/App.jsx:23)
- **Hierarchical creation**: Each tenant row has a **"Create Gateway"** action button → navigates to Gateways page with `tenant_id` pre-selected in the create form
- **Add tenant selector dropdown** to: Resources, Gateways, Policies, Users, Sessions, DeviceHealth pages (admin sees all, tenant-scoped filters by tenant_id)

---

## Phase 2: Identity Provider Configuration & Attribute Mapping

### Business Rationale
The solution document (line 259) requires "mecanisme de mapare a atributelor provenite din furnizorii de identitate în roluri interne." Current federation infrastructure exists ([`federation.go`](pdp/idp/federation.go)) and per-gateway `FederationConfig` is defined, but:
- `FederationConfig` has no `RoleMapping` or `DefaultRole`
- The Gateway create form in the dashboard has no IdP config fields
- The federation test endpoint exists but the UI is disconnected from the create flow
- No tenant-level IdP configuration

### Data Model

#### 2.1 Extend `FederationConfig` in [`models.go`](pdp/models/models.go:555)
```go
type FederationConfig struct {
    Issuer        string            `json:"issuer"`
    ClientID      string            `json:"client_id"`
    ClientSecret  string            `json:"client_secret,omitempty"`
    Scopes        string            `json:"scopes"`                  // default "openid profile email"
    ClaimMapping  map[string]string `json:"claim_mapping,omitempty"` // external claim → internal field
    RoleMapping   map[string]string `json:"role_mapping,omitempty"`  // NEW: external role/value → internal PDP role
    DefaultRole   string            `json:"default_role,omitempty"`  // NEW: fallback role when no mapping matches
    AutoDiscovery bool              `json:"auto_discovery"`
}
```

#### 2.2 Extend `FederatedClaims` in [`federation.go`](pdp/idp/federation.go:67)
Add `Groups []string` and `Roles []string` to parse group/role claims from the external `id_token` based on well-known claim names (`groups`, `roles`, `realm_access.roles`).

#### 2.3 Claim Mapping Logic
Extend `MapExternalClaims` in [`federation.go`](pdp/idp/federation.go:217) to:
- Extract groups/roles from the id_token
- Apply `RoleMapping` to determine internal PDP role
- Fall back to `DefaultRole` when no mapping matches
- Auto-provision user with mapped role on first federation login

### Dashboard

#### 2.4 Update Gateway Form ([`Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx:66))
- Add **tenant selector** dropdown (populated from `/admin/tenants`)
- Add **AuthMode** dropdown in create form (currently only in edit/IdP settings modal)
- Add **FederationConfig** fields directly in create/edit form:
  - Issuer URL
  - Client ID
  - Client Secret
  - Scopes
  - Claim mapping (username, email)
  - **NEW**: Role mapping table (key-value pairs: external role → internal role)
  - **NEW**: Default role dropdown
  - Auto-discovery toggle
- Show "Test Federation" button in both create and edit modes
- Federation config should be serialized and sent in gateway create/update payload

#### 2.5 API Client Updates ([`api.js`](pdp/pa/dashboard/src/api.js))
- Add tenant CRUD functions
- Ensure `createGateway`/`updateGateway` sends `federation_config` in payload

---

## Phase 3: Gateway Enrollment & Administration (Enhancement)

### Business Rationale
Gateway enrollment via one-time tokens and mTLS certificates already works ([`router.go`](pdp/pa/transport/router.go:3802)). The dashboard Gateway management page ([`Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx)) is well-developed (668 lines). Enhancements needed:
- Tenant scoping
- Improved mTLS certificate lifecycle display
- PKI status integration

### Enhancements

#### 3.1 Gateway Model Extensions
- Add `TenantID` (Phase 1)
- Add `CertIssuedAt` and `CertRenewedAt` display fields to Gateway (optional, for UI)

#### 3.2 Dashboard ([`Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx))
- Add **tenant filter** at top of page
- Show **tenant column** in gateway table
- Show **certificate status** indicator (valid/expiring/expired/revoked)
- Add **Renew Certificate** button alongside Regenerate Token
- Display **PKI health** summary (via Vault status — Phase 7)
- Show **assigned resource count** as badge
- **Hierarchical creation**: Each gateway row has a **"Create Resource"** action button → navigates to Resources page with `gateway_id` and `tenant_id` pre-selected in the create form

#### 3.3 API Endpoints (already exist, verify payloads)
- `POST /admin/gateways` — ensure `tenant_id` and full `federation_config` are accepted
- `PUT /admin/gateways/{id}` — same
- `POST /admin/gateways/{id}/regenerate-token` — exists, no changes needed
- `POST /admin/gateways/{id}/revoke` — exists, no changes needed
- `POST /admin/gateways/{id}/test-federation` — exists, no changes needed

---

## Phase 4: Resource Definition (FQDN/Port/Protocol)

### Business Rationale
The solution document (lines 254-258) requires: "definirea resurselor protejate (FQDN intern/extern, port, protocol, gateway asignat)." Current `Resource` model has `Host`, `Port`, `Type` but conflates internal and external addressing. The UI has no protocol field and no gateway assignment in the resource form.

### Data Model

#### 4.1 Extend `Resource` in [`models.go`](pdp/models/models.go:335)
```go
type Resource struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    Description string `json:"description,omitempty"`
    Type        string `json:"type"`           // "ssh", "rdp", "web", "gateway"
    Protocol    string `json:"protocol"`       // NEW: "tcp", "udp", "http", "https" (derived from type: ssh→tcp, rdp→tcp, web→https)
    
    // Internal addressing (what the Gateway connects to)
    InternalHost string `json:"internal_host"` // e.g. "10.0.1.50" or "sql.internal.local"
    InternalPort int    `json:"internal_port"`
    
    // External addressing (what the Agent connects to via DNS interception)
    ExternalFQDN string `json:"external_fqdn,omitempty"` // e.g. "sql.company.com" (DNS suffix from catalog)
    ExternalPort int    `json:"external_port,omitempty"` // if different from internal
    
    // Legacy fields (keep for backward compat, populate from InternalHost/InternalPort)
    Host string `json:"host"`
    Port int    `json:"port"`
    
    // Gateway assignment
    AssignedGatewayIDs []string `json:"assigned_gateway_ids,omitempty"` // NEW
    
    // Tenant
    TenantID string `json:"tenant_id,omitempty"` // Phase 1
    
    // ... existing fields: ExternalURL, Enabled, Tags, Metadata, ClientID, ClientSecret, CertMode, CertPEM, KeyPEM, CertExpiry, CertDomain, AllowedRoles, RequireMFA, CreatedAt, UpdatedAt
}
```

#### 4.2 SQLite Schema
- `ALTER TABLE resources ADD COLUMN protocol TEXT DEFAULT ''`
- `ALTER TABLE resources ADD COLUMN internal_host TEXT DEFAULT ''`
- `ALTER TABLE resources ADD COLUMN internal_port INTEGER DEFAULT 0`
- `ALTER TABLE resources ADD COLUMN external_fqdn TEXT DEFAULT ''`
- `ALTER TABLE resources ADD COLUMN external_port INTEGER DEFAULT 0`
- `ALTER TABLE resources ADD COLUMN assigned_gateway_ids_json TEXT DEFAULT '[]'`
- `ALTER TABLE resources ADD COLUMN tenant_id TEXT DEFAULT ''`
- **Migration**: populate `internal_host` from `host`, `internal_port` from `port` for existing rows

### Dashboard

#### 4.3 Update Resource Form ([`Resources.jsx`](pdp/pa/dashboard/src/pages/Resources.jsx:40))
- **Hierarchical creation support**: Accept `?tenant_id=X&gateway_id=Y` query params to pre-fill the create form when arriving from the Gateway page's "Create Resource" button
- Add **tenant selector** dropdown (pre-filled if coming from Tenant or Gateway)
- Add **Gateway assignment** multi-select dropdown (populated from gateways list in same tenant, pre-filled if coming from Gateway page)
- Add **Protocol** field (auto-derived from type: ssh→tcp, rdp→tcp, web→https, gateway→all; editable)
- Replace single `Host` field with:
  - **Internal Host** (e.g. IP or internal DNS name)
  - **Internal Port**
  - **External FQDN** (e.g. publicly accessible DNS name)
  - **External Port** (if different)
- Move `ExternalURL` under external addressing section
- Show **certificate info** in detail view (CertPEM, CertExpiry, CertDomain)

#### 4.4 API Client ([`api.js`](pdp/pa/dashboard/src/api.js))
- Update `createResource`/`updateResource` to send new fields

---

## Phase 5: Access Policies with Scope Levels

### Business Rationale
The solution document (lines 265-277) describes comprehensive policy conditions: user, role, device, time window, IP range, risk score, health score, process identity. The current `PolicyRule.Conditions` in [`models.go`](pdp/models/models.go:144) is already complete at the model layer. However:
- The dashboard form only exposes a subset of condition fields
- There is no policy **scope** concept — policies should be definable at Global, Gateway, or Resource level
- The PE must evaluate rules with scope-aware precedence

### Policy Scoping Levels

| Scope | `scope` value | `gateway_id` | `resource_id` | Applies to |
|-------|--------------|-------------|--------------|-----------|
| **Global (Tenant-wide)** | `"global"` | empty | empty | All gateways and resources in the tenant |
| **Gateway-level** | `"gateway"` | set | empty | A specific gateway and all resources assigned to it |
| **Resource-level (Local)** | `"resource"` | set (implicit) | set | A single specific resource |

### Data Model

#### 5.1 Add Scope Fields to `PolicyRule` in [`models.go`](pdp/models/models.go:131)
```go
type PolicyRule struct {
    // ... existing fields ...
    TenantID   string `json:"tenant_id,omitempty"`   // Phase 1
    Scope      string `json:"scope"`                  // NEW: "global", "gateway", "resource"
    GatewayID  string `json:"gateway_id,omitempty"`   // NEW: set when scope="gateway" or scope="resource"
    ResourceID string `json:"resource_id,omitempty"`  // NEW: set when scope="resource"
    // ... Conditions, Action, etc. ...
}
```

#### 5.2 SQLite Schema
- `ALTER TABLE policy_rules ADD COLUMN tenant_id TEXT DEFAULT ''`
- `ALTER TABLE policy_rules ADD COLUMN scope TEXT DEFAULT 'global'`
- `ALTER TABLE policy_rules ADD COLUMN gateway_id TEXT DEFAULT ''`
- `ALTER TABLE policy_rules ADD COLUMN resource_id TEXT DEFAULT ''`

#### 5.3 Policy Engine Evaluation Order
In [`engine.go`](pdp/pe/evaluation/engine.go), rules are evaluated with scope-aware precedence:
1. **Resource-level** rules (most specific) — highest effective priority
2. **Gateway-level** rules — medium effective priority
3. **Global (tenant-wide)** rules — lowest effective priority

Within each scope level, the existing `Priority` field determines ordering. A resource-level `deny` with priority 100 beats a global `allow` with priority 1.

### Gap: Dashboard Form Missing Fields

| Condition Field | In Model? | In Dashboard Form? |
|-----------------|-----------|-------------------|
| `min_health_score` | ✅ | ✅ |
| `required_checks` | ✅ | ✅ |
| `required_check_status` | ✅ | ❌ MISSING |
| `allowed_roles` | ✅ | ✅ |
| `allowed_users` | ✅ | ❌ MISSING |
| `allowed_ips` | ✅ | ✅ |
| `blocked_ips` | ✅ | ❌ MISSING |
| `allowed_time_start/end` | ✅ | ✅ |
| `allowed_days` | ✅ | ✅ |
| `timezone` | ✅ | ❌ MISSING |
| `blocked_dates` | ✅ | ❌ MISSING |
| `date_range_start/end` | ✅ | ❌ MISSING |
| `target_resources` | ✅ | ✅ |
| `target_ports` | ✅ | ✅ |
| `max_risk_score` | ✅ | ✅ |
| `require_process_identity` | ✅ | ❌ MISSING |
| `allowed_process_names` | ✅ | ❌ MISSING |
| `blocked_process_names` | ✅ | ❌ MISSING |
| `allowed_process_hashes` | ✅ | ❌ MISSING |
| `blocked_process_hashes` | ✅ | ❌ MISSING |

### Dashboard

#### 5.4 Update Policy Form ([`Policies.jsx`](pdp/pa/dashboard/src/pages/Policies.jsx:23))
Organize form into collapsible sections:

**Section 0: Scope (NEW — always visible, first decision)**
- Tenant (dropdown, required)
- Scope (radio or dropdown: Global / Gateway / Resource)
- Gateway (dropdown, shown only when scope = "gateway" or "resource", populated from tenant's gateways)
- Resource (dropdown, shown only when scope = "resource", populated from selected gateway's resources)

**Section 1: Basic Info**
- Name, Description, Action (allow/deny/mfa_required/restrict), Priority, Enabled

**Section 2: User & Role Conditions**
- Allowed Roles (multi-select, existing)
- Allowed Users (multi-select, populated from users in tenant — NEW)

**Section 3: Device & Health Conditions**
- Min Health Score (slider 0-100, existing)
- Required Checks (tag input, existing)
- Required Check Status (dropdown: good/warning/any — NEW)

**Section 4: Network Conditions**
- Allowed IPs (CIDR tag input, existing)
- Blocked IPs (CIDR tag input — NEW)

**Section 5: Time Conditions**
- Allowed Time Start/End (time picker, existing)
- Allowed Days (checkboxes Mon-Sun, existing)
- Timezone (IANA dropdown, default "Europe/Bucharest" — NEW)
- Date Range Start/End (date pickers — NEW)
- Blocked Dates (date picker + tag list — NEW)

**Section 6: Resource Conditions**
- Target Resources (multi-select, existing)
- Target Ports (tag input, existing)

**Section 7: Risk & Process Conditions**
- Max Risk Score (slider 0-100, existing)
- Require Process Identity (toggle — NEW, shows/hides sub-fields)
- Allowed Process Names (tag input — NEW)
- Blocked Process Names (tag input — NEW)
- Allowed Process Hashes (tag input — NEW)
- Blocked Process Hashes (tag input — NEW)

**Section 8: MFA (defined but inactive)**
- Require MFA (toggle — display only, non-functional in this flow)

#### 5.5 Policy List View
- Show **Scope** column with badge: 🏢 Global / 🔀 Gateway / 📌 Resource
- Show **Tenant** column
- Show **Gateway/Resource name** (resolved from IDs)
- Filter dropdowns: by Tenant, by Scope, by Gateway

#### 5.6 API Client ([`api.js`](pdp/pa/dashboard/src/api.js))
- Update `createRule`/`updateRule` to send `tenant_id`, `scope`, `gateway_id`, `resource_id` + all condition fields

#### 5.7 Backend Verification
- Ensure [`router.go`](pdp/pa/transport/router.go) policy CRUD handlers correctly deserialize and persist `scope`, `gateway_id`, `resource_id`
- Update [`engine.go`](pdp/pe/evaluation/engine.go) to filter rules by scope and evaluate with scope-aware precedence

---

## Phase 6: Device Management & Certificate Lifecycle

### Business Rationale
The solution document (line 254) requires: "gestionarea dispozitivelor și certificatelor asociate acestora." Device enrollment infrastructure exists ([`enrollment/service.go`](pdp/pa/enrollment/service.go), [`router.go`](pdp/pa/transport/router.go:3070)) but:
- No dashboard page for device enrollment management
- DeviceHealth page shows posture but not enrollment status
- No way to approve/revoke device enrollments from UI
- No certificate lifecycle visibility (issued, expires, renewal)

### Dashboard

#### 6.1 New Page: Device Management ([`DeviceManagement.jsx`](pdp/pa/dashboard/src/pages/))
- **Table columns**: Device ID, Hostname, Component, Status (pending/enrolled/revoked), User, Cert Serial, Cert Fingerprint, Enrolled At, Expires At, Approved By
- **Actions**: Approve (for pending), Revoke (for enrolled), View Certificate
- **Filters**: Tenant, Status
- **Summary cards**: Total devices, Pending approval, Active, Revoked

#### 6.2 Enhance DeviceHealth Page ([`DeviceHealth.jsx`](pdp/pa/dashboard/src/pages/DeviceHealth.jsx:21))
- Add **enrollment status** column
- Add **certificate expiry** column
- Add **associated user** column
- Add **tenant** column
- Link to Device Management for enrollment details

#### 6.3 API Endpoints
- `GET /admin/devices/enrollments` — list all device enrollments (with tenant filter)
- `POST /admin/devices/{id}/approve` — approve pending enrollment
- `POST /admin/devices/{id}/revoke` — revoke enrollment (revokes cert + marks enrollment revoked)
- `GET /admin/devices/{id}/certificate` — view certificate details

#### 6.4 Store Operations ([`store.go`](pdp/store/store.go))
- `ListDeviceEnrollmentsByTenant(tenantID string)` — with tenant filter
- `UpdateDeviceEnrollmentStatus(id, status string)` — approve/revoke
- Existing `ListDeviceEnrollments()` already exists (line 1326)

---

## Phase 7: Vault PKI Infrastructure & Status

### Business Rationale
The solution document (line 263) requires: "infrastructura PKI prin Vault pentru emiterea și gestionarea ciclului de viață al certificatelor." Vault PKI already exists ([`pki/vault.go`](pdp/pki/vault.go)) but there's no dashboard visibility into PKI status.

### Dashboard

#### 7.1 New Page: PKI Status ([`PKIStatus.jsx`](pdp/pa/dashboard/src/pages/))
- **PKI Health Summary**: CA certificate validity, CRL status, Vault connectivity
- **Certificate Inventory**: All issued certs (gateway mTLS, device mTLS, resource TLS) with expiry dates
- **Expiring Soon** alert section (certs expiring within 30 days)
- **Revoked Certificates** list
- **CA Certificate** display (fingerprint, expiry, issuer)

#### 7.2 API Endpoints
- `GET /admin/pki/status` — Vault health, CA info, cert counts
- `GET /admin/pki/certificates` — list all issued certificates with metadata
- `GET /admin/pki/certificates/expiring?days=30` — certs expiring within N days
- `GET /admin/pki/revoked` — list revoked certificates (from `revoked_certs` table)

#### 7.3 Store
- Existing `revoked_certs` table and `GetRevokedSerials()` already exist (line 1378)
- New: `ListAllCerts()` — UNION of gateway certs + device enrollment certs + resource certs

---

## Phase 8: Session Monitoring & Revocation (Enhancement)

### Business Rationale
The solution document (line 261) requires: "monitorizarea sesiunilor active între agent și gateway cu posibilitatea de revocare." Session listing and revocation already works ([`Sessions.jsx`](pdp/pa/dashboard/src/pages/Sessions.jsx)). Enhancements needed:
- Additional columns for better monitoring
- Gateway association (which gateway is proxying this session)
- Tenant scoping

### Enhancements

#### 8.1 Session Model Extensions
- Add `GatewayID string` to [`Session`](pdp/models/models.go:291)
- Add `TenantID string` (Phase 1)
- Add `GatewayFQDN string` (display-only, looked up by GatewayID)

#### 8.2 SQLite Schema
- `ALTER TABLE sessions ADD COLUMN gateway_id TEXT DEFAULT ''`
- `ALTER TABLE sessions ADD COLUMN tenant_id TEXT DEFAULT ''`

#### 8.3 Dashboard ([`Sessions.jsx`](pdp/pa/dashboard/src/pages/Sessions.jsx:13))
- Add columns: **Device ID**, **Gateway** (FQDN), **Tenant** (name)
- Add **tenant filter** at top
- Add **Protocol** column
- Enhanced **status badge** with colors (active=green, expired=yellow, revoked=red)
- Add **bulk revoke** for all sessions of a user/device

#### 8.4 Backend
- Populate `GatewayID` when session is created in `handleStartSession` ([`router.go`](pdp/pa/transport/router.go:1808))
- Populate `TenantID` from user's tenant or gateway's tenant
- Revocation already cascades to Gateway via [`control.go`](pdp/pa/gateway/control.go:115)

---

## Phase 9: Complete Audit Trail

### Business Rationale
The solution document (line 264) requires: "auditul complet al evenimentelor de securitate și administrare." Tamper-evident audit log with SHA-256 hash chain already exists ([`store.go`](pdp/store/store.go:720-848)). The dashboard page exists ([`Audit.jsx`](pdp/pa/dashboard/src/pages/Audit.jsx)). Enhancements needed:
- More event types (admin actions: create/update/delete tenant, gateway, resource, policy, user)
- Tenant scoping in audit entries
- Audit chain verification UI

### Enhancements

#### 9.1 Audit Model Extensions
- Add `TenantID string` to [`AuditEntry`](pdp/models/models.go:307)
- Add `AdminAction string` for admin CRUD events

#### 9.2 Backend — Audit All Admin Actions
Add audit entries for every admin CRUD operation:
- Tenant create/update/delete
- Gateway create/update/delete/enroll/revoke
- Resource create/update/delete/cert-regenerate
- Policy create/update/delete
- User create/update/delete (once user CRUD is added)
- Device enrollment approve/revoke

#### 9.3 Dashboard ([`Audit.jsx`](pdp/pa/dashboard/src/pages/Audit.jsx))
- Add **tenant filter**
- Add **event type filter** dropdown
- Add **date range filter**
- Add **"Verify Chain Integrity"** button → calls `GET /admin/audit/verify`
- Show **chain status** indicator (valid/broken)

#### 9.4 API Endpoints
- `GET /admin/audit?tenant_id=X&event_type=Y&from=Z&to=W&limit=N` — enhanced filtering
- `GET /admin/audit/verify` — runs `VerifyAuditChain()` and returns result

---

## Phase 10: User Management CRUD

### Business Rationale
The dashboard Users page ([`Users.jsx`](pdp/pa/dashboard/src/pages/Users.jsx)) is read-only. Admins need full CRUD to manage users within tenants. Federation users are auto-provisioned, but built-in users need manual management.

### Dashboard

#### 10.1 Update Users Page ([`Users.jsx`](pdp/pa/dashboard/src/pages/Users.jsx:13))
- **Add User** button → modal/form with: username, email, password, role (admin/user), tenant (dropdown), MFA methods (checkboxes: totp, webauthn, push)
- **Edit User** → modal with same fields (password optional)
- **Delete User** → confirmation dialog
- **Enable/Disable toggle** in table
- **Columns**: Username, Email, Role, Tenant, MFA Status, Auth Source (builtin/federated), External Subject (for federated users), Status, Last Login, Created
- **Tenant filter** at top

#### 10.2 API Endpoints
- `POST /admin/users` — create user (already exists in router for registration)
- `PUT /admin/users/{id}` — update user (already exists)
- `DELETE /admin/users/{id}` — delete user (backend `DeleteUser` exists in store, line 471)

#### 10.3 API Client ([`api.js`](pdp/pa/dashboard/src/api.js))
- Add `createUser`, `updateUser`, `deleteUser` functions

---

## Implementation Order & Dependencies

| Phase | Description | Depends On | Key Files Modified |
|-------|-------------|-----------|-------------------|
| **1** | Tenant model + CRUD + dashboard page | None | `models.go`, `store.go`, `router.go`, `Tenants.jsx` (new), `Layout.jsx`, `App.jsx`, `api.js` |
| **2** | IdP config + attribute mapping (RoleMapping, DefaultRole) | Phase 1 | `models.go`, `federation.go`, `Gateways.jsx`, `router.go` |
| **3** | Gateway enrollment enhancements (tenant, cert lifecycle) | Phase 1, 2 | `Gateways.jsx`, `models.go` |
| **4** | Resource definition (FQDN, protocol, gateway assignment) | Phase 1 | `models.go`, `store.go`, `Resources.jsx`, `router.go`, `api.js` |
| **5** | Policy scope levels + complete condition form | Phase 1 | `models.go`, `store.go`, `engine.go`, `router.go`, `Policies.jsx`, `api.js` |
| **6** | Device management (enrollment CRUD, cert lifecycle) | Phase 1 | `DeviceManagement.jsx` (new), `DeviceHealth.jsx`, `router.go`, `store.go`, `api.js` |
| **7** | Vault PKI status dashboard | Phase 1, 3, 6 | `PKIStatus.jsx` (new), `router.go`, `store.go`, `api.js`, `Layout.jsx`, `App.jsx` |
| **8** | Session monitoring enhancements (gateway, tenant, bulk revoke) | Phase 1, 3 | `models.go`, `store.go`, `Sessions.jsx`, `router.go` |
| **9** | Complete audit (admin action logging, chain verification) | Phase 1 | `Audit.jsx`, `router.go`, `models.go`, `store.go`, `api.js` |
| **10** | User management CRUD | Phase 1 | `Users.jsx`, `router.go`, `api.js` |

### Recommended Execution Order
1. **Phase 1** (Tenant) — foundational, all other phases depend on it
2. **Phase 4** (Resources) — core to access flow, can be done in parallel with Phase 2
3. **Phase 2** (IdP Config) — enables federation scenarios
4. **Phase 3** (Gateway Enhancements) — completes Gateway story
5. **Phase 5** (Policies) — completes policy engine configurability
6. **Phase 6** (Device Management) — independent, can be done anytime after Phase 1
7. **Phase 10** (User CRUD) — independent, can be done anytime after Phase 1
8. **Phase 8** (Sessions) — depends on Phase 3 for GatewayID
9. **Phase 7** (PKI Status) — read-only dashboard, can be done anytime after Phase 1
10. **Phase 9** (Audit) — touches all modules, best done last to capture all new audit events

---

## New Dashboard Pages Summary

| Page | Route | Status |
|------|-------|--------|
| Tenants | `/dashboard/tenants` | **NEW** — Phase 1 |
| Device Management | `/dashboard/devices` | **NEW** — Phase 6 |
| PKI Status | `/dashboard/pki` | **NEW** — Phase 7 |

## Existing Dashboard Pages — Modifications

| Page | Route | Key Changes |
|------|-------|-------------|
| Resources | `/dashboard/resources` | Hierarchical create from Gateway, tenant selector, protocol, internal/external FQDN, gateway assignment |
| Gateways | `/dashboard/gateways` | Hierarchical create from Tenant, tenant selector, IdP config in create form, role mapping, cert lifecycle |
| Policies | `/dashboard/policies` | Scope selector, tenant selector, 12 new condition fields, scope badges in list view |
| Users | `/dashboard/users` | CRUD operations, tenant selector, federation fields |
| Sessions | `/dashboard/sessions` | Gateway column, device column, tenant filter, bulk revoke |
| Device Health | `/dashboard/device-health` | Enrollment status, cert expiry, tenant column |
| Audit Log | `/dashboard/audit` | Tenant filter, event type filter, chain verification |
| Layout | (sidebar) | Add Tenants, Devices, PKI to nav |

---

## MFA Status in This Flow

All MFA-related structures are **defined but inactive**:
- `PolicyRule.Conditions` may include a `require_mfa` boolean (displayed in form, saved to DB)
- `Resource.RequireMFA` exists — displayed but not enforced
- User MFA methods are configurable via user CRUD
- Policy engine does NOT trigger `mfa_required` decisions (action allowed but PE returns `allow`/`deny` only)
- The `mfa_required` action in policies is shown in the dropdown but treated as `deny` by PE for now
- MFA enrollment (TOTP setup, WebAuthn registration, Push device binding) remains functional for user self-service but is not required for resource access

This preserves all MFA data model and UI investment while keeping the access flow simple for the initial functional milestone.

---

## Features Already Implemented (No Action Needed)

| Feature | Location | Status |
|---------|----------|--------|
| PA/PE separation with `EvaluateAccess` | [`policy_evaluation.go`](pdp/pa/policy_evaluation.go:13) | ✅ |
| PE deterministic evaluation | [`engine.go`](pdp/pe/evaluation/engine.go:39) | ✅ |
| Temporal policies (time windows, days) | [`engine.go`](pdp/pe/evaluation/engine.go:116) | ✅ |
| CAEP event infrastructure (pub/sub) | [`broker.go`](pdp/pa/events/broker.go) | ✅ |
| OIDC federation (discovery, PKCE, token exchange) | [`federation.go`](pdp/idp/federation.go) | ✅ |
| Catalog with SHA-256 versioning, TTL | [`catalog.go`](pdp/pa/catalog/catalog.go) | ✅ |
| Agent authorization gRPC | [`agent_authorization_grpc.go`](pdp/pa/transport/agent_authorization_grpc.go) | ✅ |
| MFA: TOTP, WebAuthn, Push (functional but not enforced) | [`totp.go`](pdp/idp/totp.go), [`webauthn.go`](pdp/mfa/webauthn.go), [`push.go`](pdp/mfa/push.go) | ✅ |
| Browser MFA step-up (MFAStepUp/MFAVerify) | [`router.go`](pdp/pa/transport/router.go:607,564) | ✅ |
| Gateway control plane (provision/revoke/heartbeat) | [`control.go`](pdp/pa/gateway/control.go) | ✅ |
| OIDC IdP with PKCE (built-in) | [`oidc.go`](pdp/idp/oidc.go) | ✅ |
| Geo-velocity / impossible travel detection | [`geo.go`](pdp/pa/policies/geo.go:213) | ✅ |
| Device health & posture telemetry | [`telemetry.go`](pdp/pa/devices/telemetry.go) | ✅ |
| Tamper-evident audit log (SHA-256 hash chain) | [`store.go`](pdp/store/store.go:799) | ✅ |
| Admin dashboard (React + Tailwind CSS) | [`dashboard/`](pdp/pa/dashboard/) | ✅ |
| EST enrollment for devices | [`router.go`](pdp/pa/transport/router.go:3374) | ✅ |
| Vault PKI certificate management | [`vault.go`](pdp/pki/vault.go) | ✅ |
| Gateway enrollment with one-time token | [`router.go`](pdp/pa/transport/router.go:3802) | ✅ |
| Session revocation cascade to Gateway | [`control.go`](pdp/pa/gateway/control.go:115) | ✅ |
| Risk scoring (PE risk engine) | [`risk.go`](pdp/pe/risk/risk.go) | ✅ |
| Process identity matching in policies | [`engine.go`](pdp/pe/evaluation/engine.go:255) | ✅ |
| Dashboard stats endpoint | [`router.go`](pdp/pa/transport/router.go:2307) | ✅ |

---

## File Map — All Files Modified in This Plan

| File | Phase | Change Summary |
|------|-------|----------------|
| [`pdp/models/models.go`](pdp/models/models.go) | 1,2,4,5,8,9 | Add Tenant, TenantID on 7 structs, FederationConfig.RoleMapping/DefaultRole, Resource.InternalFQDN/ExternalFQDN/Protocol/AssignedGatewayIDs, PolicyRule.Scope/GatewayID/ResourceID, Session.GatewayID, AuditEntry.TenantID |
| [`pdp/store/store.go`](pdp/store/store.go) | 1,4,6,8,9 | Tenant CRUD, tenant-aware queries on all list ops, new columns for resources/sessions, PKI cert listing |
| [`pdp/pa/transport/router.go`](pdp/pa/transport/router.go) | 1,2,4,6,7,8,9,10 | Tenant CRUD endpoints, device management endpoints, PKI status endpoints, session enhanced listing, audit verification, user CRUD endpoints, populate GatewayID+TenantID on session create, audit all admin actions |
| [`pdp/idp/federation.go`](pdp/idp/federation.go) | 2 | Extend FederatedClaims with Groups/Roles, apply RoleMapping in MapExternalClaims |
| [`pdp/pa/dashboard/src/App.jsx`](pdp/pa/dashboard/src/App.jsx) | 1,6,7 | Add routes for /tenants, /devices, /pki |
| [`pdp/pa/dashboard/src/components/Layout.jsx`](pdp/pa/dashboard/src/components/Layout.jsx) | 1,6,7 | Add nav items: Tenants, Devices, PKI |
| [`pdp/pa/dashboard/src/api.js`](pdp/pa/dashboard/src/api.js) | 1,2,4,5,6,7,9,10 | Add all new API functions |
| [`pdp/pa/dashboard/src/pages/Tenants.jsx`](pdp/pa/dashboard/src/pages/) | 1 | **NEW** — Tenant CRUD page |
| [`pdp/pa/dashboard/src/pages/Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx) | 2,3 | Tenant selector, IdP config in create, role mapping, cert lifecycle display |
| [`pdp/pa/dashboard/src/pages/Resources.jsx`](pdp/pa/dashboard/src/pages/Resources.jsx) | 4 | Tenant selector, protocol, internal/external FQDN, gateway assignment |
| [`pdp/pa/dashboard/src/pages/Policies.jsx`](pdp/pa/dashboard/src/pages/Policies.jsx) | 5 | Scope selector, tenant selector, 12 new condition fields, scope badges in list view |
| [`pdp/pa/dashboard/src/pages/Users.jsx`](pdp/pa/dashboard/src/pages/Users.jsx) | 10 | Full CRUD, tenant selector, federation fields |
| [`pdp/pa/dashboard/src/pages/Sessions.jsx`](pdp/pa/dashboard/src/pages/Sessions.jsx) | 8 | Gateway, device, tenant columns, bulk revoke |
| [`pdp/pa/dashboard/src/pages/DeviceHealth.jsx`](pdp/pa/dashboard/src/pages/DeviceHealth.jsx) | 6 | Enrollment status, cert expiry, tenant column |
| [`pdp/pa/dashboard/src/pages/DeviceManagement.jsx`](pdp/pa/dashboard/src/pages/) | 6 | **NEW** — Device enrollment CRUD page |
| [`pdp/pa/dashboard/src/pages/PKIStatus.jsx`](pdp/pa/dashboard/src/pages/) | 7 | **NEW** — PKI/Vault status dashboard |
| [`pdp/pa/dashboard/src/pages/Audit.jsx`](pdp/pa/dashboard/src/pages/Audit.jsx) | 9 | Tenant filter, event type filter, chain verification |
