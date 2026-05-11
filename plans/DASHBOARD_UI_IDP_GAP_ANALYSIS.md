# Dashboard Admin UI — IdP Management Gap Analysis

## Current State vs. Required State

Backend Phase 1-4 au adăugat suport complet pentru Identity Provider per Tenant cu HRD și group mapping, dar interfața de administrare (React dashboard) NU a fost actualizată. Mai jos este analiza completă a discrepanțelor.

---

## 1. Entități noi fără corespondent în UI

| Entitate backend | Status UI | Ce lipsește |
|-----------------|-----------|-------------|
| [`IdentityProviderConfig`](pdp/models/models.go:124) | ❌ **Nu există deloc** | Pagină nouă sau secțiune în Tenant detail pentru CRUD IdP |
| [`GroupRoleRule`](pdp/models/models.go:158) | ❌ **Nu există deloc** | Editor de reguli grup→rol în formularul de IdP |
| `Tenant.Domains[]` | ❌ Câmpul `domain` (singular) există, dar `domains` (plural) nu | Adăugare input pentru domenii multiple |
| `Tenant.DefaultIdPID` | ❌ Nu există | Dropdown/selector pentru IdP-ul implicit al tenant-ului |
| `Gateway.TenantIDs[]` | ❌ Nu există | Selector multi-tenant în formularul de creare/editare gateway |
| `FederatedClaims.Groups` | ❌ Nu există | Câmp `groups` claim în claim mapping + editor group→role mapping |

---

## 2. API Client ([`api.js`](pdp/pa/dashboard/src/api.js)) — funcții lipsă

Funcțiile de mai jos trebuie adăugate pentru a susține noul API backend:

```javascript
// ─── Identity Providers (per Tenant) ─────────

export async function getIdPs(tenantId) {
  return apiFetch(`/admin/tenants/idps?tenant_id=${encodeURIComponent(tenantId)}`);
}

export async function createIdP(tenantId, data) {
  return apiFetch(`/admin/tenants/idps?tenant_id=${encodeURIComponent(tenantId)}`, {
    method: 'POST',
    body: JSON.stringify(data),
  });
}

export async function getIdP(id) {
  return apiFetch(`/admin/tenants/idps/${id}`);
}

export async function updateIdP(id, data) {
  return apiFetch(`/admin/tenants/idps/${id}`, {
    method: 'PUT',
    body: JSON.stringify(data),
  });
}

export async function deleteIdP(id) {
  return apiFetch(`/admin/tenants/idps/${id}`, {
    method: 'DELETE',
  });
}

// Federation discovery test for tenant-level IdP (new endpoint needed in backend)
export async function testIdPFederation(tenantId, issuer) {
  return apiFetch(`/admin/tenants/idps/discover`, {
    method: 'POST',
    body: JSON.stringify({ tenant_id: tenantId, issuer }),
  });
}
```

---

## 3. Pagina Tenants ([`Tenants.jsx`](pdp/pa/dashboard/src/pages/Tenants.jsx)) — modificări necesare

### 3.1 Formularul de creare/editare tenant

**Câmpuri existente**: `name`, `domain` (singular), `description`, `enabled`

**Câmpuri de adăugat**:

| Câmp | Tip | Descriere |
|------|-----|-----------|
| `domains` | Input multi-valoare (tags/chips) | Domenii suplimentare pentru HRD |
| `default_idp_id` | Dropdown (populat după crearea IdP-urilor) | IdP-ul implicit al tenant-ului |

### 3.2 Acțiuni per tenant

Fiecare rând din tabelul de tenant-i trebuie să aibă o acțiune nouă:

```
[🏢 IdP Settings]  [🔗 Create Gateway]  [✏️ Edit]  [🗑️ Delete]
```

Butonul **"IdP Settings"** deschide o pagină nouă sau un drawer/modal care listează IdP-urile configurate pentru acel tenant și permite CRUD.

### 3.3 Coloane noi în tabel

| Coloană | Sursă date | Descriere |
|---------|-----------|-----------|
| **IdP** | `default_idp_id` → `getIdP(id).name` | Numele IdP-ului implicit sau "—" dacă nu e setat |
| **HRD Domains** | `domains` | Lista domeniilor pentru HRD (compactată) |

---

## 4. Pagină nouă: Identity Providers (sau secțiune în Tenant detail)

### 4.1 Ce trebuie construit

O pagină nouă [`IdPManagement.jsx`] sau un modal în [`Tenants.jsx`] care oferă:

- **Listă IdP-uri** pentru tenant-ul selectat (tabel cu: name, type, issuer, enabled, domains, acțiuni)
- **Formular de adăugare/editare IdP** cu câmpurile:

| Câmp | Tip | Validare |
|------|-----|----------|
| `name` | text | required |
| `type` | dropdown (`oidc`) | default: oidc |
| `issuer` | URL | required |
| `client_id` | text | required |
| `client_secret` | password | opțional |
| `scopes` | text | default: "openid profile email" |
| `domains` | tags/chips multi-valoare | pentru HRD |
| `auto_discovery` | checkbox | default: true |
| `enabled` | checkbox | default: true |

- **Claim mapping** (sub-secțiune avansată):

| Câmp | Descriere |
|------|-----------|
| `claim_username` | Default: `preferred_username` |
| `claim_email` | Default: `email` |
| `claim_groups` | Default: `groups` — **NOU** |

- **Group → Role mapping** (sub-secțiune avansată, **NOUĂ**):
  - Tabel/editabil cu rânduri: `Group Name` → `Role` (dropdown: admin, operator, auditor, user)
  - Buton "Add Rule" / "Remove Rule"
  - Fiecare regulă = un obiect `{ group_name, role }`

- **Buton "Test Connection"** — face OIDC discovery pe issuer și afișează endpoint-urile

### 4.2 Mock al structurii

```
┌─────────────────────────────────────────────────────┐
│  Identity Providers — Company HQ (tenant_abc123)    │
│                                                     │
│  [Lista IdP-urilor existente]                       │
│  ┌──────────────────────────────────────────────┐   │
│  │ Name          │ Issuer         │ Status │ Act │   │
│  │ Entra ID      │ login.micro... │ Active │ ⋯  │   │
│  │ Keycloak Dev  │ keycloak.la... │ Active │ ⋯  │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  [+ Add Identity Provider]                          │
│                                                     │
│  ── Formular IdP (expandat la click pe Add/Edit) ── │
│  Name: [________________]                           │
│  Issuer URL: [________________]                     │
│  Client ID: [________________]                      │
│  Client Secret: [________________]                  │
│  Domains (HRD): [company.com] [subsidiary.com] [+ Add]│
│                                                     │
│  ── Advanced: Claim Mapping ──                      │
│  Username claim: [preferred_username]               │
│  Email claim:    [email]                            │
│  Groups claim:   [groups]              ← NOU        │
│                                                     │
│  ── Advanced: Group → Role Mapping ──     ← NOU     │
│  ┌──────────────────────────────────────┐          │
│  │ Group Name          │ Role           │ [×]      │
│  │ Domain Admins       │ admin      ▾   │          │
│  │ Engineering         │ user       ▾   │          │
│  │ Auditors            │ auditor    ▾   │          │
│  └──────────────────────────────────────┘          │
│  [+ Add Rule]                                       │
│                                                     │
│  [Test Connection]  [Cancel]  [Save]                │
└─────────────────────────────────────────────────────┘
```

---

## 5. Pagina Gateways ([`Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx)) — modificări necesare

### 5.1 Marcaj "Deprecated" pe Federation Config per Gateway

Formularul actual de IdP din modalul "Identity Source Settings" și din "Create Gateway" trebuie să reflecte că această configurație este **deprecated** în favoarea `IdentityProviderConfig` per Tenant.

**Acțiuni**:
- Adăugare badge/warning text: "⚠️ Legacy — configure IdP at the Tenant level instead"
- Păstrarea funcționalității pentru backward compatibility
- Adăugare link către noua pagină de IdP management: "Manage tenant IdPs →"

### 5.2 Câmpuri noi în formularul de creare/editare gateway

| Câmp | Tip | Descriere |
|------|-----|-----------|
| `tenant_ids` | Multi-select | Ce tenant-i deservește acest gateway (dacă gol = single-tenant legacy) |

### 5.3 Coloane noi în tabelul de gateway-uri

| Coloană | Sursă | Descriere |
|---------|-------|-----------|
| **Tenants** | `tenant_ids` | Lista de tenant-i (sau "—" dacă single-tenant) |

---

## 6. Rezumatul acțiunilor necesare

### Prioritate 🔴 (critic — fără acestea, funcționalitatea nouă e inaccesibilă)

| # | Acțiune | Fișier(e) | Efort |
|---|---------|-----------|-------|
| 1 | Adăugare funcții API pentru IdP CRUD | [`api.js`](pdp/pa/dashboard/src/api.js) | 15 linii |
| 2 | Creare pagină/componentă IdP Management (listă + formular CRUD) | Nou: `IdPManagement.jsx` sau secțiune în `Tenants.jsx` | ~250 linii |
| 3 | Adăugare buton "IdP Settings" per tenant | [`Tenants.jsx`](pdp/pa/dashboard/src/pages/Tenants.jsx) | ~5 linii |
| 4 | Rută nouă în React Router | [`App.jsx`](pdp/pa/dashboard/src/App.jsx) | ~3 linii |

### Prioritate 🟡 (important — completează experiența)

| # | Acțiune | Fișier(e) | Efort |
|---|---------|-----------|-------|
| 5 | Adăugare `domains` (plural) + `default_idp_id` în formularul Tenant | [`Tenants.jsx`](pdp/pa/dashboard/src/pages/Tenants.jsx) | ~20 linii |
| 6 | Adăugare `tenant_ids` în formularul Gateway | [`Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx) | ~25 linii |
| 7 | Adăugare group→role mapping editor în formularul IdP | `IdPManagement.jsx` | ~60 linii |
| 8 | Adăugare `groups` claim în claim mapping | `IdPManagement.jsx` | ~5 linii |

### Prioritate 🟢 (nice-to-have)

| # | Acțiune | Fișier(e) | Efort |
|---|---------|-----------|-------|
| 9 | Marcaj "Deprecated" pe Federation Config per Gateway | [`Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx) | ~10 linii |
| 10 | Coloană "HRD Domains" în tabelul de tenant-i | [`Tenants.jsx`](pdp/pa/dashboard/src/pages/Tenants.jsx) | ~5 linii |
| 11 | Coloană "Tenants" în tabelul de gateway-uri | [`Gateways.jsx`](pdp/pa/dashboard/src/pages/Gateways.jsx) | ~5 linii |
| 12 | Endpoint backend pentru test OIDC discovery la nivel de tenant | [`router.go`](pdp/pa/transport/router.go) | ~30 linii |

---

## 7. Diagrama fluxului de navigare (propus)

```
Dashboard
├── Tenants
│   └── [IdP Settings] → Identity Providers (per tenant)
│       ├── List IdPs
│       ├── Add/Edit IdP (formular cu claim mapping + group→role mapping)
│       ├── Test Connection (OIDC discovery)
│       └── Delete IdP
├── Gateways
│   ├── Create Gateway (cu tenant_ids + legacy federation warning)
│   └── Identity Source Settings (legacy, cu link către tenant IdPs)
├── Resources
├── Policies
├── Users
├── Sessions
├── Audit
└── Device Health
```

---

## Concluzie

**Interfața de administrare NU este actualizată** conform modificărilor din backend. Sunt necesare:

1. **O pagină nouă** (Identity Providers per Tenant) — aceasta este cea mai mare lipsă
2. **6 funcții API noi** în [`api.js`](pdp/pa/dashboard/src/api.js)
3. **Modificări la paginile existente** Tenants și Gateways pentru a expune noile câmpuri și a ghida utilizatorul către noul model
4. **Un endpoint backend nou** pentru OIDC discovery la nivel de tenant (opțional, se poate refolosi funcția `Discover()` existentă)

Fără aceste modificări, noile capabilități (IdP per Tenant, HRD, group mapping) sunt **complet inaccesibile din interfața de administrare**, putând fi configurate doar prin API direct.
