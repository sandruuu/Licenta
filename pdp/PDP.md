# TrustCloud PDP Documentation

`pdp/` este componenta TrustCloud care implementeaza Policy Decision Point-ul.
Procesul ruleaza ca o singura aplicatie Go, dar codul pastreaza doua limite
interne clare:

- PA, Policy Administrator: orchestreaza fluxuri, sesiuni, identitati,
  certificate, Gateway-uri, resurse, audit si transport.
- PE, Policy Engine: evalueaza determinist contextul de acces si returneaza
  `allow`, `deny` sau `mfa_required`.

Documentul acesta este documentatia canonica pentru implementarea existenta din
`pdp/`. Nu include functionalitati planificate care nu exista in cod.

## Runtime

- Modul Go: `pdp`
- Entrypoint: `cmd/pdp`
- Config principal: `config.json`
- Database: SQLite prin `modernc.org/sqlite`
- Server HTTP/gRPC: `pa/transport`
- Dashboard admin: React + Vite in `pa/dashboard`
- TLS server identity: certificat PDP emis prin Vault PKI self-enrollment
- Client mTLS: obligatoriu pentru endpoint-uri Agent/Gateway care cer identitate
  de dispozitiv sau Gateway

La pornire, `cmd/pdp/main.go`:

1. incarca `config.json`;
2. aplica valorile implicite din `config.Config.ApplyDefaults`;
3. creeaza directorul de date;
4. restaureaza sau creeaza cheia privata PDP protejata prin Vault Transit;
5. face self-enrollment la Vault PKI pentru certificatul TLS al PDP;
6. salveaza certificatul si CA-ul rezultat;
7. porneste loop-ul de reinnoire a certificatului PDP;
8. deschide SQLite store-ul;
9. creeaza `pa.PolicyAdministrator`;
10. asigura bootstrap admin-ul daca `bootstrap_admin.enabled=true`;
11. creeaza `transport.Server`;
12. porneste HTTPS cu TLS 1.3 si multiplexeaza HTTP + gRPC peste acelasi port.

## Structura Directoarelor

```text
pdp/
  cmd/pdp/              entrypoint runtime
  config/               model config, defaults, loader JSON
  models/               modele API, auth, audit, tenant, resource, policy, device
  store/                SQLite schema, migrari, CRUD pe entitati
  pa/                   Policy Administrator
    auth/               user auth, JWT, OIDC, federation, TOTP
    audit/              audit logger
    catalog/            catalog resurse pentru Agent
    devices/            device health si device data
    enrollment/         enrollment Agent/device si certificate device
    events/             broker CAEP-style in-memory
    gateway/            Gateway admin, enrollment, control plane
    policies/           geo/risk helpers pentru PA
    resources/          CRUD resurse protejate si certificate resursa
    sessions/           sesiuni PA si revocare
    transport/          HTTP/gRPC handlers, middleware, browser flows
    dashboard/          React admin dashboard
  pe/
    evaluation/         evaluator deterministic al politicilor
    risk/               scoring risc 0-100
  pki/                  Vault PKI, Vault Transit, self-enrollment PDP, CA guard
  mfa/                  WebAuthn provider
  certs/                utilitare certificate/fingerprint
  util/                 utilitare mici, de exemplu ID generation
```

## Configuratie

`config.Config` include urmatoarele zone:

- server: `listen_addr`, `pdp_fqdn`, `tls_cert`, `mtls_ca`;
- Vault PKI: `pki_url`, `pki_token`, `pki_path`, roluri PDP/device/Gateway,
  `pki_transit_key`, CA file, SNI si timeout;
- JWT: expiry, MFA token expiry, Vault Transit key pentru cheia JWT;
- sesiuni: durata sesiune si numar maxim de sesiuni per user;
- securitate: lockout dupa login attempts;
- date: `data_dir`, `database_path`, fisiere encrypted key;
- WebAuthn: RPID, RP name, origins;
- CORS;
- runtime knobs: timeout-uri HTTP, cleanup loops, TTL catalog, rate limits,
  TTL-uri OIDC, TTL-uri enrollment browser, buffer evenimente;
- bootstrap admin;
- dashboard public config;
- Gateway defaults;
- enrollment defaults;
- geo locator;
- risk model.

Configuratia este validata prin aplicarea default-urilor inainte ca PA si
transportul sa fie initializate.

## Persistenta

Persistenta este SQLite si este initializata in `store/schema.go`.
Schema curenta include:

- `users`
- `tenants`
- `schema_meta`
- `policy_rules`
- `policy_assignments`
- `sessions`
- `resources`
- `audit_log`
- `device_health`
- `device_data`
- `login_attempts`
- `revoked_tokens`
- `device_enrollments`
- `revoked_certs`
- `device_users`
- `gateways`
- `login_locations`
- `webauthn_credentials`
- `rate_limits`
- `identity_provider_configs`
- `directory_users`
- `directory_groups`
- `directory_group_members`

Store-ul este impartit pe fisiere pe domenii: `users.go`, `tenants.go`,
`resources.go`, `policies.go`, `sessions.go`, `gateways.go`,
`enrollments.go`, `device_data.go`, `audit.go`, `directory.go`,
`identity_auth.go`, `tokens.go`, `pending.go`, `serialization.go` si
`schema.go`.

Migrarile sunt idempotente si ignora erorile de coloana duplicata. Exista o
migrare explicita din tabela istorica `device_posture` catre tabela curenta
`device_data`, pentru compatibilitate cu baze de date create inainte de
redenominarea device-data.

## Modele Principale

Modelele sunt in `models/`.

- `Tenant`: organizatie izolata, domenii HRD, IdP implicit.
- `IdentityProviderConfig`: IdP OIDC per tenant, domenii, discovery, claim
  mapping, group-role mapping si token SCIM.
- `User`: utilizator local sau federat, rol, tenant, MFA methods, sursa auth.
- `DirectoryUser`, `DirectoryGroup`: obiecte provisionate prin SCIM.
- `Resource`: resursa protejata, host intern, port, `external_url`, tenant,
  Gateway, cert metadata, tag-uri, metadata.
- `Gateway`: Gateway inscris, tenant, certificat mTLS, token enrollment,
  endpoint public/listen, resurse asignate, federation config legacy.
- `PolicyRule`: regula reutilizabila, conditii, prioritate, actiune.
- `PolicyAssignment`: atasare regula la nivel `organization`, `group`,
  `resource` sau `resource_group`.
- `Session`: sesiune autorizata PA, user, device, resursa, Gateway, protocol,
  risc, tenant, expirare si revocare.
- `DeviceEnrollment`: stare enrollment device, CSR/certificat, user si tenant.
- `DeviceHealthReport`: raport compatibil scorificat.
- `DeviceDataReport`: date brute normalizate de dispozitiv.
- `AuditEntry`: eveniment audit.
- `WebAuthnCredential`: credential passkey/WebAuthn.

## Policy Administrator

`pa.PolicyAdministrator` este compus in `pa/admin.go` si detine:

- `Auth`
- `Engine`
- `Geo`
- `Catalog`
- `Devices`
- `Enrollment`
- `Gateways`
- `Resources`
- `Sessions`
- `Audit`
- `Store`
- `Cfg`

PA coordoneaza fluxurile cu efecte laterale si apeleaza PE doar pentru decizia
determinista. PA valideaza tokenuri, incarca user/tenant/grupuri/resurse,
incarca device-data, calculeaza context geo, creeaza sesiuni, provision-eaza
Gateway-ul, publica evenimente si scrie audit.

## Policy Engine

PE este in `pe/evaluation` si `pe/risk`.

Inputul PE este `evaluation.AccessContext`, care contine:

- `models.AccessRequest`
- reguli deja incarcate de PA/store
- rol si email user
- identitate directory si grupuri
- failed login attempts
- timpul curent
- geo velocity si impossible travel

`Engine.Evaluate`:

1. calculeaza scorul de risc prin `pe/risk.CalculateRiskScore`;
2. parcurge regulile active in ordinea furnizata de PA/store;
3. verifica toate conditiile;
4. intoarce actiunea primei reguli potrivite;
5. daca nu exista regula potrivita, returneaza `deny` fail-closed.

Conditiile existente includ:

- roluri, useri, grupuri;
- IP-uri permise/blocate;
- endpoint trust policy si bypass IP;
- block compromised endpoints;
- comportament separat pentru endpoint-uri mobile;
- date range, blocked dates, timezone, time window, zile permise;
- resurse tinta si porturi tinta;
- process identity required;
- procese permise/blocate dupa nume;
- hash-uri proces permise/blocate;
- scor minim device health;
- required checks si status cerut.

Risk score-ul include device health/data staleness, scor health, check-uri
critice, failed login attempts, business hours, protocol, impossible travel,
geo velocity si anomaly score.

## Autentificare, OIDC si MFA

`pa/auth` implementeaza:

- user manager cu register, authenticate, lockout, role update;
- TOTP RFC 6238;
- JWT ES256 pentru auth token, MFA token, enrollment token si agent session
  token;
- JWKS;
- OIDC manager cu authorization code, PKCE, refresh token si native Connect-App
  public client;
- OIDC federation catre IdP extern cu discovery, token exchange si claim
  mapping;
- user auto-provisioning pentru utilizatori federati.

`mfa/webauthn.go` implementeaza WebAuthn/passkey prin `go-webauthn`.
TOTP este implementat in `pa/auth/totp.go`. Modelul `PushChallenge` exista in
`models/mfa.go`, dar nu exista in prezent un serviciu push MFA activ in runtime.

Endpoint-uri relevante:

- `/api/auth/login`
- `/api/auth/verify-mfa`
- `/api/auth/mfa-step-up`
- `/api/auth/register`
- `/api/auth/enroll-mfa`
- `/api/auth/activate-mfa`
- `/api/auth/revoke-token`
- `/api/mfa/webauthn/register/begin`
- `/api/mfa/webauthn/register/finish`
- `/api/mfa/webauthn/authenticate/begin`
- `/api/mfa/webauthn/authenticate/finish`
- `/auth/authorize`
- `/auth/token`
- `/auth/userinfo`
- `/auth/federated/callback`
- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`

## Multi-Tenant, HRD si SCIM

Multi-tenancy este modelata prin `Tenant`, `IdentityProviderConfig`,
`tenant_id` pe entitati si prin paginile de organizatii din dashboard.

Home Realm Discovery este in `pa/transport/oidc_hrd.go`. Rezolutia IdP-ului
urmeaza aceasta ordine:

1. `idp_id` explicit;
2. domeniu din `login_hint`;
3. `tenant_id` explicit;
4. context tenant derivat din Gateway client legacy;
5. fallback single-tenant.

SCIM inbound este in `pa/transport/scim_handlers.go` si expune o suprafata
deliberat mica pentru IdP provisioning:

- service provider config;
- users CRUD/patch/list cu filtrare simpla;
- groups CRUD/patch/list;
- memberships pentru grupuri;
- autentificare bearer token din `IdentityProviderConfig.SCIMToken`.

Datele SCIM se salveaza in `directory_users`, `directory_groups` si
`directory_group_members`.

## Enrollment Agent/Device

Enrollment-ul Agent/device este in `pa/enrollment` si in handler-ele din
`pa/transport`.

Fluxuri existente:

- browser interactive enrollment;
- sesiune browser cu OIDC/IdP;
- status polling pentru Agent;
- device proof si completare enrollment;
- EST enrollment device-bound;
- one-time enrollment token;
- certificate renewal prin mTLS;
- same-key renewal;
- changed-key revocation;
- admin list/approve/revoke pentru enrollment-uri;
- owner binding intre device si user.

Certificatele device sunt semnate prin signer-ul configurat in transport:
Vault PKI cand este configurat, cu rolul device stabilit prin componenta.

Endpoint-uri principale:

- `trustagent.enrollment.EnrollmentService/StartSession`
- `trustagent.enrollment.EnrollmentService/SessionStatus`
- `trustagent.enrollment.EnrollmentService/CompleteSession`
- `/browser/enroll/{session_id}`
- `/api/enroll/renew`
- `/api/admin/enrollments`
- `/api/admin/enrollments/{id}/approve`
- `/api/admin/enrollments/{id}/revoke`

## Sesiune User Agent si Catalog

Dupa enrollment, Agentul porneste autentificarea userului local prin
`trustagent.session.AgentSessionService`.

Serviciul gRPC include:

- `StartSession`
- `SessionStatus`
- `ClaimSession`
- `GetCatalog`
- `RevokeSession`

PDP creeaza o tranzactie de autentificare browser, mediaza OIDC/IdP, apoi la
claim emite `agent_session_token`. Tokenul este legat de certificatul mTLS al
device-ului prin thumbprint si include scope-uri precum:

- `catalog:read`
- `flow:authorize`
- `session:revoke`

Catalogul este construit in `pa/catalog` si contine:

- `version`
- `resources`
- `ttl_seconds`
- `policy_epoch`
- `device_data_policy`

Resursele din catalog sunt filtrate pe tenant, user, grupuri si politici.
`external_url` este sursa FQDN-ului expus catre Agent. Catalogul include doar
resurse active si accesibile explicit prin politicile aplicabile.

## Device Data si Device Health

`pa/devices` primeste doua forme de stare device:

- `DeviceHealthReport`: raport scorificat, compatibilitate;
- `DeviceDataReport`: date brute normalizate trimise de TrustAgent.

Fluxul activ de Agent foloseste:

- `trustagent.device.DeviceDataService/ReportDeviceData`
- `trustagent.device.DeviceDataService/Heartbeat`

PDP nu are incredere in `device_id` din payload. Handler-ul compara `device_id`
cu identitatea certificatului mTLS. `overall_score` este respins pe raportul
raw device data; scorarea ramane responsabilitatea PDP/PE.

Datele sunt salvate in tabela `device_data`, auditate si publica evenimente
health/device-data prin broker-ul PA.

## Resurse Protejate

`pa/resources` implementeaza:

- list/create/get/update/delete resurse;
- validare tenant si Gateway;
- generare credentiale per-app ramase compatibile cu baze vechi;
- metadata, tags, certificate fields;
- emitere evenimente CAEP-style pentru resurse actualizate.

`Resource` foloseste:

- `host` si `port` pentru target intern Gateway;
- `external_url` pentru FQDN-ul vazut de Agent;
- `tenant_id` pentru izolare;
- `gateway_id` pentru Gateway-ul care poate ajunge la target;
- `type` pentru protocol derivat in catalog (`web` -> `http/https` dupa URL).

Endpoint-uri admin:

- `/api/admin/resources`
- `/api/admin/resources/{id}`

## Gateway Management si Control Plane

`pa/gateway` implementeaza:

- CRUD Gateway;
- regenerare token enrollment;
- revocare administrativa;
- enrollment mTLS cu CSR;
- certificate renewal;
- revocarea certificatului vechi la renewal;
- validare tenant si resurse asignate;
- registry de conexiuni control plane;
- comenzi `provision_session`, `revoke_session`, `heartbeat`.

Servicii gRPC:

- `gateway.GatewayEnrollmentService/Enroll`
- `gateway.GatewayEnrollmentService/RenewCertificate`
- `gateway.GatewayTrustService/GetCACertificate`
- `gateway.GatewayTrustService/GetRevokedSerials`
- `gateway.GatewayControlService/ControlStream`

Endpoint-uri admin:

- `/api/admin/gateways`
- `/api/admin/gateways/{id}`

Cand Agentul cere autorizarea unei conexiuni si PE returneaza `allow`, PA:

1. alege Gateway-ul conectat pentru resursa;
2. creeaza sesiune PA;
3. genereaza un `session_token` pentru Gateway;
4. trimite `ProvisionSession` catre Gateway;
5. returneaza Agentului `session_id`, `session_token`, Gateway si expiry.

Daca provisioning-ul Gateway esueaza, sesiunea PA este revocata.

## Agent Flow Authorization

Autorizarea per flow este implementata in `pa/agent_authorization.go` si
`pa/transport/agent_authorization_grpc.go`.

Serviciu:

- `trustcloud.agent.AgentAuthorizationService/AuthorizeResource`

Inputul include:

- identitatea mTLS device;
- `agent_session_token`;
- `resource_id`;
- protocol;
- port;
- process identity optional;
- source IP.

Validari importante:

- tokenul trebuie sa aiba audience/purpose de Agent session;
- tokenul trebuie sa fie legat de certificatul device curent;
- tokenul trebuie sa includa scope-ul `flow:authorize`;
- resursa trebuie sa fie activa;
- resursa trebuie sa aiba tenant si Gateway;
- Gateway-ul trebuie sa fie conectat pentru provisioning.

## Audit si Evenimente

`pa/audit` scrie evenimente structurate in `audit_log`.
`store/audit.go` mentine hash chain cu `prev_hash` si `entry_hash`, iar store-ul
poate verifica integritatea lantului.

`pa/events` este un broker in-memory CAEP-style. Subiectele sunt folosite pentru
schimbari de sanatate/device-data, resurse, politici, sesiuni, revocari si
alte notificari interne. Broker-ul tine buffer configurabil si numara mesaje
drop-uite per subscription.

Endpoint-uri admin:

- `/api/admin/audit`
- `/api/admin/dashboard`

## PKI si Chei

`pki/` implementeaza:

- `VaultClient` pentru Vault PKI;
- `SignCSR`, `SignCSRVerbatim`, `SignCSRWithOptions`;
- `GetCAPEM`;
- `RevokeCertificate`;
- Vault Transit encrypt/decrypt pentru chei private;
- `RestoreOrCreateNamedKey`;
- self-enrollment PDP;
- loop de reinnoire certificat PDP;
- CA guard care refuza schimbarea necontrolata a CA-ului pentru a nu invalida
  certificatele deja emise pentru Agent/Gateway.

PDP foloseste Vault PKI pentru:

- certificatul TLS propriu;
- certificate device TrustAgent;
- certificate Gateway;
- certificate resursa, unde este cazul.

## HTTP Surface

Categorii HTTP expuse de `pa/transport`:

- public health/config/cert:
  - `/health`
  - `/api/config/public`
  - `/api/ca/cert`
  - `/api/cert-fingerprint`
- browser auth:
  - `/auth/login`
  - `/browser/enroll/`
  - `/browser/session/`
- OIDC:
  - `/auth/authorize`
  - `/auth/token`
  - `/auth/userinfo`
  - `/auth/federated/callback`
  - `/.well-known/openid-configuration`
  - `/.well-known/jwks.json`
- SCIM:
  - `/scim/v2/{tenant_id}/...`
- auth/MFA:
  - `/api/auth/*`
  - `/api/mfa/webauthn/*`
- admin:
  - `/api/admin/users`
  - `/api/admin/tenants`
  - `/api/admin/sessions`
  - `/api/admin/audit`
  - `/api/admin/directory/users`
  - `/api/admin/directory/groups`
  - `/api/admin/enrollments`
  - `/api/admin/resources`
  - `/api/admin/policies`
  - `/api/admin/policy-assignments`
  - `/api/admin/device-data`
  - `/api/admin/dashboard`
  - `/api/admin/gateways`
  - `/api/admin/tenants/idps`
- dashboard SPA:
  - `/dashboard`
  - `/dashboard/`

## gRPC Surface

PDP inregistreaza aceste servicii gRPC peste acelasi listener HTTPS:

- `trustagent.enrollment.EnrollmentService`
- `trustagent.session.AgentSessionService`
- `trustcloud.catalog.DeviceCatalogService`
- `trustagent.device.DeviceDataService`
- `trustcloud.agent.AgentAuthorizationService`
- `gateway.GatewayEnrollmentService`
- `gateway.GatewayTrustService`
- `gateway.GatewayControlService`

Transportul gRPC foloseste struct protobuf generic (`structpb.Struct`) in loc de
fisiere `.proto` generate in repo. Descriptorii sunt definiti manual in
`pa/transport/*_grpc.go`.

## Admin Dashboard

Dashboard-ul este in `pa/dashboard` si se construieste cu Vite.

Rute curente:

- `/dashboard`
- `/dashboard/login`
- `/dashboard/organizations`
- `/dashboard/organizations/:organizationId`
- `/dashboard/organizations/:organizationId/idps/:idpId`
- `/dashboard/resources`
- `/dashboard/resources/:resourceId`
- `/dashboard/policies`
- `/dashboard/gateways`
- `/dashboard/gateways/:gatewayId`
- `/dashboard/protect-app`
- `/dashboard/sessions`
- `/dashboard/device-health`
- `/dashboard/audit`

`/dashboard/tenants` redirecteaza catre `/dashboard/organizations`, deoarece UI
foloseste termenul organizatie pentru modelul `Tenant`.

Dashboard-ul acopera:

- overview si statistici;
- organizatii/tenants si IdP-uri;
- Gateway-uri si detalii Gateway;
- resurse si detalii resursa;
- protect app flow;
- politici si policy assignments;
- sesiuni;
- device health/device data;
- audit.

## Security Properties

Proprietati relevante implementate:

- TLS 1.3 pe server;
- client CA configurata obligatoriu pentru server;
- mTLS pentru identitati Agent/Gateway;
- rate limit pentru enrollment si auth;
- JWT ES256;
- token revocation store;
- lockout dupa failed login attempts;
- agent session token legat de certificatul mTLS;
- scope checks pentru Agent catalog/flow/session revoke;
- zero-trust default deny in PE;
- audit hash chain;
- Vault Transit pentru chei private PDP/JWT;
- Vault PKI CA guard;
- CORS si security headers in transport;
- SCIM bearer token comparat constant-time.

## Compatibilitate si Migrari

- Tabela veche `device_posture` este migrata in `device_data`.
- Campurile `client_id` si `client_secret` de pe `resources` sunt pastrate doar
  pentru baze de date mai vechi; resursele protejate nu mai sunt clienti OIDC.
- `gateway.FederationConfig` este pastrat ca model legacy pentru configuratii
  Gateway mai vechi; fluxul curent foloseste IdP-uri per tenant.
- `/dashboard/tenants` ramane redirect catre `/dashboard/organizations`.

## Validare

Backend PDP:

```powershell
cd pdp
go test ./...
go vet ./...
go run golang.org/x/tools/cmd/deadcode@latest ./...
go mod tidy -diff
```

Dashboard PDP:

```powershell
cd pdp/pa/dashboard
npm run lint
npm run build
```

Gateway trebuie testat separat daca modificarea atinge contractul Gateway sau
testele de control plane:

```powershell
cd gateway
go test ./...
```
