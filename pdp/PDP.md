# TrustCloud PDP Documentation

`pdp/` este componenta TrustCloud care implementeaza Policy Decision Point-ul.
Procesul ruleaza ca o singura aplicatie Go, dar codul pastreaza doua limite
interne clare:

- PA, Policy Administrator: orchestreaza fluxuri, sesiuni, identitati,
  certificate, Gateway-uri, resurse, audit si transport.
- PE, Policy Engine: evalueaza determinist contextul de acces si returneaza
  `allow`, `deny` sau `step_up_required`.

Documentul acesta este documentatia canonica pentru implementarea existenta din
`pdp/`.

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
  models/               modele API, auth, audit, organization, resource, policy, device
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
- JWT: auth token expiry, enrollment token TTL, Vault Transit key pentru cheia JWT;
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
- `organizations`
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

Store-ul este impartit pe fisiere pe domenii: `users.go`, `organizations.go`,
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

- `Organization`: organizatie izolata, domenii HRD, IdP implicit.
- `IdentityProviderConfig`: IdP OIDC per organization, domenii, discovery, claim
  mapping, group-role mapping si token SCIM.
- `User`: utilizator local sau federat, rol, organization, MFA methods, sursa auth.
- `DirectoryUser`, `DirectoryGroup`: obiecte provisionate prin SCIM.
- `Resource`: resursa protejata, host intern, port, `external_url`, organization,
  Gateway, cert metadata, tag-uri, metadata.
- `Gateway`: Gateway inscris, organization, certificat mTLS, token enrollment,
  endpoint public/listen, resurse asignate, federation config legacy.
- `PolicyRule`: regula reutilizabila de conditional access, cu sectiuni de
  conditii, actiune si metadate de aplicare.
- `PolicyAssignment`: atasare regula la nivel `organization`, `group`,
  `resource` sau `resource_group`.
- `Session`: sesiune autorizata PA, user, device, resursa, Gateway, protocol,
  risc, organization, expirare si revocare.
- `DeviceEnrollment`: stare enrollment device, CSR/certificat, user si organization.
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
determinista. PA valideaza tokenuri, incarca user/organization/grupuri/resurse,
incarca device-data, calculeaza context geo, creeaza sesiuni, provision-eaza
Gateway-ul, publica evenimente si scrie audit.

## Policy Engine

PE este in `pe/evaluation` si `pe/risk`.

Inputul PE este `evaluation.AccessContext`, care contine:

- `models.AccessRequest`
- reguli deja incarcate de PA/store
- context MFA/step-up deja satisfacut, prin `models.AuthContext`
- rol si email user
- identitate directory si grupuri
- failed login attempts
- starea MFA a utilizatorului
- tara/cod tara si daca locatia IP este cunoscuta
- timpul curent
- geo velocity, new location, impossible travel si baseline anomaly

`Engine.Evaluate`:

1. calculeaza scorul de risc prin `pe/risk.CalculateRiskScore`;
2. construieste semnalele de acces observate, de exemplu `new_location`,
   `impossible_travel` si `sensitive_protocol`;
3. parcurge toate regulile active furnizate de PA/store;
4. ignora regulile care nu se potrivesc contextului cererii;
5. combina efectele tuturor regulilor care se potrivesc;
6. returneaza `deny` fail-closed daca nicio regula nu se potriveste.

Modelul curent este similar Microsoft Entra Conditional Access: mai multe
politici pot fi aplicate aceluiasi target, iar PE nu foloseste ordinea ca
mecanism principal de override. Ordinea din store ramane utila doar pentru
determinism si pentru alegerea unei reguli reprezentative in `matched_rule`.
Decizia finala respecta prioritatea:

```text
Block/Deny > Require MFA/step_up_required > Skip MFA > Allow
```

`Skip MFA` este tratat ca un efect de permitere fara step-up doar daca nicio
alta politica potrivita nu cere MFA si nicio politica potrivita nu blocheaza.
Daca o politica globala cere MFA si o politica de aplicatie incearca bypass,
rezultatul final ramane `step_up_required`.

Politicile sunt atasate prin `PolicyAssignment` pe patru niveluri:

- `organization`: global pentru organizatie;
- `group`: pentru un grup de utilizatori, indiferent de aplicatie;
- `resource`: pentru o aplicatie/resursa, indiferent de grup;
- `resource_group`: pentru un grup care acceseaza o resursa specifica.

Se pot aplica mai multe politici pe acelasi nivel/target. UI-ul nu mai expune
ordonare manuala pentru assignments.

Pentru fiecare organizatie, store-ul creeaza automat o politica globala default:

- ID: `policy-global-default-{organization_id}`;
- assignment: `assignment-global-default-{organization_id}`;
- scope: `organization`;
- New User Policy: `require_enrollment`;
- Authentication Policy: `enforce_mfa`;
- metode step-up: `totp`, `webauthn`.

Politica globala default este creata la initializarea store-ului si la crearea
unei organizatii noi. Ea nu poate fi stearsa si nu poate fi asignata manual.

Sectiunile de politica implementate in model/UI:

- Details: nume, descriere, enabled si assignments curente.
- New User Policy:
  - `require_enrollment`;
  - `allow_without_mfa`;
  - `deny`.
- Authentication Policy:
  - `enforce_mfa`;
  - `bypass_mfa`;
  - `deny`;
  - metode step-up disponibile cand MFA este cerut: TOTP si WebAuthn/passkey.
- Risk-Based Authentication:
  - cand este activata, cere MFA pentru semnale interne de risc:
    `new_location`, `unrealistic_travel`/`impossible_travel` si
    `user_baseline_anomaly`;
  - baseline-ul utilizatorului necesita istoric suficient de accesuri
    geolocate, calculat in componenta geo/policies.
- User Location:
  - reguli pe tari selectate;
  - actiune pentru toate celelalte tari;
  - actiune pentru locatii necunoscute;
  - actiuni posibile: allow, require MFA, skip MFA, block.
- Authorized Networks:
  - allow access from these networks;
  - skip MFA from these networks;
  - require MFA from these networks every time;
  - block access from these networks;
  - block access from any other network not specified above;
  - valorile acceptate sunt IP, CIDR si intervale IP `start-end`.
- Device Health:
  - required checks;
  - expected status, implicit `good`;
  - daca politica se potriveste si un required check lipseste sau nu are
    statusul asteptat, PE returneaza `deny`.

Conditiile suplimentare suportate in model/engine, chiar daca nu toate au UI
dedicat in editorul curent:

- roluri, useri si grupuri permise;
- ferestre de timp, zile permise, blocked dates, date range si timezone;
- resurse tinta si porturi tinta;
- process identity obligatoriu;
- procese permise/blocate dupa nume;
- hash-uri de proces permise/blocate;
- risk score minim/maxim, niveluri de risc si semnale de risc;
- session controls: max age, revalidate interval, revoke on posture change si
  revoke on risk increase.

Cand mai multe politici potrivite definesc session controls, PE combina
valorile restrictiv: cea mai mica durata nenula pentru expirare/revalidare si
OR logic pentru revocari.

Risk score-ul include device health/data staleness, scor health, check-uri
critice, failed login attempts, business hours, new device, new location,
protocol, impossible travel, geo velocity, user baseline anomaly si anomaly
score.

## Autentificare, OIDC si MFA

`pa/auth` implementeaza:

- user manager cu register, authenticate, lockout, role update;
- TOTP RFC 6238;
- JWT ES256 pentru auth token, enrollment token si agent session
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
- `/api/auth/mfa/verify`
- `/api/auth/register`
- `/api/auth/revoke-token`
- `/browser/step-up/{challenge_id}`
- `/api/step-up/webauthn/begin`
- `/api/step-up/webauthn/finish`
- `/api/step-up/webauthn/register/begin`
- `/api/step-up/webauthn/register/finish`
- `/auth/authorize`
- `/auth/token`
- `/auth/userinfo`
- `/auth/federated/callback`
- `/.well-known/openid-configuration`
- `/.well-known/jwks.json`

## Organizations, HRD si SCIM

Izolarea este modelata prin `Organization`, `IdentityProviderConfig`,
`organization_id` pe entitati si prin paginile de organizatii din dashboard.

Home Realm Discovery este in `pa/transport/oidc_hrd.go`. Rezolutia IdP-ului
urmeaza aceasta ordine:

1. `idp_id` explicit;
2. domeniu din `login_hint`;
3. `organization_id` explicit;
4. context organization derivat din Gateway client legacy;
5. fallback single-organization.

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
- `trustagent.events.AgentEventsService/Watch`, ca stream separat pentru
  invalidari de catalog si revocari relevante pentru sesiunea Agent.

PDP creeaza o tranzactie de autentificare browser, mediaza OIDC/IdP, apoi la
claim emite `agent_session_token`. Tokenul este legat de certificatul mTLS al
device-ului prin thumbprint si include scope-uri precum:

- `catalog:read`
- `flow:authorize`
- `session:revoke`
- `events:read`

Catalogul este construit in `pa/catalog` si contine:

- `version`
- `resources`
- `ttl_seconds`
- `policy_epoch`
- `device_data_policy`

Resursele din catalog sunt filtrate pe organization, user, grupuri si politici.
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
- validare organization si Gateway;
- generare credentiale per-app ramase compatibile cu baze vechi;
- metadata, tags, certificate fields;
- emitere evenimente CAEP-style pentru resurse actualizate.

`Resource` foloseste:

- `host` si `port` pentru target intern Gateway;
- `external_url` pentru FQDN-ul vazut de Agent;
- `organization_id` pentru izolare;
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
- validare organization si resurse asignate;
- registry de conexiuni control plane;
- comenzi `provision_session`, `revoke_session`, `heartbeat`.

Servicii gRPC:

- `gateway.GatewayEnrollmentService/Enroll`
- `gateway.GatewayEnrollmentService/RenewCertificate`
- `gateway.GatewayTrustService/GetCACertificate`
- `gateway.GatewayTrustService/GetRevokedSerials`
- `gateway.GatewayTrustService/RevalidateSessions`
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

Daca PE returneaza `step_up_required`, PA creeaza un `StepUpChallenge` cu TTL,
metode permise si URL browser. In acest caz PA nu creeaza sesiune de resursa si
nu provisioneaza Gateway-ul. Agentul primeste decizia impreuna cu URL-ul de
step-up, afiseaza/deschide browserul pentru utilizator, iar dupa finalizarea
MFA trimite o noua cerere de autorizare pentru aceeasi resursa. PE vede atunci
contextul MFA satisfacut prin `AuthContext` si poate returna `allow`.

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
- resursa trebuie sa aiba organization si Gateway;
- Gateway-ul trebuie sa fie conectat pentru provisioning.
- daca decizia este `step_up_required`, raspunsul include `step_up_url`,
  `step_up_challenge_id`, metodele permise si ACR-ul cerut.

## Audit si Evenimente

`pa/audit` scrie evenimente structurate in `audit_log`.
`store/audit.go` mentine hash chain cu `prev_hash` si `entry_hash`, iar store-ul
poate verifica integritatea lantului.

`pa/events` este un broker in-memory CAEP-style. Subiectele sunt folosite pentru
schimbari de sanatate/device-data, resurse, politici, sesiuni, revocari si
alte notificari interne. Broker-ul tine buffer configurabil si numara mesaje
drop-uite per subscription.

Agentul consuma evenimente relevante prin
`trustagent.events.AgentEventsService/Watch`. Stream-ul este filtrat pe
identitatea din `agent_session_token` si pe certificatul mTLS device. Evenimente
transmise catre Agent:

- `access.revoked`, pentru sesiuni sterse, device revocat sau acces revocat;
- `catalog.invalidated`, pentru schimbari de resurse, politici sau Gateway-uri.

Agentul reactioneaza fie prin revocarea sesiunii locale, fie prin refresh de
catalog. Broker-ul este in-memory; pentru productie multi-instanta ar fi nevoie
de un broker persistent/distribuit.

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
  - `/browser/step-up/`
- OIDC:
  - `/auth/authorize`
  - `/auth/token`
  - `/auth/userinfo`
  - `/auth/federated/callback`
  - `/.well-known/openid-configuration`
  - `/.well-known/jwks.json`
- SCIM:
  - `/scim/v2/{organization_id}/...`
- auth:
  - `/api/auth/*`
- resource step-up MFA:
  - `/api/step-up/webauthn/*`
- admin:
  - `/api/admin/users`
  - `/api/admin/organizations`
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
  - `/api/admin/organizations/idps/discover`
  - `/api/admin/organizations/idps`
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
- `trustagent.events.AgentEventsService`
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

Dashboard-ul acopera:

- overview si statistici;
- organizatii si IdP-uri;
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
  Gateway mai vechi; fluxul curent foloseste IdP-uri per organization.

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
