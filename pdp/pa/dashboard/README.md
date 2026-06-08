# TrustCloud Admin Dashboard

`pdp/pa/dashboard` este interfata React/Vite servita de PDP la `/`.
Dashboard-ul este consola administrativa pentru organizatii, IdP-uri, resurse,
Gateway-uri, politici, sesiuni, device health si audit.

## Runtime

- Framework: React + Vite.
- Entrypoint: `src/App.jsx`.
- Build output: `dist/`, copiat in imaginea Docker PDP.
- Autentificare: token administrativ salvat in `localStorage` sub
  `admin_token`.
- Rutele protejate folosesc `PrivateRoute`; fara token, utilizatorul este
  trimis la `/login`.

Comenzi:

```powershell
cd pdp/pa/dashboard
npm run lint
npm run build
```

## Rute

Rutele canonice definite in `src/App.jsx`:

- `/login`: login administrator.
- `/`: overview.
- `/organizations`: lista organizatii.
- `/organizations/:organizationId`: detalii organizatie.
- `/organizations/:organizationId/idps/:idpId`: detalii IdP.
- `/resources`: resurse protejate.
- `/resources/:resourceId`: detalii resursa.
- `/policies`: politici si assignments.
- `/gateways`: Gateway-uri.
- `/gateways/:gatewayId`: detalii Gateway.
- `/protect-app`: flow ghidat pentru protejarea unei aplicatii.
- `/sessions`: sesiuni active.
- `/device-data`: rapoarte device-data/device-health.
- `/audit`: audit log.

Rutele vechi `/dashboard...` sunt pastrate ca redirect catre URL-urile
canonice de la radacina.

## API Client

Clientul HTTP este in `src/api.js`.

Dashboard-ul foloseste endpointurile PDP admin:

- `/api/auth/login`
- `/api/auth/mfa/verify`
- `/api/config/public`
- `/api/admin/users`
- `/api/admin/organizations`
- `/api/admin/organizations/idps`
- `/api/admin/organizations/idps/discover`
- `/api/admin/resources`
- `/api/admin/gateways`
- `/api/admin/policies`
- `/api/admin/policy-assignments`
- `/api/admin/device-data`
- `/api/admin/directory/users`
- `/api/admin/directory/groups`
- `/api/admin/sessions`
- `/api/admin/audit`
- `/api/admin/dashboard`

## Login Admin

Pagina de login foloseste fluxul in doi pasi:

1. `POST /api/auth/login` valideaza parola si intoarce fie token final, fie o
   stare MFA pending.
2. Daca serverul cere MFA, UI-ul trimite codul la `/api/auth/mfa/verify`.

Tokenul administrativ este emis doar dupa satisfacerea politicii MFA pentru
administrator, conform `admin_auth.require_mfa` din config.

## Organizations si IdP

Modulele de organizatii permit:

- creare, listare, editare si stergere organizatii;
- asociere domenii pentru Home Realm Discovery;
- configurare IdP OIDC per organizatie;
- discovery OIDC dupa issuer;
- configurare claim mapping, domenii, grupuri si token SCIM.

Contextul de organizatie este important pentru toate celelalte module: resurse,
Gateway-uri, grupuri directory si politici sunt izolate prin `organization_id`.

## Resources si Gateways

Resursele protejate definesc:

- `host` si `port`: tinta interna accesibila din Gateway;
- `external_url`: FQDN-ul vazut de Agent si introdus in catalog;
- `type`: web/ssh/rdp sau alt tip folosit pentru protocol/port;
- `organization_id`;
- `gateway_id`;
- tags si metadata.

Gateway-urile pot fi create, editate, revocate si pot primi token nou de
enrollment. Detaliile Gateway includ starea de conectare si resursele asociate.

## Policies

Pagina `/policies` este editorul pentru conditional access.

O politica este un `PolicyRule` reutilizabil. Aplicarea pe organizatie, grup,
resursa sau combinatie resursa+grup se face separat prin `PolicyAssignment`.

Tipuri de assignment:

- Global policy: se aplica intregii organizatii.
- User-Group policy: se aplica unui grup de utilizatori.
- Application policy: se aplica unei resurse/aplicatii.
- Application-Group policy: se aplica unui grup care acceseaza o resursa.

UI-ul permite mai multe assignments/politici pe acelasi target. Nu exista
ordonare manuala in Apply Policy. Cand mai multe politici se potrivesc aceleiasi
cereri, PE le evalueaza impreuna, cu prioritatea:

```text
Block access > Require MFA > Skip MFA > Allow access
```

Politicile globale default au ID prefixat cu `policy-global-default-` si
assignment prefixat cu `assignment-global-default-`. Ele sunt create automat per
organizatie, afisate ca system default si nu pot fi sterse sau aplicate manual.

## Policy Editor Sections

Sectiuni active in editor:

- Details: nume, descriere, enabled si lista assignments.
- New User Policy:
  - Require enrollment;
  - Allow access without MFA;
  - Deny access.
- Authentication Policy:
  - Enforce MFA;
  - Bypass MFA;
  - Deny access;
  - metode step-up cand MFA este enforced: authenticator app/TOTP si
    passkey/security key/WebAuthn.
- Risk-Based Authentication:
  - activeaza MFA pentru semnale interne de risc;
  - semnalele sunt new location, unrealistic travel si user baseline anomaly;
  - baseline-ul necesita minim 5 accesuri geolocate reusite pe 3 zile distincte
    in ultimele 30 de zile.
- User Location:
  - reguli pe tari selectate;
  - actiune pentru toate celelalte tari;
  - actiune pentru locatii necunoscute;
  - actiuni: require MFA, skip MFA, allow, block.
- Device Health:
  - required device health checks;
  - buton Select all;
  - status asteptat implicit `good`;
  - daca un check cerut lipseste sau nu are statusul asteptat, PE blocheaza
    accesul.
- Authorized Networks:
  - allow access from these networks;
  - skip MFA from these networks;
  - require MFA from these networks every time;
  - block access from these networks;
  - block access from any other network not specified above.

Editorul de retele accepta IP-uri, CIDR-uri si intervale IP `start-end`.
Valorile sunt adaugate ca token-uri individuale, nu ca text liber cu virgule.

## Device Health

Pagina Device Health afiseaza rapoarte trimise de TrustAgent prin
`trustagent.device.DeviceDataService`. Dashboard-ul foloseste aceste rapoarte si
pentru a popula optiunile de required checks din Policy Editor.

Checks implicite:

- Operating System
- Windows Updates
- Password & Lock
- Disk Encryption
- Firewall
- Antivirus

Check-ul legacy `Connectivity` este ignorat in UI.

## Audit si Sesiuni

Pagina Sessions foloseste `/api/admin/sessions` pentru vizibilitatea sesiunilor
PA. Pagina Audit foloseste `/api/admin/audit`; auditul este generat de backend
si are hash-chain in store.

## Design Notes

- UI-ul este operational, nu landing page.
- Cards sunt folosite pentru elemente repetate, modaluri si formulare incadrate.
- Actiunile destructive folosesc modaluri de confirmare, nu `window.confirm`.
- Apply Policy si Unassign afiseaza contextul organizatiei pentru ca aceeasi
  resursa/grup poate exista in organizatii diferite.
