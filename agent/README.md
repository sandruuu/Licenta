# TrustAgent

`agent/` contine executabilul endpoint-side final: `trust-agent.exe`.
Agentul este Windows-only si este gandit ca un singur binar care se comporta diferit in functie de context:

- pornit de Windows SCM: ruleaza ca serviciu LocalSystem;
- pornit interactiv de user: deschide tray-ul Wails/React;
- instalat prin setup enterprise: copiaza binarul/configul, instaleaza serviciul si configureaza pornirea tray-ului la logon.

Nu mai exista public OIDC client in Tray si nu mai exista flow vechi in care Tray-ul primeste tokenuri.

## Structura

```text
cmd/agent/             Entry point pentru trust-agent.exe
internal/app/          Config loading si dispatch service/gui
internal/shared/ipc/   Named Pipe IPC, framing, contracte, peer identity
internal/service/      Serviciul LocalSystem, enrollment, user session, SCM
internal/tray/         Tray Wails/React si client IPC catre service
packaging/             Setup enterprise, script install-service, build package
../features/           Modul separat pentru capabilitati dormant: DNS/TUN/Gateway/network
```

Nu exista root `main.go`. Binarul se construieste din `cmd/agent/`.

## Functionalitati Curente

Serviciul LocalSystem:

- asculta pe `\\.\pipe\trust-agent`;
- raporteaza starea agentului si a enrollment-ului;
- verifica local daca device-ul este enrolled;
- porneste enrollment interactiv prin PDP gRPC;
- detine cheia privata machine-scope `TrustAgentDeviceKey`;
- genereaza CSR si proof-of-possession;
- instaleaza certificatul de device in `LocalMachine\My`;
- porneste login de user prin PDP gRPC mTLS dupa enrollment;
- revendica sesiunea userului si cere catalogul;
- pastreaza `agent_session_token` in memoria serviciului, per user local;
- sterge sesiunea userului la logout, fara sa stearga enrollment-ul device-ului.

Tray-ul:

- este UI-only;
- vorbeste doar cu serviciul prin named pipe;
- afiseaza starea de enrollment, login si catalog;
- primeste doar `auth_url` pentru browser;
- nu primeste CSR, private key, poll secret, claim secret, certificate PEM sau tokenuri.

Capabilitatile de trafic real, DNS/TUN/Gateway routing si autorizare flow pe pachete sunt tinute separat in `../features` si nu sunt pornite de serviciul curent.

## IPC Security

Pipe-ul local este:

```text
\\.\pipe\trust-agent
```

Pipe-ul are DACL explicit:

- `SYSTEM`: full access;
- `Administrators`: full access;
- `Interactive Users`: read/write.

Pentru operatiile user-bound, serviciul nu accepta un SID trimis de Tray. Identitatea este extrasa din peer-ul named pipe:

- process id;
- Windows user SID;
- Windows logon session id;
- Windows session id.

`StartUserLoginInteractive` si `LogoutUserSession` sunt fail-closed: daca peer identity nu este verificata sau lipsesc SID/logon session/session id, operatia este respinsa.

Operatii IPC curente:

- `Ping`
- `GetStatus`
- `GetDevicePosture`
- `GetDashboard`
- `StartEnrollmentInteractive`
- `StartUserLoginInteractive`
- `LogoutUserSession`

Nu exista operatie IPC care trimite access token, refresh token sau ID token catre Tray.

## Config

`trust-agent.exe` citeste `config.json` de langa binar. Exemplu minim:

```json
{
  "tray_timeout": "10s",
  "dashboard_refresh_interval": "30s",
  "pdp_grpc_endpoint": "pdp.example.com:443",
  "pdp_tls_server_name": "pdp.example.com",
  "pdp_ca_file": "pdp-ca.pem",
  "enrollment_timeout": "10m",
  "enrollment_poll_interval": "3s",
  "login_timeout": "10m",
  "login_poll_interval": "3s"
}
```

Configul nu contine `issuer_url`, client OIDC public, redirect-uri local sau setari de token refresh pentru Tray.

## Instalare

Build si instalare enterprise:

```powershell
.\packaging\build-enterprise-package.ps1
.\build\TrustAgent-Setup.exe
```

Setup-ul cere UAC cand este rulat manual. In deployment enterprise poate fi rulat elevated sau ca `SYSTEM` prin Intune/SCCM/GPO.

Pachetul:

- instaleaza `trust-agent.exe` si `config.json` in `%ProgramFiles%\TrustAgent`;
- instaleaza serviciul Windows `TrustAgent` ca LocalSystem;
- configureaza service recovery;
- porneste serviciul;
- adauga HKLM Run pentru pornirea tray-ului la logon.

## Flux Enrollment Device

Stare initiala:

1. Agentul este instalat, dar device-ul nu este enrolled.
2. Serviciul verifica local:
   - exista cheia `TrustAgentDeviceKey`;
   - exista certificat device in `LocalMachine\My`;
   - certificatul este valid;
   - certificatul este asociat cu cheia privata locala.
3. Daca verificarea nu trece, serviciul raporteaza `UNENROLLED` catre Tray.

Pornire enrollment:

1. Userul apasa `Inroleaza`.
2. Tray trimite `StartEnrollmentInteractive` catre serviciu.
3. Serviciul creeaza/deschide cheia machine-scope `TrustAgentDeviceKey`.
4. Serviciul genereaza CSR-ul si calculeaza:
   - `csr_sha256`;
   - `spki_sha256`;
   - `device_nonce`.
5. Serviciul apeleaza PDP prin gRPC:
   - service: `trustagent.enrollment.EnrollmentService`;
   - method: `StartSession`.
6. PDP creeaza `EnrollmentTransaction` cu status `WAITING_FOR_IDP_DISCOVERY`.
7. PDP salveaza hash-urile CSR/SPKI, `device_nonce`, `device_challenge`, hash pentru `poll_secret`, TTL si status.
8. PDP returneaza catre serviciu:
   - `enrollment_session_id`;
   - `auth_url`;
   - `device_challenge`;
   - `poll_secret`;
   - `expires_at`;
   - `poll_interval_seconds`.
9. Serviciul pastreaza secretele si trimite catre Tray doar `auth_url`.
10. Tray deschide browserul catre URL-ul HTTPS.

Browser si IdP:

1. Browserul ajunge la `https://pdp.example.com/browser/enroll/{enrollment_session_id}`.
2. PDP afiseaza Home Realm Discovery.
3. Userul introduce emailul organizational.
4. PDP rezolva domeniul catre `auth_realm_id` si `idp_profile_id`.
5. Tranzactia este blocata pe acel IdP; IdP-ul nu mai poate fi schimbat pentru aceeasi sesiune.
6. PDP genereaza `state`, `nonce` si PKCE pentru relatia PDP -> IdP.
7. `state` este secret random separat, nu `enrollment_session_id`.
8. Browserul este redirectat la IdP.
9. Userul face login/MFA.
10. IdP face callback la PDP.
11. PDP face code exchange server-side si valideaza ID token-ul.
12. PDP marcheaza sesiunea `READY_FOR_DEVICE_PROOF`.

Finalizare:

1. Serviciul face polling prin gRPC `SessionStatus` cu `enrollment_session_id`, `device_nonce` si `poll_secret`.
2. Cand statusul este `READY_FOR_DEVICE_PROOF`, serviciul trimite prin gRPC `CompleteSession`:
   - CSR complet;
   - `device_nonce`;
   - `poll_secret`;
   - proof-of-possession semnat cu `TrustAgentDeviceKey`.
3. PDP verifica:
   - sesiunea exista si nu a expirat;
   - statusul este corect;
   - sesiunea nu a fost consumata;
   - `device_nonce`, `poll_secret`, `device_challenge`;
   - `csr_sha256` si `spki_sha256`;
   - semnatura PoP;
   - cheia publica din CSR.
4. PDP stabileste `device_id` final.
5. PDP emite certificatul device prin CA/Vault PKI.
6. PDP ignora identitatea din CSR si suprascrie identitatea certificatului cu `device_id` decis de PDP.
7. PDP valideaza ca certificatul emis contine acelasi `device_id`; altfel enrollment-ul esueaza.
8. Serviciul instaleaza certificatul in `LocalMachine\My` si il asociaza cu cheia privata.
9. Serviciul persista:
   - `enrollment_state = ENROLLED`;
   - `device_id`;
   - `device_key_name`;
   - `device_cert_thumbprint`;
   - `certificate_expiry`;
   - `pdp_endpoint`;
   - `gateway_endpoints`;
   - `enrolled_by_idp_profile_id`.
10. Tray primeste doar update de stare.

## Flux Login User

Acest flux ruleaza doar dupa ce device-ul este enrolled.

Pornire login:

1. Tray afiseaza `Dispozitiv inrolat` si butonul `Autentifica-te`.
2. Userul apasa `Autentifica-te`.
3. Tray trimite `StartUserLoginInteractive` catre serviciu.
4. Serviciul determina identitatea userului local din peer-ul named pipe.
5. Serviciul construieste cheia locala de sesiune din:
   - `device_id`;
   - Windows user SID;
   - Windows logon session id;
   - Windows session id.
6. Serviciul apeleaza PDP prin gRPC mTLS:
   - service: `trustagent.session.AgentSessionService`;
   - method: `StartSession`.
7. Requestul include device context, posture revision si local user context hash-uit.
8. PDP nu are incredere in `device_id` din request; identitatea device-ului vine din certificatul mTLS.
9. PDP creeaza `AgentSessionTransaction` cu status `WAITING_FOR_USER_LOGIN`.
10. PDP returneaza `auth_url`, `claim_secret`, TTL si poll interval.
11. Serviciul pastreaza `claim_secret`; Tray primeste doar `auth_url`.

Browser si IdP:

1. Tray deschide browserul catre `https://pdp.example.com/browser/session/{session_request_id}`.
2. PDP stie tenant/auth realm-ul din certificatul device si din enrollment.
3. User login nu poate schimba tenantul/contextul device-ului.
4. PDP alege IdP-ul configurat sau face discovery limitat la contextul device-ului.
5. PDP genereaza `state`, `nonce` si PKCE pentru PDP -> IdP.
6. Browserul este redirectat la IdP.
7. Userul face login/MFA.
8. IdP face callback la PDP.
9. PDP valideaza tokenurile OIDC si ruleaza policy user + device + posture.
10. Daca policy permite, statusul devine `READY_TO_CLAIM`.

Claim si catalog:

1. Serviciul face polling prin gRPC `SessionStatus` cu `session_request_id` si `claim_secret`.
2. Cand statusul este `READY_TO_CLAIM`, serviciul apeleaza `ClaimSession`.
3. PDP verifica:
   - sesiunea exista si nu a expirat;
   - statusul este `READY_TO_CLAIM`;
   - `claim_secret`;
   - certificatul mTLS este acelasi cu cel de la StartSession;
   - local user SID hash, logon session si Windows session se potrivesc;
   - sesiunea nu a fost consumata.
4. PDP emite `agent_session_token`.
5. Tokenul este intern TrustAgent, nu token IdP.
6. Tokenul are:
   - audience `ztna-agent-api`;
   - purpose `ztna.agent_session`;
   - scope-uri precum `catalog:read`, `flow:authorize`, `session:revoke`;
   - binding la certificatul device prin `cnf.x5t#S256`.
7. Serviciul cere catalogul prin gRPC mTLS + `agent_session_token`.
8. PDP verifica tokenul, scope-ul `catalog:read` si binding-ul certificatului.
9. Serviciul salveaza catalogul per sesiune locala.
10. Tray afiseaza userul autentificat si resursele.

Logout:

1. Tray trimite `LogoutUserSession`.
2. Serviciul determina userul local din peer identity.
3. Serviciul revoca doar sesiunea acelui user prin gRPC mTLS + `agent_session_token`.
4. PDP verifica scope-ul `session:revoke` si binding-ul certificatului.
5. Serviciul sterge tokenul din memorie si cache-ul catalogului pentru user.
6. Enrollment-ul device-ului ramane intact.

## Securitate Aplicata

Remedieri curente:

- Named pipe cu DACL explicit, nu pipe deschis implicit.
- User-session IPC fail-closed pe peer identity.
- Enrollment OIDC `state` random separat de `enrollment_session_id`.
- PDP valideaza OIDC discovery issuer.
- PDP valideaza ID token cu JWKS, `iss`, `aud`, `exp`, `nonce` si `azp` cand exista mai multe audiences.
- PDP accepta doar algoritmi asimetrici OIDC expliciti: RS*, PS*, ES*.
- Enrollment gRPC StartSession este rate-limited per peer IP.
- PDP nu are incredere in Subject/CN/SAN din CSR pentru certificatul device.
- PDP verifica dupa emitere ca certificatul contine `device_id` decis de PDP.
- `agent_session_token` este sender-constrained prin `cnf.x5t#S256`.
- Catalog, flow authorization si session revoke cer scope explicit.
- PDP cere `local_user.sid_hash`, `windows_logon_session_id` si `windows_session_id` atat la StartSession, cat si la ClaimSession.

## Verificare Locala

Teste Go:

```powershell
cd agent
go test ./...

cd ..\pdp
go test ./...
```

Smoke-ul end-to-end trebuie sa dovedeasca:

- enrollment start;
- browser HRD + IdP login;
- `READY_FOR_DEVICE_PROOF`;
- certificate issue si instalare;
- user session start peste mTLS;
- browser login;
- `READY_TO_CLAIM`;
- `agent_session_token`;
- catalog request peste mTLS + token bound la certificat.

