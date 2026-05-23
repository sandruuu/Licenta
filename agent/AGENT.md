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
internal/app/          Config loading si dispatch service/tray
internal/shared/ipc/   Named Pipe IPC, framing, contracte, peer identity
internal/service/      Serviciul LocalSystem si orchestrarea modulelor privilegiate
internal/tray/         Tray Wails/React si client IPC catre service
packaging/             Setup enterprise, script install-service, build package
wfp-driver/            Driver KMDF pentru redirectionare WFP connect
```

Nu exista root `main.go`. Binarul se construieste din `cmd/agent/`.

## Harta Implementarii

Entry point:

- `cmd/agent/main.go`: porneste aplicatia prin `internal/app`.
- `internal/app/run.go`: decide daca procesul ruleaza ca serviciu Windows sau ca tray interactiv.
- `internal/app/config.go`: incarca `config.json` si normalizeaza duratele/configul.

Service:

- `internal/service/runtime.go`: porneste listener-ul IPC si device-data sync runner-ul.
- `internal/service/service.go`: defineste configuratia, dependintele si starea serviciului.
- `internal/service/constructor.go`: construieste enrollment manager, user-session manager, protected resources si device-data sync runner-ul.
- `internal/service/ipc_handlers.go`: implementeaza operatiile IPC expuse catre Tray.
- `internal/service/dashboard.go`: compune dashboard-ul livrat catre Tray.
- `internal/service/state.go`: tranzitii de stare pentru serviciu.
- `internal/service/process_identity.go`: identitatea procesului care ruleaza serviciul.
- `internal/service/host/*`: rulare ca serviciu Windows SCM sau ca proces console.
- `internal/service/device-data/collector_windows.go`: colecteaza cele 6 controale device-data pe Windows.
- `internal/service/device-data/watcher_windows.go`: asculta evenimente Windows si declanseaza recoltare imediata de device-data.
- `internal/service/device-data-sync/runner.go`: decide cand trimite raportul catre PDP: dupa enrollment, la eveniment, la schimbare detectata sau periodic.
- `internal/service/device-data-sync/grpc.go`: trimite `DeviceDataReport` catre PDP prin gRPC mTLS.
- `internal/service/dns-resolver/*`: resolver DNS local UDP/TCP pentru resursele din catalog.
- `internal/service/dns-control/*`: instalare/curatare reguli NRPT pentru FQDN-urile resurselor din catalog.
- `internal/service/traffic-interception/*`: proxy local TCP si managerul regulilor de interceptare pentru IP-urile sintetice.
- `internal/service/wfp-control/*`: clientul user-mode care trimite regulile catre driverul WFP prin IOCTL.
- `internal/service/flow-authorization/*`: client gRPC/mTLS catre PDP pentru decizia per flow si sesiunea provisionata de Gateway.
- `internal/service/gateway-tunnel/*`: client mTLS + yamux catre Gateway, cu handshake `hello` si stream-uri `connect`.
- `internal/service/protected-resources/*`: orchestreaza catalog -> resolver DNS local -> WFP -> NRPT.
- `internal/service/enrollment/*`: enrollment device, cheie privata, CSR, certificate store, client gRPC.
- `internal/service/usersession/*`: login user, claim session, catalog, logout.
- `wfp-driver/*`: contractul IOCTL si driverul KMDF pentru `trustagent_wfp.sys`.

Tray:

- `internal/tray/tray.go`: porneste UI-ul Wails si clientul IPC.
- `internal/tray/client.go`: client named pipe catre service.
- `internal/tray/frontend/src/components/AppLayout.jsx`: ecran enrollment, login, sidebar, resources, logout.
- `internal/tray/frontend/dist/`: build-ul frontend livrat cu binarul.

Contracte comune:

- `internal/shared/ipc/protocol.go`: operatii IPC.
- `internal/shared/ipc/*_contracts.go`: payload-uri pentru status, dashboard, enrollment, user session, catalog si device-data.

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
- foloseste un singur client PDP gRPC mTLS partajat dupa enrollment pentru login user, device-data sync si autorizare per flow;
- revendica sesiunea userului si cere catalogul;
- aplica catalogul in resolverul DNS local si instaleaza reguli NRPT inainte sa marcheze userul ca autentificat;
- returneaza IP-uri sintetice din `100.64.0.0/10` pentru FQDN-urile resurselor protejate;
- poate prealoca mapping-urile IP sintetic -> resursa si instala reguli WFP pentru redirectarea conexiunilor catre proxy-ul local;
- are clientul de autorizare per flow catre PDP si clientul de tunnel mTLS/yamux catre Gateway;
- pastreaza `agent_session_token` in memoria serviciului, per user local;
- sterge sesiunea userului la logout, curata regulile NRPT si nu sterge enrollment-ul device-ului.
- colecteaza device-data pentru 6 controale Windows;
- trimite device-data la PDP prin gRPC mTLS imediat dupa enrollment, la evenimente relevante, la schimbare detectata si periodic;
- pastreaza in cache ultimul device-data report pentru dashboard si pentru device data revision in login.

Tray-ul:

- este UI-only;
- vorbeste doar cu serviciul prin named pipe;
- afiseaza starea de enrollment, login si catalog;
- primeste doar `auth_url` pentru browser;
- nu primeste CSR, private key, poll secret, claim secret, certificate PEM sau tokenuri.

Proxy-ul local este legat de autorizarea per flow si de tunnel-ul Gateway prin `resourceStreamConnector`: pentru fiecare conexiune redirectionata de WFP, service-ul identifica resursa din catalog, cere decizia PDP prin `flow-authorization`, iar pentru decizia `allow` deschide un stream mTLS/yamux catre Gateway folosind materialul de sesiune provisionat de PDP.

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
- `GetDashboard`
- `StartEnrollmentInteractive`
- `StartUserLoginInteractive`
- `LogoutUserSession`

Nu exista operatie IPC care trimite access token, refresh token sau ID token catre Tray.
Device-data si catalogul sunt incluse in dashboard doar dupa autentificarea userului.

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
  "login_poll_interval": "3s",
  "device_data_sync_interval": "30m",
  "device_data_sync_change_scan_interval": "30s",
  "local_dns_listen_address": "127.0.0.1:53",
  "local_dns_server": "127.0.0.1",
  "synthetic_ip_cidr": "100.64.0.0/10",
  "harden_browser_doh": false,
  "traffic_interception_enabled": false,
  "traffic_proxy_listen_address": "127.0.0.1:18787",
  "wfp_driver_device_path": "\\\\.\\TrustAgentWfp",
  "wfp_fail_closed": true
}
```

Configul nu contine `issuer_url`, client OIDC public, redirect-uri local sau setari de token refresh pentru Tray.

Campuri relevante:

- `pdp_grpc_endpoint`: endpoint-ul gRPC al PDP.
- `pdp_tls_server_name`: SNI/numele asteptat in certificatul TLS al PDP.
- `pdp_ca_file`: CA-ul folosit pentru validarea PDP.
- `enrollment_timeout`: limita maxima pentru flow-ul interactiv de enrollment.
- `enrollment_poll_interval`: intervalul de polling catre PDP in timpul enrollment-ului.
- `login_timeout`: limita maxima pentru flow-ul interactiv de user login.
- `login_poll_interval`: intervalul de polling catre PDP in timpul login-ului.
- `device_data_sync_interval`: sync-ul periodic pentru device-data; default 30 minute.
- `device_data_sync_change_scan_interval`: scan fallback pentru detectarea schimbarilor; default 30 secunde. Evenimentele Windows pot declansa raportare mai devreme.
- `local_dns_listen_address`: adresa pe care asculta resolverul DNS local al agentului; default `127.0.0.1:53`.
- `local_dns_server`: IP-ul scris in regulile NRPT; default se deriveaza din `local_dns_listen_address`, de obicei `127.0.0.1`.
- `synthetic_ip_cidr`: pool-ul pentru IP-uri sintetice returnate de resolver; default `100.64.0.0/10`.
- `harden_browser_doh`: cand este `true`, serviciul seteaza politici HKLM pentru dezactivarea DoH in Chrome, Edge si Firefox.
- `traffic_interception_enabled`: activeaza instalarea regulilor WFP pentru IP-urile sintetice. Implicit `false`, pana cand `trustagent_wfp.sys` este disponibil.
- `traffic_proxy_listen_address`: adresa proxy-ului TCP local catre care driverul redirectioneaza conexiunile; default `127.0.0.1:18787`.
- `wfp_driver_device_path`: device object user-mode al driverului; default `\\.\TrustAgentWfp`.
- `wfp_fail_closed`: cand este `true`, o eroare la aplicarea regulilor WFP blocheaza aplicarea catalogului si implicit autentificarea locala.

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
3. Serviciul verifica daca exista deja o inrolare locala valida. Daca device-ul este deja enrolled, nu porneste o noua sesiune si nu roteste cheia.
4. Serviciul creeaza/deschide cheia machine-scope `TrustAgentDeviceKey`.
   - cheia este ECDSA P-256;
   - se foloseste `Microsoft Platform Crypto Provider` cand acesta este disponibil;
   - fallback-ul `Microsoft Software Key Storage Provider` este acceptat doar daca Platform Crypto Provider nu poate fi deschis;
   - daca Platform Crypto Provider exista, erorile de creare/deschidere pe platform provider nu sunt mascate prin fallback software.
5. Serviciul genereaza CSR-ul si calculeaza:
   - `csr_sha256`;
   - `spki_sha256`;
   - `device_nonce`.
6. Serviciul apeleaza PDP prin gRPC:
   - service: `trustagent.enrollment.EnrollmentService`;
   - method: `StartSession`.
7. PDP creeaza `EnrollmentTransaction` cu status `WAITING_FOR_IDP_DISCOVERY`.
8. PDP salveaza hash-urile CSR/SPKI, `device_nonce`, `device_challenge`, hash pentru `poll_secret`, TTL si status.
9. PDP returneaza catre serviciu:
   - `enrollment_session_id`;
   - `auth_url`;
   - `device_challenge`;
   - `poll_secret`;
   - `expires_at`;
   - `poll_interval_seconds`.
10. Serviciul pastreaza secretele si trimite catre Tray doar `auth_url`.
11. Tray deschide browserul catre URL-ul HTTPS.

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
   - proof-of-possession ES256 semnat cu `TrustAgentDeviceKey`.
3. PDP verifica:
   - sesiunea exista si nu a expirat;
   - statusul este corect;
   - sesiunea nu a fost consumata;
   - `device_nonce`, `poll_secret`, `device_challenge`;
   - `csr_sha256` si `spki_sha256`;
   - semnatura PoP;
   - cheia publica din CSR;
   - CSR-ul/proof-ul folosesc ECDSA P-256.
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

Imediat dupa ce enrollment-ul este salvat, service-ul declanseaza device-data sync. Raportarea se face peste gRPC mTLS folosind certificatul de device nou instalat.

Enrollment-ul foloseste un client gRPC separat, deoarece ruleaza inainte ca device-ul sa aiba certificat. Dupa enrollment, serviciul creeaza un client PDP gRPC mTLS partajat, legat de `device_id` si thumbprint-ul certificatului curent. Acelasi `ClientConn` este refolosit de user session, device-data sync si flow authorization; daca certificatul se schimba, conexiunea partajata este recreata.

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
7. Requestul include device context, device data revision si local user context hash-uit.
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
9. PDP valideaza tokenurile OIDC si ruleaza policy user + device + device-data.
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
   - audience `trustagent-api`;
   - purpose `trustagent.session`;
   - scope-uri precum `catalog:read`, `flow:authorize`, `session:revoke`;
   - binding la certificatul device prin `cnf.x5t#S256`.
7. Serviciul cere catalogul prin gRPC mTLS + `agent_session_token`.
8. PDP verifica tokenul, scope-ul `catalog:read` si binding-ul certificatului.
9. Serviciul aplica catalogul in `protected-resources`:
   - incarca resursele in resolverul DNS local;
   - daca interceptarea este activata, prealoca IP-urile sintetice si instaleaza regulile WFP inainte de NRPT;
   - instaleaza reguli NRPT doar pentru FQDN-urile exacte ale resurselor primite in catalog;
   - directioneaza aceste FQDN-uri protejate catre `local_dns_server`;
   - blocheaza finalizarea autentificarii locale daca aplicarea catalogului esueaza.
10. Serviciul salveaza catalogul per sesiune locala.
11. Tray afiseaza userul autentificat si resursele.

Logout:

1. Tray trimite `LogoutUserSession`.
2. Serviciul determina userul local din peer identity.
3. Serviciul revoca doar sesiunea acelui user prin gRPC mTLS + `agent_session_token`.
4. PDP verifica scope-ul `session:revoke` si binding-ul certificatului.
5. Serviciul sterge tokenul din memorie si cache-ul catalogului pentru user.
6. Serviciul curata regulile NRPT `TRUSTAGENT-*` si goleste resolverul local.
7. Enrollment-ul device-ului ramane intact.

## Catalog, NRPT si DNS Local

Aceste functii ruleaza in serviciul LocalSystem, nu in Tray.

Componente:

- `dns-resolver`: tine catalogul curent, aloca IP-uri sintetice si raspunde la query-uri DNS A/AAAA.
- `dns-control`: instaleaza regulile NRPT prin cmdlet-urile Windows DNS Client si curata cheile registry legacy `TRUSTAGENT-*`.
- `traffic-interception`: porneste proxy-ul TCP local si tine tabela `synthetic_ip:port -> resource_id`.
- `wfp-control`: trimite catre driver regulile de redirect pentru `ALE_CONNECT_REDIRECT_V4` si citeste contextul WFP al conexiunii acceptate de proxy.
- `protected-resources`: porneste resolverul local, primeste catalogul autentificat si sincronizeaza resolverul + WFP + NRPT.

Flux dupa autentificare:

1. Userul finalizeaza login-ul in browser.
2. Serviciul revendica sesiunea prin `ClaimSession`.
3. Serviciul cere catalogul prin `GetCatalog`.
4. Catalogul contine:
   - `version`;
   - `resources`;
   - `ttl_seconds`;
   - `policy_epoch`.
5. `protected-resources` aplica intai catalogul in resolver.
6. Daca `traffic_interception_enabled=true`, resolverul prealoca IP-urile sintetice pentru fiecare resursa.
7. Service-ul trimite catre WFP lista de reguli `synthetic_ip, port, protocol -> proxy local`.
8. Apoi instaleaza regulile NRPT pentru fiecare FQDN exact din `resources`.
9. Daca lista `resources` este goala, agentul nu instaleaza nicio regula NRPT si nicio regula WFP.
10. Abia dupa ce pasii de mai sus reusesc, user-session devine `AUTHENTICATED`.

Resolverul DNS local:

- asculta implicit pe `127.0.0.1:53`, UDP si TCP;
- raspunde doar pentru FQDN-uri prezente explicit in catalog;
- pentru query A valid returneaza un IP sintetic din `100.64.0.0/10`;
- pentru FQDN-uri necunoscute returneaza `NXDOMAIN`;
- pentru AAAA raspunde fara adrese, ca sa nu expuna rute IPv6 neimplementate;
- prelungeste TTL-ul mapping-ului la fiecare acces;
- sterge mapping-urile expirate sau resursele scoase din catalog.

NRPT:

- creeaza reguli cu `Add-DnsClientNrptRule` si `DisplayName` prefixat cu `TRUSTAGENT-`;
- foloseste namespace-ul exact al resursei, de exemplu `crm.internal.example`, nu suffix `.crm.internal.example`;
- seteaza `NameServers = local_dns_server`;
- nu activeaza DirectAccess pe regula si nu modifica setarile globale DirectAccess;
- curata regulile vechi cu `Comment = TRUSTAGENT` sau `DisplayName = TRUSTAGENT-*`;
- curata si cheile registry legacy `TRUSTAGENT-*` din `DnsPolicyConfig`;
- ruleaza `ipconfig /flushdns` dupa aplicare.

Exemplu:

```text
Catalog:
  resources:
    - fqdn: "crm.internal.example"

NRPT:
  crm.internal.example -> 127.0.0.1

DNS:
  crm.internal.example A -> 100.64.0.2
```

## Interceptare Trafic WFP

Scopul acestei componente este sa prinda conexiunile catre IP-urile sintetice returnate de DNS si sa le mute in proxy-ul local al serviciului.
Implementarea curenta este deliberat limitata la conexiuni TCP IPv4. Nu exista interceptare WFP pentru IPv6 sau UDP.

Arhitectura:

```text
aplicatie -> 100.64.x.y:port
       -> trustagent_wfp.sys, ALE_CONNECT_REDIRECT_V4
       -> 127.0.0.1:<traffic_proxy_listen_address>
       -> traffic-interception proxy
       -> resource_id din catalog
       -> decizie PA si stream Gateway
```

Responsabilitati:

- `trustagent_wfp.sys` redirectioneaza conexiuni. Nu decide allow/deny si nu vorbeste cu PDP.
- `wfp-control` trimite regulile catre driver prin IOCTL si cere destinatia originala pentru conexiunea acceptata de proxy.
- `traffic-interception` tine tabela activa de reguli si inchide conexiunea daca destinatia originala nu exista in catalog.
- `resourceStreamConnector` cere decizia PDP pentru `resource_id + protocol + port` folosind sesiunea userului autentificat.
- `flow-authorization` intoarce decizia si, pentru `allow`, materialul de sesiune necesar Gateway-ului.
- `gateway-tunnel` deschide stream-ul mTLS/yamux catre Gateway si trimite cererea `connect` cu `session_id` si `session_token`.
- `protected-resources` aplica WFP inainte de NRPT cand interceptarea este activata, ca DNS-ul sa nu directioneze aplicatiile catre IP-uri sintetice fara capturare.

Fail-closed:

- daca `traffic_interception_enabled=false`, WFP nu este folosit si comportamentul ramane DNS/NRPT only;
- daca `traffic_interception_enabled=true` si driverul nu este disponibil, aplicarea catalogului esueaza;
- daca proxy-ul primeste o conexiune pentru care driverul nu poate raporta destinatia originala, conexiunea este inchisa;
- daca destinatia originala nu este in catalogul autentificat, conexiunea este inchisa.
- daca nu exista sesiune de user autentificata, PDP raspunde cu deny/MFA, lipseste sesiunea Gateway sau Gateway-ul nu poate fi contactat, conexiunea este inchisa.

Implementare driver:

- `trustagent_wfp.sys` creeaza device object-ul `\\.\TrustAgentWfp`;
- service-ul trimite regulile prin `IOCTL_TRUSTAGENT_WFP_APPLY_RULES`;
- driverul inregistreaza provider, sublayer, callout si filtru WFP pe `ALE_CONNECT_REDIRECT_V4`;
- filtrul este limitat la TCP IPv4 catre `100.64.0.0/10`;
- classify callback-ul cauta regula `synthetic_ip, port, protocol`;
- la match, modifica destinatia conexiunii catre `127.0.0.1:<traffic_proxy_listen_address>`;
- seteaza `localRedirectTargetPID` la PID-ul proxy-ului Go, pentru redirect localhost;
- ataseaza contextul original al destinatiei ca WFP redirect context, ca proxy-ul Go sa poata identifica resursa;
- evita redirect loop cand conexiunea a fost deja redirectionata de acelasi callout;
- curata filtrele, callout-ul, redirect handle-ul si regulile la unload.

## Device Data Sync

Agentul colecteaza doar urmatoarele controale device-data:

- `Operating System`
- `Windows Updates`
- `Password & Lock`
- `Disk Encryption`
- `Firewall`
- `Antivirus`

Nu se mai trimite check artificial `Connectivity`.

Payload-ul intern este `DeviceDataReport`:

```json
{
  "device_id": "dev_...",
  "hostname": "HOSTNAME",
  "os": "Microsoft Windows ...",
  "checks": [
    {
      "name": "Firewall",
      "status": "good",
      "description": "Firewall is enabled for all profiles",
      "details": {
        "DomainEnabled": "true",
        "PrivateEnabled": "true",
        "PublicEnabled": "true"
      }
    }
  ],
  "collected_at": "2026-05-22T10:00:00Z"
}
```

Statusurile posibile sunt:

- `good`
- `warning`
- `critical`
- `unavailable`

Colectarea este facuta in serviciul LocalSystem, nu in Tray.

### Operating System

Implementare:

- PowerShell/CIM: `Get-CimInstance Win32_OperatingSystem`.

Date in `details`:

- `Version`
- `BuildNumber`
- `Architecture`
- `ProductType`
- `InstallDate`
- `LastBootUpTime`

Status:

- `good` daca OS-ul raportat este Windows;
- `warning` daca nu pare Windows;
- `unavailable` daca detaliile OS nu pot fi citite.

### Windows Updates

Implementare:

- status serviciu: `Get-Service wuauserv`;
- Windows Update Agent COM: `Microsoft.Update.Session`;
- pending reboot prin chei Windows standard:
  - `Component Based Servicing\RebootPending`;
  - `WindowsUpdate\Auto Update\RebootRequired`;
  - pending file rename operations.

Date in `details`:

- `ServiceStatus`
- `MissingUpdateCount`
- `RebootPending`
- `SearchError`

Status:

- `good` daca serviciul ruleaza, nu exista update-uri vizibile lipsa si nu este pending reboot;
- `warning` daca serviciul nu ruleaza, exista update-uri lipsa sau este pending reboot;
- `unavailable` daca Windows Update Agent nu poate raporta starea.

### Password & Lock

Implementare:

- export local security policy cu `secedit /export`;
- politica de inactivity lock din `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs`.

Date in `details`:

- `MinimumPasswordLength`
- `PasswordComplexity`
- `LockoutBadCount`
- `LockoutDuration`
- `MaximumPasswordAge`
- `InactivityTimeoutSeconds`

Status:

- `good` daca parola are minim 8 caractere, complexity este activ, lockout threshold este intre 1 si 10, iar inactivity lock este maxim 15 minute;
- `warning` daca una dintre politici este slaba sau lipseste;
- `unavailable` daca Windows nu raporteaza politica.

### Disk Encryption

Implementare:

- preferat: `Get-BitLockerVolume -MountPoint $env:SystemDrive`;
- fallback: WMI `root/CIMV2/Security/MicrosoftVolumeEncryption:Win32_EncryptableVolume`.

Date in `details`:

- `MountPoint`
- `ProtectionStatus`
- `VolumeStatus`
- `EncryptionPercentage`
- `EncryptionMethod`
- `LockStatus`

Status:

- `good` daca drive-ul de sistem este protejat si complet criptat;
- `warning` daca protectia este pornita, dar criptarea nu este completa;
- `critical` daca BitLocker protection este off;
- `unavailable` daca starea nu poate fi citita.

### Firewall

Implementare:

- preferat: COM `HNetCfg.FwPolicy2`;
- fallback: `Get-NetFirewallProfile`.

Date in `details`:

- `{Profile}Enabled`
- `{Profile}DefaultInboundAction`
- `{Profile}DefaultOutboundAction`

Profile:

- `Domain`
- `Private`
- `Public`

Status:

- `good` daca firewall-ul este enabled pentru toate profilele;
- `critical` daca cel putin un profil are firewall disabled;
- `unavailable` daca profilele nu pot fi citite.

### Antivirus

Implementare:

- preferat pentru Defender: `Get-MpComputerStatus`;
- fallback third-party: WMI `root/SecurityCenter2:AntiVirusProduct`.

Date in `details`:

- `Provider`
- `ProductName`
- `AntivirusEnabled`
- `RealTimeProtectionEnabled`
- `AMServiceEnabled`
- `AntispywareEnabled`
- `NISEnabled`
- `SignatureAge`
- `SignatureLastUpdated`
- `ProductState`

Status:

- `good` pentru Defender cand antivirus, realtime protection si serviciul sunt active, iar semnaturile nu sunt invechite;
- `warning` pentru Defender instalat dar protectie incompleta;
- `good` pentru produs third-party raportat de Windows Security Center;
- `unavailable` daca nu este detectat produs AV sau starea nu poate fi citita.

### Cand se trimite catre PDP

Device-data sync runner-ul reciteste device-data si calculeaza un fingerprint peste `device_id`, `hostname`, `os` si lista de checks. Campul `collected_at` nu intra in fingerprint, ca sa nu produca schimbari false.

Raportarea catre PDP se face:

- imediat dupa enrollment;
- imediat cand watcher-ul Windows observa un eveniment relevant;
- la scan fallback, daca fingerprint-ul s-a schimbat;
- periodic la `device_data_sync_interval`, chiar daca nu s-a schimbat nimic.

Evenimentele Windows sunt folosite doar ca trigger de recitire. Agentul nu trimite evenimentul brut la PDP si nu trateaza evenimentul ca adevar final. Dupa fiecare trigger, service-ul colecteaza din nou toate cele 6 checks si trimite raportul doar daca s-a schimbat sau daca heartbeat-ul periodic este scadent.

Watcher-ul Windows monitorizeaza:

- serviciul `wuauserv`;
- serviciul `mpssvc`;
- serviciul `WinDefend`;
- registry pentru Windows Firewall policy;
- registry pentru BitLocker;
- registry pentru Microsoft Defender;
- registry pentru Windows policies;
- registry pentru Windows Update reboot/policy changes.

Transmiterea catre PDP:

- service gRPC: `trustagent.device.DeviceDataService`;
- method: `ReportDeviceData`;
- transport: gRPC peste clientul PDP mTLS partajat;
- certificatul mTLS este certificatul de device instalat dupa enrollment;
- PDP nu are incredere in `device_id` din payload, ci il compara cu identitatea din certificatul mTLS.

## Securitate Aplicata

Remedieri curente:

- Named pipe cu DACL explicit, nu pipe deschis implicit.
- User-session IPC fail-closed pe peer identity.
- Re-enrollment local este blocat daca exista deja enrollment valid.
- Cheia de device este ECDSA P-256 si prefera `Microsoft Platform Crypto Provider`.
- Fallback software pentru cheia de device este permis doar cand Platform Crypto Provider nu este disponibil.
- Enrollment OIDC `state` random separat de `enrollment_session_id`.
- PDP valideaza OIDC discovery issuer.
- PDP valideaza ID token cu JWKS, `iss`, `aud`, `exp`, `nonce` si `azp` cand exista mai multe audiences.
- PDP accepta doar algoritmi asimetrici OIDC expliciti: RS*, PS*, ES*.
- Enrollment gRPC StartSession este rate-limited per peer IP.
- PDP nu are incredere in Subject/CN/SAN din CSR pentru certificatul device.
- PDP accepta proof-ul interactiv TrustAgent doar cu ECDSA P-256.
- PDP verifica dupa emitere ca certificatul contine `device_id` decis de PDP.
- `agent_session_token` este sender-constrained prin `cnf.x5t#S256`.
- Catalog, flow authorization si session revoke cer scope explicit.
- User-session devine `AUTHENTICATED` doar dupa ce catalogul a fost aplicat in resolverul local si NRPT.
- Resolverul DNS local raspunde doar pentru resursele explicite din catalog si foloseste IP-uri sintetice CGNAT.
- PDP cere `local_user.sid_hash`, `windows_logon_session_id` si `windows_session_id` atat la StartSession, cat si la ClaimSession.
- Device-data catre PDP este trimis doar prin gRPC mTLS cu certificatul de device.

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

