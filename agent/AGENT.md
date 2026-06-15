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

- `internal/service/runtime.go`: porneste listener-ul IPC, device-data sync runner-ul si watcher-ele de evenimente Agent.
- `internal/service/agent_events.go`: porneste stream-uri de evenimente pentru sesiunile de user autentificate si reactioneaza la revocari/invalidari de catalog.
- `internal/service/access_prompt.go`: tine mesajele locale pentru sign-in required si step-up required afisate in Tray.
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
- `internal/service/agent-events/*`: client gRPC/mTLS catre PDP pentru `trustagent.events.AgentEventsService/Watch`.
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
- afiseaza prompt local cand utilizatorul incearca accesul fara sesiune activa;
- cand PDP returneaza `step_up_required`, salveaza mesajul si URL-ul de step-up in starea sesiunii, iar Tray-ul il deschide in browser daca URL-ul este HTTPS si apartine PDP-ului configurat;
- urmareste stream-ul `trustagent.events.AgentEventsService/Watch` pentru sesiunile autentificate si reactioneaza la `access.revoked` si `catalog.invalidated`;
- pastreaza `agent_session_token` in memoria serviciului, per user local;
- sterge sesiunea userului la logout, curata regulile NRPT si nu sterge enrollment-ul device-ului.
- colecteaza device-data pentru 6 controale Windows;
- trimite device-data la PDP prin gRPC mTLS imediat dupa enrollment, la evenimente relevante, la schimbare detectata si periodic;
- pastreaza in cache ultimul device-data report pentru dashboard si pentru device data revision in login.

Tray-ul:

- este UI-only;
- vorbeste doar cu serviciul prin named pipe;
- afiseaza starea de enrollment, login si catalog;
- afiseaza mesajele de acces refuzat, sign-in required si step-up required;
- deschide automat URL-ul de step-up primit de la serviciu cand acesta este
  valid si apartine PDP-ului configurat;
- primeste doar `auth_url` pentru browser;
- nu primeste CSR, private key, poll secret, claim secret, certificate PEM sau tokenuri.

Proxy-ul local este legat de autorizarea per flow si de tunnel-ul Gateway prin `resourceStreamConnector`: pentru fiecare conexiune redirectionata de WFP, service-ul identifica resursa din catalog, cere decizia PDP prin `flow-authorization`, iar pentru decizia `allow` deschide un stream mTLS/yamux catre Gateway folosind materialul de sesiune provisionat de PDP.

Pentru decizia `step_up_required`, service-ul nu deschide stream catre Gateway.
In schimb, inregistreaza URL-ul browser primit de la PDP, Tray-ul il deschide
pentru utilizator, iar dupa finalizarea MFA urmatoarea incercare de acces
declanseaza o noua autorizare per flow.

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

### Contract IPC Detaliat

Protocol:

- `ProtocolVersion = trust-agent-ipc.v1`;
- `PipeName = \\.\pipe\trust-agent`;
- `MaxMessageBytes = 1 << 20`, adica 1 MiB;
- requestul are `version`, `id`, `operation`, `body`;
- raspunsul are `version`, `id`, `ok`, `body` sau `error`;
- `id` este obligatoriu si este trim-uit;
- o operatie necunoscuta este respinsa cu `unsupported_operation`;
- o versiune diferita de `trust-agent-ipc.v1` este respinsa;
- un body peste 1 MiB este respins inainte de procesare;
- un raspuns `ok=true` nu poate include `error`;
- un raspuns `ok=false` trebuie sa includa `error.code` si `error.message`.

Framing IPC:

- fiecare mesaj JSON este incadrat cu header de 4 bytes;
- headerul este lungimea body-ului in big-endian;
- body-ul este JSON marshalled;
- `ReadFrame` citeste intai headerul cu `io.ReadFull`, apoi exact numarul de bytes declarat;
- `WriteFrame` respinge payload-uri peste `MaxMessageBytes`;
- frame-ul zero-length este permis la nivel de framing, dar request/response validation cere campurile contractului;
- clientul seteaza deadline-ul conexiunii daca `context.Context` are deadline;
- dupa raspuns, clientul verifica strict ca `response.id` sa fie egal cu `request.id`;
- serverul proceseaza mai multe frame-uri pe aceeasi conexiune pana la EOF, context cancel sau eroare;
- daca requestul nu poate fi decodat, serverul raspunde cu `id = invalid` si `invalid_request`.

Peer identity Windows:

- serviciul foloseste `GetNamedPipeClientProcessId` pentru PID-ul clientului;
- deschide procesul cu `PROCESS_QUERY_LIMITED_INFORMATION`;
- deschide tokenul procesului cu `TOKEN_QUERY`;
- citeste SID-ul userului din `TokenUser`;
- citeste logon session din `TokenStatistics.AuthenticationID`;
- citeste Windows session id din `TokenSessionId`;
- formatul logon session id este `highpart:lowpart` hex;
- formatul Windows session id este decimal;
- daca SID-ul lipseste sau PID-ul este zero, peer identity este nevalid.

Pipe security descriptor:

- descriptor implicit: `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)`;
- `SY` si `BA` primesc generic all;
- `IU` primeste generic read/write;
- daca se cere SID explicit, ACE-ul `IU` este inlocuit cu acel SID;
- SID-ul explicit trebuie sa inceapa cu `S-1-`.

Coduri de eroare IPC:

- `invalid_request`;
- `unsupported_operation`;
- `internal_error`;
- `service_unavailable`.

`Ping`:

- request body: `message`, `tray_pid`, `tray_user`, `tray_user_sid`, `sent_at`;
- response body: `message`, `echo`, `protocol`, `pipe_name`, `service_state`, `service_pid`, `service_user`, `service_user_sid`, `received_at`;
- daca requestul nu trimite mesaj, echo-ul implicit este `ping`;
- raspunsul contine mereu protocolul si pipe-ul efectiv, util pentru smoke test.

`GetStatus`:

- request body gol;
- response body: `service_state`, `service_pid`, `service_user`, `service_user_sid`, `enrollment_state`, `enrollment_device_id`, `enrollment_last_error`, `device_data_status`, `device_data_check_count`, `device_data_collected_at`, `device_data_last_error`, `reported_at`;
- device-data status-ul service-level poate fi `unknown`, `collected`, `collect_error` sau `disabled`;
- daca device-data collector-ul nu este configurat, status-ul local este `disabled`.

`GetDashboard`:

- request body gol;
- response body: `connection`, `status`, `enrollment`, `user_session`, `catalog`, `device_data`, `reported_at`;
- `connection.state` poate fi `connected`, `unenrolled` sau `enrolling`;
- dashboard-ul ascunde catalogul si device-data cand userul nu este autentificat;
- daca userul este signed-out si a incercat sa acceseze o resursa, dashboard-ul poate afisa mesajul local `Sign in required to access ...`;
- ultimul mesaj de sign-in required expira dupa 5 minute;
- device-data din dashboard este considerat vechi dupa 2 minute si se incearca o colectare imediata;
- daca recoltarea imediata esueaza, dashboard-ul returneaza un check `Device Data` cu status `unavailable`.

`StartEnrollmentInteractive`:

- request body gol;
- response body: `started`, `auth_url`, `enrollment_session_id`, `state`, `message`, `expires_at`, `poll_interval_seconds`, `reported_at`;
- daca enrollment-ul ruleaza deja, `started=false`, dar raspunsul pastreaza URL-ul si sesiunea curenta;
- daca device-ul este deja enrolled local, `started=false` si mesajul este `Device is already enrolled`;
- Tray-ul primeste `auth_url`, dar nu primeste `poll_secret`, `device_nonce`, `device_challenge`, CSR sau cheia privata.

`StartUserLoginInteractive`:

- request body gol;
- necesita peer identity verificata pe named pipe;
- response body: `started`, `auth_url`, `session_request_id`, `state`, `message`, `expires_at`, `poll_interval_seconds`, `reported_at`;
- daca exista deja o sesiune de login in curs pentru acelasi user local, `started=false` si se refoloseste tranzactia curenta;
- daca userul este deja autentificat, nu se porneste o noua sesiune;
- Tray-ul primeste URL-ul, dar nu primeste `claim_secret`, token de sesiune sau catalog brut inainte de claim.

Stari user-session in contractele locale:

- `SIGNED_OUT`;
- `AUTHENTICATING`;
- `AUTHENTICATED`;
- `FAILED`.

Stari tranzactie PDP pentru login:

- `WAITING_FOR_USER_LOGIN`;
- `READY_TO_CLAIM`;
- `DENIED`;
- `CLAIMED`.

`LogoutUserSession`:

- request body gol;
- necesita peer identity verificata pe named pipe;
- response body: `logged_out`, `state`, `reported_at`;
- revoca doar sesiunea userului local asociat peer-ului IPC, nu toate sesiunile de pe masina;
- dupa logout, enrollment-ul device-ului ramane intact.

## Config

`trust-agent.exe` citeste `config.json` de langa binar, adica din acelasi director cu executabilul returnat de `os.Executable()`.

Detalii de loader:

- fisierul se numeste exact `config.json`;
- continutul este decodat ca JSON;
- daca fisierul incepe cu UTF-8 BOM, BOM-ul este eliminat inainte de decode;
- `pdp_ca_file` relativ este rezolvat relativ la directorul in care se afla `config.json`;
- stringurile sunt `TrimSpace`;
- duratele sunt parse-uite cu formatul Go `time.ParseDuration`, de exemplu `10s`, `3s`, `30m`, `12h`;
- duratele zero sau negative sunt respinse;
- daca fisierul lipseste, serviciul se poate construi cu default-uri interne, dar Tray-ul nu porneste fara `tray_timeout` si `dashboard_refresh_interval`;
- daca fisierul exista si un camp duration este invalid, pornirea esueaza explicit.

Configul curent din repository:

```json
{
  "tray_timeout": "10s",
  "dashboard_refresh_interval": "5s",
  "pdp_grpc_endpoint": "localhost:8443",
  "pdp_tls_server_name": "localhost",
  "pdp_ca_file": "C:\\Users\\laura\\Desktop\\Licenta\\pdp\\data\\vault-pki-ca-cert.pem",
  "enrollment_timeout": "10m",
  "enrollment_poll_interval": "3s",
  "certificate_renew_before": "12h",
  "certificate_renew_check_interval": "1h",
  "certificate_renew_timeout": "20s",
  "device_data_sync_interval": "30m",
  "device_data_sync_change_scan_interval": "5s",
  "local_dns_listen_address": "127.0.0.1:53",
  "local_dns_server": "127.0.0.1",
  "synthetic_ip_cidr": "100.64.0.0/10",
  "harden_browser_doh": false,
  "traffic_interception_enabled": true,
  "traffic_proxy_listen_address": "127.0.0.1:18787",
  "wfp_driver_device_path": "\\\\.\\TrustAgentWfp",
  "wfp_fail_closed": true
}
```

Campuri citite de `internal/app/config.go`:

- `tray_timeout`: timeout-ul folosit de Tray pentru requesturi IPC; este obligatoriu pentru rularea interactiva si trebuie sa fie pozitiv.
- `dashboard_refresh_interval`: intervalul la care Tray-ul cere dashboard proaspat prin IPC; este obligatoriu pentru rularea interactiva si trebuie sa fie pozitiv.
- `pdp_grpc_endpoint`: endpoint-ul gRPC al PDP. Poate fi `host:port` sau URL cu schema; clientii interni il normalizeaza cand este nevoie.
- `pdp_tls_server_name`: SNI/numele asteptat in certificatul TLS al PDP. Este folosit si ca host de incredere pentru URL-uri de step-up.
- `pdp_ca_file`: CA-ul folosit pentru validarea PDP. Daca lipseste, TLS foloseste root-urile sistemului; daca este setat, fisierul trebuie sa contina certificate PEM valide.
- `enrollment_timeout`: limita maxima pentru flow-ul interactiv de enrollment; default intern `10m`.
- `enrollment_poll_interval`: interval fallback de polling catre PDP in timpul enrollment-ului; default intern `3s`. Daca PDP returneaza `poll_interval_seconds`, valoarea PDP poate controla polling-ul sesiunii.
- `certificate_renew_before`: cat timp inainte de expirarea certificatului agentul incearca renewal; default intern `12h`.
- `certificate_renew_check_interval`: cat de des ruleaza verificarea periodica de renewal; default intern `1h`.
- `certificate_renew_timeout`: timeout-ul pentru un apel concret de renewal; default intern `20s`.
- `device_data_sync_interval`: heartbeat-ul periodic pentru device-data; default intern `30m`.
- `device_data_sync_change_scan_interval`: scan fallback pentru detectarea schimbarilor; default intern in runner este `30s`, iar configul curent il seteaza la `5s`. Evenimentele Windows pot declansa raportare mai devreme.
- `enrollment_state_path`: cale optionala pentru fisierul de enrollment. Daca lipseste, store-ul foloseste `%ProgramData%\TrustAgent\enrollment.json`.
- `local_dns_listen_address`: adresa pe care asculta resolverul DNS local; default `127.0.0.1:53`.
- `local_dns_server`: IP-ul scris in regulile NRPT. Daca lipseste, serviciul il deriveaza din host-ul lui `local_dns_listen_address`, de obicei `127.0.0.1`.
- `synthetic_ip_cidr`: pool-ul pentru IP-uri sintetice returnate de resolver; default `100.64.0.0/10`. CIDR-ul trebuie sa fie IPv4 si sa nu fie prea mic (`/31` sau mai strict este respins).
- `harden_browser_doh`: cand este `true`, serviciul seteaza politici HKLM pentru dezactivarea DoH in Chrome, Edge si Firefox.
- `traffic_interception_enabled`: activeaza proxy-ul local si regulile WFP pentru IP-urile sintetice. Cand este `false`, agentul ramane in mod DNS/NRPT only.
- `traffic_proxy_listen_address`: adresa proxy-ului TCP local catre care driverul redirectioneaza conexiunile; default `127.0.0.1:18787`.
- `wfp_driver_device_path`: device object user-mode al driverului; default `\\.\TrustAgentWfp`.
- `wfp_fail_closed`: cand este `true`, payload-ul WFP include flag fail-closed, iar o eroare la aplicarea regulilor blocheaza aplicarea catalogului si implicit autentificarea locala. Daca valoarea lipseste complet din JSON, default-ul aplicat de loader este `true`.

Campuri care nu sunt citite din JSON in implementarea curenta:

- `login_timeout`;
- `login_poll_interval`.

Exista default-uri interne pentru login in `usersession` (`10m` si `3s`), dar `internal/app/config.go` nu parseaza in prezent aceste doua chei din `config.json`. Daca apar in fisier, sunt ignorate de decoder-ul Go pentru ca structura `configFile` nu le contine.

Configul nu contine `issuer_url`, client OIDC public, redirect-uri local sau setari de token refresh pentru Tray. Browser login-ul este orchestrat de PDP, iar Tray-ul primeste doar URL-uri HTTPS de browser.

## Instalare

Build si instalare enterprise:

```powershell
.\packaging\build-enterprise-package.ps1
.\build\TrustAgent-Setup.exe
```

Setup-ul cere UAC cand este rulat manual. In deployment enterprise poate fi rulat elevated sau ca `SYSTEM` prin Intune/SCCM/GPO.

Pachetul:

- instaleaza `trust-agent.exe` si `config.json` in `%ProgramFiles%\TrustAgent`;
- copiaza `pdp-ca.pem` daca este prezent in build output;
- instaleaza serviciul Windows `TrustAgent` ca LocalSystem;
- configureaza service recovery;
- porneste serviciul;
- adauga HKLM Run pentru pornirea tray-ului la logon.

Build enterprise:

- script: `packaging/build-enterprise-package.ps1`;
- output implicit: `agent/build`;
- ruleaza `npm run build` in `internal/tray/frontend`;
- normalizeaza numele asseturilor Vite ca build-ul embedded sa ramana stabil;
- compileaza binarul cu `go build -tags "desktop,production" -ldflags "-H windowsgui" -o build\trust-agent.exe ./cmd/agent`;
- copiaza `trust-agent.ico` daca exista;
- copiaza `install-service.ps1` si `Test-AgentConfig.ps1`;
- cere config explicit prin `-ConfigPath` sau foloseste `agent/config.json`;
- daca `pdp_ca_file` este relativ sau absolut si exista, copiaza CA-ul in output ca `pdp-ca.pem` si rescrie configul build-ului sa pointeze la `pdp-ca.pem`;
- ruleaza preflight cu `-SkipEnvironmentChecks`;
- daca `ISCC.exe` este gasit, genereaza `TrustAgent-Setup.exe` cu Inno Setup 6;
- daca `ISCC.exe` lipseste, lasa pachetul build fara installer exe si afiseaza mesaj.

Installer Inno Setup:

- `AppName = TrustAgent`;
- `AppVersion = 1.0.0`;
- `DefaultDirName = {autopf}\TrustAgent`;
- necesita admin (`PrivilegesRequired=admin`);
- permite arhitecturi x64-compatible;
- copiaza `trust-agent.exe`, `config.json`, optional `pdp-ca.pem`;
- copiaza temporar scripturile de install/preflight;
- scrie HKLM Run `Software\Microsoft\Windows\CurrentVersion\Run\TrustAgent`;
- scrie HKLM `Software\TrustAgent\Agent\InstallDir`;
- scrie HKLM `Software\TrustAgent\Agent\RuntimePath`;
- ruleaza `install-service.ps1` hidden si asteapta terminarea;
- dupa instalare poate lansa `trust-agent.exe` in mod postinstall, exceptand instalari silent;
- la uninstall opreste si sterge serviciul `TrustAgent`.

`install-service.ps1`:

- cere `RuntimePath`;
- seteaza service name `TrustAgent`;
- seteaza display name `TrustAgent`;
- seteaza descrierea `Privileged TrustAgent endpoint service.`;
- daca serviciul exista, il opreste in maxim 30s si ii actualizeaza `binPath`, `start` si `DisplayName`;
- daca serviciul nu exista, il creeaza ca `Automatic`;
- daca serviciul driver `trustagent_wfp` exista si nu ruleaza, incearca sa il porneasca si asteapta maxim 15s;
- ruleaza `Test-AgentConfig.ps1 -RepairPaths`;
- seteaza start delayed-auto;
- configureaza service recovery: restart dupa 10s, 30s si 60s;
- seteaza failure flag;
- porneste serviciul.

Preflight `Test-AgentConfig.ps1`:

- cere `pdp_grpc_endpoint`;
- cere `pdp_tls_server_name`;
- cere `pdp_ca_file` si verifica existenta si markerul PEM `BEGIN CERTIFICATE`;
- poate repara `pdp_ca_file` relativ in cale absoluta cand `-RepairPaths` este activ;
- cere `tray_timeout` si `dashboard_refresh_interval`;
- valideaza optional `enrollment_timeout`, `enrollment_poll_interval`, `device_data_sync_interval`, `device_data_sync_change_scan_interval`;
- validarea duratelor foloseste sintaxa Go, de exemplu `10s`, `3m`, `1h30m`;
- cere `local_dns_listen_address` in forma host:port;
- impune portul DNS `53`, pentru ca Windows NRPT nu poate targeta un port DNS custom;
- cere `local_dns_server` ca IP si verifica sa se potriveasca cu IP-ul de listen, cu exceptia listen pe all interfaces;
- cere `synthetic_ip_cidr` IPv4 cu prefix intre `0` si `30`;
- daca `traffic_interception_enabled=true`, cere `traffic_proxy_listen_address`, `wfp_driver_device_path` si `wfp_fail_closed=true`;
- cand nu este `-SkipEnvironmentChecks`, verifica disponibilitatea UDP/TCP pentru DNS local, TCP pentru proxy si existenta/starea driverului `trustagent_wfp`.

`install-local-build.ps1`:

- necesita rulare ca Administrator;
- gaseste directorul executabilului instalat citind serviciul `TrustAgent`;
- opreste serviciul si procesele `trust-agent`;
- copiaza `build\trust-agent.exe`, `build\config.json` si optional `build\pdp-ca.pem`;
- porneste driverul `trustagent_wfp` daca exista si este oprit;
- ruleaza preflight cu `-RepairPaths`;
- reporneste serviciul;
- afiseaza statusul serviciilor si SHA256-ul binarului instalat.

## Tray si Dashboard UI

Tray-ul este o aplicatie Wails/React legata de serviciu doar prin IPC.

Metode Go expuse catre frontend:

- `GetDashboard`;
- `StartEnrollmentInteractive`;
- `StartUserLoginInteractive`;
- `LogoutUserSession`;
- `HideWindow`;
- `ShowWindow`;
- `FlashWindowAttention`.

Comportament Wails:

- la startup, fereastra este centrata si afisata;
- se logheaza `tray_pid` si userul curent;
- titlul ferestrei este `TRUSTAgent`;
- dimensiunea implicita este `680x560`;
- resize-ul este dezactivat;
- fereastra este frameless;
- fundalul Wails este `RGBA(242, 242, 240, 1)`;
- asseturile sunt servite din `frontend/dist` embedded in binar;
- tema Windows este `Light`;
- title bar-ul custom light foloseste `RGB(253, 246, 244)` pentru activ/inactiv;
- textul title bar-ului este `RGB(17, 17, 17)`;
- border-ul title bar-ului este `RGB(226, 218, 216)`;
- un ticker emite evenimentul `dashboard:updated` la `dashboard_refresh_interval`;
- frontend-ul asculta `dashboard:updated` si reincarca dashboard-ul;
- dupa start enrollment, start login sau logout, aplicatia emite imediat `dashboard:updated`;
- `HideWindow` ascunde fereastra;
- butonul de minimize apeleaza runtime-ul Wails `WindowMinimise`;
- pe Windows, `FlashWindowAttention` cauta fereastra cu `FindWindowW` dupa titlul `TRUSTAgent`;
- apoi apeleaza `FlashWindowEx` cu flagurile `FLASHW_TRAY` si `FLASHW_TIMERNOFG`;
- numarul de flash-uri este `4`;
- pe alte platforme, `FlashWindowAttention` este no-op.

Frontend build:

- `package.json` are `name = trust-agent-tray-frontend`;
- `version = 0.1.0`;
- `type = module`;
- scripturi: `dev = vite`, `build = vite build`, `preview = vite preview`;
- dependinte runtime: `react`, `react-dom`, `vite`, `@vitejs/plugin-react`, `lucide-react`;
- dependinte build: `tailwindcss`, `postcss`, `autoprefixer`;
- Vite foloseste pluginul React;
- `clearScreen=false`;
- serverul Vite are `strictPort=true`;
- Tailwind scaneaza `index.html` si `src/**/*.{js,jsx,ts,tsx}`;
- Tailwind extinde culorile `surface`, `card`, `accent`, `graphite`;
- border radius-ul `agent` este `6px`.

Identitatea Tray:

- procesul citeste PID-ul propriu;
- citeste userul curent prin `os/user`;
- retine `Username` si `UserSID`;
- aceste date pot fi trimise in `Ping`, dar pentru operatii user-bound serviciul foloseste peer identity de named pipe, nu valorile declarate de Tray.

Fallback dashboard in Go:

- daca IPC-ul esueaza si exista un dashboard anterior, Tray-ul pastreaza ultimul dashboard;
- marcheaza `connection.service_state = unavailable`;
- seteaza mesajul `Agent service IPC is temporarily unavailable`;
- actualizeaza `reported_at`;
- daca nu exista device-data in ultimul dashboard, adauga un report indisponibil;
- daca nu exista dashboard anterior, construieste o stare `disconnected` sau `unenrolled`, cu `service_state = unavailable`.
- cand nu exista dashboard anterior, `status.service_user` este setat la `LocalSystem`, `service_pid = 0`, iar `enrollment.state` este `UNENROLLED`;
- fallback-ul fara service seteaza `connection.message = Agent service IPC is unavailable`;
- daca starea fallback este `UNENROLLED`, mesajul devine `Device is not enrolled; Agent service IPC is unavailable`;
- reportul device-data indisponibil foloseste `hostname` din userul Tray, `os = Unknown`, check `Device Data`, status `unavailable`, descriere `Agent service pipe is not reachable` si `details.Reason = eroarea IPC`;
- fallback-ul produs de service cand collector-ul nu are date foloseste `hostname = Unknown`, `os = Unknown`, check `Device Data`, status `unavailable`, descriere `Device data is not available from the service`.

Fallback dashboard in frontend:

- daca runtime-ul Wails nu este gata, frontend-ul foloseste `fallbackDashboard`;
- fallback-ul are `connection.state = unenrolled`;
- `user_session.state = SIGNED_OUT`;
- `catalog.resources = []`;
- `device_data.checks = []`.

Ecrane:

- loading: afisat cand se asteapta primul dashboard;
- unenrolled: afiseaza brandul si actiunea `ENROLL`;
- enrolled signed-out: afiseaza mesajul de sign-in si actiunea `SIGN IN`;
- authenticated: afiseaza sidebar si continut;
- `security`: lista celor 6 checks device-data;
- `resources`: resursele din catalog.

Deschidere browser:

- dupa `StartEnrollmentInteractive`, frontend-ul deschide `auth_url` doar daca incepe cu `https://`;
- dupa `StartUserLoginInteractive`, frontend-ul deschide `auth_url` doar daca incepe cu `https://`;
- pentru step-up, `AppLayout` deschide automat `step_up_url` doar daca incepe cu `https://`;
- acelasi `step_up_url` nu este redeschis repetat, fiind retinut in `openedStepUpURLRef`.

Toasts:

- toasts sunt deduplicate dupa `id`;
- toasts inchise manual sunt tinute in `dismissedToastIdsRef`;
- la toast nou sau actualizat, UI-ul cere `FlashWindowAttention`;
- step-up produce toast `Security verification required`;
- mesajele pozitive precum `Access granted to ...` sau `restored` folosesc varianta success;
- mesajele care contin `denied`, `revoked`, `expired`, `canceled`, `cancelled`, `failed` sau `paused` folosesc varianta danger;
- restul mesajelor de sesiune folosesc varianta warning.

Texte si fallback-uri UI:

- loading: `Please wait...`;
- fallback dashboard frontend: `Device is not enrolled`;
- fallback timp/format data: `Not reported`;
- fallback status normalizat: `unknown`;
- eroare dashboard: `Agent dashboard is unavailable`;
- eroare enrollment: `Enrollment could not be started`;
- eroare login: `Login could not be started`;
- eroare logout: `Logout failed`;
- ecran unenrolled: `Device enrollment is required before signing in.`;
- buton enrollment: `ENROLL`, iar in timpul apelului `STARTING...`;
- ecran signed-out: `Sign in required to access protected resources.`;
- buton login: `SIGN IN`, iar in timpul apelului `STARTING...`;
- sidebar: `Security`, `Resources`, `Logout`;
- titlebar: `Minimize`, `Close`;
- toast close: `Dismiss`;
- titluri toast: `Security verification required`, `Access granted`, `Security notification`, `Security verification failed`, `TrustAgent`;
- resurse: titlu `Your resources`, subtitlu `Resources available for access.`, fallback `No resources available.`, endpoint fallback `Resource access`;
- security header: `Your device`, fallback host `Checking device`, fallback OS `Your System`, loading `Collecting device data`;
- footer health: `Collecting device health data` sau `Last checked <data>`.

Security view:

- recunoaste checks dupa aliasuri, nu doar dupa nume exact;
- `Operating System`: `operating system`, `os`;
- `Windows Updates`: `windows updates`, `updates`, `software updates`;
- `Password & Lock`: `password & lock`, `password and lock`, `password`, `screen lock`;
- `Disk Encryption`: `disk encryption`, `bitlocker`, `filevault`;
- `Firewall`: `firewall`;
- `Antivirus`: `antivirus`, `anti virus`, `endpoint protection`;
- daca un check lipseste, randul este afisat ca `unavailable`;
- checks necunoscute sunt adaugate ca randuri extra;
- randurile `warning`, `critical` si `unavailable` sunt actionabile si deschid view de remediere.

Remedieri UI:

- Windows Updates si Operating System deschid `ms-settings:windowsupdate`;
- Password & Lock deschide `ms-settings:signinoptions`;
- Disk Encryption deschide `ms-settings:deviceencryption`;
- Firewall deschide `windowsdefender://firewall`;
- Antivirus deschide `windowsdefender:`;
- remedierea este UI guidance, nu modifica automat setarile Windows.

Titluri si texte Security view:

- `Operating System`: `Operating system is detected` cand statusul este bun, altfel descrierea primita de la collector; fallback subtitle `Operating system status`;
- `Windows Updates`: `Windows is up to date` sau `Windows is not up to date`; fallback subtitle `Windows update status`;
- `Password & Lock`: `System password is set`, `Screen lock needs attention` sau `System password is not set`; fallback subtitle `System password status`;
- `Disk Encryption`: `BitLocker is enabled` sau `BitLocker is not enabled`; fallback subtitle `BitLocker status`;
- `Firewall`: `Firewall is enabled` sau `Firewall is not enabled`; fallback subtitle `Firewall status`;
- `Antivirus`: `Antivirus is enabled` sau `Antivirus needs attention`; fallback subtitle `Antivirus status`;
- lipsa raport: `No data reported yet`;
- rand in loading: `Checking status`;
- view remediere fallback: `This device check needs attention.`;
- titlu remediere generic: `Device Data Check`;
- actiune remediere generica: `Review settings`;
- explicatie remediere generica: `This device data check must be healthy before the device can be considered compliant.`;
- pas generic: `Review the reported status and apply the required organization policy.`.

Texte remedieri configurate:

- Operating System: `Review operating system data`, actiune `Open Windows Update`, pasi `Install the latest Windows security updates.` si `Restart the device if Windows asks for it.`;
- Windows Updates: `Install Windows security update`, actiune `Open Windows Update`, pasi `Install all pending Windows updates.` si `Restart the device if Windows asks for it.`;
- Password & Lock: `Set password and screen lock`, actiune `Open sign-in options`, pasi `Set a password or Windows Hello sign-in method.` si `Enable automatic screen lock after inactivity.`;
- Disk Encryption: `Enable BitLocker protection`, actiune `Open device encryption`, pasi `Turn on BitLocker or device encryption for the system drive.` si `Wait until encryption finishes before retrying access.`;
- Firewall: `Turn on Windows Firewall`, actiune `Open Windows Security`, pasi `Enable Microsoft Defender Firewall for every network profile.` si `Retry the health check after the profiles show as enabled.`;
- Antivirus: `Enable antivirus protection`, actiune `Open Windows Security`, pasi `Turn on real-time protection in Windows Security.` si `Update antivirus definitions and retry the health check.`.

Texte `why` din remedieri:

- Operating System: `Operating system device data confirms the device is supported and ready for access.`;
- Windows Updates: `Security updates reduce exposure to known endpoint vulnerabilities.`;
- Password & Lock: `Password and lock settings protect the device when it is unattended.`;
- Disk Encryption: `Disk encryption protects data if the device is lost or stolen.`;
- Firewall: `Firewall protection blocks unwanted inbound connections to the device.`;
- Antivirus: `Antivirus protection helps detect malicious software before access is granted.`.

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
   - method: `StartSession`;
   - path complet: `/trustagent.enrollment.EnrollmentService/StartSession`.
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

Payload `StartSession` construit de agent:

- `csr_sha256`;
- `spki_sha256`;
- `device_nonce`;
- `hostname`;
- `agent_platform = windows`;
- `agent_name = TrustAgent`.

Validari locale pe raspunsul `StartSession`:

- `enrollment_session_id` sau aliasul `session_id` trebuie sa fie prezent;
- `auth_url` trebuie sa fie HTTPS si sa aiba host;
- `device_challenge` trebuie sa fie prezent;
- `poll_secret` trebuie sa fie prezent;
- `expires_at` trebuie sa fie prezent.

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
   - path complet: `/trustagent.enrollment.EnrollmentService/SessionStatus`.
2. Cand statusul este `READY_FOR_DEVICE_PROOF`, serviciul trimite prin gRPC `CompleteSession`:
   - CSR complet;
   - `device_nonce`;
   - `poll_secret`;
   - proof-of-possession ES256 semnat cu `TrustAgentDeviceKey`.
   - path complet: `/trustagent.enrollment.EnrollmentService/CompleteSession`.
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

Persistenta enrollment:

- store implicit: `%ProgramData%\TrustAgent\enrollment.json`;
- daca `enrollment_state_path` este setat, se foloseste acea cale in locul default-ului;
- la salvare, directorul parinte este creat cu permisiuni restrictive;
- fisierul este scris cu permisiuni restrictive;
- `updated_at` este setat la timpul curent UTC la fiecare salvare;
- daca `%ProgramData%` lipseste si nu este setata o cale explicita, store-ul raporteaza eroare.

Campuri persistate in `EnrollmentRecord`:

- `enrollment_state`;
- `device_id`;
- `device_key_name`;
- `device_key_provider`;
- `device_cert_thumbprint`;
- `device_certificate_chain_pem`;
- `certificate_expiry`;
- `pdp_endpoint`;
- `gateway_endpoints`;
- `enrolled_by_idp_profile_id`;
- `updated_at`.

Proof-of-possession canonical:

- `type` este `trustagent-device-enrollment-proof-v1`;
- payload-ul include `enrollment_session_id`, `device_nonce`, `device_challenge`, `csr_sha256`, `spki_sha256` si `pdp_origin`;
- `pdp_origin` este derivat din `auth_url`;
- semnatura este ECDSA P-256/ES256 si este codata base64 raw URL;
- requestul `CompleteSession` trimite structura `proof` cu `alg`, `payload_type`, `payload` si `signature`.

## Certificate Renewal Device

Agentul nu asteapta ca certificatul de device sa expire ca sa ceara alt certificat. Serviciul porneste un worker de renewal dupa startup si dupa ce enrollment-ul a fost refresh-uit.

Default-uri:

- `certificate_renew_before = 12h`;
- `certificate_renew_check_interval = 1h`;
- `certificate_renew_timeout = 20s`.

Flux:

1. Worker-ul ruleaza un check imediat la startup.
2. Apoi ruleaza periodic la `certificate_renew_check_interval`.
3. Agentul incarca `EnrollmentRecord`.
4. Agentul verifica local certificatul curent prin `CheckLocalEnrollment`.
5. Daca nu exista certificat sau certificatul nu se potriveste cu cheia locala, renewal-ul nu continua.
6. Daca `certificate_expiry` lipseste, agentul nu forteaza renewal.
7. Daca certificatul este expirat deja, starea devine `UNENROLLED`.
8. Daca timpul curent este inainte de `certificate_expiry - certificate_renew_before`, nu se face nimic.
9. Daca renewal-ul este scadent, agentul creeaza CSR nou folosind aceeasi cheie de device.
10. Agentul face request HTTP mTLS catre PDP pe endpoint-ul de renewal.
11. Dupa raspuns valid, instaleaza certificatul nou si actualizeaza enrollment record-ul.

Endpoint renewal:

- path HTTP: `/api/enroll/renew`;
- metoda: `POST`;
- transport: HTTPS cu client certificate;
- endpoint-ul se deriveaza din `pdp_grpc_endpoint`;
- daca endpoint-ul nu are schema, se adauga `https://`;
- endpoint-ul trebuie sa fie HTTPS si sa aiba host;
- raspunsul este limitat la 1 MiB.

Payload renewal trimis de agent:

- `device_id`;
- `component = endpoint`;
- `hostname`;
- `csr_pem`;
- `public_key_fingerprint`, adica SPKI hash.

Raspuns renewal acceptat:

- `certificate_pem` sau aliasul `cert_pem`;
- `certificate_chain_pem` sau aliasul `ca_pem`;
- `certificate_thumbprint`;
- `expires_at`.

Comportament la eroare:

- daca apelul HTTP intoarce non-2xx, mesajul include statusul si, cand exista, `error` sau `message` din body;
- daca renewal-ul esueaza, agentul pastreaza enrollment-ul existent si seteaza mesajul `Device enrolled; certificate renewal failed`;
- daca renewal-ul reuseste, mesajul devine `Device certificate renewed`;
- mutex-ul de renewal impiedica doua renewal-uri simultane.

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
   - method: `StartSession`;
   - path complet: `/trustagent.session.AgentSessionService/StartSession`.
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
   - path complet: `/trustagent.session.AgentSessionService/SessionStatus`.
2. Cand statusul este `READY_TO_CLAIM`, serviciul apeleaza `ClaimSession`.
   - path complet: `/trustagent.session.AgentSessionService/ClaimSession`.
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
   - scope-uri precum `catalog:read`, `flow:authorize`, `session:revoke`, `events:read`;
   - binding la certificatul device prin `cnf.x5t#S256`.
7. Serviciul cere catalogul prin gRPC mTLS + `agent_session_token`.
   - path complet: `/trustagent.session.AgentSessionService/GetCatalog`.
8. PDP verifica tokenul, scope-ul `catalog:read` si binding-ul certificatului.
9. Serviciul aplica catalogul in `protected-resources`:
   - incarca resursele in resolverul DNS local;
   - daca interceptarea este activata, prealoca IP-urile sintetice si instaleaza regulile WFP inainte de NRPT;
   - instaleaza reguli NRPT doar pentru FQDN-urile exacte ale resurselor primite in catalog;
   - directioneaza aceste FQDN-uri protejate catre `local_dns_server`;
   - blocheaza finalizarea autentificarii locale daca aplicarea catalogului esueaza.
10. Serviciul salveaza catalogul per sesiune locala.
11. Serviciul porneste watcher-ul de evenimente PDP pentru sesiunea autentificata.
12. Tray afiseaza userul autentificat si resursele.

Evenimente remote:

- `access.revoked`: serviciul revoca sesiunea locala sau afiseaza mesajul de
  revocare; pentru `device_posture_changed`, opreste accesul la resurse pana la
  autentificare/reevaluare.
- `catalog.invalidated`: serviciul cere din nou catalogul prin sesiunea curenta
  si reaplica DNS/NRPT/WFP.

Logout:

1. Tray trimite `LogoutUserSession`.
2. Serviciul determina userul local din peer identity.
3. Serviciul revoca doar sesiunea acelui user prin gRPC mTLS + `agent_session_token`.
4. PDP verifica scope-ul `session:revoke` si binding-ul certificatului.
   - path complet: `/trustagent.session.AgentSessionService/RevokeSession`.
5. Serviciul sterge tokenul din memorie si cache-ul catalogului pentru user.
6. Serviciul curata regulile NRPT `TRUSTAGENT-*` si goleste resolverul local.
7. Enrollment-ul device-ului ramane intact.

Payload `StartSession` construit de agent:

- `device_id`;
- `agent_version`, valoarea curenta fiind `TrustAgent`;
- `device_cert_thumbprint`;
- `device_data_revision`;
- `local_user.sid_hash`;
- `local_user.windows_logon_session_id`;
- `local_user.windows_session_id`.

`device_data_revision`:

- se calculeaza din raportul device-data aflat in cache;
- forma efectiva este `deviceID:unixCollectedAt:checkCount`;
- daca nu exista device-data colectat, poate fi gol;
- campul este retrimis la `ClaimSession`, nu doar la `StartSession`.

Cheia locala de sesiune user:

- include SID-ul Windows;
- include Windows logon session id;
- include Windows session id;
- este separata de `device_id`;
- impiedica un proces din alta sesiune Windows sa revendice logout/login pentru userul curent.

Payload `ClaimSession`:

- `session_request_id`;
- `claim_secret`;
- `device_id`;
- `device_cert_thumbprint`;
- `device_data_revision`;
- `local_user.sid_hash`;
- `local_user.windows_logon_session_id`;
- `local_user.windows_session_id`.

Payload `GetCatalog`:

- `access_token`;
- `current_version`.

Mesaje locale din flow-ul de login:

- daca exista deja login in curs pentru acelasi peer local, raspunsul are `started=false` si mesaj `Authentication is already running`;
- cand login-ul porneste cu succes, mesajul sesiunii este `Open your browser to sign in.`;
- daca polling-ul catre PDP da eroare tranzitorie, mesajul devine `Checking sign-in status...`;
- pentru status PDP `WAITING_FOR_USER_LOGIN`, mesajul devine `Sign-in is in progress.`;
- pentru statusuri necunoscute, dar nefinale, mesajul devine `Finalizing sign in...`;
- daca deadline-ul local expira inainte de claim, eroarea devine `Authentication request expired`;
- pentru status PDP `DENIED` fara reason, reason-ul local este `authentication_failed_or_policy_denied`;
- la claim reusit, starea devine `AUTHENTICATED`, mesajul devine `Authenticated`, iar `display_name` este primul non-gol dintre `display_name` si `email`;
- la eroare de autentificare, starea devine `FAILED`, mesajul devine `Authentication failed`, iar eroarea este pusa in `last_error`;
- daca eroarea indica lipsa driverului WFP sau imposibilitatea aplicarii regulilor de trafic, UI-ul primeste mesajul prietenos `Local traffic protection is not available. Reinstall TRUSTAgent, then sign in again.`.

Catalogul parsat de agent:

- `version`;
- `resources`;
- `ttl_seconds`;
- `policy_epoch`;
- `device_data_policy`;
- `updated_at`.

Fiecare resource accepta:

- `resource_id`;
- `display_name`;
- `fqdn`;
- `protocol`;
- `port`;
- `access_mode`.

Policy device-data din catalog:

- `required_checks`;
- `required_check_status`;
- daca `required_check_status` lipseste in policy locala, agentul foloseste `good`.

Sesiuni multiple:

- user-session manager-ul pastreaza sesiuni autentificate per user local;
- pentru interceptarea unui flow, `resourceStreamConnector` cere exact o sesiune autentificata activa;
- daca nu exista sesiune, accesul este marcat ca `authentication required`;
- daca exista mai multe sesiuni active si flow-ul nu poate fi asociat fara ambiguitate, stream-ul nu este deschis.

Expirare sesiune:

- `agent_session_token` ramane doar in memoria serviciului;
- manager-ul porneste watcher de expirare dupa autentificare;
- watcher-ul revoca remote inainte de expirare cu un lead implicit de `30s`;
- daca durata ramasa este foarte mica, lead-ul devine aproximativ o zecime din timpul ramas;
- timeout-ul pentru revocarea la expirare este `10s`;
- la expirare se sterg tokenul, step-up state-ul, mesajele signed-out si catalogul local.

Step-up:

- decizia `step_up_required` vine din flow authorization, nu din IPC;
- URL-ul de step-up trebuie sa fie HTTPS;
- path-ul URL-ului trebuie sa inceapa cu `/browser/step-up/`;
- host-ul trebuie sa se potriveasca cu `pdp_tls_server_name`, host-ul din `pdp_grpc_endpoint` sau varianta host:port derivata;
- mesajul si URL-ul sunt pastrate in `UserSessionInfo.step_up_url`;
- dupa acces permis pentru aceeasi resursa, step-up state-ul poate fi marcat ca allowed;
- dupa denial, mesajul include resursa sau motivul returnat de PDP.

Mesaje exacte step-up si denial:

- mesaj implicit step-up: `Additional verification is required to access this resource.`;
- mesaj service pentru resurse nespecifice: `Additional security verification is required to access protected resources.`;
- mesaj service pentru resursa cunoscuta: `Additional security verification is required to access <target>.`;
- cand accesul este permis dupa step-up, mesajul devine `Access granted to <target>.`;
- daca step-up expira, `last_error` devine `Security verification expired for <target>. Additional security verification is required to access <target>.`;
- daca reason-ul contine `cancelled`, `canceled` sau `abort`, mesajul devine `Security verification was canceled for <target>. Additional security verification is required to access <target>.`;
- daca reason-ul contine `denied`, `reject` sau `failed`, mesajul devine `Security verification was rejected for <target>. Additional security verification is required to access <target>.`;
- pentru alte reason-uri, mesajul devine `Security verification was not completed for <target>. Additional security verification is required to access <target>.`;
- daca accesul este refuzat fara step-up activ, mesajul devine `Access to <target> was denied.` sau `Access to <target> was denied. <reason>`;
- target-ul afisat este primul non-gol dintre FQDN, `resource_id` si `this resource`;
- `ClearAuthenticatedStepUp` curata URL-ul, resource id-ul, target-ul si watcher-ul de expirare, apoi readuce mesajul la `Authenticated`.

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
- daca adresa este data doar ca IP, portul implicit devine `53`;
- daca portul configurat este `0`, serverul incearca pana la 20 de perechi UDP/TCP pe acelasi port local alocat;
- semnalul `Ready` se inchide si pe eroare de listen, ca orchestratorul sa nu astepte indefinit;
- raspunde doar pentru FQDN-uri prezente explicit in catalog;
- pentru query A valid returneaza un IP sintetic din `100.64.0.0/10`;
- pentru FQDN-uri necunoscute returneaza `NXDOMAIN`;
- pentru AAAA raspunde fara adrese, ca sa nu expuna rute IPv6 neimplementate;
- pentru alte tipuri de query raspunde `NotImplemented`;
- prelungeste TTL-ul mapping-ului la fiecare acces;
- elibereaza mapping-urile cand resursa dispare din catalog;
- nu elibereaza un mapping doar pentru ca `ExpiresAt` a trecut; TTL-ul din raspunsul DNS devine minim `1` si este reimprospatat la urmatorul `Resolve`/`Lookup` valid.

Normalizarea resurselor DNS:

- FQDN-ul este trim-uit, lower-case si fara punct final;
- resursele fara punct in nume sunt ignorate;
- IP-urile literale sunt ignorate;
- numele cu spatiu, slash, backslash, colon, byte nul sau wildcard sunt ignorate;
- label-urile goale sunt respinse;
- protocolul gol devine `tcp`;
- porturile negative devin `0`;
- resursele duplicate dupa FQDN sunt deduplicate, ultima valoare normalizata ramanand in set;
- lista finala este sortata dupa FQDN.

NRPT:

- creeaza reguli cu `Add-DnsClientNrptRule` si `DisplayName` prefixat cu `TRUSTAGENT-`;
- foloseste namespace-ul exact al resursei, de exemplu `crm.internal.example`, nu suffix `.crm.internal.example`;
- seteaza `NameServers = local_dns_server`;
- cand exista cel putin o regula, ruleaza `Set-DnsClientNrptGlobal -EnableDAForAllNetworks EnableAlways -QueryPolicy QueryBoth -SecureNameQueryFallback FallbackPrivate`;
- curata regulile vechi cu `Comment = TRUSTAGENT` sau `DisplayName = TRUSTAGENT-*`;
- curata si cheile registry legacy `TRUSTAGENT-*` din `DnsPolicyConfig`;
- ruleaza `ipconfig /flushdns` dupa aplicare.

Normalizarea pentru NRPT:

- `NormalizeDNSNames` deduplica si sorteaza numele;
- `RuleKey(name)` produce `TRUSTAGENT-` urmat de numele lower-case in care caracterele diferite de litere/cifre/dot/hyphen devin `-`;
- punctul devine tot `-` in display name;
- numele care incep cu `.` sau `*.` sunt respinse;
- `local_dns_server` trebuie sa fie IP valid; daca are forma `host:port`, se pastreaza doar host-ul;
- daca exista nume NRPT dar serverul local DNS nu poate fi normalizat la IP, aplicarea esueaza.

Hardening DoH optional:

- ruleaza doar cand `harden_browser_doh=true`;
- Chrome: scrie HKLM `SOFTWARE\Policies\Google\Chrome`, valoarea `DnsOverHttpsMode = off`;
- Edge: scrie HKLM `SOFTWARE\Policies\Microsoft\Edge`, valoarea `DnsOverHttpsMode = off`;
- Firefox: scrie HKLM `SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS`, valorile DWORD `Enabled = 0` si `Locked = 1`.

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
- device name kernel: `\Device\TrustAgentWfp`;
- symbolic link: `\DosDevices\TrustAgentWfp`;
- cod device custom: `FILE_DEVICE_TRUSTAGENT_WFP = 0x8000`;
- WDF creeaza context per device cu `TRUSTAGENT_DEVICE_CONTEXT`;
- contextul contine spinlock, setul curent de reguli, engine handle WFP, redirect handle, callout id si filter id;
- device-ul ruleaza cu `WdfExecutionLevelPassive`;
- coada WDF este default queue cu `WdfIoQueueDispatchSequential`;
- service-ul trimite regulile prin `IOCTL_TRUSTAGENT_WFP_APPLY_RULES`;
- IOCTL-urile user-mode sunt:
  - apply rules: function `0x801`;
  - clear rules: function `0x802`;
  - query original target: function `0x803`;
- driverul inregistreaza provider, sublayer, callout si filtru WFP pe `ALE_CONNECT_REDIRECT_V4`;
- sesiunea WFP este dinamica (`FWPM_SESSION_FLAG_DYNAMIC`) si kernel-mode;
- la inregistrare sterge provider/sublayer/callout/filter vechi dupa cheile statice, apoi le recreeaza;
- filtrul este limitat la TCP IPv4 catre `100.64.0.0/10`;
- classify callback-ul cauta regula `synthetic_ip, port, protocol`;
- la match, modifica destinatia conexiunii catre `127.0.0.1:<traffic_proxy_listen_address>`;
- seteaza `localRedirectTargetPID` la PID-ul proxy-ului Go, pentru redirect localhost;
- ataseaza contextul original al destinatiei ca WFP redirect context, ca proxy-ul Go sa poata identifica resursa;
- evita redirect loop cand conexiunea a fost deja redirectionata de acelasi callout;
- daca protocolul nu este TCP, daca remote IP este loopback `127.0.0.1`, daca nu exista regula sau daca flow-ul a fost deja redirectionat de agent, driverul da permit;
- daca redirectarea esueaza si `TRUSTAGENT_WFP_FLAG_FAIL_CLOSED` este setat, driverul blocheaza flow-ul;
- daca redirectarea esueaza si fail-closed nu este setat, driverul da permit;
- curata filtrele, callout-ul, redirect handle-ul si regulile la unload.

GUID-uri WFP statice:

- provider: `63d5b615-3845-477e-b795-897f2286ea0d`;
- sublayer: `a39863e8-4a36-46e8-a6a8-3eaa3bee6a12`;
- callout connect v4: `f3d09a6e-2a89-4fd9-8e7d-9d6b46884f11`;
- filter connect v4: `889a3f61-73ad-4276-89f5-d76a9f39c629`.

Provider/sublayer/filter WFP:

- provider name: `TrustAgent WFP Provider`;
- provider description: `TrustAgent traffic redirection provider`;
- sublayer name: `TrustAgent`;
- sublayer description: `TrustAgent protected resource redirection`;
- sublayer weight: `0x8000`;
- callout name: `TrustAgent ALE connect redirect v4`;
- callout description: `Redirects TrustAgent synthetic IPv4 connections`;
- filter name: `TrustAgent protected IPv4 redirect`;
- filter description: `Routes 100.64.0.0/10 TCP connections through TrustAgent`;
- filter layer: `FWPM_LAYER_ALE_CONNECT_REDIRECT_V4`;
- filter action: `FWP_ACTION_CALLOUT_TERMINATING`;
- filter weight: `0x0F`;
- conditii filter: `FWPM_CONDITION_IP_REMOTE_ADDRESS` in `100.64.0.0/10` si `FWPM_CONDITION_IP_PROTOCOL = 6`.

Payload-ul binar trimis catre driver:

- magic `0x46574154`, adica `TAWF`;
- versiune payload `1`;
- flags, unde bitul `1` inseamna `fail_closed`;
- IPv4-ul proxy-ului local;
- portul proxy-ului local;
- PID-ul procesului proxy, adica PID-ul serviciului Go;
- numarul de reguli;
- pentru fiecare regula: IPv4 sintetic, port, protocol numeric.
- `RuleCount` peste `4096` este respins;
- payload mai scurt decat headerul sau decat lungimea calculata a regulilor este respins cu buffer-too-small;
- magic sau versiune gresita sunt respinse;
- `ProxyIpv4`, `ProxyPort` sau `ProxyPid` zero sunt respinse.

Structuri native declarate in `trustagent_wfp.h`:

- `TRUSTAGENT_WFP_RULE`;
- `TRUSTAGENT_WFP_APPLY_RULES`;
- `TRUSTAGENT_WFP_CONNECTION_QUERY`;
- `TRUSTAGENT_WFP_ORIGINAL_TARGET`;
- `EVT_WDF_DRIVER_DEVICE_ADD TrustAgentEvtDeviceAdd`;
- `EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL TrustAgentEvtIoDeviceControl`.

Payload query original target:

- magic `TAWF`;
- versiune `1`;
- IPv4 local;
- port local;
- IPv4 remote;
- port remote;
- protocol.

Raspuns original target:

- magic `TAWF`;
- versiune `1`;
- IPv4 original;
- port original;
- protocol;
- `OriginalProcessId`.

Starea reala a query-ului original target:

- proxy-ul Go incearca intai `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT` pe socketul TCP acceptat;
- acest mecanism citeste contextul atasat in classify prin `localRedirectContext`;
- daca acel mecanism esueaza, Go face fallback la `IOCTL_TRUSTAGENT_WFP_QUERY_ORIGINAL_TARGET`;
- implementarea curenta a fallback-ului valideaza input/output si construieste structura de raspuns, dar intoarce `STATUS_NOT_FOUND`;
- comentariul din driver marcheaza persistenta flow-urilor pentru acest IOCTL ca pas de productie ramas;
- deci comportamentul functional curent se bazeaza pe redirect context-ul socketului, nu pe lookup-ul IOCTL.

Protocol WFP acceptat in payload:

- `tcp`, `http`, `https` sau gol inseamna protocol TCP numeric `6`;
- `udp` inseamna protocol numeric `17`, dar managerul de trafic filtreaza in prezent rutele non-TCP inainte de aplicare;
- orice alt protocol produce eroare de normalizare.

Statusuri `traffic-interception`:

- `disabled`;
- `starting`;
- `ready`;
- `degraded`;
- `stopped`.

Statusuri `wfp-control`:

- `disabled`;
- `ready`;
- `driver_missing`;
- `error`.

Proxy local:

- asculta pe `traffic_proxy_listen_address`, default `127.0.0.1:18787`;
- timeout-ul pe un flow local este `15s` daca nu este configurat altfel prin dependinte interne;
- asteapta proxy-ul maxim `2s` la aplicarea catalogului;
- fiecare conexiune acceptata creste `accepted_count`;
- fiecare conexiune respinsa creste `denied_count`;
- cere destinatia originala intai din redirect context-ul socketului, apoi prin IOCTL catre driver;
- inchide conexiunea daca destinatia originala nu este TCP IPv4, nu se poate citi sau nu exista in tabela activa;
- identifica procesul sursa prin PID, path, nume si SHA256 al executabilului;
- identitatea de proces este cache-uita 30s;
- `signer` exista in contract, dar implementarea curenta lasa validarea Authenticode pentru un verifier dedicat si returneaza string gol.

Normalizarea rutelor de trafic:

- `SyntheticIP` trebuie sa fie IPv4;
- portul trebuie sa fie intre `0` si `65535`;
- protocolul gol devine `tcp`;
- `http`, `https`, `rdp`, `ssh` si `tcp` sunt tratate ca transport TCP;
- `udp` este recunoscut la normalizare, dar rutele UDP sunt sarite de manager pentru ca proxy-ul curent este TCP;
- cheia de ruta este `protocol|ip|port`;
- daca nu exista match exact pe port, se incearca fallback la port `0` pentru acelasi IP/protocol;
- rutele duplicate se deduplica dupa IP, port si protocol.

INF driver:

- `Class = System`;
- `ClassGuid = {4d36e97d-e325-11ce-bfc1-08002be10318}`;
- `Provider = TrustAgent`;
- `CatalogFile = trustagent_wfp.cat`;
- `DriverVer = 05/23/2026,1.0.0.0`;
- `PnpLockdown = 1`;
- device hardware id: `Root\TrustAgentWfp`;
- service name: `trustagent_wfp`;
- `ServiceType = 1`, driver kernel-mode;
- `StartType = 3`, manual start;
- `ErrorControl = 1`;
- service binary: `%12%\trustagent_wfp.sys`;
- display string: `TrustAgent WFP Redirect Driver`.

Build driver:

- script: `wfp-driver/build-driver.ps1`;
- configuratii acceptate: `Debug`, `Release`;
- platforma acceptata: `x64`;
- proiect: `trustagent_wfp.vcxproj`;
- cauta `msbuild.exe` in PATH sau sub directoarele Visual Studio;
- cere Windows Driver Kit sub `C:\Program Files (x86)\Windows Kits\10\Include`;
- ruleaza MSBuild cu `/m`, `Configuration`, `Platform` si `SkipPackageVerification=true`;
- daca MSBuild intoarce exit code diferit de zero, scriptul esueaza.

Instalare driver de test:

- script: `wfp-driver/install-test-driver.ps1`;
- cere PowerShell Administrator;
- poate sari instalarea driverului cu `-SkipDriverInstall`;
- poate sari restartul TrustAgent cu `-SkipTrustAgentRestart`;
- verifica `trustagent_wfp.inf`, certificatul `.cer`, `devcon.exe` si `agent\config.json`;
- verifica Windows test-signing prin `bcdedit /enum`;
- daca test-signing lipseste, ruleaza `bcdedit.exe /set testsigning on` si intoarce exit code `3010`;
- importa certificatul de test in `LocalMachine\Root` si `LocalMachine\TrustedPublisher`;
- opreste `TrustAgent` inainte de instalarea driverului;
- opreste `trustagent_wfp` daca ruleaza;
- sterge device-uri stale pentru serviciul `trustagent_wfp`;
- instaleaza sau updateaza driverul cu `devcon install/update`;
- porneste serviciul `trustagent_wfp`;
- seteaza in config `traffic_interception_enabled=true`, `traffic_proxy_listen_address=127.0.0.1:18787`, `wfp_driver_device_path=\\.\TrustAgentWfp`, `wfp_fail_closed=true`;
- valideaza device-ul cu `CreateFileW("\\.\TrustAgentWfp")`;
- verifica device-ul PnP sa fie `OK`;
- scrie log in `install-test-driver.log`.

## Autorizare Per Flow si Gateway Tunnel

Pentru fiecare conexiune redirectionata de WFP, agentul face autorizare per flow inainte sa deschida tunel catre Gateway.

Pasii efectivi:

1. Proxy-ul primeste conexiunea redirectionata.
2. WFP raporteaza destinatia originala: IP sintetic, port, protocol si optional PID-ul procesului.
3. Proxy-ul cauta IP-ul sintetic in tabela de rute generata din catalog.
4. `resourceStreamConnector` cere exact o sesiune user autentificata activa.
5. Daca nu exista sesiune, agentul inregistreaza promptul local `Sign in required to access ...` si inchide conexiunea.
6. Daca exista sesiune, agentul incarca enrollment record-ul si foloseste clientul PDP mTLS partajat.
7. Agentul apeleaza PDP:
   - service: `trustcloud.agent.AgentAuthorizationService`;
   - method: `AuthorizeResource`;
   - path complet: `/trustcloud.agent.AgentAuthorizationService/AuthorizeResource`.
8. Pentru `allow`, PDP returneaza material de sesiune Gateway.
9. Agentul deschide sau refoloseste un tunnel mTLS/yamux catre Gateway.
10. Agentul deschide un stream yamux si trimite mesajul `connect`.
11. Daca Gateway raspunde `connected`, proxy-ul face copy bidirectional intre aplicatie si stream.
12. Daca PDP sau Gateway refuza, conexiunea locala este inchisa.

Payload `AuthorizeResource`:

- `access_token`, adica `agent_session_token`;
- `resource_id`;
- `protocol`;
- `port`;
- `process.pid`;
- `process.name`;
- `process.path`;
- `process.sha256`;
- `process.signer`.

Decizii PDP acceptate:

- `allow`;
- `deny`;
- `step_up_required`.

Raspuns `AuthorizeResource` parsat de agent:

- `decision`;
- `reason`;
- `risk_score`;
- `matched_rule`;
- `policies`;
- `session_id`;
- `session_token`;
- `gateway_id`;
- `gateway_endpoint`;
- `gateway_server_name` sau aliasul `gateway_tls_server_name`;
- `resource_id`;
- `protocol`;
- `port`;
- `expires_at`;
- `step_up_challenge_id`;
- `step_up_url`;
- `step_up_methods`;
- `step_up_required_acr`;
- `step_up_expires_at`.

Cache sesiune de resursa:

- se pastreaza doar raspunsuri `allow`;
- cheia cache include `agent_session_id`, `resource_id`, `protocol`, `port` si `processKey`;
- `processKey` prefera `sha256`, apoi `path`, apoi `name`, apoi `pid`;
- cache-ul este folosit doar daca `session_id`, `session_token`, `resource_id`, `protocol` si `port` sunt prezente;
- o sesiune cache-uita trebuie sa fie valida cel putin pana la `now + 1m`;
- daca Gateway intoarce `session_invalid`, `session_expired` sau `session_store_unavailable`, agentul sterge cache-ul, cere autorizare fortata si incearca o singura data din nou.

Renewal sesiune de resursa:

- pentru stream-uri deschise, agentul porneste un renewal goroutine;
- renewal-ul ruleaza la `expires_at - 1m`;
- daca timpul calculat este mai mic de `5s`, asteapta minim `5s`;
- fiecare apel de renewal are timeout `15s`;
- renewal-ul refoloseste `AuthorizeResource` fortat;
- daca PDP intoarce alt `session_id`, agentul logheaza replacement si opreste renewal-ul pentru stream-ul curent;
- daca decizia nu mai este `allow`, cache-ul este sters.

Step-up per flow:

- la `step_up_required`, agentul nu deschide stream catre Gateway;
- inregistreaza mesajul `Additional security verification is required to access ...`;
- salveaza `step_up_url`, `resource_id`, target-ul si expirarea in user-session;
- Tray-ul poate deschide URL-ul daca trece validarile HTTPS/host/path descrise in fluxul de login;
- urmatoarea incercare de acces declanseaza o noua autorizare.

Gateway tunnel:

- transport: TCP + TLS 1.3 + client certificate + yamux;
- certificatul client este certificatul de device curent;
- CA-ul folosit este `GatewayCAFile` daca exista intern, altfel `pdp_ca_file`;
- daca nu exista `ServerName`, se foloseste host-ul din `gateway_endpoint`;
- timeout implicit `10s`;
- keepalive yamux implicit `10s`;
- reconnect backoff initial `1s`, maxim `30s`;
- `ClientBuild` implicit este `dev`.

Handshake Gateway `hello`:

- mesajul are `type = hello`;
- `client_version = 1.0`;
- `client_app = trustagent`;
- `client_build`;
- `features = ["pa-provisioned-connect", "yamux", "mtls"]`;
- raspunsul poate include `server_version`;
- raspunsul poate include `min_client_version`;
- raspunsul poate include `max_client_version`;
- raspunsul poate include `features`;
- raspunsul poate include `message`;
- daca raspunsul are `code` diferit de gol si de `ok`, tunnel-ul este refuzat.

Mesaj Gateway `connect`:

- `type = connect`;
- `remote_addr`;
- `remote_port`;
- `session_id`;
- `session_token`;
- `resource_id`;
- `protocol`;
- `device_id`;
- `process`.

Raspuns Gateway `connect`:

- succes doar daca `status = connected` si `code` este gol sau `ok`;
- altfel se construieste `GatewayError` cu `status`, `code`, `message`, `acr_values`.

Coduri Gateway cunoscute de agent:

- `ok`;
- `auth_required`;
- `auth_invalid`;
- `step_up_required`;
- `policy_denied`;
- `risk_denied`;
- `session_invalid`;
- `session_expired`;
- `session_store_unavailable`;
- `trustcloud_unreachable`;
- `rate_limited`;
- `resource_unknown`;
- `resource_unavailable`;
- `dns_not_found`;
- `dns_resolve_failed`;
- `internal_error`;
- `bad_request`.

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
Pe Windows, fiecare script de colectare este rulat prin `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <script>`.
Timeout-ul pentru fiecare comanda PowerShell de colectare este `20s`.
Daca procesul PowerShell scrie stderr si iese cu eroare, eroarea returnata include si textul stderr.
Output-ul este asteptat ca JSON compact; pentru liste, collector-ul accepta atat array JSON, cat si un singur obiect JSON.

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

Descrieri exacte:

- la eroare: `Operating system details are unavailable`;
- la succes/warning: descrierea este chiar caption-ul OS-ului raportat, de exemplu valoarea `Caption` din `Win32_OperatingSystem`.

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

Descrieri exacte:

- search COM indisponibil fara numar de update-uri: `Windows Update Agent search is unavailable`;
- serviciu oprit sau alta stare: `Windows Update service is <ServiceStatus>`;
- reboot pending: `Windows updates require a reboot`;
- update-uri lipsa: `<n> visible Windows updates are not installed`;
- stare buna: `Windows Update service is running and no visible updates are pending`.

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

Descrieri exacte:

- la eroare de colectare: `Password and lock policy is unavailable`;
- cand Windows nu raporteaza niciun camp relevant: `Password and lock policy was not reported by Windows`;
- motive warning posibile, concatenate cu `; `:
  - `minimum password length is below 8`;
  - `password complexity is not enabled`;
  - `account lockout threshold is not enforced tightly`;
  - `machine inactivity lock is not enforced within 15 minutes`;
- stare buna: `Password complexity, account lockout and inactivity lock policies are enforced`.

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

Descrieri exacte:

- la eroare de colectare: `Disk encryption status is unavailable`;
- stare buna: `System drive is protected by BitLocker`;
- protectie pornita, criptare incompleta: `Disk encryption protection is on but encryption is not complete`;
- protectie oprita: `System drive BitLocker protection is off`.

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

Descrieri exacte:

- la eroare sau lista goala: `Firewall status is unavailable`;
- stare buna: `Firewall is enabled for all profiles`;
- stare critica: `Firewall is disabled for one or more profiles`.

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

Descrieri exacte:

- la eroare de colectare: `Antivirus status is unavailable`;
- fara produs detectat: `Antivirus product was not detected`;
- Defender sanatos: `Microsoft Defender real-time protection is enabled`;
- Defender incomplet: `Microsoft Defender is installed but protection is not fully healthy`;
- pentru produs third-party, descrierea este `ProductName` raportat de Windows Security Center.

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

Detalii watcher Windows:

- watcher-ul ruleaza tot prin `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass`;
- scriptul seteaza `$ErrorActionPreference = 'SilentlyContinue'`;
- inregistrarea se face cu `Register-WmiEvent`;
- daca inregistrarea unui event esueaza, scriptul scrie `trustagent-watcher_error_<Id>`;
- evenimentele de servicii folosesc `__InstanceModificationEvent WITHIN 3`;
- `wuauserv` este urmarit ca `trustagent-windows_updates_service`;
- `mpssvc` este urmarit ca `trustagent-firewall_service`;
- `WinDefend` este urmarit ca `trustagent-antivirus_service`;
- Windows Firewall policy este urmarit in namespace `root/default`, `RegistryTreeChangeEvent`, hive `HKEY_LOCAL_MACHINE`, root path `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`;
- BitLocker este urmarit in root path `SYSTEM\CurrentControlSet\Control\BitLocker`;
- Microsoft Defender este urmarit in root path `SOFTWARE\Microsoft\Windows Defender`;
- password/lock policy este urmarit in root path `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`;
- Windows Update reboot/policy este urmarit in root path `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`;
- bucla watcher face `Wait-Event -Timeout 60`;
- dupa primirea unui event, scrie `SourceIdentifier` pe stdout si sterge eventul cu `Remove-Event`;
- in Go, reason-ul primit este trim-uit, prefixul `trustagent-` este eliminat, `:` si spatiile devin `_`, apoi textul este facut lowercase;
- daca reason-ul este gol, runner-ul il normalizeaza la `event`;
- daca channel-ul de trigger este plin, watcher-ul arunca triggerul si logheaza debug `Device data trigger dropped because sync queue is full`.

Transmiterea catre PDP:

- service gRPC: `trustagent.device.DeviceDataService`;
- method: `ReportDeviceData`;
- path complet: `/trustagent.device.DeviceDataService/ReportDeviceData`;
- transport: gRPC peste clientul PDP mTLS partajat;
- certificatul mTLS este certificatul de device instalat dupa enrollment;
- PDP nu are incredere in `device_id` din payload, ci il compara cu identitatea din certificatul mTLS.

Payload `ReportDeviceData`:

- `device_id`;
- `hostname`;
- `os`;
- `checks`;
- `checks[].name`;
- `checks[].status`;
- `checks[].description`;
- `checks[].details`;
- `collected_at` in RFC3339Nano UTC, doar daca timpul nu este zero.

Cache si client:

- runner-ul tine minte ultimul fingerprint trimis;
- tine minte timpul ultimului report periodic;
- tine minte `last_enrolled_device_id`;
- daca device ID-ul enrollment-ului se schimba, cache-ul de fingerprint si heartbeat se reseteaza;
- clientul gRPC device-data este refolosit cat timp `device_id` si `device_cert_thumbprint` raman aceleasi;
- daca enrollment-ul dispare sau `device_id` este gol, clientul se inchide si state-ul runner-ului se reseteaza;
- coada de trigger are capacitate `8`;
- un trigger este normalizat la `event` daca reason-ul primit este gol;
- `reportReason` devine `device_data_changed` cand fingerprint-ul s-a schimbat, cu exceptia triggerelor `startup` si `enrollment`.

Postura locala dupa colectare:

- serviciul compara raportul curent cu `device_data_policy` primit in catalog;
- `required_checks` este comparat case-insensitive dupa numele checkului;
- daca `required_check_status` lipseste, statusul cerut implicit este `good`;
- daca un check cerut lipseste, motivul devine `<check> is not reported`;
- daca un check cerut are alt status, motivul devine `<check> is <status>, required <required_status>`;
- daca postura nu mai satisface politica, serviciul goleste protected resources cu timeout `10s`;
- mesajul userului devine `Protected resource access is paused because device posture no longer satisfies policy.`;
- daca postura revine la conformitate, serviciul reaplica ultimul catalog cu timeout `15s`;
- dupa restaurare, mesajul devine `Device posture restored. Protected resource access is available.`;
- evenimentul remote `access.revoked` cu reason `device_posture_changed` foloseste acelasi mecanism de suspendare locala.

## Evenimente Agent de la PDP

Serviciul urmareste evenimente remote pentru fiecare sesiune user autentificata.

Pornire watcher:

- worker-ul ruleaza numai daca exista `agentEventsFactory`, `userSessions` si `enrollment`;
- sincronizarea watcher-elor are loc la fiecare `2s`;
- pentru fiecare sesiune autentificata cu `agent_session_id` si `agent_session_token`, serviciul porneste un stream separat;
- daca sesiunea dispare local, watcher-ul este anulat;
- daca stream-ul se termina, watcher-ul se sterge din mapa si poate fi recreat la urmatoarea sincronizare daca sesiunea inca exista.

Contract gRPC:

- service: `trustagent.events.AgentEventsService`;
- method: `Watch`;
- path complet: `/trustagent.events.AgentEventsService/Watch`;
- stream: server-streaming;
- request initial: `access_token`, `session_id`;
- transport: gRPC peste clientul PDP mTLS partajat.

Campuri de eveniment parsate:

- `type` sau aliasul `event_type`;
- `message`;
- `reason`;
- `session_id`;
- `device_id`;
- `user_id`;
- `tenant_id`;
- `resource_id`;
- `gateway_id`;
- `policy_id`;
- `action`.

Tipuri tratate explicit:

- `access.revoked`;
- `catalog.invalidated`.

`access.revoked`:

- daca evenimentul nu are `session_id`, se aplica sesiunii urmarite;
- daca `session_id` se potriveste cu sesiunea curenta, agentul revoca sesiunea locala remote;
- mesaj implicit: `Protected resource access was revoked. Sign in again to continue.`;
- daca reason-ul este `device_posture_changed`, agentul suspenda si protected resources local;
- daca revocarea locala reuseste, stream-ul se opreste.

`catalog.invalidated`:

- agentul cere din nou catalogul pentru sesiunea curenta;
- daca refresh-ul reuseste, protected resources sunt reaplicate;
- daca PDP raspunde `Unauthenticated` sau `PermissionDenied`, sesiunea este revocata local cu mesajul `Your session is no longer valid. Sign in again to access protected resources.`;
- pentru alte erori, agentul logheaza warning si pastreaza watcher-ul.

## Suprafata Externa Folosita de Agent

gRPC fara certificat de device, inainte de enrollment:

- `/trustagent.enrollment.EnrollmentService/StartSession`;
- `/trustagent.enrollment.EnrollmentService/SessionStatus`;
- `/trustagent.enrollment.EnrollmentService/CompleteSession`.

HTTP mTLS pentru renewal certificat:

- `POST /api/enroll/renew`.

gRPC mTLS dupa enrollment:

- `/trustagent.session.AgentSessionService/StartSession`;
- `/trustagent.session.AgentSessionService/SessionStatus`;
- `/trustagent.session.AgentSessionService/ClaimSession`;
- `/trustagent.session.AgentSessionService/GetCatalog`;
- `/trustagent.session.AgentSessionService/RevokeSession`;
- `/trustagent.device.DeviceDataService/ReportDeviceData`;
- `/trustagent.events.AgentEventsService/Watch`;
- `/trustcloud.agent.AgentAuthorizationService/AuthorizeResource`.

Gateway:

- TCP + TLS 1.3 + client certificate;
- yamux peste TLS;
- stream `hello`;
- stream `connect`.

IPC local:

- named pipe `\\.\pipe\trust-agent`;
- protocol JSON framed;
- versiune `trust-agent-ipc.v1`;
- limita mesaj 1 MiB.

Driver local:

- device path `\\.\TrustAgentWfp`;
- apply rules;
- clear rules;
- query original target.

## Index Tehnic de Simboluri

Aceasta sectiune este un index mecanic pentru numele exportate/importante din cod. Functionalitatile sunt explicate in sectiunile de mai sus; indexul exista ca sa fie usor de cautat simbolurile exacte.

Tipuri exportate si contracte:

- `AgentDashboard`, `AgentEventsClient`, `AgentEventsClientFactory`, `AgentStatus`, `ApplyRequest`, `AuthenticatedSession`, `AuthorizeRequest`, `AuthorizeResponse`, `CatalogInfo`, `CatalogResource`, `CatalogResponse`, `CertificateRenewalRequest`, `CertificateRenewalResponse`, `ClaimSessionRequest`, `ClaimSessionResponse`, `ClientCertificateProvider`, `ClientFactory`, `CollectorFunc`, `ConnectRequest`, `ConnectResponse`, `Controller`, `DashboardConnection`, `DashboardRequest`, `Dependencies`, `Destination`, `DeviceDataCheck`, `DeviceDataCollector`, `DeviceDataPolicy`, `DeviceDataSyncClient`, `DeviceDataSyncClientFactory`, `DeviceDataWatcher`, `DeviceIdentity`, `DeviceIDProvider`, `Dialer`, `DNSControl`, `EnrollmentCompleteSessionRequest`, `EnrollmentCompleteSessionResponse`, `EnrollmentCSR`, `EnrollmentInfo`, `EnrollmentProvider`, `EnrollmentRecordProvider`, `EnrollmentSessionStatusRequest`, `EnrollmentSessionStatusResponse`, `EnrollmentStartSessionRequest`, `EnrollmentStartSessionResponse`, `EnrollmentState`, `FileEnrollmentStore`, `GetCatalogRequest`, `GRPCClient`, `GRPCEnrollmentClient`, `GUIApp`, `HelloRequest`, `HelloResponse`, `HTTPRenewalClient`, `InstallCertificateRequest`, `InstalledCertificate`, `LocalEnrollmentCheck`, `LogoutUserSessionRequest`, `LogoutUserSessionResponse`, `PeerIdentity`, `PingRequest`, `PingResponse`, `ProcessIdentity`, `ProtectedResourcesManager`, `QueryResolver`, `RenewalClient`, `ResourceMapping`, `ResourceStreamRequest`, `ResponseError`, `RevokeSessionRequest`, `RuntimeState`, `ServerOptions`, `ServiceConfig`, `SessionStatusRequest`, `SessionStatusResponse`, `StartEnrollmentInteractiveRequest`, `StartEnrollmentInteractiveResponse`, `StartSessionRequest`, `StartSessionResponse`, `StartUserLoginInteractiveRequest`, `StartUserLoginInteractiveResponse`, `StatusRequest`, `StreamRequest`, `TrafficInterceptor`, `TrayConfig`, `WatchRequest`.

Functii si metode exportate:

- `AcceptedCount`, `ActiveAuthenticatedSession`, `ActiveAuthenticatedSessions`, `ApplyCatalog`, `ApplyMappings`, `ApplyPolicy`, `ApplyRules`, `CallRequest`, `ClearAuthenticatedStepUp`, `ClientCertificate`, `ConnectTo`, `ConnectToServerName`, `ContextWithPeerIdentity`, `CreateCertificateRenewalCSR`, `CreateEnrollmentCSR`, `DashboardSnapshot`, `DecodeBody`, `DecodeRequest`, `DecodeResponse`, `DeniedCount`, `Dial`, `DialPath`, `EncodeBody`, `EnsureMappings`, `Execute`, `HandleIPC`, `InstallDeviceCertificate`, `IsServiceContext`, `ListenAt`, `LoadServiceConfig`, `LoadTrayConfig`, `LocalAddr`, `LocalDNSAddress`, `LookupSyntheticIP`, `MarkAuthenticatedResourceDenied`, `MarkAuthenticatedStepUpAllowed`, `NewClient`, `NewController`, `NewDefaultClient`, `NewDefaultCollector`, `NewDefaultDeviceIdentity`, `NewDefaultWatcher`, `NewErrorResponse`, `NewFileEnrollmentStore`, `NewGRPCClientFromConnection`, `NewGRPCEnrollmentClient`, `NewGUIApp`, `NewHTTPRenewalClient`, `NewManager`, `NewRequest`, `NewRequestID`, `NewResponse`, `NewRunner`, `NewServer`, `NewTLSConfig`, `NormalizedType`, `OpenResourceStream`, `PeerIdentityFromContext`, `PipePath`, `PipeSecurityDescriptor`, `ReadFrame`, `RefreshCatalog`, `RenewCertificate`, `RenewCertificateIfNeeded`, `ResolveOriginalDestination`, `RevokeRemote`, `RouteCount`, `RunCertificateRenewal`, `RunService`, `Save`, `ServeConn`, `SetAuthenticatedMessage`, `SetAuthenticatedStepUp`, `SetRoutes`, `SignEnrollmentProof`, `Snapshot`, `StartInteractive`, `SupportedOperations`, `WriteFrame`, `WriteJSON`.

Constante, statusuri si valori exportate/importante:

- `Caption`, `CodeAuthInvalid`, `CodeAuthRequired`, `CodeBadRequest`, `CodeDNSNotFound`, `CodeDNSResolveFailed`, `CodeInternalError`, `CodeOK`, `CodePolicyDenied`, `CodeRateLimited`, `CodeResourceUnavailable`, `CodeResourceUnknown`, `CodeRiskDenied`, `CodeSessionExpired`, `CodeSessionInvalid`, `CodeSessionStoreUnavailable`, `CodeStepUpRequired`, `CodeTrustCloudUnreachable`, `DecisionAllow`, `DecisionDeny`, `DecisionStepUpRequired`, `DefaultCallTimeout`, `DefaultCertificateRenewBefore`, `DefaultCertificateRenewCheckInterval`, `DefaultCertificateRenewTimeout`, `DefaultCGNATCIDR`, `DefaultChangeScanInterval`, `DefaultDeviceKeyName`, `DefaultDevicePath`, `DefaultExpiryRevokeLead`, `DefaultExpiryRevokeTimeout`, `DefaultInterval`, `DefaultPollInterval`, `DefaultProxyListenAddress`, `DefaultTimeout`, `DeviceDataStatusCritical`, `DeviceDataStatusGood`, `DeviceDataStatusUnavailable`, `DeviceDataStatusWarning`, `ErrorCodeInternal`, `ErrorCodeInvalidRequest`, `ErrorCodeServiceUnavailable`, `ErrorCodeUnsupported`, `ErrPoolExhausted`, `ErrResourceNotInCatalog`, `ProofType`, `ProtocolMaxClientVersion`, `ProtocolMinClientVersion`, `ServiceDescription`, `ServiceDisplayName`, `ServiceName`, `StatusClaimed`, `StatusCritical`, `StatusDegraded`, `StatusDenied`, `StatusDisabled`, `StatusDriverMissing`, `StatusError`, `StatusGood`, `StatusReady`, `StatusReadyForDeviceProof`, `StatusReadyToClaim`, `StatusStarting`, `StatusStopped`, `StatusUnavailable`, `StatusWaiting`, `StatusWaitingForIDPDiscovery`, `StatusWaitingForUserLogin`, `StatusWarning`, `TypeAccessRevoked`, `TypeCatalogInvalidated`, `UserSessionStateAuthenticated`, `UserSessionStateAuthenticating`, `UserSessionStateFailed`, `UserSessionStateSignedOut`.

Literaluri si API-uri Windows importante:

- `powershell.exe`, `-NoProfile`, `-NonInteractive`, `-ExecutionPolicy`, `Bypass`;
- `ncrypt.dll`, `NCryptOpenStorageProvider`, `NCryptCreatePersistedKey`, `NCryptFinalizeKey`, `NCryptOpenKey`, `NCryptExportKey`, `NCryptSetProperty`, `NCryptSignHash`, `NCryptFreeObject`, `NCryptDeleteKey`;
- `crypt32.dll`, `CertSetCertificateContextProperty`;
- `user32.dll`, `FindWindowW`, `FlashWindowEx`;
- `ECCPUBLICBLOB`, `bcryptECCPublicBlob`, `bcryptECDSAPublicP256`;
- watcher reasons: `trustagent-windows_updates_service`, `trustagent-firewall_service`, `trustagent-antivirus_service`, `trustagent-firewall_policy`, `trustagent-bitlocker_policy`, `trustagent-antivirus_policy`, `trustagent-password_lock_policy`, `trustagent-windows_updates_reboot_required`;
- mesaje/statusuri interne: `authentication_failed_or_policy_denied`, `waiting_for_catalog`, `stopping`, `nrpt_rules`, `catalog_version`, `retry_in`.

Tipuri interne relevante:

- `accessPromptState`, `agentEventWatcher`, `authenticatedSessionProvider`, `cachedProcessIdentity`, `cryptKeyProvInfo`, `deviceDataState`, `disabledController`, `driverController`, `ecdsaSignature`, `enrollmentProofPayload`, `flashWindowInfo`, `flowAuthorizer`, `gatewayTunnel`, `guiWindowConfig`, `handleConn`, `localAccessState`, `ncryptSigner`, `peerIdentityContextKey`, `processIdentityResolver`, `proxyServer`, `resourceSessionCacheKey`, `resourceSessionRenewal`, `resourceSessionRenewConn`, `resourceStreamConnectorConfig`, `routeTable`, `tunnelConnection`, `tunnelKey`, `unsupportedController`, `windowsDeviceIdentity`, `windowsService`.

Functii si metode interne relevante:

```text
accessPromptResourceID, accessPromptTarget, accessPromptTargetForResource,
acquireCertificatePrivateKey, acquireResourceSessionRenewal, allocateLocked,
antivirusCheck, applyDoHPolicies, applyNRPT, applyNRPTWithCmdlets,
applyPlatform, applyServiceConfig, applyTrayConfig,
authenticatedSessionExpiryWait, authorizePayload, authorizeResourceSession,
authorizeResponseFromStruct, authorizerFor, boolFromMap, cacheable,
cachedDeviceDataReport, cacheDeviceDataReport, cachedResourceSession,
canonicalEnrollmentProof, catalogPolicyForLocalPosture, catalogResources,
certificateAllowsClientAuth, certificateDERBlocks, clearLocalAccessSuspension,
clearStepUpLocked, clientForLogout, clientPurpose, cloneDeviceDataReport,
cloneProcessIdentity, cloneReport, closeLocked, closePDPClient, closeSession,
closeSessionLocked, closeTunnelConnection, closeWrite, collectDeviceData,
collectExpiredLocked, collectWindowsOSInfo, completeEnrollmentSession,
connectLocked, connectToLocked, contextError, copyBidirectional, copyMapping,
createCSRWithSigner, createNCryptSignerWithProvider, currentProcessIdentity,
dashboardDeviceData, dashboardEnrollment, decodeDestinationPayload,
deleteEmptyLegacyNRPTKey, deleteLegacyNRPTKeys, deletePersistedDeviceKey,
dependenciesWithDefaults, detailsFromMap, deviceDataCollectorFromDependencies,
deviceDataPayload, deviceDataRevision, deviceDataSatisfiesPolicy,
deviceDataSyncCollector, deviceDataSyncConfig, deviceIdentityURI,
deviceIoControl, diskEncryptionCheck, dnsServerFromListenAddress,
emitDashboardUpdates, encodeApplyRequest, encodeConnectionQuery,
encodeECDSASignature, endpointURL, enforceLocalDevicePosture,
enrollmentConfig, ensureClient, ensureEnrollmentClient, ensureNCryptSigner,
ensureRenewalClient, eventFromStruct, expireAuthenticatedSession, fileSHA256,
fileSigner, findCertificateByThumbprint, finishResourceSessionRenewal,
firewallCheck, firstNonEmpty, firstNonEmptyServiceString, firstNonEmptyString,
firstPEMCertificate, firstPositiveDuration, flowAuthorizationClientFromPDP,
flowAuthorizationProcess, forgetResourceSession, forgetResourceSessionID,
gatewayTunnel, gatewayTunnelProcess, handleAgentEvent, handleQuery,
helloLocked, intFromMap, isLocalTrafficProtectionUnavailable,
isRetryableGatewaySessionError, isStepUpRequired,
keepEnrolledAfterTransientCheckFailure, lastKnownDashboard, loadConfig,
loadRootCAs, localUserKey, logEvent, loggerOrDefault, mapField, mappingTTL,
markLocalAccessSuspended, markStepUpExpired, matchesDashboardFallbackSession,
namedPipeClientIdentity, ncryptCreatePersistedECDSAP256Key,
ncryptECDSAPublicKey, ncryptSetPropertyDWORD, ncryptSignHashECDSA,
newBaseService, newProxyServer, newResourceStreamConnector, newRouteTable,
normalizeConfig, normalizeDeviceDataStatus, normalizeDNSServer,
normalizedProtocol, normalizeHost, normalizeResources, normalizeRoute,
normalizeTrustedStepUpHosts, normalizeWatchReason, notifyEnrolled,
nrptNamesFromCatalog, nrptNameValue, numberField, openLocalMachineMyStore,
openNCryptSigner, openNCryptSignerWithProvider, operatingSystemCheck,
optionalConfigDuration, originFromURL, parseECDSAPublicBlob,
passwordLockCheck, pathOrDefault, pauseProtectedResourcesFromRemoteEvent,
pdpClientConfig, peerIdentityForConnection, pollEnrollmentSession,
pollSession, powerShellString, processImagePath, protectedResourcesConfig,
protocolName, protocolNumber, queryRedirectContextFromSocket, randomURLToken,
readFileConfig, recordAuthenticationRequired, recordResourceAllowed,
recordResourceDenied, recordStepUpRequired, recordStream,
refreshResourceSessionID, releaseLocked, releaseResourceSessionRenewal,
rememberDashboard, rememberResourceSession, renewalErrorMessage,
renewCertificateWithLogging, renewResourceSessionUntilReleased,
reportFingerprint, requiredConfigDuration, resetEnrollment,
resolveConfigFilePaths, resolveLocked, resolveProcessIdentity,
resolveProcessIdentityCached, resolveReferencedConfigPath,
resolverPolicyFromCatalog, resourceAccessDeniedMessage,
resourceSessionProcessKey, resourceSessionUsable, routeKey, runAgentEvents,
runDeviceDataSync, runEnrollmentSession, runGUI, runPowerShell,
runPowerShellJSONList, runPowerShellJSONMap, runProtectedResources,
runSession, runtimeForSession, secondsField, securityVerificationExpiredMessage,
securityVerificationFailedMessage, serviceConfigFromConfig,
sessionForKeyLocked, setBrowserDoHOff, setCatalogApplied,
setCertificateKeyProviderInfo, setEnrollmentEnrolled, setEnrollmentFailure,
setEnrollmentMessage, setEnrollmentRuntime, setError, setFailure, setMessage,
setRunning, setStartedAt, setState, setStatus, sha256Hex, shutdown, sidHash,
signalReady, signedOutAccessPrompt, signedOutRuntime, snapshotByKeyLocked,
splitHostPort, startAuthenticatedSessionExpiryWatcher,
startStepUpExpiryWatcherLocked, stepUpDisplayTarget, stepUpMatches,
stringField, stringFromMap, stringListField, stringSliceField,
syncAgentEventWatchers, timeField, tlsConfigFor, tokenLogonSessionID,
trafficConfigFromConfig, trafficMappingsFromDNS, transition,
trayOptionsFromConfig, triggerReason, trustedStepUpHosts, tunnelKey,
uint32ToIP, unavailableCheck, unavailableDashboard, unavailableDeviceDataReport,
unavailableEnrollmentState, usableEnrollmentRecord, userSessionClientFactory,
userSessionConfig, userSessionFailureMessage, validateAllowedResourceAuthorization,
validateHTTPSURL, validateStartResponse, validateStartSessionResponse,
validStepUpURL, valueToString, wailsAppOptions, waitForDisconnect,
waitUntilDNSReady, waitUntilProxyReady, warnResourceSession,
watchAgentSessionEvents, windowsUpdatesCheck, withResourceSessionRenewal
```

Index fisiere production scanate:

```text
agent\wfp-driver\README.md
agent\packaging\trust-agent-setup.iss
agent\internal\tray\window_attention_windows.go
agent\internal\tray\window_attention_other.go
agent\internal\tray\gui_config.go
agent\internal\tray\gui.go
agent\cmd\agent\trust_agent_windows_amd64.syso
agent\internal\app\options.go
agent\internal\shared\ipc\peer.go
agent\internal\shared\ipc\messages.go
agent\internal\shared\ipc\framing.go
agent\internal\shared\ipc\enrollment_contracts.go
agent\internal\shared\ipc\device_data_contracts.go
agent\internal\shared\ipc\dashboard_contracts.go
agent\internal\shared\ipc\pipe_windows.go
agent\internal\shared\ipc\pipe_acl_windows.go
agent\internal\shared\ipc\peer_windows.go
agent\internal\tray\frontend\package.json.md5
agent\internal\shared\ipc\status_contracts.go
agent\internal\tray\frontend\index.html
agent\internal\shared\ipc\server.go
agent\internal\shared\ipc\user_session_contracts.go
agent\internal\tray\frontend\package.json
agent\internal\tray\frontend\package-lock.json
agent\internal\service\resource_stream_connector.go
agent\internal\tray\frontend\postcss.config.cjs
agent\internal\tray\frontend\tailwind.config.cjs
agent\internal\tray\frontend\vite.config.js
agent\internal\service\device-data\collector_other.go
agent\internal\service\device-data\types.go
agent\internal\service\device-data\watcher_other.go
agent\internal\service\enrollment\types.go
agent\internal\service\enrollment\renewal_http.go
agent\internal\service\enrollment\manager.go
agent\internal\service\enrollment\device_identity_windows.go
agent\internal\service\pdp-transport\transport.go
agent\internal\service\host\types.go
agent\internal\service\host\scm_windows.go
agent\internal\service\host\scm_other.go
agent\internal\service\device_data.go
agent\internal\tray\frontend\src\styles.css
agent\internal\service\gateway-tunnel\messages.go
agent\internal\tray\frontend\src\main.jsx
agent\internal\service\gateway-tunnel\manager.go
agent\internal\service\device_posture.go
agent\internal\service\traffic-interception\types.go
agent\internal\service\traffic-interception\rules.go
agent\internal\service\traffic-interception\proxy.go
agent\internal\service\traffic-interception\process_identity_windows.go
agent\internal\service\traffic-interception\process_identity_other.go
agent\internal\service\traffic-interception\manager.go
agent\internal\tray\frontend\src\App.jsx
agent\internal\tray\frontend\src\assets\trust-agent-mark.svg
agent\internal\service\agent-events\types.go
agent\internal\service\wfp-control\controller_other.go
agent\internal\service\wfp-control\controller_windows.go
agent\internal\service\dns-resolver\resolver.go
agent\internal\service\dns-resolver\server.go
agent\internal\tray\frontend\src\lib\dashboard.js
agent\internal\service\wfp-control\payload.go
agent\internal\service\wfp-control\types.go
agent\internal\service\dns-control\platform_windows.go
agent\internal\service\dns-control\platform_other.go
agent\internal\service\dns-control\manager.go
agent\internal\tray\frontend\src\components\SecurityView.jsx
agent\internal\service\usersession\manager.go
agent\internal\service\usersession\types.go
agent\internal\service\flow-authorization\types.go
agent\internal\service\protected-resources\manager.go
```

Index C/WFP driver:

```text
TRUSTAGENT_CGNAT_BASE, TRUSTAGENT_CGNAT_MASK, TRUSTAGENT_IPV4_LOOPBACK,
TRUSTAGENT_RULE_SET, TRUSTAGENT_TCP_PROTOCOL, TRUSTAGENT_WFP_CALLOUT_CONNECT_V4_KEY,
TRUSTAGENT_WFP_DEVICE_NAME, TRUSTAGENT_WFP_FILTER_CONNECT_V4_KEY,
TRUSTAGENT_WFP_MAGIC, TRUSTAGENT_WFP_PROVIDER_KEY, TRUSTAGENT_WFP_SUBLAYER_KEY,
TRUSTAGENT_WFP_SYMBOLIC_LINK, TRUSTAGENT_WFP_VERSION,
FWPM_CALLOUT0, FWPM_FILTER_CONDITION0, FWPM_FILTER0, FWPM_PROVIDER0,
FWPM_SESSION0, FWPM_SUBLAYER0, FWPS_CALLOUT_NOTIFY_TYPE, FWPS_CALLOUT1,
FWPS_CLASSIFY_OUT0, FWPS_CONNECT_REQUEST0,
FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF, FWPS_CONNECTION_REDIRECT_STATE,
FWPS_CONNECTION_REDIRECTED_BY_SELF, FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL,
FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS,
FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT, FWPS_FILTER1,
FWPS_INCOMING_METADATA_VALUES0, FWPS_INCOMING_VALUES0,
FWPS_IS_METADATA_FIELD_PRESENT, FWPS_METADATA_FIELD_PROCESS_ID,
FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE, FWPS_RIGHT_ACTION_WRITE,
STATUS_BUFFER_TOO_SMALL, STATUS_FWP_ALREADY_EXISTS,
STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_DEVICE_REQUEST,
STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
TrustAgentAddCallout, TrustAgentAddConnectFilter, TrustAgentAddProvider,
TrustAgentAddSublayer, TrustAgentClassifyConnectRedirectV4,
TrustAgentEnsureWfpRegistered, TrustAgentEvtDeviceContextCleanup,
TrustAgentFindMatchingRule, TrustAgentFreeRules, TrustAgentGetDeviceContext,
TrustAgentNotifyFn, TrustAgentQueryOriginalTarget, TrustAgentRedirectConnectV4,
TrustAgentRegisterWfp, TrustAgentRuleMatches, TrustAgentSetBlock,
TrustAgentSetPermit, TrustAgentStoreRules, TrustAgentUnregisterWfp,
TrustAgentWasAlreadyRedirected
```

Identificatori low-level C/WDF/FWP scanati:

```text
actionType, applicableLayer, attributes, BOOLEAN, break, bytesReturned,
calloutId, CalloutIdV4, calloutKey, ClassifyContext, classifyFn,
classifyHandle, ClassifyOut, conditions, conditionValue, CTL_CODE,
DeviceInit, deviceName, displayData, DriverObject, endif, EngineHandle,
EvtCleanupCallback, ExAllocatePoolWithTag, ExFreePoolWithTag, expectedLength,
FIELD_OFFSET, fieldKey, FILE_ANY_ACCESS, filterCondition, filterId,
FilterIdV4, FilterKey, FlowContext, FWP_ACTION_BLOCK, FWP_ACTION_PERMIT,
FWP_MATCH_EQUAL, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
FwpmCalloutAdd0, FwpmCalloutDeleteByKey0, FwpmEngineClose0, FwpmEngineOpen0,
FwpmFilterAdd0, FwpmFilterDeleteById0, FwpmFilterDeleteByKey0, fwpmk,
FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmSubLayerAdd0,
FwpmSubLayerDeleteByKey0, FwpsAcquireClassifyHandle0,
FwpsAcquireWritableLayerDataPointer0, FwpsApplyModifiedLayerData0,
FwpsCalloutRegister1, FwpsCalloutUnregisterById0, fwpsk,
FwpsQueryConnectionRedirectState0, FwpsRedirectHandleCreate0,
FwpsRedirectHandleDestroy0, FwpsReleaseClassifyHandle0, ifndef,
incomingValue, InFixedValues, initguid, InMetaValues, InputBuffer,
InputBufferLength, InputLength, IoControlCode, IOCTL_TRUSTAGENT_WFP_CLEAR_RULES,
LayerData, layerKey, LocalIpv4, LocalPort, localRedirectContextSize,
localRedirectHandle, looks, matchedRule, matchType, MetaValues,
METHOD_BUFFERED, NonPagedPoolNx, NotifyType, NT_SUCCESS, ntddk,
numFilterConditions, oldRules, OriginalIpv4, OriginalPort, outputBuffer,
OutputBufferLength, OutputLength, PDRIVER_OBJECT, pragma, providerKey,
PTRUSTAGENT_DEVICE_CONTEXT, PTRUSTAGENT_RULE_SET, PTRUSTAGENT_WFP_APPLY_RULES,
PTRUSTAGENT_WFP_CONNECTION_QUERY, PTRUSTAGENT_WFP_ORIGINAL_TARGET,
PTRUSTAGENT_WFP_RULE, PUNICODE_STRING, PWDFDEVICE_INIT, queueConfig,
rawContext, RedirectHandle, redirectRecords, redirectState, RegistryPath,
remoteAddress, remoteAddressAndPort, remoteIpv4, RemotePort, Reserved,
Reserved2, rights, RPC_C_AUTHN_WINNT, RTL_NUMBER_OF, RtlCopyMemory,
RtlInitUnicodeString, RtlUlongByteSwap, RtlUshortByteSwap, RtlZeroMemory,
rulesCopy, RuleSet, rulesLength, runtimeCallout, S_addr, sin_addr,
sin_family, sin_port, sizeof, subLayerKey, switch, symbolicLink,
SyntheticIpv4, syntheticRange, tuple, typedef, UINT_PTR, ULONG,
UNREFERENCED_PARAMETER, using, v4AddrMask, valueCount, wchar_t,
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME, WDF_DRIVER_CONFIG, WDF_DRIVER_CONFIG_INIT,
WDF_IO_QUEUE_CONFIG, WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE,
WDF_OBJECT_ATTRIBUTES, WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE,
WdfDeviceCreate, WdfDeviceCreateSymbolicLink, WdfDeviceInitAssignName,
WdfDeviceWdmGetDeviceObject, WdfDriverCreate, WdfIoQueueCreate,
WdfIoQueueGetDevice, WdfRequestCompleteWithInformation,
WdfRequestRetrieveInputBuffer, WdfRequestRetrieveOutputBuffer,
WdfSpinLockAcquire, WdfSpinLockCreate, WdfSpinLockRelease
```

Identificatori C/WDK primitivi si tipuri auxiliare care apar in driver:

```text
AF_INET, NTAPI, NULL, PVOID, SOCKADDR_IN, UINT16, UINT64, VOID,
WDF_NO_HANDLE, WDF_NO_OBJECT_ATTRIBUTES, WDFOBJECT, WDFQUEUE
```

Index frontend React/helpers:

```text
AgentLoadingScreen, BrandMark, BrandWordmark, buildHealthRows, checkingTitle,
dismissToast, enqueueToast, EnrolledScreen, EnrolledSignInScreen,
enrollmentStateOf, findCheck, formatDateTime, formatResourceEndpoint,
formatStatusLabel, formatStepUpToastMessage, getRemediation, handleHide,
handleLogout, handleStartEnrollment, handleStartLogin, HealthFooter,
HealthHeader, HealthList, HealthRow, healthSubtitle, healthTitle,
isActionable, isDeviceEnrolled, isPipeUnavailable, isWailsRuntimeReady,
loadDashboard, matchesCheck, normalizeName, normalizeStatus,
openRemediationUri, RemediationView, requestWindowAttention, ResourcesView,
rowFromCheck, ScreenStatusMessage, sessionToastTitle, sessionToastVariant,
SidebarButton, StatusIcon, StepNumber, toastErrorTitle, ToastItem,
ToastMessage, ToastResourceName, ToastStack, toastTone, UnenrolledScreen,
WindowTitleBar, CHECKS, REMEDIATIONS
```

Variabile locale frontend scanate:

```text
colorClass, content, deniedMatch, displayError, existing, footerText, iconClass,
matchIndex, nextDashboard, osName, problem, selectedRow, sessionMessage, signals,
stepUpMessage, strokeWidth, successMatch, trimmed, unsubscribe,
verificationMatch, waitingForDashboard
```

Index runtime Wails generat:

```text
args, BrowserOpenURL, CanResolveFilePaths, CheckNotificationAuthorization,
CleanupNotifications, ClipboardGetText, ClipboardSetText, EventsEmit,
EventsOff, EventsOffAll, EventsOn, EventsOnce, EventsOnMultiple,
InitializeNotifications, IsNotificationAvailable, LogDebug, LogError,
LogFatal, LogPrint, LogTrace, LogWarning, OnFileDrop, OnFileDropOff,
Quit, RegisterNotificationCategory, RemoveAllDeliveredNotifications,
RemoveAllPendingNotifications, RemoveDeliveredNotification, RemoveNotification,
RemoveNotificationCategory, RemovePendingNotification,
RequestNotificationAuthorization, ResolveFilePaths, ScreenGetAll,
SendNotification, SendNotificationWithActions, WindowCenter,
WindowFullscreen, WindowGetPosition, WindowGetSize, WindowHide,
WindowIsFullscreen, WindowIsMaximised, WindowIsMinimised, WindowIsNormal,
WindowMaximise, WindowReload, WindowReloadApp, WindowSetAlwaysOnTop,
WindowSetBackgroundColour, WindowSetDarkTheme, WindowSetLightTheme,
WindowSetMaxSize, WindowSetMinSize, WindowSetPosition, WindowSetSize,
WindowSetSystemDefaultTheme, WindowSetTitle, WindowShow, WindowToggleMaximise,
WindowUnfullscreen, WindowUnmaximise, WindowUnminimise
```

Index functii PowerShell:

```text
Assert-DriverDeviceHealthy, Copy-AgentConfig, Copy-WithRetry,
Find-InnoSetupCompiler, Get-FirstAssetName, Get-JsonPropertyValue,
Get-OptionalBool, Get-RequiredString, Get-ServiceExecutableDirectory,
Normalize-ViteAssets, Parse-AgentIPAddress, Read-AgentConfig,
Resolve-AgentConfigPath, Resolve-AgentReferencedPath, Resolve-ConfigReferencedPath,
Set-AgentJsonProperty, Set-JsonProperty, Split-AgentHostPort,
Test-AgentCertificateFile, Test-AgentInstallConfig, Test-AgentIPv4CIDR,
Test-DriverDevicePath, Test-GoDuration, Test-TcpPortAvailable,
Test-UdpPortAvailable, Write-Step
```

Module si dependinte Go:

- `go.mod` declara modulul `agent`;
- versiunea Go este `1.25.0`;
- dependinte directe: `github.com/Microsoft/go-winio`, `github.com/hashicorp/yamux`, `github.com/miekg/dns`, `github.com/wailsapp/wails/v2`, `golang.org/x/sys`, `google.golang.org/grpc`, `google.golang.org/protobuf`;
- `go.sum` fixeaza hash-urile modulelor;
- dependintele indirecte includ runtime/build support pentru Wails, WebView2, Echo/Gorilla websocket, crypto/net/text/tools si genproto.

Build tags si comportament non-Windows:

- build tag `windows` este folosit pentru binarul principal, named pipe, peer identity, SCM, device identity, WFP control, DNS control Windows, collector/watcher Windows si process identity Windows;
- build tag `!windows` este folosit pentru stub-uri cross-platform de test/dezvoltare;
- `host/scm_other.go`: `RunService` ruleaza functia primita cu un context local si `IsServiceContext` intoarce `false`;
- `wfp-control/controller_other.go`: controllerul raporteaza `WFP is supported only on Windows`; daca interceptarea este activa, statusul este `driver_missing`;
- `dns-control/platform_other.go`: daca exista DNS names, intoarce `NRPT is available only on Windows`; daca nu exista reguli, este no-op;
- `device-data/collector_other.go`: returneaza doar checkul `Operating System` cu `runtime.GOOS`;
- `device-data/watcher_other.go`: nu emite trigger-e si asteapta pana cand contextul este anulat;
- `window_attention_other.go`: `FlashWindowAttention` este no-op.

Directoare si artefacte speciale:

- `agent\cmd\ipcprobe` exista in workspace ca director gol; in starea curenta nu contine fisiere Go si nu implementeaza o comanda;
- `agent\wfp-driver\trustagent_wfp\x64\Release\trustagent_wfp.tlog` si `agent\wfp-driver\x64\Release\trustagent_wfp.tlog` sunt artefacte MSBuild/WDK generate, nu sursa functionala;
- fisierele `.tlog` contin urme de compilare/link/Inf2Cat/signtool/stampinf si pot aparea dupa build-uri locale.

Inventar directoare scanate:

```text
assets
cmd/agent
cmd/ipcprobe
internal/app
internal/service
internal/service/agent-events
internal/service/device-data
internal/service/device-data-sync
internal/service/dns-control
internal/service/dns-resolver
internal/service/enrollment
internal/service/flow-authorization
internal/service/gateway-tunnel
internal/service/host
internal/service/pdp-client
internal/service/pdp-transport
internal/service/protected-resources
internal/service/traffic-interception
internal/service/usersession
internal/service/wfp-control
internal/shared/ipc
internal/tray
internal/tray/frontend
internal/tray/frontend/src
internal/tray/frontend/src/assets
internal/tray/frontend/src/components
internal/tray/frontend/src/lib
internal/tray/frontend/wailsjs/go
internal/tray/frontend/wailsjs/go/tray
internal/tray/frontend/wailsjs/runtime
packaging
wfp-driver
```

Inventar complet fisiere agent, cu cale relativa normalizata:

```text
AGENT.md
assets/trust-agent.ico
assets/trust-agent-icon.png
cmd/agent/main.go
cmd/agent/trust_agent_windows_amd64.syso
config.json
go.mod
go.sum
install-local-build.ps1
internal/app/config.go
internal/app/options.go
internal/app/options_test.go
internal/app/run.go
internal/service/access_prompt.go
internal/service/agent_events.go
internal/service/agent-events/grpc.go
internal/service/agent-events/types.go
internal/service/constructor.go
internal/service/dashboard.go
internal/service/device_data.go
internal/service/device_posture.go
internal/service/device-data/collector_other.go
internal/service/device-data/collector_windows.go
internal/service/device-data/types.go
internal/service/device-data/watcher_other.go
internal/service/device-data/watcher_windows.go
internal/service/device-data-sync/grpc.go
internal/service/device-data-sync/runner.go
internal/service/dns-control/manager.go
internal/service/dns-control/manager_test.go
internal/service/dns-control/platform_other.go
internal/service/dns-control/platform_windows.go
internal/service/dns-resolver/resolver.go
internal/service/dns-resolver/resolver_test.go
internal/service/dns-resolver/server.go
internal/service/dns-resolver/server_test.go
internal/service/enrollment/device_identity_windows.go
internal/service/enrollment/grpc.go
internal/service/enrollment/manager.go
internal/service/enrollment/renewal_http.go
internal/service/enrollment/renewal_test.go
internal/service/enrollment/types.go
internal/service/flow-authorization/grpc.go
internal/service/flow-authorization/grpc_test.go
internal/service/flow-authorization/types.go
internal/service/gateway-tunnel/manager.go
internal/service/gateway-tunnel/manager_test.go
internal/service/gateway-tunnel/messages.go
internal/service/host/scm_other.go
internal/service/host/scm_windows.go
internal/service/host/types.go
internal/service/ipc_handlers.go
internal/service/pdp-client/client.go
internal/service/pdp-client/client_test.go
internal/service/pdp-transport/transport.go
internal/service/pdp-transport/transport_test.go
internal/service/process_identity.go
internal/service/protected-resources/manager.go
internal/service/protected-resources/manager_test.go
internal/service/resource_stream_connector.go
internal/service/resource_stream_connector_test.go
internal/service/runtime.go
internal/service/service.go
internal/service/service_test.go
internal/service/state.go
internal/service/traffic-interception/manager.go
internal/service/traffic-interception/manager_test.go
internal/service/traffic-interception/process_identity.go
internal/service/traffic-interception/process_identity_other.go
internal/service/traffic-interception/process_identity_windows.go
internal/service/traffic-interception/proxy.go
internal/service/traffic-interception/rules.go
internal/service/traffic-interception/types.go
internal/service/usersession/active_session_test.go
internal/service/usersession/grpc.go
internal/service/usersession/manager.go
internal/service/usersession/stepup_url_test.go
internal/service/usersession/types.go
internal/service/wfp-control/controller_other.go
internal/service/wfp-control/controller_windows.go
internal/service/wfp-control/payload.go
internal/service/wfp-control/payload_test.go
internal/service/wfp-control/types.go
internal/shared/ipc/client.go
internal/shared/ipc/dashboard_contracts.go
internal/shared/ipc/device_data_contracts.go
internal/shared/ipc/enrollment_contracts.go
internal/shared/ipc/framing.go
internal/shared/ipc/messages.go
internal/shared/ipc/messages_test.go
internal/shared/ipc/peer.go
internal/shared/ipc/peer_windows.go
internal/shared/ipc/peer_windows_test.go
internal/shared/ipc/pipe_acl_windows.go
internal/shared/ipc/pipe_windows.go
internal/shared/ipc/protocol.go
internal/shared/ipc/server.go
internal/shared/ipc/status_contracts.go
internal/shared/ipc/transport_test.go
internal/shared/ipc/user_session_contracts.go
internal/tray/client.go
internal/tray/frontend/index.html
internal/tray/frontend/package.json
internal/tray/frontend/package.json.md5
internal/tray/frontend/package-lock.json
internal/tray/frontend/postcss.config.cjs
internal/tray/frontend/src/App.jsx
internal/tray/frontend/src/assets/trust-agent-mark.svg
internal/tray/frontend/src/components/AppLayout.jsx
internal/tray/frontend/src/components/SecurityView.jsx
internal/tray/frontend/src/lib/dashboard.js
internal/tray/frontend/src/main.jsx
internal/tray/frontend/src/styles.css
internal/tray/frontend/tailwind.config.cjs
internal/tray/frontend/vite.config.js
internal/tray/frontend/wailsjs/go/models.ts
internal/tray/frontend/wailsjs/go/tray/GUIApp.d.ts
internal/tray/frontend/wailsjs/go/tray/GUIApp.js
internal/tray/frontend/wailsjs/runtime/package.json
internal/tray/frontend/wailsjs/runtime/runtime.d.ts
internal/tray/frontend/wailsjs/runtime/runtime.js
internal/tray/gui.go
internal/tray/gui_config.go
internal/tray/tray.go
internal/tray/tray_test.go
internal/tray/window_attention_other.go
internal/tray/window_attention_windows.go
packaging/build-enterprise-package.ps1
packaging/install-service.ps1
packaging/Test-AgentConfig.ps1
packaging/trust-agent-setup.iss
reset-local-enrollment.ps1
wfp-driver/build-driver.ps1
wfp-driver/install-test-driver.ps1
wfp-driver/README.md
wfp-driver/trustagent_wfp.c
wfp-driver/trustagent_wfp.h
wfp-driver/trustagent_wfp.inf
wfp-driver/trustagent_wfp.vcxproj
```

Proiect driver VCXPROJ:

- fisier: `agent\wfp-driver\trustagent_wfp.vcxproj`;
- `ProjectGuid = {B80C4A53-7F49-4B97-A9B8-0D08456226A4}`;
- `RootNamespace = trustagent_wfp`;
- `WindowsTargetPlatformVersion = 10.0.26100.0`;
- configuratii: `Debug|x64` si `Release|x64`;
- `ConfigurationType = Driver`;
- `DriverType = KMDF`;
- `PlatformToolset = WindowsKernelModeDriver10.0`;
- `CharacterSet = Unicode`;
- Debug foloseste debug libraries, Release nu;
- warning level `Level4`;
- warnings ca erori: `TreatWarningAsError=true`;
- warnings dezactivate: `4201`, `4214`, `4996`;
- include directories: KM, shared si WDF KMDF `1.35`;
- preprocessor: `NTDDI_VERSION=NTDDI_WIN10`, `_WIN32_WINNT=0x0A00`;
- link libraries: `ntoskrnl.lib`, `hal.lib`, `BufferOverflowK.lib`, `fwpkclnt.lib`, `wdfdriverentry.lib`;
- semnare driver: `FileDigestAlgorithm=sha256`;
- compileaza `trustagent_wfp.c`, include `trustagent_wfp.h`, ambaleaza `trustagent_wfp.inf`;
- targetul `TrustAgentPackageDriverBinary` adauga `$(TargetPath)` in pachet inainte de `DriverPackageTarget`.

Script reset enrollment local:

- fisier: `agent\reset-local-enrollment.ps1`;
- cere PowerShell elevated;
- parametri: `ServiceName`, default `TrustAgent`, si `InstallDir` optional;
- daca `InstallDir` lipseste, il deduce din serviciu sau foloseste `C:\Program Files\TrustAgent`;
- cere artefacte build: `build\trust-agent.exe`, `build\config.json`, `build\pdp-ca.pem`;
- ruleaza preflight `packaging\Test-AgentConfig.ps1 -RepairPaths`;
- opreste serviciul si procesele `trust-agent`;
- copiaza binarul/configul/CA-ul cu retry;
- face backup la `C:\ProgramData\TrustAgent\enrollment.json` in `enrollment.before-reenroll-<timestamp>.json`;
- sterge enrollment state-ul curent;
- sterge certificatele din `LocalMachine\My` cu Subject `CN=dev_...`;
- sterge cheia `TrustAgentDeviceKey` din `Microsoft Platform Crypto Provider`;
- sterge cheia `TrustAgentDeviceKey` din `Microsoft Software Key Storage Provider`;
- sterge regulile NRPT cu `Comment = TRUSTAGENT`;
- ruleaza `ipconfig /flushdns`;
- porneste serviciul;
- porneste `trust-agent.exe`;
- afiseaza SHA256-ul binarului instalat;
- mesaj final asteptat: UI-ul trebuie sa arate `UNENROLLED DEVICE`.

Fisiere generate Wails:

- `agent\internal\tray\frontend\wailsjs\go\models.ts` contine clase TypeScript generate pentru contractele IPC expuse UI-ului;
- `agent\internal\tray\frontend\wailsjs\go\tray\GUIApp.js` si `.d.ts` expun metodele `GetDashboard`, `FlashWindowAttention`, `HideWindow`, `ShowWindow`, `StartEnrollmentInteractive`, `StartUserLoginInteractive`, `LogoutUserSession`;
- `agent\internal\tray\frontend\wailsjs\runtime\runtime.js` si `.d.ts` expun runtime-ul Wails folosit de frontend, inclusiv event bus, log, window control si browser open;
- aceste fisiere sunt generate si nu trebuie editate manual.

Fisiere generate/test mentionate explicit:

```text
agent\AGENT.md
agent\internal\tray\frontend\wailsjs\runtime\runtime.d.ts
agent\internal\tray\frontend\wailsjs\go\tray\GUIApp.d.ts
agent\internal\tray\tray_test.go
agent\internal\app\options_test.go
agent\internal\shared\ipc\transport_test.go
agent\internal\shared\ipc\peer_windows_test.go
agent\internal\shared\ipc\messages_test.go
agent\internal\service\pdp-transport\transport_test.go
agent\internal\service\wfp-control\payload_test.go
agent\internal\service\resource_stream_connector_test.go
agent\internal\service\pdp-client\client_test.go
agent\internal\service\usersession\active_session_test.go
agent\internal\service\enrollment\renewal_test.go
agent\internal\service\service_test.go
agent\internal\service\usersession\stepup_url_test.go
agent\internal\service\dns-control\manager_test.go
agent\internal\service\dns-resolver\server_test.go
agent\internal\service\dns-resolver\resolver_test.go
agent\internal\service\protected-resources\manager_test.go
agent\internal\service\flow-authorization\grpc_test.go
agent\internal\service\gateway-tunnel\manager_test.go
agent\internal\service\traffic-interception\manager_test.go
```

Assets:

- `agent\assets\trust-agent.ico` este copiat in build output si folosit de installer;
- `agent\assets\trust-agent-icon.png` este asset de brand disponibil in repository;
- `agent\internal\tray\frontend\src\assets\trust-agent-mark.svg` este folosit in UI ca logo mark.

Index teste Go:

```text
TestAccessPromptFallsBackToAuthorizationResourceID
TestActiveAuthenticatedSessionIgnoresExpiredSession
TestActiveAuthenticatedSessionRejectsMultipleAuthenticatedSessions
TestActiveAuthenticatedSessionReturnsOnlyAuthenticatedSession
TestAgentDashboardRoundTrip
TestAgentUIDoesNotUseWindowsNotifications
TestApplyRequiresDNSServerForDNSNames
TestAuthenticatedSessionExpiryRevokesAndClears
TestAuthenticatedStepUpDeniedKeepsResourceTarget
TestAuthenticatedStepUpExpirySetsErrorToastMessage
TestAuthenticatedStepUpMessagesIncludeResourceTarget
TestAuthorizePayloadIncludesSessionAndProcess
TestAuthorizeResponseFromStructParsesGatewaySession
TestClientReusesConnectionForSameDeviceCertificate
TestClientServerPingRoundTrip
TestDashboardSnapshotDoesNotFallbackWhenSameUserSessionsAreAmbiguous
TestDashboardSnapshotFallsBackToSameUserSessionWhenPeerKeyIsIncomplete
TestDecodeDestinationPayloadIncludesProcessIDWhenPresent
TestDeviceDataReportRoundTrip
TestEncodeApplyRequestRejectsUnsupportedProtocol
TestEncodeApplyRequestRequiresProxyPID
TestEncodeApplyRequestValidatesProxyAndRules
TestFrameRoundTrip
TestGatewayErrorFormatsStructuredCode
TestLoadRootCAsParsesPEM
TestLoadRootCAsRejectsFileWithoutCertificates
TestLoadServiceConfigAcceptsUTF8BOM
TestLoadServiceConfigAllowsMinimalServiceConfig
TestLoadServiceConfigKeepsAbsolutePDPCAFile
TestLoadServiceConfigLoadsServiceConfig
TestLoadTrayConfigLoadsSharedConfig
TestLoadTrayConfigLoadsTrayConfig
TestManagerAppliesCatalogAfterUnknownDNSLookup
TestManagerAppliesCatalogToResolverAndNRPT
TestManagerAppliesMappingsToWFP
TestManagerAppliesTrafficInterceptionMappingsWhenEnabled
TestManagerClearAttemptsNRPTEvenWhenTrafficClearFails
TestManagerClearsCatalogAndNRPT
TestManagerClearsStaleRulesOnRun
TestNewGUIAppPreservesTimeout
TestNewGUIAppRequiresExplicitTimeout
TestNewManagerDisabledWhenNoGatewayConfigured
TestNewTLSConfigDefaultsToTLS13
TestNewTLSConfigDoesNotDowngradeBelowTLS13
TestNormalizeDNSNames
TestNormalizeDNSServer
TestNRPTNameValueUsesExactResourceFQDN
TestOpenResourceStreamIncludesProvisionedSessionFields
TestOpenResourceStreamKeepsSeparateSessionsPerGateway
TestOpenResourceStreamRequiresProvisionedSessionFields
TestPingRequestRoundTrip
TestProxyPassesWFPProcessIdentityToConnector
TestRefreshCatalogAppliesUpdatedCatalog
TestRefreshKeepsEnrolledStateWhenLocalEnrollmentCheckErrors
TestRemoteRevokeSignsOutAndClearsAccess
TestRenewCertificateIfNeededRenewsAndSavesUpdatedRecord
TestRenewCertificateIfNeededSkipsBeforeRenewalWindow
TestResolverEnsuresMappingsForCatalogResources
TestResolverKeepsSyntheticIPStableAfterTTLWhileResourceIsActive
TestResolverRejectsUnknownResources
TestResolverResolvesOnlyCatalogResources
TestResolverReusesAndPurgesMappings
TestResourceStreamConnectorAuthorizesAndOpensGatewayStream
TestResourceStreamConnectorDoesNotReuseCachedSessionAcrossProcesses
TestResourceStreamConnectorDropsCachedSessionAfterGatewayRejectsIt
TestResourceStreamConnectorRecordsResourceDenied
TestResourceStreamConnectorRecordsStepUpRequired
TestResourceStreamConnectorRequiresAuthenticatedSession
TestResourceStreamConnectorReusesCachedResourceSession
TestResourceStreamConnectorSharesRenewalForSameProvisionedSession
TestRouteTableMapsApplicationProtocolsToTCP
TestRouteTableRejectsInvalidSyntheticIP
TestRuleKey
TestRunRejectsNilManager
TestServeConnAttachesNamedPipePeerIdentity
TestServerReturnsNXDOMAINForUnknownCatalogResource
TestServerReturnsSyntheticARecordForCatalogResource
TestServiceDashboardPromptsSignInWhenEnrolledAndSignedOut
TestServiceDashboardRefreshesUnusableEnrollment
TestServiceDoesNotStartInteractiveEnrollmentWhenAlreadyEnrolled
TestServiceHandlesPing
TestServiceLogoutRevokesSessionAndClearsCatalog
TestServicePausesAndRestoresProtectedResourcesOnLocalPostureChange
TestServiceReportsDeviceDataImmediatelyAfterEnrollment
TestServiceReportsDeviceDataImmediatelyOnDeviceDataSyncTrigger
TestServiceReportsDeviceDataWhenChecksChange
TestServiceReportsUnenrolledStatus
TestServiceReturnsAgentDashboard
TestServiceRunsWithInjectedListener
TestServiceStartsInteractiveEnrollmentAndCompletesInBackground
TestServiceStartsUserLoginAndLoadsCatalog
TestSetFailureUsesFriendlyMessageForMissingWFPDriver
TestUnavailableDashboardPreservesLastKnownDashboard
TestValidStepUpURLRequiresTrustedHTTPSBrowserStepUpURL
TestWailsAppOptionsUsesWindowConfig
```

Tipuri helper/fake folosite in teste:

```text
fakeAuthenticatedSessionProvider, fakeDeviceDataCollector,
fakeDeviceDataSyncClient, fakeDeviceIdentity, fakeDNSControl,
fakeEnrollmentClient, fakeEnrollmentRecordProvider, fakeFlowAuthorizer,
fakeGatewayTunnel, fakeProtectedResources, fakeProxyStreamConnector,
fakeTrafficInterceptor, fakeUserSessionClient, fakeWFPController,
memoryEnrollmentStore, pipeAddr, pipeListener, recordingRenewalClient,
recordingSessionClient, renewalTestIdentity, revokedSession,
sequenceDeviceDataCollector, serviceTestOptions, testEnrollmentStore,
testHandlerFunc
```

Functii helper folosite in teste:

```text
activeRenewalStats, appliedCatalogs, assertSyntheticAnswer,
awaitConnectRequest, captureConnectRequest, clearCount, currentUserSID,
enrolledRecord, escapeJSONPath, exchangeDNS, lastApplied, mustCIDR,
newPipeListener, newTestService, revokeRequests, serviceConfigJSON,
startTestServer, waitForEnrollmentState, waitForManagerDNS, waitForReports,
waitForState, waitForUserSessionState, writeConfig, writeTempPEM, yamuxPair
```

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

