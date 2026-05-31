# Analiza diferente documentatie - implementare

Data verificarii: 2026-05-31

Documentul acesta sincronizeaza descrierea solutiei cu implementarea curenta din cod. Analiza este bazata pe fisierele din repository, in special pe componentele PDP/PA/PE, Agent, Gateway, SCIM/Keycloak si infrastructura Docker.

## Concluzie executiva

Implementarea actuala acopera arhitectura de baza Zero Trust descrisa in documentatie: PDP central, Agent local, Gateway de acces, politici conditionale, MFA/step-up, posture checks, audit si integrare Keycloak/SCIM. Totusi, exista cateva diferente importante care trebuie reflectate clar in documentatie:

1. PDP, PA si PE ruleaza in acelasi proces Go, nu ca servicii separate independente.
2. Pentru accesul la resurse, decizia de autentificare suplimentara este `step_up_required`, nu `mfa_required`.
3. Autentificarea MFA pentru dashboard-ul de administrare este un flux separat, unde API-ul foloseste in continuare starile `mfa_required` si `mfa_setup_required`.
4. Exista o politica globala implicita per tenant, creata automat, care cere step-up pentru utilizatorii noi si pentru accesul implicit.
5. Motorul de politici evalueaza toate regulile relevante si aplica prioritate efectiva `deny` > `step_up_required` > `allow`.
6. Agentul implementeaza interceptare DNS plus WFP pe Windows pentru trafic TCP IPv4, cu IP-uri sintetice din `100.64.0.0/10`.
7. Gateway-ul foloseste TLS 1.3 cu mTLS pentru Agent si yamux pentru multiplexare, dar listener-ul Agent este inca fix pe `:9443`; `public_endpoint` este configurabil si publicat catre Agent.
8. Exista control continuu al sesiunilor: revalidare, revocare la schimbari de postura, politici, resurse, device sau gateway.
9. Resursele accepta tipurile `ssh`, `rdp` si `web`; pentru `web`, catalogul Agentului foloseste protocolul `https` si portul implicit `443`.
10. SCIM este implementat in PDP ca service provider, iar `connectors/keycloak-scim-sync` este un adaptor de laborator care sincronizeaza utilizatori si grupuri din Keycloak.

## Surse principale din cod

| Zona | Fisiere relevante | Observatie principala |
| --- | --- | --- |
| Pornire PDP | `pdp/cmd/pdp/main.go`, `pdp/pa/transport/router.go` | PDP porneste PA, PE, router HTTP/gRPC, broker de evenimente si serviciile de background in acelasi proces. |
| Model decizie | `pdp/models/decision.go` | Deciziile de acces sunt `allow`, `deny`, `step_up_required`. |
| Model politici | `pdp/models/policy.go` | Politicile includ scope-uri, conditii de risc, locatie, retea, autentificare, device posture, sesiune si proces. |
| Evaluare politici | `pdp/pe/evaluation/engine.go` | Regulile potrivite se evalueaza cumulativ; deny are prioritate maxima. |
| Persistenta politici | `pdp/store/policies.go`, `pdp/store/policy_defaults.go` | Exista assignment-uri ordonate si politica globala implicita per tenant. |
| API politici | `pdp/pa/transport/policy_handlers.go` | API-ul valideaza politicile si protejeaza politica globala implicita impotriva modificarilor manuale. |
| UI politici | `pdp/frontend/src/components/Policy*.jsx` | Dashboard-ul permite editarea politicilor, dar nu expune control manual pentru ordinea top/bottom/replace. |
| Admin MFA | `pdp/pa/transport/auth_handlers.go`, `pdp/pa/auth/secret_protector.go` | Login-ul de dashboard are MFA separat, cu TOTP protejat prin AES-GCM. |
| Step-up resurse | `pdp/pa/stepup.go`, `pdp/pa/transport/agent_stepup_browser_handlers.go` | Step-up-ul pentru resurse este challenge-based si poate folosi TOTP sau WebAuthn. |
| Agent | `agent/internal/service/*` | Agentul gestioneaza sesiuni, catalog, DNS, WFP, token-uri de sesiune si tunel Gateway. |
| Gateway | `gateway/internal/dataplane/server.go`, `gateway/internal/config/config.go` | Gateway-ul valideaza sesiuni PA, token-uri, certificat mTLS si revocari. |
| Catalog resurse | `pdp/pa/catalog/catalog.go`, `pdp/pa/resources/service.go` | Catalogul include doar resurse permise sau cu step-up, nu resurse deny. |
| Evenimente si revocari | `pdp/pa/events/broker.go`, `pdp/pa/enforcement/enforcer.go`, `pdp/pa/transport/session_revocation.go` | Brokerul intern publica invalidari, revocari si schimbari de postura. |
| SCIM/Keycloak | `pdp/pa/transport/scim_handlers.go`, `connectors/keycloak-scim-sync/main.go` | PDP expune SCIM, iar sincronizatorul citeste din Keycloak si scrie in PDP. |
| Infrastructura | `docker-compose.yml`, `infrastructure/web-app/*`, `.env.example` | Mediul de laborator include Vault, Keycloak, PDP, Gateway, DNS, SSH, RDP si web-app HTTPS. |

## Diferente si clarificari fata de documentatie

### 1. Separarea PDP/PA/PE este logica, nu operationala

Documentatia poate sugera ca PDP, PA si PE sunt servicii separate. In cod, ele sunt module distincte, dar ruleaza in acelasi binar/proces PDP.

Implementare curenta:

- `pdp/cmd/pdp/main.go` initializeaza configuratia, baza de date, Vault/PKI, store-urile, serviciile PA si PE si router-ul.
- PE este invocat din serviciile PA pentru decizii de acces.
- Brokerul de evenimente si enforcement-ul continuu ruleaza local in acelasi proces.

Impact in documentatie:

- Se poate pastra separarea conceptuala PDP/PA/PE.
- Trebuie precizat ca implementarea actuala este monolitica la nivel runtime.
- Pentru productie multi-nod, brokerul in-memory si challenge-urile in-memory trebuie inlocuite sau completate cu mecanisme distribuite.

### 2. Decizia de acces cu autentificare suplimentara este `step_up_required`

Pentru accesul la resurse, modelul de decizie nu foloseste `mfa_required`. In `pdp/models/decision.go`, deciziile sunt:

- `allow`
- `deny`
- `step_up_required`

`step_up_required` contine metodele acceptate, ACR-ul cerut, durata maxima, politica aplicata si date despre completarea step-up-ului.

Nuanta importanta:

- Pentru dashboard-ul de administrare, fluxul de login foloseste starile `mfa_required` si `mfa_setup_required`.
- Pentru resurse prin Agent/Gateway, termenul corect este `step_up_required`.

### 3. Dashboard MFA si resource step-up sunt fluxuri diferite

Autentificarea MFA pentru dashboard:

- este implementata in `pdp/pa/transport/auth_handlers.go`;
- verifica parola administratorului;
- respinge credentialele implicite `admin` / `admin`;
- poate cere `mfa_setup_required` daca administratorul nu are TOTP;
- poate cere `mfa_required` daca TOTP exista deja;
- foloseste provocari MFA cu TTL si numar maxim de incercari;
- protejeaza secretele TOTP si credentialele WebAuthn serializate prin `pdp/pa/auth/secret_protector.go`.

Step-up-ul pentru resurse:

- este creat de PA in timpul autorizarii unui flow Agent;
- returneaza catre Agent o pagina HTTPS de step-up;
- foloseste challenge-uri in-memory cu TTL implicit de 5 minute;
- dupa completare, validitatea este controlata de `MaxAgeSeconds`, implicit 600 secunde;
- poate permite enrollment inline pentru TOTP sau WebAuthn daca metoda nu este configurata pentru utilizator.

### 4. Politica globala implicita exista si trebuie documentata

Store-ul creeaza automat o politica globala pentru fiecare tenant:

- ID politic: `policy-global-default-{tenantID}`;
- ID assignment: `assignment-global-default-{tenantID}`;
- scope: organizatie;
- action: `step_up_required`;
- metode MFA: `totp`, `webauthn`;
- regula pentru utilizatori noi: cere enrollment;
- `order_index` mare, pentru a actiona ca fallback.

API-ul protejeaza aceasta politica:

- nu poate fi stearsa manual;
- nu poate fi asignata manual;
- assignment-ul implicit nu poate fi eliminat prin fluxurile normale.

Documentatia trebuie sa explice ca accesul nu porneste de la "allow implicit", ci de la o politica globala de step-up/fallback.

### 5. Ordinea si prioritatea politicilor sunt mai complexe decat o lista simpla

Implementarea foloseste assignment-uri pe mai multe niveluri:

- `resource_group`
- `resource`
- `group`
- `organization`

Ordinea efectiva foloseste prioritatea nivelului si `order_index`. Backend-ul suporta plasare prin `order_placement` cu valori precum `top`, `bottom` si `replace`.

Limitare UI:

- componenta `PolicyApplyModal.jsx` trimite in prezent `order_placement: ""`;
- dashboard-ul nu expune inca un control explicit pentru top/bottom/replace;
- utilizatorul vede informatii despre evaluarea mai multor politici, dar nu controleaza manual ordinea avansata.

### 6. Motorul de evaluare aplica deny-first si step-up ca rezultat cumulativ

`pdp/pe/evaluation/engine.go` nu se opreste la prima regula `allow`. El evalueaza regulile potrivite, calculeaza risc si combina controale de sesiune.

Prioritatea efectiva:

1. lipsa health check-urilor cerute sau regula `deny` produce `deny`;
2. conditiile de retea blocate produc `deny`;
3. cerintele de autentificare/risc pot produce `step_up_required`;
4. regulile `allow` permit accesul doar daca nu exista o cerinta mai puternica;
5. daca nu exista nicio regula potrivita, decizia este `deny`.

Pentru conditiile de retea, ordinea este:

1. retele blocate;
2. retele care cer MFA/step-up;
3. retele care sar peste MFA;
4. retele permise;
5. deny pentru restul.

### 7. Politicile includ si conditii de proces, dar semnatura nu este inca folosita complet

Modelul de politica si Agentul pot transmite identitatea procesului:

- PID;
- cale executabil;
- nume proces;
- hash SHA-256;
- user SID;
- session ID.

Politica poate verifica:

- daca identitatea procesului este obligatorie;
- nume de procese permise sau blocate;
- hash-uri permise sau blocate.

Limitare curenta:

- campul de semnatar exista in structuri, dar Agentul lasa in prezent semnatarul gol;
- verificarea Authenticode nu este implementata in enforcement-ul curent.

### 8. Session controls si enforcement continuu sunt implementate

Politicile pot seta controale de sesiune prin `SessionPolicyControls`:

- durata maxima a sesiunii;
- interval de revalidare;
- revocare la schimbare de postura;
- revocare la crestere de risc.

`pdp/pa/sessions/manager.go` creeaza sau reinnoieste sesiuni de resursa si persista controalele relevante. `pdp/pa/enforcement/enforcer.go` asculta evenimente si reevalueaza sesiunile.

Sesiunile pot fi revocate cand:

- se schimba postura device-ului;
- se modifica politicile;
- se modifica sau se dezactiveaza o resursa;
- un device este revocat;
- un gateway este revocat;
- riscul creste peste pragul permis.

Revocarea publica evenimente si trimite comenzi catre Gateway prin registrul de control.

### 9. Catalogul Agentului nu contine toate resursele existente

Catalogul generat pentru Agent este filtrat de politici:

- include doar resurse enabled;
- include resurse cu decizie `allow` sau `step_up_required`;
- exclude resursele cu deny neconditionat;
- include politica de date de device necesara pentru evaluari ulterioare;
- publica `policy_epoch`, TTL, IP sintetic si protocol.

Pentru tipul `web`, catalogul map-eaza resursa la:

- protocol `https`;
- port implicit `443`;
- `external_url` valid doar daca este HTTPS.

### 10. Agentul implementeaza DNS privat, interceptare WFP si sesiuni locale

Implementare curenta Agent:

- mentine sesiuni de utilizator si device;
- obtine catalogul de resurse de la PDP;
- creeaza inregistrari DNS sintetice din `100.64.0.0/10`;
- foloseste NRPT/WFP pe Windows pentru rutare catre proxy-ul local;
- rezolva destinatia originala pentru conexiuni TCP;
- transmite catre PDP contextul flow-ului si identitatea procesului;
- cache-uieste sesiuni de resursa permise;
- reinnoieste sesiunile inainte de expirare;
- deschide tunel yamux catre Gateway numai dupa autorizare.

Limitari importante:

- controller-ele WFP sunt Windows-specific;
- interceptarea efectiva documentata in cod este pentru TCP IPv4;
- UDP, QUIC, IPv6 complet si DoH necesita extindere/hardening;
- verificarea semnaturii executabilelor nu este inca activa.

### 11. Token-ul de sesiune Agent este legat de device si certificat

PDP emite sesiuni Agent cu token-uri legate de context:

- audience `trustagent-api`;
- purpose `trustagent.session`;
- scope-uri precum `catalog:read`, `device-data:write`, `events:read`, `flow:authorize`, `session:renew`, `session:revoke`;
- `device_id`;
- thumbprint-ul certificatului mTLS prin `cnf` / `x5t#S256`;
- SID hash si context de logon Windows unde este disponibil.

Autorizarea flow-urilor verifica token-ul Agentului, certificatul mTLS si scope-ul `flow:authorize`.

### 12. Securitatea paginii de step-up este mai stricta decat o redirectionare simpla

Paginile de step-up pentru Agent includ masuri explicite:

- URL-ul acceptat de Agent trebuie sa fie HTTPS;
- path-ul trebuie sa fie `/browser/step-up/...`;
- host-ul trebuie sa fie de incredere, derivat din server name-ul TLS PDP sau endpoint;
- paginile seteaza headere `no-store`;
- exista protectie CSRF;
- validarea origin/referrer foloseste public origin;
- cookie-ul `tc_stepup_auth` este HttpOnly, Secure si SameSite;
- reautentificarea federata foloseste PKCE, nonce si `prompt=login`;
- subiectul extern intors de IdP trebuie sa corespunda aceluiasi utilizator/tenant.

### 13. WebAuthn este implementat pentru step-up, dar politica configurabila este inca simplificata

Codul poate inregistra si verifica credentiale WebAuthn pentru step-up:

- credentialele sunt protejate la stocare;
- completarea challenge-ului poate include AAGUID;
- se colecteaza attachment si nivel de strength;
- se poate detecta folosirea unei chei hardware/cross-platform.

Limitare curenta:

- API-ul si UI-ul de politici expun in principal selectia metodelor `totp` si `webauthn`;
- nu exista inca in UI un control complet pentru cerinte fine de tip AAGUID permis, attachment obligatoriu sau strength minim.

### 14. Gateway-ul valideaza sesiuni PA si certificat mTLS

Gateway-ul:

- asculta conexiuni Agent pe `:9443`;
- cere TLS 1.3 si mTLS;
- sincronizeaza seriale de certificate revocate;
- valideaza sesiunea PA provisionata pentru resource/protocol/port/device;
- verifica token-ul de sesiune primit de la Agent;
- verifica potrivirea dintre device ID si certificatul client;
- aplica limite de conexiuni si banda;
- inchide relay-uri la expirare, nerevalidare sau revocare;
- ruleaza revalidare periodica de sesiune;
- are bucla de reinnoire certificat Gateway.

Clarificare pentru documentatie:

- `public_endpoint` este configurabil prin config/env si este publicat catre Agent;
- listener-ul intern pentru Agent ramane fix in cod la `:9443`.

### 15. Certificarea si PKI sunt integrate cu Vault

Implementarea foloseste Vault/PKI pentru:

- certificate device;
- certificate gateway;
- verificari mTLS;
- revocare certificate;
- reinnoire certificate Gateway.

Pentru secretele MFA, codul foloseste AES-GCM cu prefix `enc:v1:`. Cheia poate fi:

- locala persistenta, in data dir;
- data key protejat prin Vault Transit;
- in-memory in scenarii fara data dir.

Exista si migrare pentru chei legacy plaintext.

### 16. Organizatiile si accesul admin sunt filtrate in API

Modelele includ tenant/organizatie si membership-uri. API-urile de administrare filtreaza resurse, politici, sesiuni si audit in functie de organizatiile la care administratorul are acces.

Consecinta:

- un admin nu vede implicit toate organizatiile daca nu are membership relevant;
- documentatia trebuie sa descrie acest control ca RBAC/organization scoping pentru dashboard.

### 17. SCIM este implementat ca endpoint PDP plus sincronizator Keycloak

PDP expune endpoint-uri SCIM:

- `/scim/v2/{tenant}/Users`;
- `/scim/v2/{tenant}/Groups`.

Autentificarea se face cu bearer token din configuratia IdP. Implementarea suporta operatii uzuale pentru users/groups, filtre si media type `application/scim+json`.

`connectors/keycloak-scim-sync`:

- citeste utilizatori si grupuri din Keycloak;
- scrie in PDP prin SCIM;
- foloseste `externalId` bazat pe ID-ul Keycloak;
- poate dezactiva utilizatorii lipsa;
- poate sterge grupurile lipsa;
- sare peste service accounts;
- ruleaza periodic.

Aceasta nu este o integrare SCIM nativa outbound din Keycloak, ci un adaptor local pentru laborator.

### 18. Mediul Docker include mai multe resurse demo decat descrierile initiale

`docker-compose.yml` include:

- Vault;
- Keycloak;
- PDP;
- Gateway;
- CoreDNS public si privat;
- resursa RDP demo;
- resursa SSH demo;
- resursa web HTTPS demo;
- profil optional `directory-sync` pentru sincronizarea Keycloak-SCIM.

Resursa web este servita prin `infrastructure/web-app` si asculta HTTPS in reteaua privata.

### 19. Auditul are lant hash, dar nu are ancora externa

Implementarea de audit foloseste evenimente si hash-chain pentru detectarea alterarii in baza locala. Totusi, nu exista in cod o ancora externa de tip WORM, timestamp authority sau publicare intr-un sistem imutabil extern.

Documentatia trebuie sa formuleze auditul ca tamper-evident local, nu ca imutabilitate criptografica externa completa.

### 20. Evenimentele CAEP/revocation sunt locale in proces

Brokerul de evenimente este in-memory:

- gestioneaza topic-uri precum `session.deleted`, `policy.updated`, `resources.updated`, `health.changed`, `device.revoked`, `gateway.revoked`;
- filtreaza evenimentele trimise Agentului;
- transforma unele evenimente in `access.revoked` sau `catalog.invalidated`;
- poate pierde mesaje pentru subscriberi lenti prin drop oldest.

Pentru productie distribuita, documentatia ar trebui sa mentioneze nevoia unui broker persistent/distribuit.

## Ce este aliniat cu documentatia

Implementarea confirma urmatoarele cerinte arhitecturale:

- accesul la resurse este mediat de Agent si Gateway, nu prin expunere directa;
- deciziile sunt centralizate in PDP/PE;
- device posture este parte din contextul deciziei;
- accesul poate cere MFA/step-up;
- se foloseste mTLS intre Agent/Gateway/PDP;
- resursele sunt izolate in reteaua privata;
- politicile pot combina utilizator, grup, locatie, retea, risc, postura si sesiune;
- exista revocare si invalidare de catalog;
- integrarea Keycloak/SCIM permite popularea identitatilor;
- Vault este folosit pentru PKI si poate proteja chei operationale.

## Limitari care trebuie mentionate explicit

1. PA si PE nu sunt microservicii separate in implementarea actuala.
2. Challenge-urile de step-up, unele sesiuni de browser si brokerul de evenimente sunt in-memory.
3. Gateway Agent listener este fix pe `:9443`, chiar daca endpoint-ul public este configurabil.
4. WFP/interceptarea este orientata pe Windows si TCP IPv4.
5. UDP, QUIC, IPv6 complet si DoH nu sunt acoperite complet.
6. Semnatura proceselor nu este verificata inca, desi campurile exista.
7. WebAuthn are date de assurance in cod, dar UI-ul de politici nu expune inca toate controalele fine.
8. UI-ul nu expune control manual pentru ordinea assignment-urilor, desi backend-ul il suporta.
9. Auditul este tamper-evident local, fara ancora externa.
10. SCIM sync este adaptor de laborator pentru Keycloak, nu o capabilitate nativa Keycloak outbound.
11. Agentul are endpoint-uri PDP pentru certificate/device, dar reinnoirea automata completa a certificatului Agent trebuie verificata separat in fluxul operational curent.

## Recomandari de actualizare a documentatiei

1. Inlocuieste referirile la `mfa_required` pentru accesul la resurse cu `step_up_required`; pastreaza `mfa_required` doar pentru login-ul de dashboard.
2. Descrie PDP/PA/PE ca module logice rulate in acelasi proces.
3. Adauga sectiune despre politica globala implicita si comportamentul default deny/step-up.
4. Actualizeaza capitolul de politici cu prioritatea deny-first si evaluarea cumulativa.
5. Adauga resource type `web` si resursa demo HTTPS din Docker.
6. Explica filtrarea catalogului Agentului pe baza politicilor.
7. Documenteaza token binding-ul sesiunii Agent si scope-urile tokenului.
8. Adauga controalele continue de sesiune si revocarea pe evenimente.
9. Clarifica limitele Agentului: WFP Windows, TCP IPv4, fara semnatura Authenticode activa.
10. Clarifica Gateway: TLS 1.3 mTLS, yamux, sesiuni PA, listener `:9443`, `public_endpoint` configurabil.
11. Marcheaza brokerul de evenimente, challenge-urile step-up si unele stari operationale drept single-process/in-memory.
12. Actualizeaza integrarea Keycloak/SCIM ca sincronizator dedicat inclus in repository.

## Status final

Documentatia tehnica poate afirma ca solutia implementeaza un flux Zero Trust functional cu MFA/step-up, policy evaluation, posture checks, Gateway mTLS, resurse private si integrare Keycloak/SCIM. Pentru acuratete, trebuie evitate formularile care sugereaza:

- servicii PA/PE complet separate operational;
- `mfa_required` ca decizie pentru acces la resurse;
- suport complet pentru toate protocoalele IP;
- broker CAEP distribuit;
- audit imutabil ancorat extern;
- control complet WebAuthn assurance in UI;
- ordonare manuala a assignment-urilor direct din dashboard.

Implementarea curenta este potrivita ca prototip/laborator avansat si baza solida pentru productie, cu hardening necesar in zonele distribuite, operationale si de acoperire protocolara.
