# TrustCloud PDP - documentatie tehnica detaliata

Acest document descrie componenta `pdp` asa cum este implementata in codul curent. PDP-ul contine in acelasi binar rolurile de Policy Administrator, Policy Enforcement Orchestrator si Policy Decision Point: primeste context de la administratori, agenti si gateway-uri, evalueaza politici Zero Trust, emite decizii, administreaza sesiuni si impinge revocari prin evenimente.

Documentatia este intentionat foarte detaliata. Include comportamentul efectiv din cod, valorile implicite, validarile, fluxurile HTTP/gRPC, modelele persistente si interactiunile intre servicii.

## 1. Rolul PDP in platforma

PDP-ul este serviciul central de decizie si administrare pentru TrustCloud. El:

- porneste un server HTTPS/gRPC peste TLS 1.3;
- isi obtine cheia privata si certificatele din Vault PKI/Transit;
- expune dashboard-ul administrativ si API-urile admin;
- autentifica administratorii locali, passkey-urile si fluxurile federate OIDC;
- gestioneaza organizatii, IdP-uri, utilizatori sincronizati, grupuri, gateway-uri, resurse, politici si assignment-uri;
- accepta rapoarte de dispozitiv de la TrustAgent;
- gestioneaza enrollment-ul dispozitivelor si al gateway-urilor;
- emite tokenuri JWT pentru administratori, agenti si enrollment;
- evalueaza fiecare cerere de acces prin motorul PE;
- creeaza, reinnoieste sau revoca sesiuni de acces;
- trimite comenzi de provisioning/revocare catre gateway-uri;
- publica evenimente interne pentru invalidarea catalogului si enforcement continuu;
- pastreaza un audit log cu hash chain.

In cod, PDP-ul este impartit in aceste zone principale:

- `cmd/pdp/main.go`: bootstrap runtime, PKI, store, server.
- `config`: configuratie, defaulturi si override-uri din variabile de mediu.
- `models`: structurile de date comune.
- `store`: persistenta SQLite si migrari.
- `pa`: Policy Administrator si serviciile lui.
- `pe`: Policy Engine si calcul de risc.
- `pa/transport`: HTTP, gRPC, middleware si dashboard.
- `pa/dashboard`: aplicatia React/Vite servita de PDP.

## 2. Bootstrap si runtime

Fisierul de intrare este `pdp/cmd/pdp/main.go`.

La pornire se executa, in ordine:

1. Se incarca `config.json` cu `config.LoadConfig`.
2. Se aplica defaulturile prin `ApplyDefaults`.
3. Se aplica override-urile din variabile de mediu prin `ApplyEnvironmentOverrides`.
4. Se creeaza directorul de date configurat, cu permisiuni `0700`.
5. Se restaureaza sau creeaza cheia privata PDP prin Vault Transit:
   - cheia este salvata criptat in `cfg.PDPKeyEncryptedPath`;
   - operatia foloseste `pki.RestoreOrCreateKey`;
   - cheia este folosita pentru certificatul serverului PDP.
6. PDP-ul se auto-inroleaza in Vault PKI:
   - rol PKI: `cfg.PKIRolePDP`;
   - FQDN: `cfg.PDPFQDN`;
   - CA: `cfg.PKICAFile`;
   - server name Vault: `cfg.PKIServerName`.
7. Certificatul PDP si CA-ul sunt salvate prin `pki.SaveEnrolledCert`.
8. Certificatul TLS curent este tinut intr-un `atomic.Pointer[tls.Certificate]`.
9. Se porneste loop-ul de reinnoire certificat cu `pki.SelfEnrollLoop`.
10. La fiecare certificat nou, pointerul atomic este actualizat, deci serverul TLS poate servi certificatul nou fara restart.
11. Se deschide store-ul SQLite prin `store.NewWithDatabasePath`.
12. Se ruleaza `InitDB`, care creeaza/migreaza schema.
13. Se porneste cleanup-ul periodic pentru tokenuri revocate, rate limits si pending enrollments.
14. Se construieste `PolicyAdministrator`.
15. Se creeaza optional un admin bootstrap daca `bootstrap_admin.enabled` este true.
16. Se porneste cleanup-ul de sesiuni.
17. Se porneste cleanup-ul de enrollment.
18. Se construieste serverul transport HTTP/gRPC.
19. Se porneste serverul TLS prin `StartTLS`.

Serverul foloseste TLS 1.3 minim. Certificatul prezentat clientilor este obtinut din callback-ul dinamic `GetCertificate`, ceea ce permite rotirea certificatului in runtime.

## 3. Configuratie

Config-ul este citit din `config.json`, apoi completat cu defaulturi si variabile de mediu.

### 3.1 Valori generale

Campuri importante:

- `pdp_fqdn`: FQDN-ul pentru certificatul PDP si pentru public origin cand nu exista alta valoare.
- `pdp_public_host`: host public optional.
- `pdp_public_origin`: origine publica explicita, de forma `https://host[:port]`.
- `pdp_federated_callback_url`: callback OIDC federat.
- `data_dir`: directorul de date, implicit `./data`.
- `db_path`: cale explicita catre SQLite; daca lipseste, se foloseste `data_dir/trustcloud.db`.
- `mtls_ca`: CA-ul folosit pentru verificarea certificatelor client.
- `listen_addr`: adresa HTTP/TLS.
- `runtime`: timeouts, rate limit-uri si TTL-uri operationale.

Artefactele locale configurate sau generate pentru chei si certificate apar de obicei in `data_dir`. Exemple concrete din setup/teste sunt `jwt_signing_key.enc` pentru cheia JWT criptata, `pdp_key.enc` pentru cheia privata PDP criptata prin Transit, `pdp-server-tls-cert.pem` pentru certificatul TLS al PDP si `vault-pki-ca-cert.pem` pentru CA-ul PKI/Vault. Acestea sunt fisiere locale, nu rute HTTP.

Campuri JSON exacte pe grupuri:

- Server si persistenta: `listen_addr`, `pdp_fqdn`, `tls_cert`, `mtls_ca`, `data_dir`, `database_path`, `pdp_key_encrypted_path`.
- Vault/PKI: `pki_url`, `pki_token`, `pki_path`, `pki_role_pdp`, `pki_role_device`, `pki_role_gateway`, `pki_transit_key`, `pki_ca_file`, `pki_server_name`, `pki_timeout`.
- JWT si MFA: `jwt_expiry`, `jwt_transit_key`, `jwt_key_encrypted_path`, `totp_issuer`, `mfa_transit_key`, `mfa_secret_key_encrypted_path`.
- WebAuthn si CORS: `webauthn_rp_id`, `webauthn_rp_name`, `webauthn_rp_origins`, `cors_origins`.
- Sesiuni si security: `session_expiry`, `max_sessions`, `max_login_attempts`, `lockout_duration`.
- Bootstrap admin: `bootstrap_admin.enabled`, `bootstrap_admin.username`, `bootstrap_admin.password`, `bootstrap_admin.email`, `bootstrap_admin.role`.
- Admin auth: `admin_auth.require_mfa`; in config-ul curent este true.
- Dashboard public: `public.device_health_agent_url`, `public.device_health_timeout_ms`, `public.device_health_retry_ms`, `public.federated_callback_url`, `public.oidc_default_scopes`, `public.oidc_default_claim_mapping`, `public.resource_default_ports`.
- Geo lookup: `geo.provider_url`, `geo.http_timeout`, `geo.cache_ttl`, `geo.cache_max_entries`, `geo.same_area_distance_km`, `geo.suspicious_travel_speed_kmh`, `geo.impossible_travel_speed_kmh`.
- Risk scoring: `risk.device_data_critical_after`, `risk.device_data_stale_after`, `risk.device_data_critical_points`, `risk.device_data_stale_points`, `risk.no_device_health_points`, `risk.health_excellent_min`, `risk.health_good_min`, `risk.health_fair_min`, `risk.health_good_points`, `risk.health_fair_points`, `risk.health_poor_points`, `risk.critical_check_points`, `risk.failed_attempts_high`, `risk.failed_attempts_medium`, `risk.failed_attempts_low`, `risk.failed_attempts_high_points`, `risk.failed_attempts_medium_points`, `risk.failed_attempts_low_points`, `risk.business_hours_start`, `risk.business_hours_end`, `risk.business_days`, `risk.outside_business_points`, `risk.night_hours_start`, `risk.night_hours_end`, `risk.night_hours_points`, `risk.new_device_points`, `risk.new_location_points`, `risk.user_baseline_anomaly_points`, `risk.protocol_points`, `risk.unknown_protocol_points`, `risk.impossible_travel_points`, `risk.suspicious_geo_velocity_kmh`, `risk.suspicious_geo_velocity_points`, `risk.max_anomaly_points`, `risk.max_score`.

Valorile publice efective din `pdp/config.json` sunt: `device_health_agent_url=http://127.0.0.1:12080`, `device_health_timeout_ms=3000`, `device_health_retry_ms=5000`, `federated_callback_url=https://localhost:8443/auth/federated/callback`, `oidc_default_scopes="openid profile email"`, claim mapping `username=preferred_username`, `email=email`, `groups=groups`, iar `resource_default_ports` este `web=443`, `ssh=22`, `rdp=3389`.

Valorile geo efective sunt: provider `https://ipapi.co/{ip}/json/`, timeout `3s`, cache TTL `1h`, maxim `10000` intrari in cache, aceeasi arie la `50km`, viteza suspecta la `500km/h` si imposibila la `900km/h`.

Valorile de risc efective sunt: device data critic dupa `30m` cu `30` puncte, device data stale dupa `10m` cu `15` puncte, lipsa health `25` puncte, health excellent minim `80`, good minim `60`, fair minim `40`, good `10` puncte, fair `20`, poor `35`, critical checks `Firewall=5`, `Antivirus=5`, `Disk Encryption=3`, `Password & Lock=2`, failed attempts high/medium/low la `5/3/1` incercari cu `20/10/5` puncte, business hours `08:00-18:00` luni-vineri, outside business `10` puncte, night hours `00:00-06:00` cu `5` puncte, device nou `10`, locatie noua `5`, protocol points `rdp=10`, `ssh=5`, `http=0`, `https=0`, protocol necunoscut `5`, impossible travel `30`, viteza geo suspecta `500km/h` cu `15` puncte, plafon anomalii `25` si scor maxim `100`.

Cand `pdp_public_origin` este setat, config-ul deriva si completeaza:

- callback federat: `<origin>/auth/federated/callback`, daca nu este setat;
- originile WebAuthn;
- RP ID WebAuthn, daca era gol sau localhost;
- lista CORS, prin adaugarea originului public.

### 3.2 Override-uri din variabile de mediu

PDP-ul citeste explicit urmatoarele variabile de mediu:

- `PDP_FQDN`
- `PDP_PUBLIC_HOST`
- `PDP_PUBLIC_ORIGIN`
- `PDP_FEDERATED_CALLBACK_URL`
- `PDP_WEBAUTHN_RP_ID`
- `PDP_WEBAUTHN_RP_ORIGINS`
- `PDP_CORS_ORIGINS`
- `PDP_ADMIN_REQUIRE_MFA`
- `PDP_PKI_URL`
- `PDP_PKI_TOKEN`
- `PDP_PKI_PATH`
- `PDP_PKI_ROLE_PDP`
- `PDP_PKI_ROLE_DEVICE`
- `PDP_PKI_ROLE_GATEWAY`
- `PDP_TRANSIT_KEY`
- `PDP_PKI_CA_FILE`
- `PDP_PKI_SERVER_NAME`

Listele din `PDP_WEBAUTHN_RP_ORIGINS` si `PDP_CORS_ORIGINS` sunt splituite dupa virgula si curatate de spatii.

`PDP_TRANSIT_KEY` este aplicat simultan la cele trei chei Transit folosite de PDP: cheia pentru PKI, cheia pentru JWT si cheia pentru MFA. Daca `mfa_transit_key` lipseste din fisier si nu este suprascris prin env, defaultul intern il copiaza din cheia JWT, iar daca nici aceasta nu exista il copiaza din cheia PKI.

### 3.3 Defaulturi runtime

Defaulturile aplicate in cod includ:

- `event_buffer_size`: `64`; este dimensiunea bufferului folosit de brokerul de evenimente server-sent events.
- `catalog_ttl_seconds`: `300s`; este TTL-ul cache-ului de catalog folosit de serviciul de catalog.
- interval verificare reinnoire certificat: `6h`;
- interval cleanup enrollment: `1m`;
- TTL token OIDC enrollment: `5m`;
- TTL challenge WebAuthn: `5m`;
- cleanup WebAuthn: `2m`;
- cache federation discovery: `6h`;
- timeout HTTP federation: `10s`;
- TTL browser auth session: `5m`;
- max age cookie CSRF: `3600s`;
- window rate limit enrollment: `1m`;
- max incercari enrollment pe window: `5`;
- timeout revocare gateway: `5s`;
- reinnoire sesiune resursa inainte de expiry: `1m`;
- issuer TOTP: `TrustCloud`;
- path secret MFA criptat: `data_dir/mfa_secret.key.enc`;
- validitate certificat gateway: `7` zile;
- TTL token enrollment gateway: `1h`;
- validitate certificat enrollment device: `1` zi;
- TTL browser enrollment session: `5m`.

Pentru MFA admin, defaultul este sigur: `AdminMFARequired()` intoarce true daca valoarea nu este setata explicit la false.

Important: `ApplyDefaults` nu seteaza fallback pentru `jwt_expiry`, `session_expiry`, `max_login_attempts` sau `lockout_duration`. In proiectul curent aceste valori sunt setate explicit in `pdp/config.json`; daca un fisier de configurare le omite, runtime-ul ar folosi valoarea zero a tipului Go, ceea ce pentru tokenuri inseamna expiry imediat.

Tot fara fallback explicit in `ApplyDefaults` sunt si cateva knob-uri runtime operationale: `store_auto_save_interval`, `session_cleanup_interval`, `certificate_renew_before`, timeout-urile HTTP `read`/`write`/`idle`, `auth_rate_limit_window`, `auth_rate_limit_max`, `oidc_authorize_session_ttl`, `oidc_auth_code_ttl`, `oidc_refresh_token_ttl` si `oidc_cleanup_interval`. Pentru acest proiect ele sunt definite in `pdp/config.json`. Daca ar lipsi intr-un config alternativ, ar ramane la zero si ar activa comportamentul specific locului de folosire: expirari imediate pentru tokenuri/sesiuni, rate limit practic nefunctional pentru auth sau tickere cu interval zero acolo unde codul creeaza `time.NewTicker`.

### 3.4 Valori efective din config.json

Fisierul `pdp/config.json` curent configureaza duratele in nanosecunde, fiindca `time.Duration` se serializeaza numeric. Conversiile relevante sunt:

- `pki_timeout = 10000000000`: 10s.
- `jwt_expiry = 3600000000000`: 1h.
- `session_expiry = 600000000000`: 10m.
- `lockout_duration = 900000000000`: 15m.
- `runtime.store_auto_save_interval = 60000000000`: 1m.
- `runtime.session_cleanup_interval = 300000000000`: 5m.
- `runtime.enrollment_cleanup_interval = 60000000000`: 1m.
- `runtime.certificate_renew_before = 86400000000000`: 24h.
- `runtime.http_read_header_timeout = 10000000000`: 10s.
- `runtime.event_buffer_size = 64`: buffer de 64 evenimente pentru brokerul SSE.
- `runtime.catalog_ttl_seconds = 300`: TTL catalog de 300s, adica 5m.
- `runtime.pki_renew_check_interval = 21600000000000`: 6h.
- `runtime.auth_rate_limit_window = 900000000000`: 15m.
- `runtime.auth_rate_limit_max = 10`: maxim 10 cereri auth pe IP/fereastra.
- `runtime.oidc_authorize_session_ttl = 300000000000`: 5m.
- `runtime.oidc_auth_code_ttl = 60000000000`: 60s.
- `runtime.oidc_refresh_token_ttl = 86400000000000`: 24h.
- `runtime.oidc_cleanup_interval = 30000000000`: 30s.
- `runtime.oidc_enrollment_token_ttl = 300000000000`: 5m.
- `runtime.webauthn_challenge_ttl = 300000000000`: 5m.
- `runtime.webauthn_cleanup_interval = 120000000000`: 2m.
- `runtime.federation_cache_ttl = 21600000000000`: 6h.
- `runtime.federation_http_timeout = 10000000000`: 10s.
- `runtime.browser_auth_session_ttl = 300000000000`: 5m.
- `runtime.csrf_cookie_max_age_seconds = 3600`: 1h.
- `runtime.enroll_rate_limit_window = 60000000000`: 1m.
- `runtime.enroll_rate_limit_max = 5`: maxim 5 incercari enrollment pe IP/fereastra.
- `runtime.gateway_revoke_timeout = 5000000000`: 5s.
- `runtime.resource_session_renew_before = 60000000000`: 1m.
- `gateway.certificate_validity_days = 7`: 7 zile.
- `gateway.enrollment_token_ttl = 3600000000000`: 1h.
- `enrollment.certificate_validity_days = 1`: 24h.
- `enrollment.browser_session_ttl = 300000000000`: 5m.
- `geo.http_timeout = 3000000000`: 3s.
- `geo.cache_ttl = 3600000000000`: 1h.
- `risk.device_data_stale_after = 600000000000`: 10m.
- `risk.device_data_critical_after = 1800000000000`: 30m.

`runtime.http_read_timeout`, `runtime.http_write_timeout` si `runtime.http_idle_timeout` sunt `0` in config-ul curent. In Go `http.Server`, valoarea zero inseamna ca timeout-ul respectiv nu este impus de acel camp.

### 3.5 Durata tokenurilor, codurilor si challenge-urilor

Duratele efective in configuratia curenta:

- Token admin dashboard: 1h. Este JWT ES256 generat cu `GenerateAuthTokenWithPurpose`, foloseste `jwt_expiry`, audience `trustcloud`, JTI revocabil si `mfa_done=true` dupa MFA.
- Token pentru passkey enrollment admin: 1h. Este acelasi tip de JWT admin, dar cu purpose `passkey_enrollment`; endpoint-urile de inrolare passkey cer acest purpose.
- Token OIDC access token emis de PDP: 1h. Raspunsul `/auth/token` intoarce `expires_in = 3600`, calculat din `JWTExpiry.Seconds()`.
- Token OIDC ID token emis de PDP: 1h. Este tot JWT PDP; daca exista nonce, tokenul este regenerat cu nonce si acelasi `jwt_expiry`.
- Token agent session: 1h. Este JWT cu audience `trustagent-api`, purpose `trustagent.session`, subject `device:{device_id}`, `mfa_done=true`, scope-uri agent si binding la certificatul mTLS prin `cnf.x5t#S256`.
- Token EST/device enrollment: 5m. Este JWT dedicat cu audience `trustcloud-enrollment`, purpose `device_enrollment`, device_id obligatoriu, JTI obligatoriu si `expires_in = 300`. Este consumat single-use prin `ConsumeTokenOnce`.
- OIDC authorize session: 5m. Este sesiunea in-memory dintre `/auth/authorize` si autentificarea browserului.
- OIDC authorization code: 60s. Codul este single-use; daca este refolosit, este sters si refuzat.
- OIDC refresh token: 24h. Este in-memory, single-use si rotit la fiecare refresh; tokenul vechi este marcat `Used=true`, iar tokenul nou primeste o noua expirare de 24h.
- Admin MFA challenge: 5m. Este in-memory, are ID cu prefix `mfa`, este sters la succes, la expirare sau dupa numarul maxim de incercari.
- WebAuthn challenge session: 5m. Este in-memory, cheia interna este `userID:ceremony:contextID`, iar cleanup-ul ruleaza la 2m.
- Browser agent session request: 5m. Este transaction-ul `srq` creat de `AgentSessionService/StartSession`; claim secret-ul este valid doar pana la expirarea transaction-ului si request-ul este consumat la `ClaimSession`.
- Browser enrollment session legacy: 5m. Este `PendingEnrollSession` cu status pending/authenticated/denied.
- Interactive TrustAgent enrollment session: 5m. Include `enrollment_session_id`, `device_challenge`, `poll_secret`, poll interval de 3s si expirare transmisa in raspunsul gRPC.
- Step-up challenge necompletat: 5m. Dupa expirare statusul devine `expired` si secretul TOTP pending este sters.
- Step-up completat: implicit 10m. Dupa completare, `ExpiresAt = CompletedAt + MaxAgeSeconds`; daca politica nu seteaza `max_age_seconds`, defaultul este `600` secunde.
- Step-up browser auth cookie/session: 5m. Cookie-ul `tc_stepup_auth` este HttpOnly, Secure, SameSite=Lax si este legat de challenge, user, metoda, hash IP si hash User-Agent.
- Token random de sesiune trimis catre gateway: expira odata cu sesiunea PA/provisioned session. In config-ul curent sesiunea globala este 10m, dar policy session controls pot scurta prin `MaxAgeSeconds` sau `RevalidateEverySeconds`. Tokenul este generat la autorizare si trimis agentului/gateway-ului; modelul `Session` persistat de PA nu contine acest token.
- Gateway enrollment token: 1h. Este generat ca 32 bytes random in hex, deci 64 caractere; in baza se salveaza doar SHA256(token). Este consumat atomic la enrollment, iar daca semnarea/validarea certificatului esueaza serviciul resalveaza gateway-ul vechi si tokenul nu este pierdut.
- Certificat gateway: 7 zile.
- Certificat device/agent: 24h.
- Catalog TTL: 300s, adica 5m.
- CSRF cookie: 1h.
- SCIM bearer token: nu are TTL in PDP. Ramane valid pana cand secretul din configuratia IdP este schimbat, IdP-ul este dezactivat sau tenant-ul este dezactivat.
- Vault `pki_token`: nu are TTL gestionat de PDP. Durata lui este controlata de Vault; PDP doar il foloseste pentru PKI/Transit.

Tokenurile revocate sunt pastrate in `revoked_tokens` pana la expirarea lor naturala. Cleanup-ul periodic sterge intrarile expirate. Pentru tokenurile single-use, acelasi mecanism este folosit ca replay guard pe JTI.

## 4. Persistenta SQLite

Store-ul este implementat in `pdp/store`.

### 4.1 Initializare SQLite

La deschiderea bazei:

- se foloseste driver SQLite;
- se activeaza `PRAGMA journal_mode=WAL`;
- se seteaza `PRAGMA synchronous=NORMAL`;
- se seteaza `PRAGMA cache_size=5000`;
- se seteaza `PRAGMA busy_timeout=5000`;
- se limiteaza conexiunile la `SetMaxOpenConns(1)`, pentru a evita conflicte de scriere;
- se ruleaza `InitDB`;
- se asigura politicile globale default pentru fiecare organizatie.

`StartAutoSave` nu este un autosave clasic al datelor, deoarece SQLite persista operatiile imediat. In implementare, el ruleaza cleanup periodic pentru:

- enrollment-uri pending expirate;
- tokenuri revocate expirate;
- ferestre de rate limit vechi.

### 4.2 Tabele principale

Schema este creata si migrata in `store/schema.go`.

Tabele:

- `users`: utilizatori locali si federati; campuri pentru username, email, password hash, rol, MFA, TOTP secret, WebAuthn, tenant, sursa auth, external subject, stare disabled.
- `tenants`: organizatii; campuri pentru nume, domeniu principal, domenii multiple, `default_idp_id`, stare enabled.
- `organization_memberships`: legatura admin-utilizator-organizatie, cu rol si timestamp-uri.
- `policy_rules`: politici; include nume, descriere, enabled, priority legacy, action, conditions JSON, tenant, session controls, auth/user/network/location/risk policies, step-up requirements.
- `policy_assignments`: assignment-uri de politici; include policy ID, tenant, nivel, target resource, target group, order index si flag default.
- `sessions`: sesiuni active de acces; include user/device/resource/gateway/tenant, protocol, expirare, session controls, risk, matched rule/policy si revocation flag.
- `resources`: resurse protejate; include tip, host, port, external URL, tenant, gateway, enabled, tags, metadata.
- `audit_log`: evenimente auditabile; include hash chain prin `prev_hash` si `entry_hash`.
- `device_health`: compatibilitate pentru rapoarte agregate de health.
- `device_data`: raport raw normalizat de device posture.
- `login_attempts`: incercari esuate, lockout si contorizare.
- `revoked_tokens`: JTI-uri revocate sau consumate o singura data.
- `device_enrollments`: dispozitive inrolate sau pending; include certificat, thumbprint, tenant, status si expiry.
- `revoked_certs`: seriale de certificate revocate.
- `device_users`: binding intre device, user, tenant si rol.
- `gateways`: gateway-uri, tokenuri de enrollment hash-uite, status, cert fingerprint, FQDN, resurse asignate.
- `login_locations`: istoric de locatie pentru detectia new location si impossible travel.
- `webauthn_credentials`: credentiale passkey admin.
- `rate_limits`: contoare persistente pentru endpoint-uri sensibile.
- `identity_provider_configs`: configuratii OIDC/SCIM per organizatie.
- `directory_users`: utilizatori sincronizati din IdP/SCIM.
- `directory_groups`: grupuri sincronizate.
- `directory_group_members`: membership-uri grup-utilizator.
- `schema_meta`: markere pentru migrari si cleanup-uri care trebuie rulate o singura data.

### 4.3 Migrari si normalizari

La `InitDB`, codul aplica migrari defensive. Printre ele:

- adauga coloane lipsa pentru versiuni mai vechi;
- adauga `prev_hash` si `entry_hash` pentru audit;
- adauga coloanele multi-tenant;
- adauga campuri pentru session controls;
- adauga HRD si default IdP pe tenant;
- adauga `tenant_ids` pentru gateway-uri;
- adauga token SCIM pe IdP;
- normalizeaza rolurile vechi de admin local la `platform_admin`;
- elimina vechile coloane de prioritate nefolosite;
- migreaza `device_posture` spre `device_data`;
- elimina audit events suprimate si recalculeaza lantul hash;
- impune un singur IdP per tenant prin index unic;
- reconciliaza IdP-ul default per tenant;
- curata date legacy de politici;
- marcheaza resetarea Duo legacy;
- canonizeaza actiunile de policy si dezactiveaza actiunile invalide.

## 5. Modele de date

### 5.1 AccessRequest

`models.AccessRequest` este contextul de intrare pentru evaluarea accesului. Include:

- `user`: identificator utilizator;
- `device_id`: dispozitivul agentului;
- `source_ip`: IP-ul observat;
- `resource`: resursa ceruta;
- `tenant_id`: organizatia;
- `gateway_id`: gateway-ul asociat;
- `port`;
- `protocol`;
- `auth_token`;
- `app`;
- `process`: identitatea procesului client;
- `device_health`: raport agregat;
- `anomaly_alerts`;
- `anomaly_score`.

### 5.2 ProcessIdentity

Identitatea procesului contine:

- `pid`;
- `name`;
- `path`;
- `sha256`;
- `signer`.

Politicile pot bloca sau permite dupa nume, path, basename si hash SHA256. Hash-ul este comparat case-insensitive.

### 5.3 AccessDecision

`models.AccessDecision` este raspunsul PE/PDP. Include:

- `decision`: `allow`, `deny` sau `step_up_required`;
- `reason`;
- `risk_score`;
- `risk_level`;
- `access_conditions`;
- `session_controls`;
- `matched_rule`;
- `matched_policies`;
- `session_id`;
- `expires_at`;
- `step_up`: cerinta detaliata de step-up.

### 5.4 Politici si conditii

`models.PolicyRule` contine:

- identificare: `id`, `name`, `description`;
- `enabled`;
- `action`;
- `conditions`;
- campuri de tenant;
- `session_controls`;
- politici pe sectiuni: new user, authentication, user location, network, risk based auth;
- cerinte step-up.

`RuleConditions` permite:

- mod de potrivire access conditions: `all` sau `any`;
- risc: scor minim/maxim, niveluri si semnale;
- roluri, useri si grupuri permise;
- locatie utilizator;
- retea;
- autentificare;
- posture device;
- sesiune;
- zile, interval orar, timezone, date blocate si date range;
- resurse tinta si porturi tinta;
- identitate proces;
- lista procese/hash-uri permise sau blocate.

### 5.5 Organizatii

In cod, termenii `tenant` si `organization` sunt folositi pentru aceeasi entitate functionala. Modelul `Tenant` include:

- `id`;
- `name`;
- `domain`;
- `domains`;
- `default_idp_id`;
- `enabled`;
- timestamp-uri.

API-ul admin expune organizatiile sub `/api/admin/organizations`, dar multe structuri interne pastreaza numele `Tenant`.

### 5.6 Resurse

`models.Resource` reprezinta o aplicatie sau tinta protejata:

- `id`;
- `name`;
- `description`;
- `type`: `ssh`, `rdp` sau `web`;
- `host`;
- `port`;
- `external_url`;
- `tenant_id`;
- `gateway_id`;
- `enabled`;
- `tags`;
- `metadata`.

Campurile legacy `client_id`, `client_secret` si `allowed_roles` sunt curatate de serviciul de resurse.

### 5.7 Gateway-uri

`models.Gateway` contine:

- `id`;
- `name`;
- `fqdn`;
- `tenant_id`;
- `tenant_ids`;
- `status`: `pending`, `enrolling`, `enrolled`, `revoked`;
- hash-ul tokenului de enrollment si expiry;
- certificat, serial, fingerprint si expiry;
- endpoint/listen address;
- resurse asignate;
- campuri legacy de federatie, care sunt respinse pentru gateway-urile builtin curente.

### 5.8 Device data si health

Exista doua forme:

- `DeviceDataReport`: raport raw normalizat, folosit preferat de runtime;
- `DeviceHealthReport`: raport agregat compatibil.

Pentru acces, daca exista `device_data`, acesta este convertit in health prin `DeviceHealthFromData`. Daca nu exista, se foloseste `device_health`.

### 5.9 Sesiuni

`models.Session` contine:

- user, username, role;
- device;
- resource;
- gateway;
- tenant;
- protocol;
- source IP;
- created/last activity/expiry;
- risk score;
- matched rule;
- matched policy list;
- session controls;
- `revoked`.

## 6. Policy Administrator

`pa.NewPolicyAdministrator` compune serviciile principale:

- `Auth`: autentificare, JWT, OIDC, WebAuthn, federation, secrete;
- `Engine`: instanta PE;
- `Geo`: istoric locatie si geo-velocity;
- `Catalog`: catalogul publicat catre agent;
- `Devices`: rapoarte device;
- `Enrollment`: inrolare dispozitive;
- `Gateways`: management gateway;
- `Resources`: management resurse;
- `Sessions`: sesiuni de acces;
- `StepUps`: challenge-uri step-up;
- `Audit`: audit;
- `Store`: persistenta.

PA-ul este stratul care aduna contextul real din store inainte sa cheme PE:

- incarca userul;
- incarca resursa;
- incarca gateway-ul;
- verifica tenant mismatch;
- incarca failed attempts;
- detecteaza new device din `device_users`;
- incarca rolul si starea MFA;
- rezolva utilizatorul din directorul IdP;
- incarca grupurile;
- construieste context de locatie si geo-velocity;
- selecteaza politicile aplicabile prin assignments.

Daca userul federat are un `directory_user` dezactivat, PA intoarce deny direct cu risc 100 si motivul `directory user is disabled`.

## 7. Policy Engine

PE-ul este in `pdp/pe/evaluation`.

### 7.1 Ordine de evaluare

`Evaluate` executa:

1. Calculeaza riscul prin `risk.CalculateRiskScore`.
2. Deriva access conditions observate.
3. Parcurge regulile enabled care se potrivesc pe scope.
4. Imbina session controls restrictiv.
5. Intoarce deny imediat daca device posture esueaza sau actiunea efectiva este deny.
6. Colecteaza regulile care cer step-up.
7. Retine prima regula allow.
8. Daca nu s-a potrivit nimic, deny fail-closed.
9. Daca exista step-up si contextul nu satisface cerinta, intoarce `step_up_required`.
10. Daca step-up-ul este satisfacut, allow.
11. Daca exista allow, allow.

Prioritatea efectiva este:

`deny` > `step_up_required` > `allow` > fail-closed deny.

### 7.2 Actiunea efectiva

Actiunea unei reguli poate fi modificata de sectiunile conditionale:

- authentication policy;
- network policy;
- user location policy;
- risk based auth policy;
- new user policy.

Exemple:

- `authentication.policy = enforce_mfa` transforma regula in step-up;
- `authentication.policy = bypass_mfa` poate lasa allow;
- network block produce deny;
- network require MFA produce step-up;
- network skip MFA poate produce allow daca nu exista block sau require;
- user location block produce deny;
- risk based auth block produce deny;
- risk based auth require MFA produce step-up;
- new user `deny` produce deny;
- new user `allow_without_mfa` permite doar daca nu exista alta conditie mai stricta;
- new user `require_enrollment` produce step-up daca userul nu are MFA.

### 7.3 Assignment-uri de politici

Politicile nu sunt aplicate direct doar pentru ca exista. Se aplica prin `policy_assignments`.

Niveluri normalizate:

- `organization`;
- `group`;
- `resource`;
- `resource_group`.

Aliasuri:

- `tenant` si `global` devin `organization`;
- `application_group` devine `resource_group`;
- `gateway` si `legacy_gateway` nu sunt suportate.

Ordinea in store este:

1. `resource_group`;
2. `resource`;
3. `group`;
4. `organization`;
5. `order_index`;
6. `created_at`;
7. `id`.

Aceasta inseamna ca politicile mai specifice apar inaintea celor organization-level.

Pentru acces, `ListPolicyRulesForAccessGroups` filtreaza dupa:

- tenant;
- resource;
- group IDs;
- group names;
- enabled policy;
- assignment aplicabil.

### 7.4 Politica globala default

Pentru fiecare organizatie, store-ul asigura o politica default:

- ID politica: `policy-global-default-{tenant_id}`;
- ID assignment: `assignment-global-default-{tenant_id}`;
- nume: `Global Policy`;
- descriere: `Default baseline policy automatically applied to this organization.`;
- actiune: `step_up_required`;
- new user policy: `require_enrollment`;
- authentication policy: `enforce_mfa`;
- step-up methods: `totp`, `webauthn`;
- order index: `1000000`.

Politica globala default nu poate fi stearsa si assignment-ul ei nu poate fi modificat manual.

Actiunile canonice acceptate de motor sunt `allow`, `deny` si `step_up_required`. Politica de autentificare se mapeaza astfel: `enforce_mfa` -> `step_up_required`, `bypass_mfa` -> `allow`, `deny` -> `deny`.

### 7.5 Conditii de risc

Riscul este transformat in nivel:

- `critical`: scor >= 80;
- `high`: scor >= 60;
- `medium`: scor >= 30;
- `low`: sub 30.

Conditiile pot verifica:

- scor minim/maxim;
- lista de niveluri acceptate;
- semnale concrete, precum new location, impossible travel, baseline anomaly.

### 7.6 Retele

Politica de retea suporta:

- IP individual;
- CIDR;
- interval `start-end`;
- liste de allow;
- liste de block;
- retele care cer MFA;
- retele care sar MFA;
- `allow_all_networks`;
- `deny_other_networks`.

Validarile importante:

- `allow_all_networks` este incompatibil cu restrictii de allow/block/require/skip;
- `deny_other_networks` trebuie sa aiba cel putin o lista allow/skip/require;
- intervalele IP trebuie sa fie valide si in aceeasi familie IPv4/IPv6.

### 7.7 Timp si calendar

Conditiile temporale includ:

- timezone;
- zile ale saptamanii;
- start/end time;
- date blocate;
- date range.

Intervalele care trec peste miezul noptii sunt suportate: daca start este mai mare decat end, motorul trateaza fereastra ca overnight.

### 7.8 Device posture

O regula poate cere checks specifice. Daca un check cerut lipseste, regula nu este satisfacuta. Daca `required_status` este setat, statusul raportat trebuie sa fie identic cu acesta.

Catalogul de device data exporta checks derivate din politicile accesibile si normalizeaza statusurile acceptate:

- `good`;
- `warning`;
- `critical`;
- `unavailable`.

Cand mai multe politici cer acelasi check, statusul `good` castiga pentru ca este mai restrictiv.

### 7.9 Proces client

Conditiile de proces permit:

- cererea prezentei identitatii de proces;
- procese permise dupa nume/path/basename;
- procese blocate dupa nume/path/basename;
- hash-uri permise;
- hash-uri blocate.

Pentru hash-uri se foloseste comparatie exacta case-insensitive. Pentru nume, motorul verifica numele procesului, path-ul si basename-ul path-ului.

Pentru o regula deny care are doar blocked process, regula se potriveste cand procesul blocat este prezent.

### 7.10 Step-up

Decizia `step_up_required` include:

- ACR cerut;
- metode cerute;
- min strength;
- max age;
- attachment;
- AAGUID-uri permise.

Metodele default pentru step-up sunt `totp` si `webauthn`. Aliasuri precum `idp`, `reauth`, `idp_reauth` si `external_idp` sunt mapate la metodele suportate.

Strength-urile includ:

- `otp`;
- `phishing_resistant`;
- `hardware_key`;
- `approved_hardware_key`.

WebAuthn/passkey/security key sunt normalizate spre strength-uri mai puternice decat OTP.

Step-up-ul este satisfacut doar daca:

- ACR-ul curent este suficient;
- AMR/metoda se intersecteaza cu cerinta;
- strength-ul minim este atins;
- attachment-ul cerut se potriveste, daca este setat;
- AAGUID-ul este permis, daca lista este setata;
- autentificarea nu este expirata fata de max age.

### 7.11 Session controls

Session controls sunt imbinate restrictiv:

- cel mai mic `max_age_seconds` pozitiv castiga;
- cel mai mic `revalidate_every_seconds` pozitiv castiga;
- `revoke_on_posture_change` se combina prin OR;
- `revoke_on_risk_increase` se combina prin OR.

## 8. Calculul de risc

Calculul este in `pe/risk/risk.go`.

Scorul este intre `0` si `100`. Semnale folosite:

- date device stale;
- statusuri device critical;
- scor device health agregat;
- checks critice configurate;
- incercari de login esuate;
- acces in afara orelor business;
- acces in ore de noapte;
- device nou;
- locatie noua;
- anomaly de baseline utilizator;
- protocol sensibil sau necunoscut;
- impossible travel;
- geo velocity suspect;
- anomaly score din request.

Protocoalele sensibile includ SSH si RDP, sau porturile 22 si 3389.

## 9. Autentificare administrator

### 9.1 Login local

Endpoint: `POST /api/auth/login`.

Comportament:

- accepta body JSON pana la `64KiB`;
- accepta username/email si parola;
- autentificarea prefera email, apoi username;
- valorile `admin`/`admin` sunt respinse explicit;
- userul trebuie sa fie activ;
- userul trebuie sa aiba rol `platform_admin`;
- aplica rate limit pe IP;
- tine cont de lockout prin `login_attempts`;
- reseteaza failed attempts la autentificare primara reusita.

Daca MFA admin este dezactivat explicit, login-ul poate intoarce token final dupa parola. In default, MFA este cerut.

### 9.2 Bootstrap si register admin

Exista doua mecanisme:

- bootstrap admin din config, la pornire;
- `POST /api/auth/register`, disponibil doar daca nu exista niciun local `platform_admin`.

Bootstrap admin nu se creeaza daca parola lipseste sau este `admin`.

### 9.3 TOTP

Daca un admin nu are TOTP activ, login-ul creeaza un secret pending si intoarce:

- status `mfa_setup_required`;
- secret TOTP;
- QR code data URL.

La `POST /api/auth/mfa/verify`:

- daca exista secret pending, codul activeaza MFA;
- altfel codul verifica TOTP existent;
- challenge-ul este consumat la succes;
- failed attempts sunt contorizate;
- la prea multe esecuri se aplica lockout.

TOTP este implementat cu:

- HMAC-SHA1;
- 6 cifre;
- perioada 30s;
- skew de ±1 perioada;
- secret de 20 bytes;
- base32 fara padding;
- preventie replay prin counterul ultimului cod folosit.

### 9.4 Passkey admin

Passkey-ul admin foloseste WebAuthn.

Endpoint-uri:

- `POST /api/auth/passkey/login/begin`;
- `POST /api/auth/passkey/login/finish`;
- `POST /api/auth/passkey/register/begin`;
- `POST /api/auth/passkey/register/finish`.

Inrolarea passkey cere un bearer token valid cu purpose `passkey_enrollment`. Acest token este emis dupa MFA/TOTP in fluxul dedicat de enrollment passkey.

Credentialele sunt salvate in `webauthn_credentials`; daca protectorul de secrete este disponibil, JSON-ul credentialului este protejat.

Pentru step-up WebAuthn de resursa, PDP expune si endpoint-uri separate:

- `POST /api/step-up/webauthn/begin`;
- `POST /api/step-up/webauthn/finish`;
- `POST /api/step-up/webauthn/register/begin`;
- `POST /api/step-up/webauthn/register/finish`.

Acestea folosesc challenge-urile WebAuthn in-memory cu TTL 5m si contextul step-up challenge-ului.

### 9.5 JWT admin

JWT-urile sunt ES256 P-256. Cand Vault Transit este configurat, cheia JWT este restaurata/creata prin Vault. Altfel se foloseste o cheie in memorie.

Tokenul admin:

- audience `trustcloud`;
- contine user ID, username, role;
- contine ACR/AMR;
- cere `mfa_done=true` pentru `ValidateAuthToken`;
- include JTI pentru revocare.

`POST /api/auth/revoke-token` revoca JTI-ul tokenului curent pana la expirarea tokenului.

## 10. OIDC, federation si HRD

### 10.1 Endpoint-uri OIDC

PDP expune:

- `GET /auth/authorize`;
- `POST /auth/token`;
- `GET|POST /auth/userinfo`;
- `GET /.well-known/jwks.json`;
- `GET /.well-known/openid-configuration`;
- `GET /auth/federated/callback`;
- `POST /api/auth/oidc-complete`.

### 10.2 Authorize

`/auth/authorize`:

- accepta doar `response_type=code`;
- valideaza clientul si redirect URI;
- cere PKCE S256 pentru clienti publici/native;
- pentru clientul native Connect-App cere `device_id`;
- accepta `login_hint` pentru rezolvare IdP dupa domeniul emailului;
- accepta `organization_id` pentru alegerea explicita a organizatiei;
- accepta `idp_id` pentru alegerea explicita a IdP-ului;
- creeaza o sesiune authorize;
- rezolva IdP-ul extern prin HRD;
- redirectioneaza catre IdP-ul extern.

Nu exista fallback local in fluxul OIDC curent: daca nu se poate rezolva un IdP, fluxul esueaza.

### 10.3 Home Realm Discovery

Ordinea de rezolvare IdP este:

1. `idp_id` explicit, cu verificari de organizatie/gateway;
2. `login_hint` dupa domeniu, prin domenii IdP sau domenii tenant;
3. `organization_id` explicit;
4. client legacy gateway ca indiciu de organizatie;
5. fallback la singura organizatie activata cu IdP, doar daca exista exact una.

Pentru o organizatie, IdP-ul default este `default_idp_id` daca este enabled; altfel primul IdP enabled.

### 10.4 Callback federat

Callback-ul OIDC:

- ruteaza mai intai callback-urile speciale pentru enrollment/session/step-up;
- valideaza sesiunea federata;
- schimba code-ul pe tokenuri;
- valideaza ID token-ul prin JWKS;
- valideaza issuer, audience, azp si nonce;
- aplica claim mapping;
- extrage grupuri;
- aplica group-role mapping, daca exista;
- gaseste sau creeaza user federat;
- emite JWT PDP;
- completeaza authorize session;
- redirectioneaza clientul inapoi cu code si state.

Algoritmii acceptati pentru ID token extern sunt asimetrici, de tip RS/PS/ES.

### 10.5 Token si refresh

`/auth/token` accepta:

- `authorization_code`;
- `refresh_token`.

La code exchange:

- valideaza code-ul;
- valideaza clientul;
- valideaza redirect URI;
- valideaza PKCE;
- emite access token PDP;
- emite ID token;
- emite refresh token;
- intoarce user, role si device metadata cand exista.

La refresh:

- valideaza refresh token-ul;
- emite un nou JWT;
- pastreaza contextul device/MFA.

## 11. Organizatii, IdP si SCIM

### 11.1 Organizatii

Endpoint-uri admin:

- `GET /api/admin/organizations`;
- `POST /api/admin/organizations`;
- `GET /api/admin/organizations/{id}`;
- `PUT /api/admin/organizations/{id}`;
- `DELETE /api/admin/organizations/{id}`.

La creare:

- se creeaza tenant-ul;
- se asigura politica globala default;
- adminul curent primeste membership in organizatie.

Citirea listelor admin este filtrata dupa membership-ul adminului curent.

### 11.2 Identity Provider Config

Endpoint-uri:

- `GET /api/admin/organizations/idps?organization_id=...`;
- `POST /api/admin/organizations/idps`;
- `GET /api/admin/organizations/idps/{id}`;
- `PUT /api/admin/organizations/idps/{id}`;
- `DELETE /api/admin/organizations/idps/{id}`;
- `POST /api/admin/organizations/idps/discover`.

Implementarea curenta permite un singur IdP per organizatie. Exista un index unic pe tenant in baza de date.

La raspuns:

- `client_secret` nu este expus;
- `scim_token` nu este expus;
- se expun flaguri precum `has_client_secret`, `has_scim_token`, `is_default`.

La creare:

- tipul default este `oidc`;
- `enabled` este true daca nu este setat;
- se seteaza scopes default;
- se seteaza claim mapping default;
- ID-ul are prefix `idp`.

### 11.3 SCIM inbound

SCIM este expus sub:

- `/scim/v2/{tenant_id}/ServiceProviderConfig`;
- `/scim/v2/{tenant_id}/Users`;
- `/scim/v2/{tenant_id}/Users/{id}`;
- `/scim/v2/{tenant_id}/Groups`;
- `/scim/v2/{tenant_id}/Groups/{id}`.

Autentificarea SCIM:

- cere Bearer token;
- tokenul este comparat constant-time cu `SCIMToken` din IdP;
- tenant-ul trebuie sa existe si sa fie enabled;
- IdP-ul trebuie sa fie enabled.

Operatii:

- ServiceProviderConfig: doar GET;
- Users: GET, POST, PUT, PATCH, DELETE;
- Groups: GET, POST, PUT, PATCH, DELETE.

DELETE pe user nu sterge randul, ci seteaza `Active=false`. DELETE pe group sterge grupul.

Lista SCIM suporta:

- `startIndex`;
- `count`;
- filter simplu `attr eq "value"`.

Filtre user suportate:

- `id`;
- `externalId`;
- `userName`;
- `emails.value`.

Filtre group suportate:

- `id`;
- `externalId`;
- `displayName`.

SCIM PATCH suporta operatii pentru active/user fields, emails si membership-uri de grup.

## 12. Resurse

Serviciul este in `pa/resources`.

Resursele pot fi:

- `ssh`;
- `rdp`;
- `web`.

Validari la creare/update:

- `name` este obligatoriu;
- `type` este obligatoriu si trebuie sa fie unul dintre tipurile suportate;
- `tenant_id`/`organization_id` este obligatoriu;
- `gateway_id` este obligatoriu;
- organizatia trebuie sa existe si sa fie enabled;
- gateway-ul trebuie sa existe;
- gateway-ul trebuie sa apartina organizatiei;
- pentru `web`, daca `external_url` este setat, trebuie sa fie URL HTTPS valid;
- pentru `web`, portul default este 443 daca lipseste sau este <= 0.

Schimbarile care revoca sesiuni:

- resursa trece din enabled in disabled;
- se schimba type;
- se schimba host;
- se schimba port;
- se schimba external URL;
- se schimba tenant;
- se schimba gateway.

La creare/update/delete, serviciul publica `resources.updated`. Eventul include:

- `resource_id`;
- `app_id`;
- `tenant_id`;
- `gateway_id`;
- `action`;
- `reason`;
- `revokes_sessions`.

## 13. Gateway-uri

### 13.1 Management gateway

Serviciul este in `pa/gateway`.

La creare:

- `name` este obligatoriu;
- organizatia trebuie sa existe;
- resursele asignate trebuie sa apartina aceleiasi organizatii;
- `auth_mode` suportat este `builtin`;
- configuratia legacy de federatie este respinsa;
- se genereaza ID gateway;
- se genereaza token de enrollment plaintext;
- in store se salveaza doar SHA256(token);
- statusul devine `pending`;
- tokenul expira implicit in `1h`;
- certificatul gateway va avea implicit validitate `7` zile.

Tokenul plaintext este intors doar la creare/regenerare.

Update:

- nu permite mutarea unui gateway enrolled intre organizatii;
- valideaza resursele asignate;
- respinge federatia legacy;
- poate curata campurile legacy daca auth mode ramane builtin.

Delete:

- revoca certificatul daca exista serial si revoker;
- sterge gateway-ul;
- publica `gateway.revoked` cu motiv `gateway_deleted`.

Revoke:

- seteaza status `revoked`;
- curata tokenul si campurile de certificat;
- revoca certificatul;
- publica `gateway.revoked`.

Actiuni admin peste `/api/admin/gateways/{id}`:

- `GET`: intoarce gateway-ul sanitizat pentru admin, fara hash/token enrollment.
- `PUT`: actualizeaza gateway-ul.
- `DELETE`: sterge gateway-ul si revoca certificatul daca exista.
- `POST /regenerate-token`: genereaza token nou de enrollment cu expirare 1h si seteaza status `pending`.
- `POST /revoke`: revoca gateway-ul.
- `POST /test-federation`: primeste `issuer`, ruleaza OIDC discovery prin providerul de federation si intoarce `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint` si `jwks_uri`; la eroare intoarce HTTP 502.

### 13.2 Identitatea certificatului gateway

Identitatea gateway-ului este in URI SAN:

`spiffe://trustcloud/gateway/organization/{organizationID}/gateway/{gatewayID}`

Autentificarea gateway verifica:

- client certificate prezent;
- URI SAN gateway valid;
- gateway existent in store;
- status `enrolled`;
- organizatia din cert egala cu `TenantID` din store;
- fingerprint certificat egal constant-time cu fingerprint-ul salvat.

### 13.3 Enrollment gateway

gRPC:

- `gateway.GatewayEnrollmentService/Enroll`;
- `gateway.GatewayEnrollmentService/RenewCertificate`.

Enroll:

- aplica rate limit dupa IP;
- cere token si CSR;
- tokenul trebuie sa existe, sa nu fie expirat si gateway-ul sa fie `pending`;
- CSR-ul trebuie sa corespunda identitatii/FQDN-ului gateway-ului;
- tokenul este consumat atomic, statusul trece prin `enrolling`;
- certificatul este semnat prin rolul gateway;
- se valideaza certificatul emis;
- statusul devine `enrolled`;
- se salveaza fingerprint, serial si expiry;
- se intoarce `cert_pem` si `ca_pem`.

Renew:

- cere mTLS gateway valid;
- valideaza CSR-ul fata de gateway;
- emite certificat nou;
- salveaza noul certificat;
- revoca serialul vechi daca s-a schimbat.

### 13.4 Control stream gateway

gRPC:

- `gateway.GatewayControlService/ControlStream`.

Flux:

1. Gateway-ul se conecteaza cu mTLS.
2. Primul mesaj trebuie sa fie `gateway_hello`.
3. `gateway_id` din hello trebuie sa fie identic cu identitatea din certificat.
4. PDP marcheaza gateway-ul ca vazut si actualizeaza endpoint-ul.
5. Conexiunea este inregistrata in `ControlRegistry`.
6. Daca apare o conexiune noua pentru acelasi gateway, cea veche este inlocuita.

Comenzi trimise de PDP:

- `provision_session`;
- `revoke_session`;
- `heartbeat`.

Fiecare comanda are `command_id` si asteapta ACK:

- type `ack`;
- acelasi `command_id`;
- status `ok`.

Daca ACK-ul lipseste, are alt command ID sau status diferit de ok, comanda este considerata esuata.

### 13.5 Gateway trust

gRPC:

- `gateway.GatewayTrustService/GetCACertificate`;
- `gateway.GatewayTrustService/GetRevokedSerials`;
- `gateway.GatewayTrustService/RevalidateSessions`.

Toate cer mTLS gateway valid.

`RevalidateSessions` primeste sesiuni raportate de gateway si intoarce cele invalide:

- `not_found`;
- `revoked`;
- `expired`;
- `gateway_mismatch`;
- `device_mismatch`;
- `resource_mismatch`;
- `protocol_mismatch`.

## 14. Enrollment dispozitive

Serviciul este in `pa/enrollment`.

### 14.1 Stari interactive

Enrollment-ul browser/agent foloseste stari:

- `WAITING_FOR_IDP_DISCOVERY`;
- `WAITING_FOR_USER_LOGIN`;
- `READY_FOR_DEVICE_PROOF`;
- `DENIED`;
- `ENROLLED`.

### 14.2 StartSession

Agentul trimite:

- hash CSR;
- hash SPKI;
- nonce dispozitiv;
- URL de autentificare baza.

PDP genereaza:

- ID sesiune cu prefix `erq`;
- device challenge random;
- poll secret random;
- hash pentru poll secret;
- URL browser `<base>/browser/enroll/{session}`;
- expiry dupa `BrowserSessionTTL`.

Statusul initial este `WAITING_FOR_IDP_DISCOVERY`.

Pagina browser de enrollment poate redirectiona inapoi la aceeasi ruta cu `?cancelled=1` cand utilizatorul anuleaza flow-ul. Session ID-ul din path este cel generat de PDP, cu prefix `erq`; valorile din teste de forma `/browser/enroll/erq_test` sunt fixture-uri, nu ID-uri reale de productie.

### 14.3 Login IdP pentru enrollment

Browserul alege/descopera IdP. PDP:

- seteaza tenant si IdP;
- retine state, nonce si PKCE;
- trece statusul in `WAITING_FOR_USER_LOGIN`;
- dupa callback valid, salveaza subiectul autentificat, email, issuer, user ID si username;
- trece statusul in `READY_FOR_DEVICE_PROOF`.

### 14.4 CompleteSession si proof

Pentru completare, PDP verifica:

- poll secret;
- device nonce;
- starea `READY_FOR_DEVICE_PROOF`;
- sesiunea nu este expirata;
- CSR-ul este PEM canonic valid;
- hash-ul DER al CSR-ului este egal cu `CSRHash` initial;
- hash-ul SPKI este egal cu `SPKIHash` initial;
- payload-ul proof optional este identic cu payload-ul canonic;
- semnatura proof este valida peste digest-ul payload-ului canonic;
- cheia publica este ECDSA P-256.

Tipul proof este:

`trustagent-device-enrollment-proof-v1`

Certificatul emis are identitatea dispozitivului alocata de PDP. PDP valideaza ca certificatul emis contine acelasi device ID, calculeaza thumbprint-ul si salveaza enrollment-ul aprobat.

### 14.5 Renewal certificat dispozitiv

Renewal-ul certificatului dispozitiv:

- verifica identitatea dispozitivului;
- valideaza CSR-ul;
- respinge schimbarea cheii daca CSR-ul nu corespunde cheii existente;
- emite certificat nou;
- revoca serialul vechi la succes.

Endpoint-ul HTTP este:

- `POST /api/enroll/renew`.

Acest endpoint este protejat cu mTLS device si `deviceAuthMiddleware`. Body-ul accepta `models.EnrollmentRequest`, iar raspunsul include certificatul nou, CA-ul si mesajul `Certificate renewed (24h validity)`.

## 15. Agent session, catalog si autorizare acces

### 15.1 AgentSessionService

gRPC:

- `trustagent.session.AgentSessionService/StartSession`;
- `SessionStatus`;
- `ClaimSession`;
- `GetCatalog`;
- `RevokeSession`.

Toate operatiile relevante cer mTLS dispozitiv. Interceptorul verifica:

- certificatul client;
- URI SAN de device;
- enrollment aprobat;
- fingerprint din certificat egal cu fingerprint-ul din store;
- certificat neexpirat.

### 15.2 StartSession agent

Agentul trebuie sa trimita informatii despre userul local Windows:

- SID hash;
- logon session ID;
- Windows session ID.

Device ID-ul din request, daca exista, trebuie sa fie identic cu cel din certificat.

PDP creeaza:

- session request ID cu prefix `srq`;
- claim secret random;
- hash claim secret;
- URL browser `/browser/session/{id}`;
- status `WAITING_FOR_USER_LOGIN`;
- policy epoch initial;
- expiry dupa `BrowserAuthSessionTTL`.

### 15.3 ClaimSession

Agentul revendica sesiunea dupa ce browser login-ul a terminat. PDP verifica:

- request-ul este `READY_FOR_CLAIM`;
- nu este expirat;
- nu este consumat;
- claim secret este valid;
- datele userului local Windows se potrivesc cu cele din StartSession;
- certificatul dispozitivului este acelasi.

La succes:

- genereaza agent session ID;
- emite JWT agent;
- leaga tokenul de thumbprint-ul certificatului prin `cnf.x5t#S256`;
- include scope-uri;
- include tenant, user, device, Windows session fields;
- intoarce user info.

### 15.4 Agent session token

Tokenul agent are:

- audience `trustagent-api`;
- purpose `trustagent.session`;
- subject `device:{deviceID}`;
- `mfa_done=true`;
- JTI;
- confirmation thumbprint certificat;
- scope-uri default:
  - `catalog:read`;
  - `device-data:write`;
  - `events:read`;
  - `flow:authorize`;
  - `session:renew`;
  - `session:revoke`.

Validarea verifica audience, purpose, scope, JTI nerevocat si thumbprint certificat.

### 15.5 Catalog

Catalogul este construit in `pa/catalog`.

PDP publica doar resurse:

- enabled;
- cu ID valid;
- cu tenant;
- cu FQDN valid;
- accesibile prin politici aplicabile userului/grupurilor.

Reguli catalog:

- assignment `resource` si `resource_group` pot publica resursa direct;
- assignment `organization` sau `group` publica resursa numai daca regula are `TargetResources`;
- politicile `allow` si `step_up_required` publica resursa;
- un deny fara access conditions blocheaza publicarea;
- un deny conditional nu blocheaza catalogul, dar poate bloca accesul ulterior.

FQDN-ul resursei este luat prioritar din hostname-ul lui `external_url`, altfel din `host`. IP-urile sunt respinse pentru catalog.

Versionarea catalogului:

- se calculeaza fingerprint SHA256 peste resurse si device data policy;
- versiunea este primele 16 bytes hex;
- `policy_epoch` este aliniat cu versiunea catalogului;
- daca request-ul trimite `current_version` egal cu versiunea curenta, raspunsul seteaza `not_modified=true`.

### 15.6 Device data policy in catalog

Catalogul include o politica de colectare device data derivata din politicile aplicabile resurselor vizibile. Pentru fiecare check cerut:

- numele este normalizat;
- duplicarile sunt eliminate;
- lista este sortata;
- status default este `good`;
- statusurile invalide sunt normalizate.

### 15.7 DeviceDataService

gRPC:

- `trustagent.device.DeviceDataService/ReportDeviceData`;
- `Heartbeat`.

`ReportDeviceData`:

- cere token cu scope `device-data:write`;
- cere mTLS device;
- respinge payload-urile legacy cu `overall_score`;
- cere `device_id` egal cu identitatea certificatului;
- seteaza tenant din enrollment;
- seteaza source IP din peer;
- seteaza `reported_at` la now UTC;
- daca `collected_at` lipseste, il seteaza egal cu `reported_at`;
- salveaza raportul;
- auditeaza `device_data_report`;
- publica `health.changed`.

`Heartbeat`:

- cere raport raw existent;
- actualizeaza timestamp-uri;
- publica `health.changed`;
- daca nu exista raport anterior, intoarce failed precondition.

### 15.8 AuthorizeResource

gRPC:

- `trustcloud.agent.AgentAuthorizationService/AuthorizeResource`.

Request-ul poate contine:

- access token agent;
- resource ID;
- protocol;
- port;
- source IP;
- public origin;
- process identity: PID, name, path, SHA256, signer.

PDP:

1. Valideaza tokenul agent si mTLS-ul.
2. Cere scope `flow:authorize`.
3. Cere device ID.
4. Verifica userul activ.
5. Rezolva resursa.
6. Verifica resursa enabled.
7. Verifica tenant/gateway.
8. Verifica gateway enrolled.
9. Verifica protocol si port fata de resursa.
10. Incarca device data sau health.
11. Incarca AuthContext din token si step-up-uri completate.
12. Cheama PE.

Daca decizia este `step_up_required`:

- creeaza challenge step-up;
- auditeaza `agent_step_up_required`;
- intoarce challenge ID, URL, metode, ACR si expiry.

Daca decizia este `deny`:

- auditeaza cererea ca esuata;
- nu creeaza sesiune gateway.

Daca decizia este `allow`:

- gaseste gateway-ul conectat;
- creeaza sau reinnoieste sesiunea PA;
- genereaza session token random base64url de 32 bytes;
- trimite `provision_session` catre gateway;
- include internal host/port/protocol;
- include constraints `policy:{matched}` si `resource:{id}`;
- seteaza policy version;
- daca provisioning esueaza si sesiunea era noua, o revoca;
- salveaza locatia de acces;
- auditeaza `agent_access_request`.

## 16. Step-up browser

Step-up-ul este gestionat in memorie de `StepUpManager`.

Stari:

- `pending`;
- `awaiting_verification`;
- `completed`;
- `denied`;
- `expired`.

Challenge key-ul include:

- agent session ID;
- user ID;
- device ID;
- resource ID;
- policy ID.

Daca exista deja un challenge activ pentru aceeasi cheie, PDP il reutilizeaza.

TTL initial este `5m`. Dupa completare, challenge-ul expira la `completed_at + max_age_seconds`.

Numarul maxim de incercari esuate este `5`.

URL-ul step-up este:

`{PublicOrigin}/browser/step-up/{challenge_id}`

Ruta browser accepta si query params de stare/UI: `method=totp` sau `method=webauthn` selecteaza metoda afisata, `completed=1` este folosit dupa finalizarea WebAuthn din asset-ul JS, iar `cancelled=1` marcheaza revenirea dupa anulare. Exemplul de test `/browser/step-up/stepup-1` este un fixture; in runtime ID-ul real este challenge ID-ul generat de `StepUpManager`.

La completare, managerul salveaza:

- metoda;
- strength;
- AAGUID;
- authenticator attachment;
- timestamp.

Aceste date sunt transformate in `AuthContext` si pot satisface PE la urmatoarea autorizare.

## 17. Sesiuni si enforcement continuu

### 17.1 Creare si reinnoire sesiuni

`CreateOrRenewSession` cauta o sesiune activa existenta pentru aceeasi combinatie:

- user;
- device;
- resource;
- gateway;
- protocol;
- tenant.

Daca exista si este valida:

- actualizeaza username/source/last activity;
- aplica session controls noi;
- reinnoieste doar daca expira inainte de `renew_before` sau daca noile controale o fac mai scurta;
- altfel o reutilizeaza.

Daca `RevokeOnRiskIncrease` este true si riscul nou este mai mare decat riscul sesiunii existente, sesiunea veche este revocata cu motiv `risk_increased` si se creeaza una noua.

Expiry-ul este minimul dintre:

- expirarea globala configurata;
- `created_at + MaxAgeSeconds`;
- `now + RevalidateEverySeconds`.

### 17.2 Limita de sesiuni

Daca exista o limita maxima de sesiuni pe user, managerul revoca cele mai vechi sesiuni active pana cand se incadreaza. Motivul publicat este `max_sessions_exceeded`.

### 17.3 Revocari

Revocarile pot fi:

- sesiune individuala;
- toate sesiunile unui device user;
- toate sesiunile unui device;
- toate sesiunile unei resurse;
- toate sesiunile unui gateway;
- toate sesiunile unui tenant.

Cleanup-ul periodic sterge sesiunile expirate sau revocate si publica `session.deleted`.

### 17.4 Event broker

Evenimentele interne sunt in `pa/events`.

Topic-uri:

- `revocation`;
- `policy.updated`;
- `resources.updated`;
- `session.deleted`;
- `health.changed`;
- `device.revoked`;
- `gateway.revoked`.

Brokerul:

- foloseste canale bounded per subscriber;
- publish nu blocheaza;
- daca un subscriber este plin, se arunca cel mai vechi eveniment si se incrementeaza contorul de drop.

### 17.5 Enforcement service

Serviciul `pa/enforcement` asculta evenimente:

- health changed;
- policy updated;
- resources updated;
- device revoked;
- gateway revoked.

Pe health changed:

- daca sesiunea are `RevokeOnPostureChange`, revoca sesiunile pentru device/tenant;
- altfel reevalueaza sesiunea si revoca daca PE nu mai intoarce allow.

Pe policy updated:

- reevalueaza sesiunile afectate;
- revoca sesiunile care nu mai sunt allow.

Pe resources updated:

- la create nu face nimic;
- la delete, disable sau schimbari cu `revokes_sessions=true`, revoca sesiunile resursei.

Pe device/gateway revoked:

- revoca in masa sesiunile relevante.

Auditul pentru revocari continue foloseste evenimentul `continuous_access_revoked`.

### 17.6 AgentEventsService

gRPC:

- `trustagent.events.AgentEventsService/Watch`.

Agentul trebuie sa aiba token cu scope `events:read` si mTLS device. Serviciul asculta topic-uri interne si trimite agentului:

- `access.revoked`;
- `catalog.invalidated`.

Evenimentele sunt filtrate dupa contextul tokenului: device, session, tenant, resource si gateway, astfel incat agentul primeste doar evenimente relevante.

## 18. PKI, certificate si CA

PDP foloseste Vault pentru:

- cheia privata a PDP prin Transit;
- semnarea certificatului PDP;
- semnarea certificatelor agent;
- semnarea certificatelor gateway;
- revocarea serialelor.

Endpoint-uri publice utile:

- `GET /api/ca/cert`: intoarce CA PEM;
- `GET /api/cert-fingerprint`: intoarce fingerprint-ul certificatului PDP.

Detalii de raspuns public:

- `/api/ca/cert` intoarce `Content-Type: application/x-pem-file` si corpul PEM al CA-ului activ; la eroare intoarce `CA not initialized`.
- `/api/cert-fingerprint` citeste certificatul din `cfg.TLSCert` si intoarce JSON `{ "sha256": "..." }`.
- `/.well-known/jwks.json` intoarce JWKS-ul ES256 si seteaza `Cache-Control: public, max-age=3600`.
- `/.well-known/openid-configuration` seteaza acelasi cache de 1h si construieste issuer/endpoints din request, respectand `X-Forwarded-Proto` si `X-Forwarded-Host`.
- `/health` verifica DB, CA extern incarcat si JWKS/auth. Daca DB sau auth esueaza, statusul devine `degraded` si HTTP 503; altfel HTTP 200.

Pentru HTTP, serverul poate folosi `mtls_ca` local. Daca `PKIURL` este configurat, serverul initializeaza client Vault si poate obtine CA PEM extern pentru endpoint-urile de trust.

Client auth TLS la nivel server este `VerifyClientCertIfGiven`, iar cerinta stricta de certificat este aplicata in middleware/interceptori pe endpoint-urile care au nevoie de mTLS.

## 19. Middleware si securitate HTTP

Middleware-ul seteaza:

- `X-Content-Type-Options`;
- `X-Frame-Options: DENY`;
- `Referrer-Policy`;
- HSTS;
- CSP;
- Permissions Policy care dezactiveaza camera, microphone si geolocation.

CSP-ul este ajustat pentru:

- step-up browser;
- enrollment browser;
- session browser.

CORS:

- permite localhost/127.0.0.1;
- permite originile configurate exact;
- metode: GET, POST, PUT, PATCH, DELETE, OPTIONS;
- headere: Content-Type, Authorization, X-CSRF-Token.

Admin middleware:

- cere Bearer token;
- valideaza tokenul cu `ValidateAuthToken`;
- verifica JTI nerevocat;
- cere purpose gol pentru API admin;
- cere rol `platform_admin`;
- seteaza headere contextuale `X-User-ID`, `X-Username`, `X-Role`.

Device middleware:

- cere certificat client verificat;
- extrage identitatea device din URI SAN;
- verifica enrollment aprobat;
- compara fingerprint constant-time;
- verifica expirarea certificatului.

## 20. Audit

Auditul este in `pa/audit` si `store/audit.go`.

Fiecare eveniment auditabil include:

- ID;
- timestamp;
- user;
- action;
- resource;
- details;
- source IP;
- tenant;
- prev hash;
- entry hash.

Hash chain:

- scrierea este serializata cu mutex;
- `entry_hash = SHA256(prev_hash || canonical_fields)`;
- `prev_hash` este hash-ul intrarii precedente;
- randurile vechi fara hash sunt tolerate de verificare;
- dupa pruning, cel mai vechi rand ramas este tratat ca genesis.

Audit log-ul este limitat la 10000 intrari. `GetAuditLog` intoarce default ultimele 100, descrescator.

Evenimente suprimate si sterse din lant:

- `oidc_authorize`;
- `oidc_token_exchange`;
- `oidc_token_refresh`;
- `token_revoked`.

## 21. Suprafata HTTP

### 21.1 Public

- `GET /health`
- `GET /api/ca/cert`
- `GET /api/cert-fingerprint`
- `GET /api/config/public`

`/api/config/public` expune doar config sigur pentru browser: URL-ul agentului de device health, timeout/retry pentru device health, callback-ul federat, scopes OIDC default, claim mapping OIDC default si porturile default pentru resurse (`web=443`, `ssh=22`, `rdp=3389` in config-ul curent).

### 21.2 Auth admin

- `POST /api/auth/login`
- `POST /api/auth/mfa/verify`
- `POST /api/auth/register`
- `POST /api/auth/revoke-token`
- `POST /api/auth/passkey/login/begin`
- `POST /api/auth/passkey/login/finish`
- `POST /api/auth/passkey/register/begin`
- `POST /api/auth/passkey/register/finish`
- `GET /api/admin/session`

### 21.3 Step-up WebAuthn API

- `POST /api/step-up/webauthn/begin`
- `POST /api/step-up/webauthn/finish`
- `POST /api/step-up/webauthn/register/begin`
- `POST /api/step-up/webauthn/register/finish`

### 21.4 Browser helper flows

- `GET /auth/login`
- `GET /browser/enroll/{session}`
- `GET /browser/session/{session}`
- `GET /browser/step-up/{challenge}`
- `GET /browser/step-up/assets/stepup.js`

### 21.5 OIDC

- `GET /auth/authorize`
- `GET /auth/federated/callback`
- `POST /auth/token`
- `GET /auth/userinfo`
- `POST /auth/userinfo`
- `POST /api/auth/oidc-complete`
- `GET /.well-known/jwks.json`
- `GET /.well-known/openid-configuration`

### 21.6 Device enrollment HTTP

- `POST /api/enroll/renew`

### 21.7 Admin data APIs

- `/api/admin/users`
- `/api/admin/organizations`
- `/api/admin/organizations/{id}`
- `/api/admin/organizations/idps`
- `/api/admin/organizations/idps/{id}`
- `/api/admin/organizations/idps/discover`
- `/api/admin/sessions`
- `/api/admin/sessions/{id}`
- `/api/admin/audit`
- `/api/admin/directory/users`
- `/api/admin/directory/groups`
- `/api/admin/enrollments`
- `/api/admin/enrollments/{id}/approve`
- `/api/admin/enrollments/{id}/revoke`
- `/api/admin/resources`
- `/api/admin/resources/{id}`
- `/api/admin/policies`
- `/api/admin/policies/{id}`
- `/api/admin/policy-assignments`
- `/api/admin/policy-assignments/{id}`
- `/api/admin/device-data`
- `/api/admin/dashboard`
- `/api/admin/gateways`
- `/api/admin/gateways/{id}`
- `/api/admin/gateways/{id}/regenerate-token`
- `/api/admin/gateways/{id}/revoke`
- `/api/admin/gateways/{id}/test-federation`

Metode exacte pentru API-urile admin:

- `GET /api/admin/session`: confirma sesiunea admin curenta si intoarce status, user_id, username si role din headerele setate de middleware.
- `GET /api/admin/users`: intoarce doar userul admin curent; campurile sensibile sunt eliminate.
- `GET /api/admin/organizations`: listeaza organizatiile unde adminul are membership.
- `POST /api/admin/organizations`: creeaza organizatie, genereaza ID cu prefix `org` daca lipseste, asigura Global Policy si creeaza membership pentru adminul curent.
- `GET /api/admin/organizations/{id}`: citeste organizatia daca adminul are acces.
- `PUT /api/admin/organizations/{id}`: inlocuieste datele organizatiei, pastreaza `CreatedAt` si `DefaultIdPID` existent daca payload-ul nu il trimite.
- `DELETE /api/admin/organizations/{id}`: sterge tenant-ul si membership-urile asociate.
- `GET /api/admin/organizations/idps?organization_id=...`: listeaza IdP-urile organizatiei, cu secretele mascate.
- `POST /api/admin/organizations/idps`: creeaza IdP; cere organization_id, name, issuer si client_id; refuza al doilea IdP pentru aceeasi organizatie.
- `GET /api/admin/organizations/idps/{id}`: citeste un IdP dupa ID, cu verificare de acces pe organizatie.
- `PUT /api/admin/organizations/idps/{id}`: actualizeaza partial IdP-ul; `client_secret` si `scim_token` sunt schimbate doar daca payload-ul trimite valori non-empty.
- `DELETE /api/admin/organizations/idps/{id}`: sterge IdP-ul si reconciliaza default IdP pe tenant.
- `POST /api/admin/organizations/idps/discover`: primeste `issuer`, ruleaza OIDC discovery si intoarce endpoints sau HTTP 502 la esec.
- `GET /api/admin/sessions`: listeaza sesiunile active filtrate pe organizatiile permise.
- `DELETE /api/admin/sessions/{id}`: revoca sesiunea si auditeaza `session_revoked`.
- `GET /api/admin/audit?limit=N`: intoarce audit filtrat pe organizatii; default `limit=100`.
- `GET /api/admin/directory/users?organization_id=&idp_id=`: listeaza useri SCIM/director filtrati optional dupa organizatie si IdP.
- `GET /api/admin/directory/groups?organization_id=&idp_id=`: listeaza grupuri cu `member_ids`.
- `GET /api/admin/enrollments`: listeaza enrollments filtrate pe organizatii.
- `POST /api/admin/enrollments/{id}/approve`: semneaza certificatul, intoarce cert+CA si auditeaza `enrollment_approved`.
- `POST /api/admin/enrollments/{id}/revoke`: revoca enrollment-ul si auditeaza `enrollment_revoked`.
- `GET /api/admin/resources`: listeaza resurse filtrate pe organizatii.
- `POST /api/admin/resources`: creeaza resursa; accepta alias `organization_id` pentru `tenant_id`.
- `GET /api/admin/resources/{id}`: citeste resursa.
- `PUT /api/admin/resources/{id}`: update cu semantica PATCH pe campurile prezente; accepta alias `organization_id`.
- `DELETE /api/admin/resources/{id}`: sterge resursa si publica event de revocare.
- `GET /api/admin/policies`: listeaza politici; daca se filtreaza pe organizatie, include politicile asignate organizatiei.
- `POST /api/admin/policies`: creeaza politica dupa validarea conditiilor; `action` este derivata din `conditions.authentication.policy`.
- `GET /api/admin/policies/{id}`: citeste politica daca adminul are acces la organizatia ei sau la assignment-urile ei.
- `PUT /api/admin/policies/{id}`: actualizeaza politica, cu aceleasi validari ca la create.
- `DELETE /api/admin/policies/{id}`: sterge politica, cu exceptia Global Policy default.
- `GET /api/admin/policy-assignments`: listeaza assignment-uri filtrate pe organizatii.
- `POST /api/admin/policy-assignments`: creeaza assignment; refuza asignarea manuala a Global Policy default si valideaza targetul.
- `GET /api/admin/policy-assignments/{id}`: citeste assignment.
- `PUT /api/admin/policy-assignments/{id}`: actualizeaza assignment, cu exceptia assignment-ului Global Policy default.
- `DELETE /api/admin/policy-assignments/{id}`: sterge assignment, cu exceptia assignment-ului Global Policy default.
- `order_placement` pentru assignment poate fi `top`, `bottom` sau `replace`; `replace` sterge celelalte assignment-uri non-default din acelasi scope de ordine.
- `GET /api/admin/device-data`: listeaza rapoarte raw device data, sortate descrescator dupa `reported_at`; endpoint-urile cu enrollment explicit neaprobat sunt ascunse.
- `GET /api/admin/device-data/{device_id}`: citeste raportul pentru un dispozitiv, cu aceeasi filtrare de organizatie si enrollment.
- `GET /api/admin/dashboard`: intoarce `DashboardStats` cu total users, active sessions, total resources, recent denials, healthy devices si total devices.
- `GET /api/admin/gateways`: listeaza gateway-uri sanitizate si filtrate pe organizatii.
- `POST /api/admin/gateways`: creeaza gateway si intoarce tokenul plaintext doar in acest raspuns.
- `GET /api/admin/gateways/{id}`: citeste gateway sanitizat.
- `PUT /api/admin/gateways/{id}`: actualizeaza gateway.
- `DELETE /api/admin/gateways/{id}`: sterge gateway.
- `POST /api/admin/gateways/{id}/regenerate-token`: genereaza token nou.
- `POST /api/admin/gateways/{id}/revoke`: revoca gateway.
- `POST /api/admin/gateways/{id}/test-federation`: testeaza discovery OIDC pentru un issuer.

### 21.8 SCIM

- `/scim/v2/{tenant_id}/ServiceProviderConfig`
- `/scim/v2/{tenant_id}/Users`
- `/scim/v2/{tenant_id}/Users/{id}`
- `/scim/v2/{tenant_id}/Groups`
- `/scim/v2/{tenant_id}/Groups/{id}`

### 21.9 Dashboard SPA

- `/` serveste dashboard-ul;
- `/dashboard` si `/dashboard/` redirectioneaza spre `/`;
- rutele rezervate API/gRPC nu sunt preluate de SPA fallback.

## 22. Suprafata gRPC

Serverul HTTP multiplexeaza gRPC peste HTTP/2 cand `Content-Type` incepe cu `application/grpc`.

Servicii:

- `trustagent.session.AgentSessionService`
  - `StartSession`
  - `SessionStatus`
  - `ClaimSession`
  - `GetCatalog`
  - `RevokeSession`
- `trustcloud.catalog.DeviceCatalogService`
  - `GetCatalog`
- `trustagent.device.DeviceDataService`
  - `ReportDeviceData`
  - `Heartbeat`
- `trustagent.events.AgentEventsService`
  - `Watch`
- `trustcloud.agent.AgentAuthorizationService`
  - `AuthorizeResource`
- `trustagent.enrollment.EnrollmentService`
  - `StartSession`
  - `SessionStatus`
  - `CompleteSession`
- `gateway.GatewayEnrollmentService`
  - `Enroll`
  - `RenewCertificate`
- `gateway.GatewayTrustService`
  - `GetCACertificate`
  - `GetRevokedSerials`
  - `RevalidateSessions`
- `gateway.GatewayControlService`
  - `ControlStream`

Interceptorul gRPC cere certificat client pentru serviciile device, cu exceptiile gestionate separat pentru gateway si enrollment.

Full method paths gRPC folosite de interceptori/logica:

- `/trustagent.session.AgentSessionService/StartSession`
- `/trustagent.session.AgentSessionService/SessionStatus`
- `/trustagent.session.AgentSessionService/ClaimSession`
- `/trustagent.session.AgentSessionService/GetCatalog`
- `/trustagent.session.AgentSessionService/RevokeSession`
- `/trustcloud.catalog.DeviceCatalogService/GetCatalog`
- `/trustagent.device.DeviceDataService/ReportDeviceData`
- `/trustagent.device.DeviceDataService/Heartbeat`
- `/trustagent.events.AgentEventsService/Watch`
- `/trustcloud.agent.AgentAuthorizationService/AuthorizeResource`
- `/trustagent.enrollment.EnrollmentService/StartSession`
- `/trustagent.enrollment.EnrollmentService/SessionStatus`
- `/trustagent.enrollment.EnrollmentService/CompleteSession`
- `/gateway.GatewayEnrollmentService/Enroll`
- `/gateway.GatewayEnrollmentService/RenewCertificate`
- `/gateway.GatewayTrustService/GetCACertificate`
- `/gateway.GatewayTrustService/GetRevokedSerials`
- `/gateway.GatewayTrustService/RevalidateSessions`
- `/gateway.GatewayControlService/ControlStream`

## 23. Dashboard

Dashboard-ul este aplicatia din `pa/dashboard`.

Functionalitati expuse:

- login admin;
- setup MFA;
- login passkey;
- enrollment passkey;
- overview dashboard;
- organizatii;
- detalii organizatie;
- IdP-uri;
- gateway-uri;
- detalii gateway;
- resurse;
- detalii resursa;
- protect app flow;
- politici;
- sesiuni;
- device health/data;
- audit log.

Dashboard-ul foloseste tokenul admin si API-urile `/api/admin`. Tema UI este persistata in local storage cu cheia `pdp_theme`.

## 24. Comportamente fail-closed si defensive

Implementarea este conservatoare:

- lipsa politicilor aplicabile produce deny;
- tenant mismatch produce deny cu risc 100;
- directory user dezactivat produce deny cu risc 100;
- resursa disabled produce deny;
- gateway lipsa, neenrolled sau din alt tenant produce deny;
- protocol/port mismatch produce deny;
- token revocat produce deny;
- certificat device/gateway cu fingerprint diferit produce deny;
- mTLS lipsa pe endpoint-uri protejate produce unauthenticated/forbidden;
- SCIM fara token valid produce unauthorized;
- IdP nerezolvabil in OIDC authorize produce eroare;
- enrollment proof invalid produce respingere;
- gateway control fara ACK corect produce provisioning failure.

## 25. Observatii importante pentru mentenanta

- PDP si PA sunt in acelasi binar; nu exista un serviciu PA separat in runtime-ul curent.
- `tenant_id` si `organization_id` trebuie tratate ca sinonime functionale, dar API-ul admin prefera `organization_id`.
- Catalogul nu publica automat toate resursele unei organizatii; are nevoie de assignment-uri care fac resursa vizibila.
- Politica globala default securizeaza accesul, dar catalogul poate avea nevoie de target resources pentru publicare.
- Device data raw este preferat fata de device health agregat.
- Gateway federation legacy este pastrata in modele, dar fluxul nou accepta doar `builtin`.
- Client auth TLS este optional la handshake si obligatoriu prin middleware/interceptori pe endpoint-urile sensibile.
- Evenimentele interne sunt in-memory; ele coordoneaza runtime-ul curent, nu sunt un bus persistent extern.
- Step-up challenges sunt in-memory; restartul PDP pierde challenge-urile active.
- Sesiunile, tokenurile revocate, auditul, policy-urile si entitatile principale sunt persistente in SQLite.

## 26. Checklist de verificare cand se schimba PDP

La modificari de cod, verificati documentatia pentru:

- endpoint-uri HTTP noi sau sterse;
- metode gRPC noi sau schimbari de payload;
- campuri noi in modele;
- migrari noi in schema;
- schimbari in defaulturi config;
- noi semnale de risc;
- schimbari in ordinea de evaluare PE;
- actiuni noi de policy;
- reguli noi de assignment;
- noi motive de revocare;
- modificari in token claims sau audiences;
- modificari in identitatea certificatelor device/gateway;
- schimbari in dashboard routes sau fluxuri UX.
