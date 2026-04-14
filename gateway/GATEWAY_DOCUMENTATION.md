# Gateway ZTNA — Documentație Tehnică Detaliată

## Cuprins

1. [Prezentare Generală](#1-prezentare-generală)
2. [Arhitectura Microserviciilor](#2-arhitectura-microserviciilor)
3. [Portal — Data Plane (PEP)](#3-portal--data-plane-pep)
4. [Admin — Management Plane](#4-admin--management-plane)
5. [Session Store](#5-session-store)
6. [Syslog Aggregator](#6-syslog-aggregator)
7. [Pachete Interne Partajate](#7-pachete-interne-partajate)
8. [Baza de Date SQLite](#8-baza-de-date-sqlite)
9. [Securitate](#9-securitate)
10. [Deployment cu Docker](#10-deployment-cu-docker)
11. [Funcționalități Enterprise (Faza 4)](#11-funcționalități-enterprise-faza-4)

---

## 1. Prezentare Generală

Gateway-ul este componenta centrală a arhitecturii ZTNA (Zero Trust Network Access), implementând rolul de **Policy Enforcement Point (PEP)** conform modelului NIST SP 800-207. Acționează ca un proxy de acces intermediar între utilizatorii externi (prin aplicația `connect-app`) și resursele interne ale rețelei protejate.

**Tehnologii principale:**
- **Limbaj**: Go 1.25 (compilare statică, `CGO_ENABLED=0`)
- **Bază de date**: SQLite în mod WAL (`modernc.org/sqlite` — implementare Go pură, fără dependențe C)
- **Transport**: TLS 1.3 minim, multiplexare yamux peste TCP
- **Container**: Alpine 3.20 multi-stage Docker builds
- **Protocol**: JSON over TCP (yamux streams) pentru comunicarea cu connect-app

---

## 2. Arhitectura Microserviciilor

Gateway-ul este compus din **4 microservicii independente** ce comunică prin HTTP/JSON intern și sunt orchestrate cu Docker Compose:

```
┌─────────────────────────────────────────────────────────────┐
│                  Docker Network: gateway-net                 │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  │
│  │  Portal   │  │  Admin   │  │ Session  │  │  Syslog   │  │
│  │  :9443    │  │  :8444   │  │ Store    │  │  :5514    │  │
│  │  :443     │  │          │  │  :6380   │  │           │  │
│  └────┬──┬──┘  └────┬─────┘  └────┬─────┘  └─────┬─────┘  │
│       │  │          │              │               │        │
│       │  └──────────┼──────────────┼───────────────┘        │
│       │  (syslog)   │  (sessions)  │                        │
│       │             └──────────────┘                        │
│       │                                                     │
│  ┌────┴────────────────────────────┐                        │
│  │  SQLite DB (gateway.db)         │   Volume: gateway-data │
│  │  Shared WAL mode                │                        │
│  └─────────────────────────────────┘                        │
└─────────────────────────────────────────────────────────────┘
         │                    │
    ┌────┴─────┐        ┌────┴─────┐
    │ connect  │        │  Cloud   │
    │   app    │        │ (PA/PE)  │
    │ (client) │        │ :8443    │
    └──────────┘        └──────────┘
```

### Volume-uri Docker partajate

| Volum | Scop | Consumatori |
|-------|------|-------------|
| `gateway-data` | Baza de date SQLite (`gateway.db`) | Portal (read), Admin (read/write), SessionStore (read/write) |
| `gateway-config` | Fișierul de configurare JSON | Portal, Admin |
| `gateway-certs` | Certificate TLS, mTLS, SSL | Portal, Admin |
| `gateway-logs` | Fișiere log JSONL rotative | Syslog |

### Ordinea de pornire (dependențe)

```
1. SessionStore  (healthcheck: wget http://localhost:6380/health)
2. Syslog        (healthcheck: nc -z localhost 5514)
3. Admin         (depends: sessionstore healthy, syslog healthy)
4. Portal        (depends: sessionstore healthy, syslog healthy, admin started)
```

---

## 3. Portal — Data Plane (PEP)

### 3.1 Prezentare

Portalul este **planul de date** al gateway-ului — componenta prin care trece tot traficul dintre utilizatorii externi și resursele interne. Implementează funcțiile PEP din modelul Zero Trust: autentificare, autorizare per-request, relay de trafic și monitorizare continuă a posturii.

**Port principal**: `:9443` (TLS listener pentru connect-app)
**Port OIDC**: `:443` (HTTPS callback server pentru autentificare browser)
Resolverul DNS intern nu mai este expus pe un port UDP dedicat în deployment-ul curent.

### 3.2 Secvența de pornire (`cmd/portal/main.go`)

Portalul se inițializează în următoarea ordine:

1. Parsare flag-uri CLI: `-config` (default `gateway-config.json`), `-store-url` (default `http://localhost:6380`), `-syslog-addr` (default `localhost:5514`), `-data` (default `/app/data`)
2. Încărcare configurare din fișier JSON cu aplicare override-uri din variabile de mediu
3. Inițializare client cloud (`auth.CloudClient`) — cu TLS 1.3 obligatoriu, CA custom, mTLS opțional
4. Inițializare client session store — conectare HTTP la `:6380` cu token partajat
5. Inițializare client syslog — conexiune TCP lazy la `:5514`
6. Deschidere bază de date SQLite (read-only pentru portal)
7. Creare relay manager — conectare TCP la resurse interne
8. Creare DNS resolver — mapări din DB + forward upstream pentru rezolvarea internă necesară portalului
9. Inițializare CGNAT allocator (dacă enabled) — TTL: 5 minute, GC interval: 30 secunde
10. Creare instanță Portal cu toate dependențele
11. Pornire listener TLS pe `:9443`
12. Pornire goroutine background: sincronizare CRL (60s), monitorizare certificate (12h), OIDC callback server (`:443`), sincronizare resurse de la cloud (120s)
13. Așteptare SIGINT/SIGTERM pentru shutdown grațios

**Limite conexiuni**: Portalul impune o limită maximă de **1000 conexiuni concurente** (configurabil via `maxConnections`). Conexiunile care depășesc limita sunt refuzate cu log de avertizare. Contorul de conexiuni active este gestionat atomic (`sync/atomic`).

**OIDC Health Flag**: Portalul menține un flag atomic `oidcHealthy` care reflectă starea serverului OIDC callback. Dacă serverul OIDC nu pornește sau eșuează, flag-ul devine `false` și redirectările OIDC sunt blocate (evitând redirecționarea utilizatorilor către un endpoint inaccesibil).

### 3.3 Configurare TLS

Listener-ul portalului folosește TLS 1.3 obligatoriu cu validare opțională a certificatelor client:

```
TLS MinVersion:     tls.VersionTLS13 (1.3)
Client cert mode:
  - RequireClientCert=false → tls.VerifyClientCertIfGiven
  - RequireClientCert=true  → tls.RequireAndVerifyClientCert
```

**Verificarea revocării certificatelor (CRL)**:
- Callback `VerifyConnection` extrage serial-ul certificatului peer din `ConnectionState.PeerCertificates[0].SerialNumber`
- Verifică contra unei liste locale (`sync.Map`) sincronizată de la cloud la fiecare **60 de secunde**
- Dacă serialul este revocat, conexiunea este refuzată imediat

**Certificate încărcate**:
- `tls_cert` + `tls_key` — certificat SSL public pentru portal
- `client_ca` (sau `tls_ca`) — CA pentru validarea certificatelor client mTLS
- Cloud CA — CA-ul cloud-ului pentru validarea certificatelor semnate de Cloud IdP

### 3.4 Multiplexare yamux

Fiecare conexiune TLS de la connect-app este multiplexată folosind protocolul **yamux** (Yet Another Multiplexer) de la HashiCorp. Aceasta permite ca o singură conexiune TLS să transporte mai multe stream-uri concurente:

```
Configurare yamux (server mode):
  MaxStreamWindowSize:  262144 (256 KB per stream)
  StreamOpenTimeout:    30 secunde
  StreamCloseTimeout:   5 minute
```

**Fluxul per conexiune**:
1. Se acceptă conexiunea TCP/TLS
2. Se creează sesiune yamux server (`yamux.Server(conn, config)`)
3. Se extrage device ID din CN-ul certificatului mTLS (dacă prezent)
4. Se inițializează `connectionState` per conexiune
5. Loop infinit de acceptare stream-uri → fiecare stream procesat într-un goroutine separat

**`connectionState`** reține starea autentificării per conexiune:
```go
type connectionState struct {
    mu            sync.RWMutex
    remoteAddr    string       // adresa IP a clientului
    certDeviceID  string       // CN din certificatul mTLS
    authenticated bool         // autentificat cu succes
    userID        string       // ID-ul utilizatorului
    username      string       // numele utilizatorului
    deviceID      string       // ID-ul dispozitivului
    authToken     string       // JWT-ul de acces
    refreshToken  string       // refresh token pentru rotație automată
    sessionID     string       // ID-ul sesiunii gateway
}
```

### 3.5 Tipuri de stream-uri procesate

Portalul procesează **3 tipuri de mesaje JSON** peste yamux:

#### 3.5.1 `auth_request` — Autentificare directă cu token JWT

Utilizat când connect-app are deja un token JWT (autentificare non-OIDC).

**Flux complet**:
1. **Verificarea identității dispozitivului**: Se compară `req.DeviceID` cu CN-ul certificatului mTLS (`state.certDeviceID`). Dacă diferă, se refuză cu `"Device identity mismatch"`.
2. **Validarea token-ului**: Apel către cloud `POST /api/gateway/validate-token` cu JWT-ul din request.
3. **Extragerea informațiilor utilizator**: `claims["user_id"]` și `claims["username"]` din răspunsul cloud.
4. **Generarea ID sesiune**: Format `"gw_" + hex(16 bytes random)` → ex. `gw_a3f8b1c0e5d94a2b...`
5. **Crearea sesiunii** în session store cu câmpuri:
   - `UserID`, `Username`, `DeviceID` din token/request
   - `SourceIP` din adresa conexiunii
   - `AuthToken` = JWT-ul original
   - `ExpiresAt` = `time.Now() + SessionTimeout` (default 8 ore / 28800s)
   - `Active` = true
6. **Actualizarea `connectionState`** cu date de autentificare (protected cu mutex)
7. **Răspuns**: `{"type": "auth_response", "status": "authorized", "message": "Welcome, username!"}`

#### 3.5.2 `connect` — Conectare la resursă internă

Aceasta este funcția principală — proxierea traficului către resurse protejate.

**Pasul 1: Verificarea autentificării**
- Dacă **nu este autentificat** și OIDC este configurat → declanșează fluxul OIDC:
  - Generează URL de autorizare cu PKCE via `GenerateAuthURL(state)`
  - Returnează `{"status": "auth_required", "auth_url": "https://cloud/auth/authorize?..."}`
  - Connect-app deschide URL-ul în browser pentru autentificare
- Dacă **nu este autentificat** și OIDC nu este configurat → `"denied"`

**Pasul 2: Rezolvarea CGNAT**
```
Dacă allocator CGNAT activ:
  1. Caută mapping dinamic: cgnat.Resolve(remoteAddr) → (internalIP, port)
  2. Dacă găsit → folosește IP-ul intern + resetează TTL-ul mapping-ului
  3. Dacă nu → fallback la relay.ResolveTunnelIP() (mapping-uri statice)
Altfel:
  Folosește relay.ResolveTunnelIP() direct
```

**Pasul 3: Căutarea resursei**
- `store.FindResourceByIP(resolvedIP, resolvedPort)` — caută după IP intern
- Fallback: `store.FindResourceByTunnelIP(resolvedIP, resolvedPort)` — caută după tunnel IP
- Verifică `resource.Enabled == true` — refuză dacă resursa este dezactivată
- Extrage `CloudAppID` pentru autorizare

**Pasul 4: Autorizarea accesului (cloud PA/PE)**
```go
decision = cloud.AuthorizeAccess(
    userID, username, deviceID, sourceIP,
    resolvedIP, resolvedPort, protocol, authToken, appID,
)
```
Cloud-ul evaluează cererea contra politicilor definite, verifică sănătatea dispozitivului și calculează scorul de risc. Decizia poate fi:
- `"allow"` → continuă la relay
- `"deny"` → refuză cu motivul specific (ex. *"Device health data unavailable"*)
- `"mfa_required"` → necesită autentificare multi-factor suplimentară

**Pasul 5: Stabilirea relay-ului**
- Conectare TCP la resursa internă: `relay.Connect(resolvedIP, resolvedPort)` cu timeout 10 secunde
- Trimite răspuns de succes: `{"status": "connected", "message": "Connected to 10.0.0.50:22"}`
- Pornire copiere bidirecțională cu `io.Copy` în 2 goroutine-uri:
  - `stream → targetConn` (client → resursă)
  - `targetConn → stream` (resursă → client)

**Pasul 6: Re-validarea continuă a posturii (Zero Trust)**
Un goroutine suplimentar monitorizează sesiunea pe durata relay-ului:
- **Interval**: la fiecare **2 minute**
- **Verificări**:
  1. **Auto-refresh token**: Dacă `refreshToken` este disponibil și token-ul curent expiră în mai puțin de 5 minute, apelează `cloud.RefreshAccessToken()` pentru a obține un nou JWT (rotație one-time-use)
  2. `cloud.ValidateSession(sessionID)` — validarea sesiunii
  3. `cloud.AuthorizeAccess(...)` cu aceleași parametri — re-evaluarea politicilor și posturii
- **Anomaly detection**: Evenimentele de acces permis/refuzat sunt înregistrate în detectorul de anomalii (`anomaly.RecordEvent()`)
- **Acțiune la eșec**: Închide ambele capete ale conexiunii (`stream.Close()` + `targetConn.Close()`), logează evenimentul `posture.recheck_failed`
- **Oprire**: Goroutine-ul se oprește când relay-ul se închide (channel `done`)

#### 3.5.3 `dns_resolve` — Rezolvare DNS internă

Mecanism de "Magic DNS" — connect-app interceptează cereri DNS pentru domenii interne și le rezolvă dinamic prin tunelul securizat.

**Flux complet**:
1. **Căutarea resursei**: `store.FindResourceByDomain(domain)` cu 5 strategii de matching (detaliate în Secțiunea 8.5)
2. **Rezolvarea target-ului**: Extrage IP-ul și portul intern din configurare. Dacă `internal_url` este setat, parsează host-ul și rezolvă via DNS privat dacă necesar.
3. **Alocarea CGNAT**: `cgnat.Allocate(domain, targetIP, targetPort)` — alocă sau refolosește o adresă din pool-ul 100.64.0.0/10
4. **Calculul TTL**: `time.Until(mapping.ExpiresAt)` în secunde
5. **Răspuns**: `{"status": "resolved", "domain": "...", "cgnat_ip": "100.64.0.5", "ttl": 300}`

### 3.6 Server OIDC Callback (Gateway ca Relying Party)

Gateway-ul acționează ca un **OIDC Relying Party** — inițiază fluxul de autentificare browser prin redirecționare către Cloud IdP.

**Port**: `:443` (HTTPS) sau configurat via `auth_source.callback_listen_addr`

**Rute HTTP**:
- `GET /auth/callback` — procesează redirect-ul din browser după autentificare
- `GET /auth/status` — endpoint de polling pentru connect-app (verifică dacă auth s-a completat)

#### Fluxul OIDC cu PKCE (RFC 7636)

**Pas 1: Generarea URL-ului de autorizare** (`GenerateAuthURL`)

Când un connect-app trimite o cerere `connect` fără a fi autentificat:

1. **Generare state token**: 16 bytes random → hex = 32 caractere
2. **Generare PKCE code_verifier**: 32 bytes random → base64url = 43 caractere (256 biți entropie)
3. **Calcul code_challenge**: `BASE64URL(SHA-256(code_verifier))` cu metoda S256
4. **Înregistrare stare pending** în memorie:
   ```go
   PendingOIDCAuth{
       State:        "a3f8b1c0...",        // 32 hex chars
       StateHash:    "sha256(state+nonce)", // hash cu server nonce
       ConnState:    *connectionState,      // legătură la conexiunea yamux
       RemoteAddr:   "192.168.1.50",        // IP-ul clientului
       CreatedAt:    time.Now(),
       ExpiresAt:    time.Now() + 5 min,    // TTL 5 minute
       CodeVerifier: "dBjftJeZ4CVP...",     // 43 base64url chars
   }
   ```
5. **Construcție URL autorizare**:
   ```
   https://cloud/auth/authorize?
     client_id=gw-<gateway-id>&
     response_type=code&
     redirect_uri=https://gateway/auth/callback&
     state=a3f8b1c0...&
     scope=openid+profile+email&
     code_challenge=E9Melhoa2OwvFrEMTJ...&
     code_challenge_method=S256
   ```

`client_id` nu mai este global pentru toate gateway-urile. El este generat de cloud la enrollment și persistat local în `config.AuthSource`.

**Pas 2: Autentificarea în browser** (Cloud IdP)

Connect-app deschide URL-ul în browser-ul utilizatorului. Cloud-ul:
1. Servește pagina de login
2. Validează credențialele (email + parolă + TOTP MFA)
3. Generează cod de autorizare (60 secunde validitate)
4. Redirecționează browser-ul către `https://gateway/auth/callback?code=xyz&state=abc`

**Pas 3: Procesarea callback-ului** (`handleCallback`)

1. **Rate limiting**: Verificare per-IP (max 10 cereri/minut). IP-urile care depășesc limita primesc **429 Too Many Requests**
2. **Parsare parametri**: `code`, `state`, `error` din URL query. Erorile de la IdP sunt logate dar **nu sunt expuse** în browser (mesaj generic)
3. **Validare state**: Lookup în `pendingStates[state]` + ștergere (single-use). Verificare hash state cu server nonce. Eroare dacă nu există sau expirat.
3. **Schimb de cod pentru token** (backend-to-backend, Gateway → Cloud):
   ```go
   cloud.ExchangeCodeForToken(
       tokenURL, clientID, clientSecret,
       code, redirectURI,
       pending.CodeVerifier,   // PKCE: cloud verifică SHA256(verifier) == challenge
   )
   ```
   Cloud-ul validează PKCE calculând `BASE64URL(SHA256(code_verifier))` și comparând cu `code_challenge` stocată.
4. **Crearea sesiunii** în session store cu datele din token response (`UserID`, `Username`, `AccessToken`)
5. **Marcarea conexiunii yamux** ca autentificată:
   ```go
   connState.authenticated = true
   connState.userID        = tokenResp.UserID
   connState.username      = tokenResp.Username
   connState.authToken     = tokenResp.AccessToken
   connState.sessionID     = sessionID
   ```
6. **Servire pagină HTML de succes**: „Autentificare reușită! Poți închide fereastra."

**Cleanup loop**: La fiecare **30 secunde**, iterează stările pending și le șterge pe cele expirate (> 5 minute). De asemenea, curăță intrările de rate limiting stale (> 2 minute).

### 3.7 Monitorizarea certificatelor

Portalul verifică expirarea a **4 certificate** din configurare:

| Certificat | Config key | Folosit pentru |
|---|---|---|
| TLS public | `tls_cert` | Listener portal + OIDC callback |
| mTLS client | `mtls_cert` | Gateway → Cloud comunicare |
| Client CA | `client_ca` | Validare cert connect-app |
| Cloud CA | `cloud_ca` | Validare cert server Cloud |

**Algoritm**: Citește fișierul PEM → decodifică → parsează X.509 → calculează `time.Until(cert.NotAfter)`

**Praguri de alertare**:
- **Expirat** (`< 0`): Nivel CRITICAL — syslog error `cert.expired`
- **< 7 zile**: Nivel WARNING — syslog warn `cert.expiring_soon`
- **< 30 zile**: Nivel NOTICE — syslog info `cert.expiring`

**Frecvență**: La pornire + la fiecare **12 ore** via ticker.

### 3.8 Sincronizarea listei de revocare (CRL)

- **Sursă**: `cloud.GetRevokedSerials()` → `GET /api/gateway/revoked-serials`
- **Format răspuns**: `{"revoked_serials": ["serial1", "serial2", ...]}`
- **Stocare locală**: `sync.Map` (thread-safe, fără lock pentru citiri)
- **Strategie**: Ștergere completă + reconstrucție la fiecare sincronizare
- **Frecvență**: La pornire + la fiecare **60 secunde**
- **Utilizare**: Callback `VerifyConnection` din TLS config verifică serial-ul oricărui certificat client

---

## 4. Admin — Management Plane

### 4.1 Prezentare

Admin-ul este **planul de management** al gateway-ului — oferă o interfață web (SPA) și API-uri REST pentru configurare, monitorizare și administrare.

**Port**: `:8444` (HTTPS dacă certificate configurate, altfel HTTP)
**UI framework**: Vanilla JavaScript cu template-uri Go `html/template`

### 4.2 Structura serverului

```go
type Server struct {
    cfg              *config.Config
    configPath       string
    mu               sync.RWMutex          // protejează config + tokenuri
    sessions         *sessionstore.Client
    syslogClient     *syslog.Client
    store            *store.Store
    enrolled         bool
    startTime        time.Time
    adminTokens      map[string]time.Time       // token_hex → expiry
    tokenActivity    map[string]time.Time       // token_hex → last activity (idle timeout 30 min)
    csrfTokens       map[string]string           // admin_token → csrf_token
    loginAttempts    map[string]*loginAttemptInfo // IP → tracking
    loginAttemptsMu  sync.Mutex                  // protejează loginAttempts
}
```

### 4.3 Lanțul de middleware

Toate request-urile HTTP trec prin 3-4 straturi de middleware:

```
Request → withLogging → withCORS → MaxBytesHandler(1MB) → [withAuth] → [withCSRF] → Handler
```

#### `withLogging`
Loghează fiecare request cu metoda HTTP, path-ul și durata de execuție:
```
[ADMIN] POST /api/resources/add 125ms
```

#### `withCORS` — Headere de securitate OWASP

**Origini permise** (doar localhost):
- `http://localhost`, `https://localhost`
- `http://127.0.0.1`, `https://127.0.0.1`
- `http://[::1]`, `https://[::1]`

**Headere de securitate setate**:

| Header | Valoare | Scop |
|--------|---------|------|
| `X-Content-Type-Options` | `nosniff` | Previne MIME sniffing |
| `X-Frame-Options` | `DENY` | Previne clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Limitează referrer |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` | Dezactivează API-uri browser |
| `Cache-Control` | `no-store` | Previne caching |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | HSTS 2 ani |
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'; ...` | CSP restrictiv |

#### `withAuth` — Autentificare bazată pe cookie + token
- **Primar**: Extrage cookie-ul HttpOnly `admin_token` din request
- **Fallback**: Extrage header-ul `X-Admin-Token` (pentru compatibilitate API/legacy)
- Caută token-ul în map-ul `adminTokens` folosind **constant-time comparison** (`subtle.ConstantTimeCompare`)
- Verifică expirarea: refuză dacă `time.Now().After(expiry)`
- Returnează **401 Unauthorized** dacă lipsește, invalid sau expirat

#### `withCSRF` — Protecție CSRF (Double-Submit Cookie Pattern)
- Se aplică **doar pe metodele POST, PUT, DELETE** (GET este safe)
- Extrage admin token din cookie `admin_token` (fallback: header `X-Admin-Token`)
- Extrage `X-CSRF-Token` din header
- Compară cu `csrfTokens[adminToken]` folosind **constant-time comparison**
- Returnează **403 Forbidden** dacă lipsește sau nu corespunde

### 4.4 Autentificare Admin

#### Fluxul de login (`POST /api/login`)

**Rate limiting per IP** cu exponential backoff:

| Încercări eșuate | Lock duration |
|---|---|
| 1-2 | Niciun lock |
| 3 | 1 secundă |
| 4 | 2 secunde |
| 5 | 4 secunde |
| ... | `2^(n-3)` secunde |
| Max | 5 minute (cap) |

**Procesul de autentificare**:
1. Verifică rate limiting per IP
2. Verifică setup complet
3. Decodifică request: `{"email": "...", "password": "..."}`
4. Compară email cu `config.Setup.AdminEmail` — eroare generică la mismatch
5. Verifică parola cu `bcrypt.CompareHashAndPassword()` — eroare generică la eșec
6. La succes, resetează contorul de eșecuri pe IP
7. **Generare token admin**: 32 bytes random → hex = 64 caractere, TTL **4 ore**
8. **Generare token CSRF**: 32 bytes random → hex = 64 caractere, stocat legat de admin token
9. **Setare cookie HttpOnly**: `admin_token` cookie cu `HttpOnly=true`, `Secure=true`, `SameSite=Strict`, `MaxAge=4h`
10. **Răspuns**:
   ```json
   {
       "status": "authorized",
       "csrf_token": "7b2e4f1a9c3d8e5b6a0f..."
   }
   ```
   **Notă**: Token-ul de autentificare nu mai este inclus în body-ul JSON. Este setat exclusiv ca HttpOnly cookie, inaccesibil din JavaScript (protecție XSS).

#### Schimbarea parolei (`POST /api/settings/password`)
1. Verifică parola curentă cu `bcrypt.CompareHashAndPassword()`
2. Validează parola nouă: minim **8 caractere**, cel puțin o literă mare, o literă mică, o cifră și un caracter special
3. Hash-uiește cu `bcrypt.GenerateFromPassword(..., 12)` (cost factor 12)
4. Actualizează `config.Setup.AdminPassHash`
5. **Invalidează TOATE sesiunile admin** imediat: `adminTokens = make(map[string]time.Time{})`
6. Salvează config pe disk
7. Logare: `settings.password.changed` cu mesaj "all sessions invalidated"

#### Cleanup tokeni expirați
Goroutine background care rulează la fiecare **5 minute**:
- Iterează `adminTokens` → șterge unde `expiry < time.Now()`
- Șterge și CSRF token-ul corespunzător din `csrfTokens`

### 4.5 Setup Wizard (First-Boot)

Wizard-ul de configurare inițială ghidează administratorul prin **2 pași**. Necesită **X-Setup-Token** generat la prima pornire (afișat în logurile containerului).

**Validare setup token**: Comparare constant-time cu `subtle.ConstantTimeCompare()`. Token-ul are **32 caractere hex** (16 bytes random). Setup token-ul **expiră după 30 de minute** de la generare — dacă a expirat, se regenerează automat. Validarea setup token-ului este **rate-limited** per IP (aceeași politică ca login).

#### Pas 1: Setup Token (`POST /api/setup/step/token`)
- **Input**: `X-Setup-Token` header
- **Validare**: Token non-vid, comparat constant-time cu token-ul din config; rate limiting per IP
- **Acțiune**: Validare token (nu creează cont admin, nu modifică config)

#### Pas 2: Hostname + Certificate (2 request-uri secvențiale)

**2a. Network** (`POST /api/setup/step/network`)
- **Input**: `fqdn` (ex. `gateway.ztna.test`)
- **Validare**: Non-vid, validat cu regex FQDN (`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`, max 253 caractere)
- **Acțiune**: Salvare `config.FQDN`, derivare automată endpoint-uri auth via `DeriveAuthEndpoints()`

**2b. Certificate SSL** (`POST /api/setup/step/certificates`)
3 opțiuni posibile:
1. **Upload PEM**: Primește `cert_pem` + `key_pem`, validează cu `tls.X509KeyPair()`, verifică expirarea certificatului (refuză certificate expirate, avertizează dacă expiră în < 24h), salvează ca `certs/gateway-ssl.crt` (0644) + `certs/gateway-ssl.key` (0600)
2. **Let's Encrypt**: Setează `config.LetsEncrypt = true`
3. **Cale existentă**: Acceptă `ssl_cert` + `ssl_key` ca path-uri pe disc

**2c. Finish** (`POST /api/setup/step/finish`)
- **Acțiune**:
  - `config.Setup.Completed = true`
  - `config.Setup.SetupDate = time.Now().Format(RFC3339)`
  - **Invalidare setup token**: `config.Setup.SetupToken = ""`
  - Creare sesiune admin (HttpOnly cookie `admin_token` + CSRF token)
  - Salvare config pe disk
  - Redirect automat la interfața de administrare (dashboard)
- **Protecție**: După completare, toate rutele de setup redirecționează la dashboard

**Notă**: Contul admin nu se creează în wizard. Se poate configura ulterior din interfață sau la pornire prin variabilele de mediu `ADMIN_AUTO_SETUP=true`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`.

#### Endpoint-uri de setup disponibile (opționale, nu fac parte din wizard)
- `POST /api/setup/step/password` — creare cont admin (email + parolă)
- `POST /api/setup/step/idp` — configurare Identity Provider (OIDC)
- `POST /api/setup/step/enroll` — enrollment cu cloud (cloud_url + token + CSR automat)

### 4.6 Managementul resurselor

#### Adăugare resursă (`POST /api/resources/add`)

**Validare**:
- Nume obligatoriu, validat ca DNS name (doar litere, cifre, cratime, max 63 char per label)
- IP intern validat cu `net.ParseIP()` (trebuie să fie IP valid)
- Tunnel IP (dacă setat) trebuie să fie în range-ul CGNAT `100.64.0.0/10`
- Port validat: 0-65535
- Protocol restricționat la whitelist: `rdp`, `ssh`, `http`, `https`, `tcp`
- Inferință automată a tipului din protocol: `ssh` → ssh, `rdp` → rdp, altfel → web
- Inferență protocol din tip: ssh → ssh, rdp → rdp, altfel → https
- `session_duration` default: 480 minute (8 ore)
- `enabled` default: true

**Verificare duplicate**:
- Unicitate nume: `store.GetResource(name)` → 409 Conflict dacă există
- Unicitate `CloudClientID`: `store.HasResourceWithClientID()` → 409 Conflict

**Gestiune certificate aplicație**:
- Dacă `cert_pem` + `key_pem` furnizate ca PEM content:
  - Validare pereche cu `tls.X509KeyPair()`
  - Salvare ca `certs/app-{hex(name)[:16]}.crt` (0644) + `.key` (0600)
  - Path-urile stocate în configurarea resursei

**Alocare CGNAT IP**:
- Dacă CGNAT activat și `tunnel_ip` gol → `store.NextTunnelIP()` alocă următorul IP disponibil din pool

**Persistare**: `store.CreateResource(&resource)`

#### Actualizare resursă (`POST /api/resources/update`)
- Similar cu adăugarea, dar preservă `created_at` original
- Detectare automată dacă `cert_pem` este conținut PEM sau cale de fișier (`isPath()`)
- 404 Not Found dacă resursa nu există

#### Ștergere resursă (`POST /api/resources/remove`)
- Șterge din SQLite: `store.DeleteResource(name)`
- Logare: `resource.removed`

#### Toggle resursă (`POST /api/resources/toggle`)
- Activează/dezactivează: `store.ToggleResource(name, enabled)`

### 4.7 Managementul certificatelor mTLS

#### Generare CSR (`POST /api/certs/generate-csr`)
- **Algoritm**: ECDSA pe curba **P-256** (secp256r1 / prime256v1)
- **Entropie**: `crypto/rand.Reader`
- **Câmpuri CSR**:
  - `CommonName`: default `"gateway.ztna.local"`
  - `Organization`: default `"Secure Alert Gateway"`
  - `Country`: din request (opțional)
- **Output**:
  - CSR PEM: returnat în răspuns
  - Private key: salvat ca `certs/mtls-gateway.key` (0600)
  - Config: `MTLSKey = keyPath`, `MTLSCSR = csrPEM`

#### Instalare certificat mTLS (`POST /api/certs/install-mtls`)
- **Validare**: Decodifică PEM → parsează cu `x509.ParseCertificate()`
- **Persistare**: `certs/mtls-gateway.crt` (0644)
- **Config**: `MTLSCert = certPath`, `MTLSCSR = ""`

#### Upload SSL (`POST /api/certs/upload-ssl`)
- **Validare**: `tls.X509KeyPair(certPEM, keyPEM)` — verifică perechea cert+key
- **Persistare**: `certs/gateway-ssl.crt` (0644) + `certs/gateway-ssl.key` (0600)
- **Config**: `TLSCert`, `TLSKey` actualizate

#### Status certificate (`GET /api/certs/status`)
- Citește certificatele de pe disk
- Returnează: subject, issuer, `NotAfter` (RFC3339), path-uri, stare mTLS

### 4.8 Configurare Identity Provider

#### `POST /api/idp/configure`

Salvează configurarea OIDC în `config.AuthSource`:

| Câmp | Exemplu | Scop |
|------|---------|------|
| `hostname` | `login.ztna.local` | Hostname-ul IdP-ului |
| `auth_url` | `https://cloud:8443/auth/authorize` | Endpoint autorizare |
| `token_url` | `https://cloud:8443/auth/token` | Endpoint schimb token |
| `userinfo_url` | `https://cloud:8443/auth/userinfo` | Endpoint informații user, opțional în implementarea actuală |
| `client_id` | `gw-<gateway-id>` | ID-ul OIDC dedicat gateway-ului |
| `client_secret` | `...` | Secret partajat |
| `redirect_uri` | `https://gateway/auth/callback` | Callback URL |
| `scopes` | `openid profile email` | Scope-uri solicitate |

**Actualizare parțială**: Doar câmpurile non-vide sunt suprascrise.

În modul built-in cloud, `client_id` și `client_secret` sunt bootstrapate din răspunsul de enrollment și nu mai sunt hardcodate în configurația implicită a gateway-ului.

#### `GET /api/idp`
Returnează starea configurării: `configured` (boolean dacă `ClientID != ""`), toate câmpurile + `client_secret_set` (boolean, nu expune secretul).

### 4.9 Configurare CGNAT

#### `POST /api/cgnat/configure`

| Câmp | Exemplu | Scop |
|------|---------|------|
| `enabled` | `true` | Activare/dezactivare |
| `pool_start` | `100.64.0.2` | Prima adresă din pool |
| `pool_end` | `100.127.255.254` | Ultima adresă din pool |
| `subnet_mask` | `255.192.0.0` (`/10`) | Masca de subrețea |

#### `GET /api/cgnat`
Returnează: configurarea curentă, `next_ip` (următorul IP disponibil), `assigned_ips` (numărul de resurse cu tunnel IP alocat).

### 4.10 Managementul sesiunilor

#### `GET /api/sessions`
Listează toate sesiunile active prin `sessions.ListActive()` — delegat la Session Store HTTP.

#### `POST /api/sessions/revoke`
Primește `session_id` → apelează `sessions.Revoke(session_id)` → logare `session.revoked`.

### 4.11 Politici de acces

#### `GET /api/policies`
Returnează lista de resurse cu informații despre politica de acces: `name`, `protocol`, `port`, `tunnel_ip`, `mfa_required`.

#### `POST /api/policies/save`
Structura politicii: `{"name": "app-name", "mfa_required": true}`. Actualizează flag-ul `mfa_required` al resursei prin `store.SetMFARequired(name, enabled)`.

### 4.12 Dashboard și Monitoring

#### Statistici (`GET /api/stats`)

Returnează structura `AdminStats`:
```json
{
    "active_sessions": 5,
    "total_resources": 3,
    "uptime_seconds": 86400.5,
    "portal_status": "unknown",
    "store_status": "healthy",
    "syslog_status": "healthy",
    "setup_complete": true,
    "enrolled": true,
    "cgnat_enabled": true,
    "mtls_configured": true,
    "idp_configured": true,
    "resources": [...]
}
```

#### Server-Sent Events (`GET /api/events`)

Stream SSE real-time cu refreshe la fiecare **3 secunde**:

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no
```

Format frame SSE:
```
data: {"active_sessions":5,"total_resources":3,...}\n\n
```

Flushing imediat cu `http.Flusher` la fiecare frame. Stream-ul se închide când clientul deconectează (`r.Context().Done()`).

### 4.13 Enrollment cu Cloud

#### `POST /api/enrollment/enroll`

Endpoint-ul admin folosit pentru enrollment manual (după setup wizard), forwardează request-ul către cloud.

**Request local (admin UI -> gateway)**:
```json
{
  "token": "<one-time enrollment token>",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----...",
  "fqdn": "gateway.ztna.test",
  "name": "Gateway Bucuresti"
}
```

**Request trimis către cloud (gateway -> cloud)**:
- **Endpoint**: `{CloudURL}/api/gateway/enroll`
- **Headere**: `Content-Type: application/json`
- **Body**: același payload (`token`, `csr_pem`, `fqdn`, `name`)
- **Timeout**: 15 secunde
- **TLS**: minim 1.3, CA custom dacă `CloudCA` este configurat

**Răspuns de succes (`status = "enrolled"`)**:
- `cert_pem` (certificat mTLS semnat de cloud)
- `ca_pem` (CA cloud)
- `oidc_client_id`, `oidc_client_secret`
- `oidc_auth_url`, `oidc_token_url`

La succes, gateway-ul:
- salvează `certs/mtls-gateway.crt`
- salvează `certs/cloud-ca.crt` (dacă este furnizat)
- actualizează config: `MTLSCert`, `CloudCA`
- bootstrap-ează `config.AuthSource` pentru modul cloud built-in (client OIDC per-gateway)
- marchează starea internă `enrolled = true`

Observație: în endpoint-ul de enrollment manual, CSR-ul trebuie furnizat de client. Generarea automată a CSR-ului este făcută explicit în setup wizard (`/api/setup/step/enroll`).

#### `GET /api/enrollment/status`
na.test:8443"
}
```
Returnează starea locală de enrollment:

```json
{
  "enrolled": true,
  "cloud_url": "https://cloud.zt

### 4.14 Interfața Web Admin (UI)

#### Servire UI

**Fișiere embedded** via `go:embed`:
- `//go:embed templates` → template-uri HTML (`layout.html`, `login.html`, `setup-wizard.html`, pages)
- `//go:embed static` → asset-uri statice (`app.js`, CSS, imagini)

**Pagini UI** (servite cu layout template):
`dashboard`, `applications`, `policies`, `sessions`, `logs`, `authentication`, `network`, `certificates`, `enrollment`, `settings`

**Rutare**:
- `/static/*` → servire fișiere statice (fără autentificare)
- `/setup` sau `/setup/*` → wizard setup (doar dacă setup incomplet)
- `/login` → pagina de login (redirect la dashboard dacă autentificat)
- `/` → redirect la `/dashboard`
- **Gate**: Dacă setup incomplet → toate rutele redirecționează la `/setup`

#### Frontend (`app.js`)

**Token management (HttpOnly Cookie + CSRF)**:

Autentificarea admin folosește un **HttpOnly cookie** (`admin_token`) setat de server la login. Token-ul de autentificare **nu este accesibil din JavaScript** — protecție contra XSS. Token-ul CSRF este stocat în `sessionStorage` (nu `localStorage`) pentru protecție CSRF double-submit:

```javascript
// CSRF token din sessionStorage (nu conține auth token)
let csrfToken = sessionStorage.getItem('csrfToken') || '';
```

**API helper universal**:
```javascript
async function api(path, opts) {
    opts.credentials = 'same-origin';  // trimite cookie-ul HttpOnly automat
    opts.headers['X-CSRF-Token'] = csrfToken;
    var r = await fetch(path, opts);
    if (r.status === 401) { clearToken(); redirect('/login'); }
    return r;
}
```
Autentificarea se face prin cookie-ul HttpOnly (trimis automat de browser cu `credentials: 'same-origin'`). Header-ul `X-CSRF-Token` protejează contra CSRF. La 401, se face logout automat.

**Endpoint logout** (`POST /api/logout`):
- Invalidează token-ul admin pe server
- Șterge cookie-ul `admin_token` (MaxAge=-1)
- Curăță `sessionStorage` pe client

---

## 5. Session Store

### 5.1 Prezentare

Session Store este un microserviciu HTTP dedicat persistării sesiunilor utilizator. Înlocuiește Redis din arhitectura Duo Network Gateway cu o soluție bazată pe SQLite.

**Port**: `:6380`
**Autentificare**: Header `X-Store-Token` cu comparare constant-time
**Bază de date**: SQLite partajată (`gateway.db`) pe volumul `gateway-data`

### 5.2 API-uri HTTP

| Metodă | Rută | Auth | Scop |
|--------|------|------|------|
| `GET` | `/sessions` | Da | Listare sesiuni active + non-expirate |
| `POST` | `/sessions/create` | Da | Creare sesiune nouă |
| `POST` | `/sessions/get` | Da | Citire sesiune după ID |
| `POST` | `/sessions/touch` | Da | Actualizare `last_activity` |
| `POST` | `/sessions/revoke` | Da | Revocare sesiune (soft delete: `active=0`) |
| `GET` | `/sessions/count` | Da | Număr sesiuni active |
| `GET` | `/health` | **Nu** | Health check: `{"status":"healthy"}` |

### 5.3 Middleware de autentificare (`requireAuth`)

Toate rutele (cu excepția `/health`) necesită header `X-Store-Token`:
- Token-ul provine din variabila de mediu `SESSION_STORE_TOKEN`
- **Fail-closed**: Dacă token-ul nu este configurat pe server, returnează **503 Service Unavailable** (refuză toate cererile)
- Comparare cu `subtle.ConstantTimeCompare()` — rezistent la timing attacks
- Răspuns 401 cu `{"error":"unauthorized"}` dacă lipsește sau invalid

### 5.4 Ciclul de viață al unei sesiuni

**Creare** (`create`):
- Setează `Active=true`, `LastActivity=time.Now()`
- Delegat la `store.CreateSession()` care **hash-uiește auth_token** cu SHA-256 înainte de INSERT

**Citire** (`get`):
- Returnează doar sesiuni unde `active=1 AND expires_at > now`

**Touch** (`touch`):
- Actualizează `last_activity = time.Now()` — extinde timestamp fără a modifica expirarea

**Revocare** (`revoke`):
- Setează `active = 0` — soft delete, sesiunea rămâne în DB pentru audit

**Cleanup automat**:
- Goroutine background cu ticker la interval configurabil (default **60 secunde**)
- Șterge sesiunile unde `active=0 OR expires_at < now`
- Logare: numărul de sesiuni curățate

### 5.5 Clientul Session Store

Biblioteca client (`sessionstore.Client`) este folosită de Portal și Admin:

```go
type Client struct {
    storeURL string
    token    string       // din SESSION_STORE_TOKEN env
    client   *http.Client
}
```

**Metode**: `Create()`, `Get()`, `Touch()`, `Revoke()`, `ListActive()`, `Count()`, `Health()`

Fiecare metodă trimite request HTTP cu header `X-Store-Token` și parsează răspunsul JSON.

---

## 6. Syslog Aggregator

### 6.1 Prezentare

Agregator centralizat de loguri structurate. Toate microserviciile trimit loguri prin conexiuni TCP, iar Syslog le scrie în fișiere JSONL cu rotație zilnică.

**Port**: `:5514` (TCP)
**Format**: O linie JSON per eveniment (JSONL — JSON Lines)

### 6.2 Serverul Syslog

```go
type Server struct {
    listenAddr string        // ":5514"
    logDir     string        // director log
    listener   net.Listener
    logFile    *os.File
    entries    int64         // contor total
    stopChan   chan struct{} // semnal shutdown
}
```

**Procesarea conexiunilor**:
- Protocol: **TCP** (conexiuni persistente, o linie per mesaj)
- Buffer: **64 KB** max per linie
- Parsare: Fiecare linie este decodificată ca JSON (`models.LogEntry`)
- Scriere: Append la fișierul curent + `Sync()` (fsync) pentru durabilitate audit

**Rotația fișierelor log**:
- **Frecvență**: Zilnic la miezul nopții
- **Denumire**: `gateway-YYYY-MM-DD.jsonl`
- **Calcul timer**: `time.Date(year, month, day+1, 0, 0, 0, ...)` — durata până la miezul nopții
- **Mod fișier**: `O_CREATE | O_APPEND | O_WRONLY`, permisiuni `0600` (doar owner)

**Afișare pe stdout** (vizibilă cu `docker logs`):
```
[nivel color] [timestamp] [serviciu] mesaj {câmpuri}
```
Coduri culoare ANSI: ERROR=roșu, WARN=galben, INFO=verde, DEBUG=cyan.

### 6.3 Clientul Syslog

```go
type Client struct {
    addr    string    // "syslog:5514"
    service string    // "portal", "admin", etc.
    conn    net.Conn  // conexiune TCP
    ringBuf [][]byte  // buffer circular (capacitate 1000)
}
```

**Strategia de conectare**:
- **Lazy connect**: Prima conexiune la primul apel `Send()`
- **Reconnect automat**: Dacă scriere eșuează → buferează mesajul în ring buffer → închide → reconectează → flush buffer
- **Timeout dial**: 5 secunde
- **Ring buffer**: Capacitate 1000 mesaje. Dacă buffer-ul este plin, cel mai vechi mesaj este suprascris (FIFO). La reconnect reușit, buffer-ul este golit automat cu flush.

**Metode non-blocking**:
- `Info(event, message, fields)` — spawns goroutine
- `Warn(event, message, fields)` — spawns goroutine
- `Error(event, message, fields)` — spawns goroutine

Fiecare metodă adaugă automat `Service` și `Timestamp`, serializează ca JSON și trimite pe TCP.

---

## 7. Pachete Interne Partajate

### 7.1 Client Cloud (`internal/auth`)

Comunicare backend-to-backend cu Cloud-ul (Policy Administrator + Policy Engine + IdP).

```go
type CloudClient struct {
    cloudURL     string
    apiKey       string
    client       *http.Client              // timeout 10s, TLS configurat
    sessionCache map[string]*CachedSession // cache local sesiuni
    breaker      *CircuitBreaker           // circuit breaker cloud
    stopCh       chan struct{}             // semnal shutdown pentru goroutine-uri
}
```

**Configurare TLS** (`buildCloudTLSConfig`):
- `MinVersion`: `tls.VersionTLS13` obligatoriu
- **CA loading**: `config.CloudCA` → fallback `config.TLSCA` → sistem
- **mTLS**: Dacă `MTLSCert` + `MTLSKey` setate → `tls.LoadX509KeyPair()` adăugat la `Certificates`

**Goroutine de cache cleanup**: La fiecare **5 minute**, `startCacheCleanup()` curăță sesiunile expirate din cache. Goroutine-ul se oprește la `Close()`.

#### API-uri Cloud apelate

| Metodă | Endpoint | Scop |
|--------|----------|------|
| POST | `/api/gateway/validate-token` | Validare token JWT |
| POST | `/api/gateway/authorize` | Decizie acces (PA/PE) |
| POST | `/api/gateway/session-validate` | Validare sesiune activă |
| POST | `/api/gateway/device-report` | Forward raport sănătate dispozitiv |
| POST | `/auth/token` | Schimb cod OIDC (cu PKCE `code_verifier`) |
| GET | `/api/ca/cert` | Descărcare CA cloud |
| GET | `/api/gateway/revoked-serials` | Lista seriale revocate |
| GET | `/api/gateway/resources` | Sincronizare resurse de la cloud |

#### Cache local sesiuni
- `map[string]*CachedSession` cu `ValidUntil = time.Unix(expiresAt, 0)`
- **TTL cap**: Maximum **15 minute** — `cacheSession()` limitează `ValidUntil` la `now + 15min` chiar dacă sesiunea cloud are TTL mai lung
- **Staleness bound**: `ValidateSession()` refuză sesiuni din cache mai vechi de **5 minute** (`CachedAt + 5min`) când circuitul este deschis
- `ValidateSession()` verifică cache-ul înainte de apelul cloud
- `CleanExpiredCache()` — iterează map-ul și șterge expirate, returnează numărul de sesiuni curățate

### 7.2 Alocator CGNAT (`internal/cgnat`)

Gestionare dinamică de adrese IP din range-ul RFC 6598 (100.64.0.0/10).

```go
type Allocator struct {
    poolStart, poolEnd uint32
    nextIP             uint32
    byIP               map[string]*Mapping // CGNAT IP → mapping
    byInternal         map[string]string   // "ip:port" → CGNAT IP
    byDomain           map[string]string   // domain → CGNAT IP
    defaultTTL         time.Duration       // 5 minute
    stopGC             chan struct{}
}

type Mapping struct {
    CGNATIP    string
    InternalIP string
    Port       int
    Domain     string
    CreatedAt  time.Time
    ExpiresAt  time.Time     // auto-refresh la acces
    LastAccess time.Time
    TTL        time.Duration
}
```

#### Algoritm de alocare (`Allocate`)

1. **Deduplicare by domain**: Dacă `byDomain[domain]` există și nu e expirat → refresh TTL → return
2. **Deduplicare by internal**: Dacă `byInternal["ip:port"]` există → refresh TTL + adaugă alias domain → return
3. **Alocare IP nou**:
   - Scanare liniară de la `nextIP` prin pool
   - Skip IP-urile deja ocupate
   - Wrap-around la capătul pool-ului: `nextIP = poolStart + 1`
   - Dacă pool-ul este epuizat:
     a. **Garbage collection agresiv**: `collectGarbageLocked()` — curăță toate mapping-urile expirate
     b. **Reîncercare**: Dacă s-au eliberat IP-uri, reia scanarea
     c. **Evicție LRU**: `evictOldest()` — eliberează mapping-ul cu `LastAccess` cel mai vechi
     d. **Reîncercare finală**: Dacă evicția a reușit, alocă IP-ul eliberat
     e. Eroare doar dacă toate strategiile au eșuat
4. **Creare mapping**: `ExpiresAt = now + defaultTTL`
5. **Inserare în 3 indecși**: `byIP`, `byInternal`, `byDomain`

#### Garbage Collector
- **Interval**: 30 secunde (configurabil)
- **Logic**: Iterează `byIP` → colectează cu `ExpiresAt < now`
- **Eliberare**: Șterge din toate cele 3 map-uri
- **Logging**: `"GC: cleaned N expired mapping(s), M active"`

### 7.3 Resolver DNS (`internal/dns`)

```go
type Resolver struct {
    cfg      *config.Config
    upstream string              // configurat via InternalDNS (default: gol)
    mappings map[string]string   // "resource.internal." → "10.0.0.50"
    cache    map[string]*cacheEntry // cache DNS cu TTL 60s
    cacheTTL time.Duration         // 60 secunde
}
```

**Strategia de rezolvare** (`ResolveHostA`):
1. Dacă input-ul este deja un IP → return direct
2. Verifică **cache-ul DNS** (thread-safe cu `sync.RWMutex`): dacă intrarea există și nu a expirat → return IP din cache
3. Verifică mapările locale (normalizare FQDN cu trailing dot)
4. Fallback la upstream DNS: `miekg/dns` client → query A record → return primul IP → **stochează în cache** cu TTL 60s

**Server DNS opțional** (`:5353` UDP): Răspunde din mapări locale sau forwardează upstream.

### 7.4 Relay Manager (`internal/relay`)

```go
type Relay struct {
    store *store.Store
}
```

| Funcție | Implementare |
|---------|-------------|
| `Connect(ip, port)` | `net.DialTimeout("tcp", "ip:port", 10s)` |
| `Bridge(client, target)` | 2× `io.Copy()` bidirecțional cu `CloseWrite()` |
| `IsResourceAllowed(ip, port)` | `FindResourceByIP()` fallback `FindResourceByTunnelIP()` |
| `ResolveTunnelIP(tunnelIP)` | Caută CGNAT mapping → IP intern sau passthrough |
| `GetResourceProtocol(ip, port)` | Din resursă sau ghicire: 3389→rdp, 22→ssh, 443→https |

### 7.5 Configurare (`internal/config`)

**Structura completă**:

```go
type Config struct {
    // Server
    ListenAddr        string  // default ":9443"
    FQDN              string
    DevMode           bool    // default false; true permite HTTP fără TLS și credențiale placeholder
    // TLS
    TLSCert, TLSKey   string
    TLSCA, ClientCA    string
    CloudCA            string
    RequireClientCert  bool
    LetsEncrypt        bool
    // mTLS (Gateway → Cloud)
    MTLSCert, MTLSKey  string
    MTLSCSR            string
    // Cloud
    CloudURL           string  // default "https://localhost:8443"
    CloudAPIKey        string
    // OIDC
    AuthSource         *AuthSourceConfig
    // CGNAT
    CGNAT              *CGNATConfig
    // DNS
    InternalDNS        string  // default "" (gol — nu forțează DNS extern)
    // Resources
    Resources          []Resource
    SessionTimeout     int     // default 28800 (8 ore)
    // Setup
    Setup              *SetupConfig
}
```

**Override-uri din variabile de mediu** (12 suportate):

| Variabilă | Config key |
|-----------|-----------|
| `GATEWAY_API_KEY` | `CloudAPIKey` |
| `CLOUD_URL` | `CloudURL` |
| `LISTEN_ADDR` | `ListenAddr` |
| `INTERNAL_DNS` | `InternalDNS` |
| `TLS_CERT` | `TLSCert` |
| `TLS_KEY` | `TLSKey` |
| `TLSCA` | `TLSCA` |
| `CLIENT_CA` | `ClientCA` |
| `CLOUD_CA` | `CloudCA` |
| `MTLS_CERT` | `MTLSCert` |
| `MTLS_KEY` | `MTLSKey` |
| `REQUIRE_CLIENT_CERT` | `RequireClientCert` |

**Salvare atomică**: Scrie cu `Create → Write → Sync (fsync) → Close → Rename` — asigură durabilitatea datelor pe disk înainte de redenumirea atomică (previne coruperea la crash).

**Verificare setup complet** (`IsSetupComplete()`):
```
Setup != nil AND Setup.Completed AND AdminEmail != "" AND AdminPassHash != ""
```

**Validare credențiale la pornire** (`ValidateSecrets()`):
- Verifică `CloudAPIKey` și `SESSION_STORE_TOKEN` contra unei liste de valori placeholder cunoscute (ex. `"change-me"`, `"changeme"`, `"placeholder"`, pattern-uri *CHANGE_ME*)
- În **producție** (`dev_mode=false`): Refuză pornirea cu `log.Fatalf` dacă detectează credențiale nesigure
- În **dev mode** (`dev_mode=true`): Afișează avertismente dar permite continuarea

---

## 8. Baza de Date SQLite

### 8.1 Configurare PRAGMA

```sql
PRAGMA journal_mode = WAL;          -- Write-Ahead Logging (citiri concurente)
PRAGMA synchronous = NORMAL;        -- Echilibru siguranță/performanță
PRAGMA cache_size = 5000;           -- ~20 MB cache în memorie
PRAGMA busy_timeout = 5000;         -- 5 secunde timeout la lock
```

**Conexiune**: `SetMaxOpenConns(1)` — un singur writer, necesar pentru WAL mode.

### 8.2 Schema bazei de date

#### Tabela `resources`

```sql
CREATE TABLE IF NOT EXISTS resources (
    name              TEXT PRIMARY KEY,
    type              TEXT,
    protocol          TEXT,
    internal_ip       TEXT,
    tunnel_ip         TEXT,
    port              INTEGER,
    mfa_required      INTEGER DEFAULT 0,
    enabled           INTEGER DEFAULT 1,
    cloud_app_id      TEXT,
    cloud_client_id   TEXT,
    cloud_secret      TEXT,
    description       TEXT,
    external_url      TEXT,
    internal_url      TEXT,
    internal_hosts_json TEXT,
    session_duration  INTEGER,
    cert_source       TEXT,
    cert_pem          TEXT,
    key_pem           TEXT,
    pass_headers      INTEGER DEFAULT 0,
    created_at        TEXT
);
```

#### Tabela `sessions`

```sql
CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    user_id         TEXT,
    username        TEXT,
    device_id       TEXT,
    source_ip       TEXT,
    auth_token      TEXT,       -- HASH SHA-256, nu plaintext
    cloud_session   TEXT,
    created_at      TEXT,
    expires_at      TEXT,
    last_activity   TEXT,
    active          INTEGER DEFAULT 1
);
```

#### Tabela `admin_logs`

```sql
CREATE TABLE IF NOT EXISTS admin_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT,
    service     TEXT,
    level       TEXT,
    event       TEXT,
    message     TEXT,
    fields_json TEXT DEFAULT '{}'
);
```

### 8.3 Indecși

```sql
CREATE INDEX IF NOT EXISTS idx_sessions_expires        ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_active          ON sessions(active);
CREATE INDEX IF NOT EXISTS idx_resources_tunnel_ip      ON resources(tunnel_ip);
CREATE INDEX IF NOT EXISTS idx_resources_cloud_client_id ON resources(cloud_client_id);
CREATE INDEX IF NOT EXISTS idx_admin_logs_timestamp     ON admin_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_admin_logs_level         ON admin_logs(level);
```

### 8.4 Hashing token-urilor de sesiune

Conform OWASP Session Management Cheat Sheet, token-urile de sesiune sunt hash-uite înainte de stocare:

```go
func hashToken(token string) string {
    h := sha256.Sum256([]byte(token))
    return hex.EncodeToString(h[:])
}
```

`CreateSession()` aplică `hashToken()` pe `auth_token` înainte de INSERT. Token-ul original este folosit în memorie pentru autorizare, dar baza de date conține doar hash-ul SHA-256.

### 8.5 Căutarea resurselor după domeniu

`FindResourceByDomain(domain)` implementează **5 strategii** de potrivire:

1. **Label exact**: Primul label al domeniului = numele resursei
   - `rdp-server.internal.lab.local` → caută resursa `rdp-server`
2. **Hyphenated**: Primele 2 label-uri concatenate cu cratimă
   - `my.app.internal.lab.local` → caută resursa `my-app`
3. **Substring**: Domeniul conține numele resursei ca substring
   - `test-rdp-server-v2.lab.local` → găsește resursa `rdp-server`
4. **ExternalURL hostname**: Hostname-ul din `external_url` corespunde domeniului
5. **TunnelIP**: Domeniul = tunnel IP-ul resursei (pentru rezolvare inversă)

### 8.6 Migrare resurse din config JSON

La prima pornire, Admin-ul migrează resursele din fișierul JSON de configurare în SQLite:
- Verifică `CountResources() > 0` → dacă da, skip (deja migrate)
- Iterează `config.Resources[]` → `CreateResource()` pentru fiecare
- Operație unilaterală — doar la prima pornire

---

## 9. Securitate

### 9.1 Măsuri implementate

| Categorie | Măsură | Implementare |
|-----------|--------|-------------|
| **Transport** | TLS 1.3 minim | `tls.VersionTLS13` pe toate conexiunile |
| **Transport** | HTTPS enforcement | Admin refuză pornirea fără TLS în producție (necesită `dev_mode` pt HTTP) |
| **Autentificare** | mTLS bidirecțional | Certificate client validate contra CA + CRL |
| **Autentificare** | HttpOnly cookie auth | Token-ul admin stocat în cookie HttpOnly+Secure+SameSiteStrict, inaccesibil din JS |
| **Autentificare** | Endpoint logout | `POST /api/logout` — invalidare server-side + ștergere cookie |
| **OIDC** | PKCE S256 (RFC 7636) | `code_verifier` 256-bit + `SHA256(verifier)` challenge |
| **OIDC** | State token one-time use | 128-bit random, TTL 5 min, deleted after use |
| **OIDC** | State hash cu server nonce | State verificat cu HMAC-like hash (server nonce + state) |
| **OIDC** | Callback rate limiting | Max 10 cereri/minut per IP pe `/auth/callback` |
| **OIDC** | Error message sanitization | Erorile IdP nu sunt expuse în browser (mesaje generice) |
| **Session** | Token hashing SHA-256 | Tokens hash-uite înainte de stocare în SQLite |
| **Session** | Re-validare continuă | Sesiunea re-validată la fiecare 2 min în relay |
| **Session** | Session store fail-closed | Dacă token-ul store nu e configurat, returnează 503 (nu allow-all) |
| **Admin** | CSRF tokens (double-submit) | Cookie HttpOnly + header X-CSRF-Token pe POST/PUT/DELETE |
| **Admin** | Rate limiting login | Exponential backoff per IP (1s→5min) după 3 eșecuri |
| **Admin** | Rate limiting setup wizard | Setup token validat cu rate limiting per IP |
| **Admin** | Setup token expiration | Setup token expiră după 30 minute, regenerat automat |
| **Admin** | Constant-time comparison | `subtle.ConstantTimeCompare` pentru tokeni |
| **Admin** | bcrypt password hashing | Cost factor **12** (upgrade de la default 10) |
| **Admin** | Politică parole complexe | Minim 8 char, majusculă + minusculă + cifră + caracter special |
| **Admin** | Mesaj generic la eșec login | Previne enumerarea conturilor |
| **Admin** | Invalidare sesiuni la schimbare parolă | Toate token-urile admin șterse imediat |
| **Admin** | Resource input validation | DNS name, IP, tunnel IP CGNAT range, port 0-65535, protocol whitelist |
| **Config** | Credential validation | Startup refuză credențiale placeholder/default (obligatorii în producție) |
| **Config** | Dev mode flag | `dev_mode: true` pentru dezvoltare, false (default) pentru producție |
| **Headers** | OWASP security headers | HSTS, CSP, X-Frame-Options, nosniff |
| **Headers** | Cache-Control: no-store | Previne caching date sensibile |
| **Certificate** | Monitorizare expirare | Alerte la 30d / 7d / expirat, check la 12h |
| **Certificate** | CRL sync | Seriale revocate sincronizate la 60s |
| **API** | Body limit 1 MB | `http.MaxBytesHandler` pe admin |
| **Config** | Salvare atomică | Write → Sync (fsync) → Rename atomic |
| **Logs** | Permisiuni restrictive | Fișiere log cu permisiuni `0600` (doar owner) |
| **Logs** | Syslog fsync | `logFile.Sync()` după fiecare intrare pentru durabilitate audit |
| **Logs** | Syslog ring buffer | Buffer circular (1000 mesaje) la deconectare, flush la reconnect |
| **Cleanup** | Token-uri admin | Goroutine cleanup la 5 min |
| **Cleanup** | Sesiuni expirate | Goroutine cleanup la 60s |
| **Cleanup** | OIDC pending states | Goroutine cleanup la 30s |
| **Cleanup** | OIDC rate limit entries | Curățare automată rate limit stale (>2 min) |
| **Cleanup** | Cache sesiuni cloud | Goroutine cleanup la 5 min, TTL cap 15 min, staleness bound 5 min |
| **Cleanup** | Loguri admin DB | Goroutine cleanup la 1 oră, max 10000 intrări |
| **Admin** | Admin idle session timeout | Sesiuni admin expiră după 30 min inactivitate |
| **Admin** | FQDN validation | Regex validare la setup (`^([a-zA-Z0-9]...)+[a-zA-Z]{2,}$`, max 253 char) |
| **Admin** | Cert expiry check | Refuzare certificate expirate la upload, avertizare <24h |
| **Admin** | CORS url.Parse | Validare origin cu `url.Parse()` — hostname switch (localhost/127.0.0.1/::1) |
| **Admin** | Credential redaction | Email admin redactat din log-urile de startup |
| **Audit** | Diff logging resurse | Logare câmpuri vechi/noi la modificare resursă (audit trail) |
| **Reziliență** | Circuit breaker cloud | Pattern closed/open/half-open (5 eșecuri, 30s timeout) cu fallback cache, logging tranziții |
| **Reziliență** | Connection limiter | Max 1000 conexiuni concurente pe portal (atomic counter) |
| **Reziliență** | OIDC health flag | Flag atomic — blochează redirect-uri OIDC dacă serverul callback nu funcționează |
| **Reziliență** | OIDC state cap | Max 500 stări OIDC pending simultan (protecție DoS) |
| **Reziliență** | DNS cache | Cache DNS cu TTL 60s, reduce latența și protejează contra DNS flood |
| **Reziliență** | CGNAT LRU eviction | GC agresiv + evicție oldest mapping la epuizarea pool-ului |
| **Reziliență** | Resource sync cloud | Sincronizare resurse de la cloud la fiecare 2 min (upsert + delete) |
| **OIDC** | Refresh token rotation | One-time-use refresh tokens cu rotație + detecție replay |
| **Detecție** | Anomaly detection engine | Monitorizare flood, brute-force, IP anomalii, off-hours + dropped alerts counter |
| **Identitate** | Device identity enforcement | Refuz conexiuni când certDeviceID lipsește dar request-ul pretinde DeviceID |
| **Secrets** | API rotație secrete | Endpoint admin pentru rotarea cheilor și invalidarea sesiunilor |
| **Deploy** | Syslog TCP healthcheck | Docker healthcheck `nc -z localhost 5514` — dependență healthy |
| **Config** | No default external DNS | `InternalDNS` implicit gol — nu forțează DNS extern (ex. 8.8.8.8) |

### 9.2 Principii Zero Trust aplicate (NIST SP 800-207)

| Principiu | Implementare |
|-----------|-------------|
| **Verificare continuă** | Re-validare sesiune + posture check la 2 min în relay |
| **Acces minim privilegiat** | Autorizare per-request per-resursă via cloud PA/PE |
| **Autentificare dispozitiv** | mTLS cu CN = device_id, verificat contra CRL |
| **Micro-segmentare** | Fiecare resursă accesibilă doar prin portal, izolată |
| **Nu presupune încredere** | Fiecare cerere autorizată independent |
| **Monitorizare și audit** | Toate evenimentele logate centralizat via syslog |
| **Cifrare end-to-end** | TLS 1.3 pe toate tronsoanele |

---

## 10. Deployment cu Docker

### 10.1 Servicii Docker Compose

| Serviciu | Imagine | Porturi | Dependințe |
|----------|---------|---------|------------|
| `sessionstore` | `Dockerfile.sessionstore` | 6380 | — |
| `syslog` | `Dockerfile.syslog` | 5514 | — |
| `admin` | `Dockerfile.admin` | 8444 | sessionstore (healthy), syslog |
| `portal` | `Dockerfile.portal` | 9443, 15353/udp | sessionstore (healthy), syslog, admin |

### 10.2 Dockerfile-uri (multi-stage build)

Toate serviciile folosesc același pattern:

```dockerfile
# Stage 1: Build
FROM golang:1.25-alpine AS builder
CGO_ENABLED=0 go build -o {service} ./cmd/{service}

# Stage 2: Runtime
FROM alpine:3.20
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser appuser
USER appuser
```

**Caracteristici**:
- Binare statice (`CGO_ENABLED=0`) — nu necesită librării shared
- User non-root (`appuser:1000`) — securitate la nivel container
- `ca-certificates` instalat pentru TLS
- Alpine minimal (~5 MB imagine bază)

### 10.3 Variabile de mediu

| Variabilă | Servicii | Scop |
|-----------|----------|------|
| `SESSION_STORE_TOKEN` | Toate | Secret partajat session store |
| `STORE_URL` | Admin, Portal | URL HTTP session store |
| `SYSLOG_ADDR` | Admin, Portal | Adresa TCP syslog |
| `ADMIN_AUTO_SETUP` | Admin | ActiveazÄƒ auto-provisionarea contului admin din env |
| `ADMIN_PASSWORD` | Admin | Parolă admin auto-setup |
| `GATEWAY_API_KEY` | Portal | API key comunicare cloud |
| `CLOUD_URL` | Portal | URL cloud PA/PE |

### 10.4 Health checks

| Serviciu | Endpoint | Interval | Timeout | Retries |
|----------|----------|----------|---------|---------|
| SessionStore | `GET http://localhost:6380/health` | 10s | 3s | 3 |
| Syslog | `nc -z localhost 5514` (TCP) | 10s | 3s | 3 |

SessionStore și Syslog sunt dependențe critice — Admin și Portal pornesc doar după ce ambele sunt healthy.

### 10.5 Rețea Docker

```yaml
networks:
  gateway-net:
    driver: bridge
```

Toate serviciile comunică pe aceeași rețea bridge (`gateway-net`), folosind hostname-urile definite de Docker Compose (ex. `sessionstore`, `syslog`, `admin`).

---

## 11. Funcționalități Enterprise (Faza 4)

### 11.1 Circuit Breaker pentru Cloud (`internal/auth/breaker.go`)

Pattern de reziliență pentru comunicarea gateway → cloud. Previne cascade de eșecuri când cloud-ul nu răspunde.

| Parametru | Valoare | Descriere |
|-----------|---------|-----------|
| `maxFailures` | 5 | Eșecuri consecutive pentru a deschide circuitul |
| `timeout` | 30s | Timp în starea Open înainte de Half-Open |
| `halfOpenMax` | 1 | Cereri de probă în starea Half-Open |

**Stări**: Closed → Open (după 5 eșecuri) → Half-Open (după 30s) → Closed (la succes probă)

**Logging tranziții**: Fiecare tranziție de stare este logată cu `log.Printf("[AUTH] Circuit breaker: %s → %s")` la toate cele 4 puncte de tranziție (closed→open, half-open→open, open→half-open, *→closed).

**Observabilitate**: Metode publice `State() CircuitState` (starea curentă) și `Metrics() (trips, successes, failures int64)` pentru monitorizare externă.

**Fallback**: Când circuitul e deschis, `ValidateSession()` returnează sesiunea din cache (stale) cu log de avertizare, dar doar dacă sesiunea cached nu este mai veche de **5 minute** (staleness bound). Asigură continuitatea serviciului fără a servi date arbitrar de vechi.

### 11.2 Refresh Token Rotation (`cloud/idp/oidc.go` + `internal/auth/auth.go`)

Implementare OAuth 2.0 Refresh Token cu rotație one-time-use (RFC 6749):

- **Generare**: La exchange-ul codului de autorizare, cloud-ul emite și un `refresh_token` (24h TTL)
- **Rotație**: Fiecare utilizare a refresh token-ului revocă tokenul vechi și emite unul nou
- **Detecție replay**: Dacă un token deja folosit este reutilizat, se logează alertă de securitate
- **Auto-refresh**: Portal-ul re-înnoiește automat token-ul la fiecare 2 minute (în goroutine-ul de posture check)
- **Grant type**: `POST /auth/token` acceptă acum și `grant_type=refresh_token`

### 11.3 Politici Time-Based Extinse (`cloud/policy/engine.go` + `cloud/models/models.go`)

Extinderi ale condițiilor temporale în motorul de politici:

| Câmp | Format | Exemplu | Efect |
|------|--------|---------|-------|
| `timezone` | IANA tz | `"Europe/Bucharest"` | Evaluare în timezone specificat (default: UTC) |
| `blocked_dates` | `[]"YYYY-MM-DD"` | `["2025-12-25"]` | Blocare acces în zile specifice (sărbători) |
| `date_range_start` | `"YYYY-MM-DD"` | `"2025-06-01"` | Regulă activă doar din această dată |
| `date_range_end` | `"YYYY-MM-DD"` | `"2025-09-30"` | Regulă activă doar până la această dată |

### 11.4 Detector de Anomalii (`internal/anomaly/detector.go`)

Motor de detecție comportamentală integrat în portal, monitorizează per-utilizator:

| Regulă | Tip | Severitate | Condiție |
|--------|-----|-----------|----------|
| Connection Flood | `connection_flood` | High | >50 conexiuni / 10 min |
| Brute Force | `brute_force` | Critical | >10 eșecuri auth / 10 min |
| IP Anomaly | `ip_anomaly` | Medium | >5 IP-uri distincte / 10 min |
| Off-Hours Spike | `off_hours_spike` | Medium | >5 conexiuni în afara orelor (22:00-06:00, weekend) |

**Alertele** sunt logate pe stdout prin `log.Printf` la momentul detecției. Detectorul este integrat direct în portal — evenimentele de `connect` (access granted) și `access_deny` sunt înregistrate automat.

**Overflow protection**: Canalul de alerte are capacitate limitată. Dacă este plin, alertele sunt numărate atomic în `droppedAlerts` (cu avertizare rate-limited la 1/minut). Metoda publică `DroppedAlerts() int64` expune contorul pentru monitorizare.

### 11.5 Rotație Secretă (`admin/secrets.go`)

API pentru rotarea secretelor gateway-ului prin interfața admin:

| Endpoint | Metodă | Secret | Efect |
|----------|--------|--------|-------|
| `/api/secrets/status` | GET | — | Metadata secrete (configured, hint ultimi 4 char) |
| `/api/secrets/rotate` | POST | `cloud_api_key` | Regenerare cheie API cloud (64 hex) + salvare config |
| `/api/secrets/rotate` | POST | `admin_tokens` | Invalidare toate sesiunile admin (force re-login) |

### 11.6 Sincronizare Resurse de la Cloud (`portal/portal.go`)

Portalul sincronizează periodic resursele de la cloud pentru a menține consistența între configurația centrală și cea locală.

- **Interval**: La fiecare **2 minute** (goroutine background)
- **Endpoint cloud**: `GET /api/gateway/resources` → `CloudClient.GetResources()`
- **Strategie upsert**: Pentru fiecare resursă din cloud:
  - Dacă nu există local → `CreateResource()` (creare)
  - Dacă există dar diferă (name, type, host, port, client_id, secret, roles, mfa, enabled) → `UpdateResource()` (actualizare)
  - Preserve câmpuri locale: `TunnelIP`, `Protocol`, `CertPEM`, `KeyPEM`, `InternalURL` (nu sunt suprascrise de cloud)
- **Ștergere**: Resursele locale cu `CloudAppID != ""` care nu mai există în cloud sunt șterse (`DeleteResource()`)
- **Logging**: `[PORTAL] Synced N created, M updated, K deleted resources from cloud`

### 11.7 Verificare Identitate Dispozitiv (`portal/portal.go`)

Enforcement suplimentar la nivelul portalului pentru identitatea dispozitivului:

- Dacă conexiunea TLS **nu** conține certificat client (`certDeviceID == ""`) dar request-ul `connect` pretinde un `DeviceID`, conexiunea este refuzată
- Motivul: previne spoofing-ul identității dispozitivului în absența dovezii criptografice (certificat mTLS)
- Log syslog: `security.device_identity_mismatch` cu nivel WARN
