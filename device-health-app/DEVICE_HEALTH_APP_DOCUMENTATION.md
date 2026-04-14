# Device Health App — Documentație Tehnică Detaliată

## Cuprins

1. [Prezentare Generală](#1-prezentare-generală)
2. [Configurare](#2-configurare)
3. [Aplicația Principală (App)](#3-aplicația-principală-app)
4. [Modele de Date](#4-modele-de-date)
5. [Monitorizare Sănătate](#5-monitorizare-sănătate)
6. [Raportare Cloud](#6-raportare-cloud)
7. [API Local](#7-api-local)
8. [Colectori Windows](#8-colectori-windows)
9. [TPM și Enrollment](#9-tpm-și-enrollment)
10. [Frontend React](#10-frontend-react)
11. [Dependențe](#11-dependențe)

---

## 1. Prezentare Generală

Device Health App (HDA) este o aplicație desktop pentru Windows care monitorizează continuu starea de sănătate a dispozitivului și raportează la cloud-ul ZTNA. Gateway-ul folosește aceste rapoarte pentru decizii de acces în timp real — un dispozitiv cu firewall dezactivat sau antivirus expirat poate fi blocat automat.

**Tehnologii principale:**
- **Framework desktop**: Wails v2.11.0 (Go backend + webview frontend)
- **Frontend**: React 18 + Vite 3
- **Colectori**: Windows-specific (netsh, WMI, PowerShell, registry)
- **Transport**: mTLS cu TLS 1.3 minim
- **Identitate**: TPM 2.0 ECDSA P-256 cu fallback software
- **Notificări**: Windows Toast notifications

**Arhitectura de ansamblu:**
```
┌──────────────────────────────────────────────────────────┐
│                     Wails Desktop App                     │
│                                                           │
│  ┌─────────────────────┐    ┌──────────────────────────┐  │
│  │   Go Backend         │    │  React Frontend          │  │
│  │                      │    │                          │  │
│  │  ┌──────────────┐   │    │  ┌────────────────────┐  │  │
│  │  │ HealthMonitor │←──│────│──│ App.jsx            │  │  │
│  │  │ (30s cycle)   │   │    │  │ health:updated evt │  │  │
│  │  └──────┬───────┘   │    │  └────────────────────┘  │  │
│  │         │            │    │  ┌────────────────────┐  │  │
│  │  ┌──────┴───────┐   │    │  │ OverallScore.jsx   │  │  │
│  │  │ 5 Collectors  │   │    │  │ (animated gauge)   │  │  │
│  │  │ OS │ FW │ AV  │   │    │  └────────────────────┘  │  │
│  │  │ DE │ PW       │   │    │  ┌────────────────────┐  │  │
│  │  └──────────────┘   │    │  │ HealthCard.jsx     │  │  │
│  │                      │    │  │ (expandable cards) │  │  │
│  │  ┌──────────────┐   │    │  └────────────────────┘  │  │
│  │  │CloudReporter  │   │    │                          │  │
│  │  │ mTLS → Cloud  │   │    │                          │  │
│  │  └──────────────┘   │    │                          │  │
│  │                      │    │                          │  │
│  │  ┌──────────────┐   │    │                          │  │
│  │  │ LocalAPI      │   │    │                          │  │
│  │  │ :12080        │   │    │                          │  │
│  │  └──────────────┘   │    │                          │  │
│  └─────────────────────┘    └──────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
                       │
              mTLS POST /api/device/health-report
                       │
                       ▼
              ┌────────────────┐
              │  Cloud Server  │
              │  :8443         │
              └────────────────┘
```

---

## 2. Configurare

### Fișier: `health-config.json`

```go
type HealthAppConfig struct {
    CloudURL       string   // URL Cloud API (ex. "https://cloud:8443")
    CertFile       string   // Cale certificat client mTLS (opțional — override enrollment)
    KeyFile        string   // Cale cheie privată client
    CAFile         string   // Cale CA pentru verificarea serverului Cloud
    DataDir        string   // Director date persistente (default "./data")
    DeviceID       string   // Identificator dispozitiv (opțional; derivat din TPM/hostname)
    ReportInterval int      // Interval raportare cloud (secunde, opțional)
}
```

### `LoadConfig(path)`

1. Citire fișier JSON de pe disc
2. **Validare securitate cale**:
   - Reject căi UNC (începe cu `\\`)
   - Reject path traversal (`..` components)
   - Reject căi absolute (root-relative)
3. Parsare în structura `HealthAppConfig`
4. Return config sau eroare

---

## 3. Aplicația Principală (App)

### 3.1 Structura `App`

```go
type App struct {
    ctx      context.Context      // Context Wails — lifecycle management
    monitor  *HealthMonitor       // Monitorizare periodică + notificări
    localAPI *LocalAPIServer      // HTTP server pe localhost:12080
    cfg      *HealthAppConfig     // Configurare
    reporter *CloudReporter       // Raportare cloud via mTLS
}
```

### 3.2 Wails Configuration (`main.go`)

```go
wails.Run(&options.App{
    Title:     "Device Health",
    Width:     520,
    Height:    600,
    MinWidth:  400,
    MinHeight: 500,
    AssetServer: &assetserver.Options{
        Assets: frontend, // embed FS cu frontend/dist
    },
    BackgroundColour: &options.RGBA{R: 18, G: 18, B: 18, A: 1}, // Dark theme
    OnStartup:        app.startup,
    OnShutdown:       app.shutdown,
    Bind: []interface{}{app}, // Expune metode Go la frontend (RPC)
})
```

### 3.3 Secvența de pornire (`startup`)

**Pasul 1: Încărcare configurare**
- `LoadConfig("health-config.json")`

**Pasul 2: Creare HealthMonitor**
- `NewHealthMonitor(ctx, 30 * time.Second)`
- Interval verificare: **30 secunde**
- Emite Wails eventi `health:updated`

**Pasul 3: Key Management & Enrollment**
- `tpmauth.NewKeyManager(cfg.DataDir)` — TPM cu fallback software
- **Dacă `cert_file` + `key_file` lipsesc** (mod enrollment):
  - Goroutine enrollment cu timeout **30 minute**
  - `EnrollAndWait(ctx, km, cloudURL, caFile, deviceID, hostname, dataDir)`
  - Generare device fingerprint, creare CSR, browser auth, poll
  - `StartAutoRenewal()` — ticker 1h, reînnoire la 12h înainte de expirare
- **Dacă cert-urile sunt setate** → mod legacy, fișiere statice

**Pasul 4: Creare CloudReporter**
- `NewCloudReporter(...)` sau `NewCloudReporterWithSigner(...)` — mTLS cu TPM signer
- TLS 1.3 minim, certificat CA din configurare

**Pasul 5: Pornire LocalAPI**
- `NewLocalAPIServer(":12080", app.GetDeviceHealth)`
- Rate limiting 5 req/min
- DNS rebinding protection

**Pasul 6: Start goroutine-uri**
- `monitor.Start()` — goroutine monitorizare
- `reporter.Start()` — goroutine raportare
- `localAPI.Start()` — HTTP server

### 3.4 Funcția `GetDeviceHealth()` — Expusă la frontend via RPC Wails

Execută toate verificările de sănătate și returnează rezultatul complet:

```go
func (a *App) GetDeviceHealth() *DeviceHealth {
    checks := []HealthCheck{}

    // 1. OS Info — întotdeauna "good"
    osInfo := collectors.GetOSInfo()
    checks = append(checks, HealthCheck{
        Name:    "Operating System",
        Status:  "good",
        Details: osInfo,
    })

    // 2. Firewall
    fwStatus := collectors.CheckFirewall()
    // Status: good (toate 3 profile) / warning (parțial) / critical (dezactivat)
    checks = append(checks, ...)

    // 3. Antivirus
    avStatus := collectors.CheckAntivirus()
    // Status: good / warning (semnături expirate) / critical (off/absent)
    checks = append(checks, ...)

    // 4. Disk Encryption (BitLocker)
    deStatus := collectors.CheckDiskEncryption()
    // Status: good (fully encrypted) / critical (lipsă)
    checks = append(checks, ...)

    // 5. Password Policy & Screen Lock
    pwStatus := collectors.CheckPassword()
    // Status: good / warning / critical
    checks = append(checks, ...)

    score := calculateScore(checks)
    return &DeviceHealth{
        Checks: checks,
        Score:  score,
    }
}
```

### 3.5 `calculateScore(checks)` — Calcul scor sănătate

**Algoritm**:
1. Fiecare verificare primește o valoare numerică:
   - `"good"` → **100**
   - `"warning"` → **50**
   - `"critical"` → **0**
2. Scorul final = **media aritmetică** a tuturor valorilor
3. Rezultat: 0-100 (integer)

**Exemplu**: OS(100) + FW(100) + AV(50) + DE(0) + PW(100) = 350/5 = **70**

---

## 4. Modele de Date

### 4.1 `HealthCheck`

```go
type HealthCheck struct {
    Name    string `json:"name"`     // Numele verificării (ex. "Firewall")
    Status  string `json:"status"`   // "good" | "warning" | "critical"
    Details string `json:"details"`  // Detalii text (ex. "All profiles enabled")
}
```

### 4.2 `DeviceHealth`

```go
type DeviceHealth struct {
    Checks []HealthCheck `json:"checks"`  // Lista verificărilor
    Score  int           `json:"score"`    // Scor agregat 0-100
}
```

### 4.3 `HealthReport` (trimis la Cloud)

```go
type HealthReport struct {
    DeviceID string       `json:"device_id"`   // Identificator dispozitiv
    Health   DeviceHealth `json:"health"`       // Stare completă
    Timestamp time.Time   `json:"timestamp"`    // Momentul verificării
}
```

---

## 5. Monitorizare Sănătate

### 5.1 Structura `HealthMonitor`

```go
type HealthMonitor struct {
    ctx            context.Context
    interval       time.Duration        // 30 secunde
    getHealth      func() *DeviceHealth // Referință la App.GetDeviceHealth
    prevStatuses   map[string]string    // Stări anterioare per verificare
    mu             sync.Mutex
}
```

### 5.2 `Start()` — Goroutine monitorizare

1. **Verificare inițială** la pornire
2. **Ticker** la fiecare `interval` (30s):
   - Apelează `getHealth()`
   - `checkAndNotify(health)` — comparare cu starea anterioară
   - Emit Wails event `health:updated` cu payload `DeviceHealth`

### 5.3 `checkAndNotify(health)` — Notificări la degradare

Pentru fiecare `HealthCheck`:

1. **Compară status curent vs anterior** (din `prevStatuses`)
2. **Dacă status s-a degradat** (`isWorse(oldStatus, newStatus) == true`):
   - Trimite **Windows Toast notification**
   - Titlu: `"Device Health Warning"`
   - Mesaj: detalii despre degradarea specifică
3. **Actualizează** `prevStatuses[check.Name] = check.Status`

### 5.4 `isWorse(old, new)` — Comparare severitate

Ordinea de severitate: `good` < `warning` < `critical`

| old | new | isWorse? |
|-----|-----|----------|
| good | warning | **da** |
| good | critical | **da** |
| warning | critical | **da** |
| critical | warning | nu |
| warning | good | nu |
| orice | orice egal | nu |

### 5.5 Toast Notifications

- Biblioteca: `github.com/go-toast/toast` v1
- Platform: Windows Notification Center
- Tip: aplicație ZTNA identificată cu app name

---

## 6. Raportare Cloud

### 6.1 Structura `CloudReporter`

```go
type CloudReporter struct {
    cloudURL    string           // URL Cloud API
    httpClient  *http.Client     // HTTP client cu transport mTLS
    getHealth   func() *DeviceHealth
    deviceID    string
    triggerChan chan struct{}     // Canal pentru trigger raportare imediată
}
```

### 6.2 Creare

#### `NewCloudReporter(cloudURL, certFile, keyFile, caFile, getHealth, deviceID)`
- Încarcă cert/key statice: `tls.LoadX509KeyPair()`
- Config TLS: `MinVersion = TLS 1.3`, cert client, CA pool
- `http.Client` cu `http.Transport{TLSClientConfig: tlsConfig}`

#### `NewCloudReporterWithSigner(cloudURL, certPEM, caPEM, signer, getHealth, deviceID)`
- Construiește `tls.Certificate` din PEM-uri + TPM signer
- Aceeași configurare TLS 1.3

### 6.3 `Start()` — Goroutine raportare

Loop infinit cu **exponential backoff**:

```
interval := 30s (inițial)
maxInterval := 5 minute

for {
    select {
    case <-ticker(interval):
        err := sendReport()
        if err != nil {
            interval = min(interval * 2, maxInterval)  // Backoff
        } else {
            interval = 30s  // Reset la succes
        }
    case <-triggerChan:
        sendReport()  // Raportare imediată (trigger extern)
    case <-ctx.Done():
        return
    }
}
```

**Comportament**:
- La succes: raportare la fiecare 30s (sau `ReportInterval` din config)
- La eroare (rețea/server): backoff → 60s, 120s, 240s, **300s max** (5 min)
- La reconectare cu succes: reset la 30s
- `TriggerReport()` — forțare raportare imediată (apelat la schimbări detectate)

### 6.4 `sendReport()` — Trimitere raport

1. Apelează `getHealth()` → stare completă
2. Construiește `HealthReport{DeviceID, Health, Timestamp}`
3. Serializare JSON
4. **POST** `{cloudURL}/api/device/health-report`
   - Header: `Content-Type: application/json`
   - Body: JSON health report
   - mTLS: certificat client obligatoriu
5. Verificare status response: 200 OK → succes

---

## 7. API Local

### 7.1 Prezentare

Server HTTP pe `localhost:12080` care permite altor aplicații locale (ex. connect-app) să interogheze starea de sănătate a dispozitivului fără a necesita acces la Cloud.

### 7.2 Structura `LocalAPIServer`

```go
type LocalAPIServer struct {
    addr      string                    // ":12080"
    getHealth func() *DeviceHealth
    server    *http.Server
}
```

### 7.3 Endpoint-uri

| Endpoint | Metodă | Scop | Răspuns |
|----------|--------|------|---------|
| `/status` | GET | Status simplificat | `{"status": "healthy", "score": 85}` |
| `/health` | GET | Raport complet | `DeviceHealth` JSON complet |

### 7.4 Protecții de securitate

#### Rate Limiting
- **5 request-uri per minut** per endpoint
- Implementat cu counter + timer reset
- La depășire: `429 Too Many Requests`

#### DNS Rebinding Protection
- Verificare header `Host` la fiecare cerere
- Acceptă doar:
  - `localhost` (cu sau fără port)
  - `127.0.0.1` (cu sau fără port)
- Alt host → `403 Forbidden`
- Previne atacuri DNS rebinding unde un domeniu malițios rezolvă la 127.0.0.1

#### CORS Headers
- `Access-Control-Allow-Origin`: doar origini localhost/127.0.0.1
- Previne accesul din pagini web externe

### 7.5 Start/Stop

- **Start()**: `go server.ListenAndServe()` — goroutine background
- **Stop()**: `server.Shutdown(ctx)` — grațios cu timeout 5s

---

## 8. Colectori Windows

### 8.1 OS Info (`collectors/os_info.go`)

**Funcție**: `GetOSInfo() string`

**Implementare**:
- Citire din Windows Registry:
  ```
  HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
  ```
- Câmpuri: `ProductName`, `CurrentBuild`, `DisplayVersion`
- **Status**: întotdeauna `"good"` (informativ)
- **Exemplu output**: `"Windows 11 Pro, Build 22631, Version 23H2"`

### 8.2 Firewall (`collectors/firewall.go`)

**Funcție**: `CheckFirewall() (status string, details string)`

**Implementare**:
- Comandă: `netsh advfirewall show allprofiles state`
- Parsare output: caută `"ON"` / `"OFF"` per profil (Domain, Private, Public)

**Logica de evaluare**:

| Condiție | Status | Detalii |
|----------|--------|---------|
| Toate 3 profile ON | `"good"` | "All profiles enabled: Domain, Private, Public" |
| 1-2 profile ON | `"warning"` | "Partial: {profiles} enabled, {profiles} disabled" |
| Toate OFF | `"critical"` | "Firewall disabled on all profiles" |
| Eroare execuție | `"critical"` | "Unable to determine firewall status: {error}" |

### 8.3 Antivirus (`collectors/antivirus.go`)

**Funcție**: `CheckAntivirus() (status string, details string)`

**Implementare**:
- **Interogare WMI** (Windows Management Instrumentation):
  ```
  SELECT displayName, productState FROM AntivirusProduct
  ```
  Namespace: `root\SecurityCenter2`
- **Decodare `productState`** (bitmask pe 32 biți):

  | Bit | Poziție | Semnificație |
  |-----|---------|-------------|
  | Protecție activă | Bit 12 (0x1000) | `productState & 0x1000 != 0` → activ |
  | Semnături actuale | Bit 4 (0x10) | `productState & 0x10 == 0` → semnături la zi |

**Logica de evaluare**:

| Condiție | Status | Detalii |
|----------|--------|---------|
| Protecție + semnături OK | `"good"` | "{name}: Active, signatures up to date" |
| Protecție activă, semnături expirate | `"warning"` | "{name}: Active, but signatures outdated" |
| Protecție dezactivată | `"critical"` | "{name}: Inactive/disabled" |
| Niciun produs detectat | `"critical"` | "No antivirus product detected" |
| Eroare WMI | `"critical"` | "Unable to query antivirus: {error}" |

### 8.4 Disk Encryption / BitLocker (`collectors/disk_encryption.go`)

**Funcție**: `CheckDiskEncryption() (status string, details string)`

**Implementare** (fallback chain):

1. **Încercare primară: PowerShell**
   ```powershell
   Get-BitLockerVolume -MountPoint C: | Select-Object -ExpandProperty ProtectionStatus
   ```
   - `"On"` → protecție activă

2. **Fallback: manage-bde**
   ```
   manage-bde -status C:
   ```
   - Parsare output: caută `"Protection Status"` linie

**Logica de evaluare**:

| Condiție | Status | Detalii |
|----------|--------|---------|
| ProtectionStatus = On | `"good"` | "BitLocker enabled on C:" |
| ProtectionStatus = Off | `"critical"` | "BitLocker not enabled on system drive" |
| Commandă eșuată | `"critical"` | "Unable to determine encryption status" |

**Notă**: Se verifică doar drive-ul `C:` (drive-ul de sistem).

### 8.5 Password Policy & Screen Lock (`collectors/password.go`)

**Funcție**: `CheckPassword() (status string, details string)`

**Implementare** (3 verificări independente):

#### Verificare 1: Complexitate parolă
- Comandă: `net accounts`
- Parsează:
  - `Minimum password length` (minim recomandat: 8 caractere)
  - `Password complexity` (enabled/disabled)

#### Verificare 2: Screen Lock timeout
- Comandă PowerShell:
  ```powershell
  powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE
  ```
- Parsează timeout-ul de stingere display (AC/DC power)
- Verifică dacă timeout ≤ threshold rezonabil (nu infinit)

#### Verificare 3: Screen Saver securizat
- Citire registry:
  ```
  HKCU\Control Panel\Desktop\ScreenSaverIsSecure
  ```
- Valoare `"1"` → screen saver necesită parolă la revenire

**Logica de evaluare**:

| Condiție | Status | Detalii |
|----------|--------|---------|
| Toate verificările OK | `"good"` | "Password policy compliant, screen lock configured" |
| Parțial conform | `"warning"` | Detalii specifice (ex. "Screen lock timeout too long") |
| Lipsă protecție | `"critical"` | "No password complexity, no screen lock" |

---

## 9. TPM și Enrollment

### 9.1 Prezentare

Device Health App utilizează aceeași arhitectură TPM ca Connect App, cu componenta identificată ca `"health"` în cererile de enrollment.

### 9.2 Key Manager (identic cu Connect App)

- `NewKeyManager(dataDir)` → încearcă TPM 2.0, fallback software ECDSA P-256
- Salvare chei în `data/tpm-key.json` (blob TPM) sau `data/client.key` (PEM)
- `DeviceFingerprint()`: `"ek-{SHA256(EKPub)}"` (TPM) sau `"sw-{SHA256(MachineGuid)}"` (software)

### 9.3 Enrollment

#### Structuri specifice

```go
type enrollmentRequest struct {
    DeviceID             string `json:"device_id"`
    Component            string `json:"component"`       // "health"
    Hostname             string `json:"hostname"`
    CSRPEM               string `json:"csr_pem"`
    PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

type enrollmentResponse struct {
    SessionID string `json:"session_id"`
    AuthURL   string `json:"auth_url"`
}
```

#### `EnrollAndWait(ctx, km, cloudURL, caFile, deviceID, hostname, dataDir)` — Flux principal

1. **Verificare cache** (`client.crt` în dataDir):
   - Certificat valid + fingerprint match → return cached
   - Expiră în < 12h → `renewCertFlow()` proactiv
   - Mismatch fingerprint → șterge cert-uri, enrollment nou

2. **Generare CSR**:
   - Subject: `CN=deviceID, O="ZeroTrust Device"`
   - Semnat cu TPM/software signer

3. **Start sesiune enrollment**:
   - POST `/api/enroll/start-session`
   - Body: `enrollmentRequest` cu `component: "health"`
   - Răspuns: `{session_id, auth_url}`
   - Deschidere browser cu `auth_url`

4. **Polling WaitForBrowserAuth**:
   - GET `/api/enroll/session-status?session={id}`
   - Interval: **3 secunde**
   - Timeout: **30 minute** (specificat în context la pornirea goroutine-ului)
   - Stări: `pending` → continuă, `authenticated` → return cert, `denied`/`expired` → eroare

5. **WaitForApproval** (dacă admin approval necesar):
   - Exponential backoff: **5s → 10s → 20s → 40s → 60s** (cap)
   - Timeout din context

6. **Cache pe disc**: `client.crt` + `ca.crt` (permisiuni 0600)

### 9.4 Auto-Renewal

#### `StartAutoRenewal(ctx, km, cloudURL, caFile, deviceID, hostname, dataDir)` — Goroutine

- **Ticker**: verificare la fiecare **1 oră**
- Per tick:
  - Citire `client.crt` → parsare `NotAfter`
  - Dacă expiră în < **12 ore**: `renewCertFlow()`
    - Generare CSR nou
    - POST `/api/enroll/renew` → certificat nou imediat (fără browser)
    - Salvare certificat nou pe disc
  - La eșec: log warning, continuă cu cert existent
- Oprire: la anulare context

**Model**: Certificate **24 ore**, reînnoire proactivă la **12h** înainte de expirare.

---

## 10. Frontend React

### 10.1 Stack tehnologic

| Tehnologie | Versiune | Scop |
|-----------|----------|------|
| React | 18 | Framework UI |
| Vite | 3 | Build tool + HMR |
| Wails Runtime | — | Bridge Go ↔ JS (RPC + evenimente) |

### 10.2 Structura fișiere

```
frontend/
├── index.html           # Entry point (dark background)
├── package.json         # Dependențe npm
├── vite.config.js       # Alias @wailsjs → wailsjs/
├── src/
│   ├── main.jsx         # ReactDOM.createRoot + <App />
│   ├── App.jsx          # Componenta principală
│   ├── App.css          # Stiluri dark theme
│   └── components/
│       ├── OverallScore.jsx    # Gauge animat SVG
│       └── HealthCard.jsx      # Card expandabil per verificare
└── wailsjs/             # Auto-generat de Wails
    ├── go/main/App.js   # Proxy JS → Go (GetDeviceHealth)
    └── runtime/          # EventsOn, EventsEmit
```

### 10.3 `App.jsx` — Componenta principală

#### State

```jsx
const [health, setHealth] = useState(null);     // DeviceHealth curent
const [loading, setLoading] = useState(true);    // Încărcare inițială
const [refreshing, setRefreshing] = useState(false); // Refresh manual
```

#### Lifecycle

1. **Mount**: Apelează `GetDeviceHealth()` via Wails RPC → setează state inițial
2. **Event listener**: `EventsOn("health:updated", handler)`
   - La fiecare event emis de `HealthMonitor` Go → actualizare `health` state
3. **Fallback poll**: `setInterval(GetDeviceHealth, 5 * 60 * 1000)` — **5 minute**
   - Safety net în caz de pierdere eventi
4. **Cleanup**: `EventsOff("health:updated")` + `clearInterval`

#### Render

```jsx
return (
    <div className="app dark-theme">
        <header>
            <h1>Device Health</h1>
            <button onClick={handleRefresh} disabled={refreshing}>
                {refreshing ? "Refreshing..." : "Refresh"}
            </button>
        </header>

        {loading ? (
            <div className="loading">Checking device health...</div>
        ) : (
            <>
                <OverallScore score={health.score} />
                <div className="health-cards">
                    {health.checks.map((check, i) => (
                        <HealthCard key={i} check={check} index={i} />
                    ))}
                </div>
            </>
        )}
    </div>
);
```

### 10.4 `OverallScore.jsx` — Gauge animat SVG

**Vizualizare**: Arc SVG semicircular (0-100) cu animație fluida + indicator color.

#### Implementare

```jsx
const OverallScore = ({ score }) => {
    const radius = 80;
    const circumference = Math.PI * radius;        // Jumătate de cerc
    const offset = circumference - (score / 100) * circumference;

    const getColor = (score) => {
        if (score >= 80) return "#4ade80";   // Verde — sănătos
        if (score >= 60) return "#facc15";   // Galben — warning
        if (score >= 40) return "#fb923c";   // Portocaliu — risc
        return "#ef4444";                     // Roșu — critic
    };

    return (
        <div className="overall-score">
            <svg viewBox="0 0 200 120">
                {/* Arc de fundal (gri) */}
                <path d="M 20 100 A 80 80 0 0 1 180 100"
                      fill="none" stroke="#333" strokeWidth="12" />
                {/* Arc de progres (colorat, animat) */}
                <path d="M 20 100 A 80 80 0 0 1 180 100"
                      fill="none"
                      stroke={getColor(score)}
                      strokeWidth="12"
                      strokeDasharray={circumference}
                      strokeDashoffset={offset}
                      strokeLinecap="round"
                      style={{ transition: "stroke-dashoffset 1s ease, stroke 0.5s ease" }}
                />
            </svg>
            <div className="score-text">
                <span className="score-number">{score}</span>
                <span className="score-label">/ 100</span>
            </div>
        </div>
    );
};
```

**Praguri de culoare**:
| Scor | Culoare | Semnificație |
|------|---------|-------------|
| 80-100 | `#4ade80` (verde) | Dispozitiv sănătos |
| 60-79 | `#facc15` (galben) | Atenție necesară |
| 40-59 | `#fb923c` (portocaliu) | Risc moderat |
| 0-39 | `#ef4444` (roșu) | Stare critică |

**Animație**: Proprietatea CSS `transition` pe `stroke-dashoffset` (1s ease) creează o animație fluida a arcului la schimbarea scorului.

### 10.5 `HealthCard.jsx` — Card expandabil

**Vizualizare**: Card per verificare cu icon status, nume, detalii expandabile la click.

#### Implementare

```jsx
const HealthCard = ({ check, index }) => {
    const [expanded, setExpanded] = useState(false);

    const statusIcons = {
        good: "✓",
        warning: "⚠",
        critical: "✕"
    };

    const statusColors = {
        good: "#4ade80",
        warning: "#facc15",
        critical: "#ef4444"
    };

    return (
        <div
            className={`health-card ${expanded ? "expanded" : ""}`}
            onClick={() => setExpanded(!expanded)}
            style={{
                animationDelay: `${index * 0.1}s`,   // Intrare staggered
                borderLeft: `3px solid ${statusColors[check.status]}`
            }}
        >
            <div className="card-header">
                <span className="status-icon"
                      style={{ color: statusColors[check.status] }}>
                    {statusIcons[check.status]}
                </span>
                <span className="check-name">{check.name}</span>
                <span className="expand-arrow">{expanded ? "▲" : "▼"}</span>
            </div>
            {expanded && (
                <div className="card-details">
                    <p>{check.details}</p>
                </div>
            )}
        </div>
    );
};
```

**Animații**:
- **Intrarea staggered**: Fiecare card apare cu delay `index * 0.1s` (efect cascadă)
  - CSS keyframe `slideIn`: translateY(20px) + opacity(0) → translateY(0) + opacity(1)
- **Expand/Collapse**: Tranziție max-height + opacity
- **Border color**: Indicare vizuală a statusului (verde/galben/roșu)

### 10.6 Stiluri CSS (`App.css`)

**Dark Theme**:
```css
.app {
    background: #121212;           /* Fundal principal */
    color: #e0e0e0;                /* Text principal */
    font-family: 'Segoe UI', sans-serif;  /* Font Windows nativ */
    min-height: 100vh;
    padding: 20px;
}

.health-card {
    background: #1e1e1e;           /* Card background */
    border-radius: 8px;
    margin-bottom: 8px;
    padding: 12px 16px;
    cursor: pointer;
    transition: background 0.2s;
}

.health-card:hover {
    background: #2a2a2a;           /* Hover highlight */
}
```

---

## 11. Dependențe

### Go (`go.mod`)

| Modul | Versiune | Scop |
|-------|----------|------|
| `github.com/wailsapp/wails/v2` | v2.11.0 | Framework desktop (Go + webview) |
| `github.com/google/go-tpm` | v0.9.8 | Comenzi TPM 2.0 |
| `github.com/go-toast/toast` | v1 | Windows toast notifications |
| `golang.org/x/sys` | — | Windows syscall-uri (registry, WMI) |

### Frontend (`package.json`)

| Pachet | Scop |
|--------|------|
| `react` + `react-dom` | React 18 runtime |
| `vite` | Build tool + dev server |
| `@vitejs/plugin-react` | JSX transform + HMR |

### Build

- **Backend**: `wails build` → compilare Go + embed frontend dist
- **Frontend**: `npm run build` → Vite → `frontend/dist/` (embed FS)
- **Output**: `build/bin/device-health-app.exe` — executabil Windows standalone
