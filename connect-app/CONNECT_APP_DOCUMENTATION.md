# Connect App — Documentație Tehnică Detaliată

## Cuprins

1. [Prezentare Generală](#1-prezentare-generală)
2. [Configurare](#2-configurare)
3. [Orchestrare (main.go)](#3-orchestrare-maingo)
4. [Adaptor TUN Windows](#4-adaptor-tun-windows)
5. [Rutare CGNAT](#5-rutare-cgnat)
6. [TCP Proxy / State Machine](#6-tcp-proxy--state-machine)
7. [Procesare Pachete TUN](#7-procesare-pachete-tun)
8. [Autentificare OIDC din Tunel](#8-autentificare-oidc-din-tunel)
9. [Tunel TLS / yamux](#9-tunel-tls--yamux)
10. [DNS Magic Resolver](#10-dns-magic-resolver)
11. [TPM și Enrollment](#11-tpm-și-enrollment)
12. [Logger](#12-logger)
13. [Dependențe](#13-dependențe)

---

## 1. Prezentare Generală

Connect App este clientul ZTNA (Zero Trust Network Access) pentru Windows care creează un tunel securizat între dispozitivul utilizatorului și gateway-ul enterprise. Implementează un **proxy TCP userspace** complet, cu adaptator TUN virtual, mașină de stare TCP cu calcul de checksum-uri, și rezolvare DNS internă prin CGNAT.

**Tehnologii principale:**
- **Limbaj**: Go (compilare statică)
- **Adaptor rețea**: Wintun (kernel-mode TUN adapter pentru Windows)
- **Multiplexare**: yamux (HashiCorp) — stream-uri multiple pe o singură conexiune TLS
- **Transport**: TLS 1.3 minim cu mTLS (certificat client obligatoriu)
- **Identitate dispozitiv**: TPM 2.0 (hardware) cu fallback ECDSA P-256 software
- **DNS**: Resolver local cu NRPT (Name Resolution Policy Table) pe Windows
- **Rețea virtuală**: CGNAT RFC 6598 (100.64.0.0/10)

**Arhitectura de ansamblu:**
```
┌─────────────────────────────────────────────────────┐
│                  Windows Client                      │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
│  │ Aplicații │  │  Magic   │  │   TUN Adapter     │  │
│  │ (RDP,    │→ │  DNS     │→ │   (Wintun)        │  │
│  │  SSH,    │  │ :53      │  │   10.0.0.1        │  │
│  │  HTTPS)  │  └──────────┘  └────────┬──────────┘  │
│  └──────────┘                         │              │
│                              ┌────────┴──────────┐   │
│                              │  TCP State Machine │   │
│                              │  (SYN/ACK/FIN/RST)│   │
│                              └────────┬──────────┘   │
│                              ┌────────┴──────────┐   │
│                              │  yamux Multiplexer │   │
│                              │  (TLS 1.3 + mTLS) │   │
│                              └────────┬──────────┘   │
└───────────────────────────────────────┼──────────────┘
                                        │
                               ┌────────┴──────────┐
                               │  Gateway Portal   │
                               │  :9443             │
                               └───────────────────┘
```

**Fluxul de date:**
1. Aplicația (ex. RDP client) rezolvă `rdp-server.lab.local` → DNS local returnează IP CGNAT `100.64.0.5`
2. Aplicația deschide conexiune TCP la `100.64.0.5:3389`
3. Ruta CGNAT dirijează pachetul prin adaptorul TUN
4. TCP state machine procesează SYN → deschide stream yamux la gateway
5. Gateway autorizează accesul și conectează relay-ul la resursa internă reală
6. Traficul curge bidirecțional: aplicație ↔ TUN ↔ yamux ↔ gateway ↔ resursă

---

## 2. Configurare

### Fișier: `connect-config.json`

```go
type Config struct {
    PEPAddress     string  // Adresa gateway PEP (host:port), ex. "gateway.local:9443"
    ServerName     string  // SNI pentru TLS handshake (opțional; default: hostname din PEPAddress)
    CertFile       string  // Legacy: cale cert mTLS static (bypass TPM enrollment)
    KeyFile        string  // Legacy: cale cheie privată statică
    CAFile         string  // Certificat CA pentru verificarea serverului TLS
    CloudURL       string  // URL Cloud API pentru enrollment device (ex. "https://cloud:8443")
    DeviceID       string  // Identificator unic dispozitiv (opțional; derivat din TPM EK sau hostname)
    DataDir        string  // Director date persistente: TPM key blobs, certificate cache (default "./data")
    TUNName        string  // Numele adaptorului TUN Windows (ex. "Wintun")
    TUNIP          string  // IP local pe adaptorul TUN (ex. "10.0.0.1")
    TUNNetmask     string  // Masca de rețea TUN (ex. "255.255.255.0")
    CGNATRange     string  // Range CGNAT pentru rutare (ex. "100.64.0.0/10")
    DNSListenAddr  string  // Adresa listener DNS magic (ex. "127.0.0.1:53")
    UpstreamDNS    string  // DNS upstream pentru domenii externe (ex. "1.1.1.1:53")
    InternalSuffix string  // Sufix domenii interne pentru Magic DNS (ex. "lab.local")
}
```

### `LoadConfig(path string)`
- Citește fișierul JSON de pe disc
- Parsează în structura `Config`
- Returnează config sau eroare

---

## 3. Orchestrare (`main.go`)

### 3.1 Structuri de date

#### `connKey` — Identificator unic al unui flux TCP

```go
type connKey struct {
    srcPort int     // Portul local al clientului din TUN
    dstIP   string  // IP-ul destinație (CGNAT)
    dstPort int     // Portul destinație (serviciu)
}
```

#### `activeConn` — Starea unui flux TCP activ

```go
type activeConn struct {
    stream           net.Conn        // Stream yamux către gateway
    flow             *tcpproxy.Flow  // Mașina de stare TCP
    mu               sync.Mutex
    closed           bool

    // Stare autentificare pending (gateway returnează auth_required)
    pendingAuth      bool            // Așteaptă completarea OIDC
    pendingSince     time.Time       // Când a fost declanșată autentificarea
    buffer           [][]byte        // Payload TCP buffered în așteptare
    bufferedBytes    int             // Total bytes buffered

    // Amânare handshake TCP
    pendingSyn       bool            // SYN primit înainte de completarea auth
    pendingClientISN uint32          // ISN-ul clientului pentru SYN-ACK amânat
}
```

#### `connTracker` — Map concurent de fluxuri TCP active

```go
type connTracker struct {
    mu    sync.RWMutex
    conns map[connKey]*activeConn
}
```

### 3.2 Constante

| Constantă | Valoare | Scop |
|-----------|---------|------|
| `maxPendingBufferBytes` | 1 MB | Maxim date buffered per flux în așteptarea auth |
| `maxAuthWait` | 2 minute | Timeout pentru autentificarea OIDC |

### 3.3 Secvența de pornire

**Pasul 1: Încărcare configurare**
- `config.LoadConfig("connect-config.json")`

**Pasul 2: Creare interfață TUN**
- `tun.New(cfg.TUNName, cfg.TUNIP, cfg.TUNNetmask)`
- Configurare IP și DNS via `netsh`

**Pasul 3: Rutare CGNAT**
- `routing.New(cfg.TUNIP)` → creare route manager
- `AddCGNATRoute()` → ruta 100.64.0.0/10 prin TUN cu metric 5

**Pasul 4: Enrollment mTLS** (punct de decizie)
- **Dacă `cert_file` + `key_file` setate** → mod legacy: fișiere statice
- **Altfel** → flux TPM/Software enrollment:
  - Creare `KeyManager` cu fallback chain (TPM → software)
  - Generare device identity (hash TPM EK sau Windows MachineGuid)
  - `EnrollAndWait()` cu timeout 5 minute browser auth
  - Start goroutine auto-renewal (reînnoire la 12h înainte de expirare, pentru certificate de 24h)

**Pasul 5: Conexiune tunel TLS**
- `connectWithRetry()` cu exponential backoff (1s, 2s, 4s, ... max 15s)
- **Mod TPM**: combină CA enrollment + CA infrastructură → `NewWithSigner()` cu TPM/software signer
- **Mod legacy**: `New()` cu fișiere cert statice
- Rezultat: conexiune mTLS cu yamux multiplexing

**Pasul 6: Setup resolver DNS**
- Creare instanță Magic DNS resolver
- Dacă `internal_suffix` configurat: setup NRPT pe Windows
- Interceptarea query-urilor pentru domenii interne → 127.0.0.1

**Pasul 7: Inițializare tracker conexiuni**
- Map gol `connTracker` pentru starea fluxurilor TCP

**Pasul 8: Goroutine monitorizare sănătate tunel**
- `tunnelHealthLoop()` — verificare conexiune la fiecare **5 secunde**
- La deconectare: `Reconnect(5)` cu exponential backoff (max 30s)

**Pasul 9: Goroutine procesare pachete TUN**
- `tunPacketLoop()` — citește pachete din device TUN
- Dispatch către handler-ele TCP state machine

**Pasul 10: Shutdown grațios**
- Așteaptă SIGINT/SIGTERM
- Închide toate conexiunile, rutele, adaptorul TUN

### 3.4 Funcții cheie de orchestrare

#### `connectWithRetry(cfg, keyMgr, enrollResult, maxAttempts)`
- Loop de retry cu exponential backoff: 1s → 2s → 4s → ... → 15s (cap)
- Rezolvă SNI din `PEPAddress` sau `ServerName`
- Returnează `Tunnel` stabilit sau nil după max încercări

#### `tunnelHealthLoop(tun_)` — Goroutine
- Verifică `tun_.IsConnected()` la fiecare **5 secunde**
- La deconectare: apelează `tun_.Reconnect(5)` cu retry

---

## 4. Adaptor TUN Windows

### 4.1 Structura `NetworkDevice`

```go
type NetworkDevice struct {
    adapter *wintun.Adapter   // Handle adaptor Wintun kernel
    session wintun.Session    // Sesiune ring buffer pentru pachete
    name    string            // Numele adaptorului (ex. "Wintun")
    tunIP   string            // IP configurat pe interfață
    netmask string            // Masca de rețea
    mu      sync.Mutex
    closed  bool
}
```

### 4.2 Constante

| Constantă | Valoare | Scop |
|-----------|---------|------|
| `RingCapacity` | 8 MB (0x800000) | Dimensiunea ring buffer-ului Wintun |

### 4.3 Funcții

#### `New(name, tunIP, netmask)` — Creare adaptor
1. **Creare adaptor kernel**: `wintun.CreateAdapter(name, "Wintun", nil)`
2. **Start sesiune**: `adapter.StartSession(RingCapacity)` cu ring 8 MB
3. **Configurare interfață** via `netsh`:
   ```
   netsh interface ip set address name={name} source=static addr={tunIP} mask={netmask} gateway=none
   netsh interface ip set dns name={name} source=static addr=127.0.0.1
   ```
   DNS-ul setat la `127.0.0.1` dirijează toate query-urile de pe TUN la resolver-ul Magic DNS local.

#### `ReadPacket()` — Citire pachet din ring buffer
- **Loop blocking**: Apelează `session.ReceivePacket()` pentru pachete raw
- **Când queue-ul e gol**: `ERROR_NO_MORE_ITEMS` → `WaitForSingleObject(session.ReadWaitEvent(), INFINITE)` — așteaptă evenimentul kernel
- **La închidere**: `ERROR_HANDLE_EOF` → return error
- Copiază pachetul într-un buffer nou (detașare de ring) → `session.ReleaseReceivePacket()`

#### `WritePacket(packet)` — Scriere pachet în ring buffer
- Thread-safe (verifică `closed` sub mutex)
- `session.AllocateSendPacket(len)` → alocă slot în ring
- Copiază datele → `session.SendPacket(buf)`

#### `Close()`
- `session.End()` — închide ring buffer
- `adapter.Close()` — eliberează handle adaptor
- Marchează `closed = true`

---

## 5. Rutare CGNAT

### 5.1 Structuri

```go
type RouteManager struct {
    routes      []route   // Rute adăugate (pentru cleanup la shutdown)
    interfaceIP string    // IP-ul TUN pentru binding rută
}

type route struct {
    destination string
    mask        string
    gateway     string
}
```

### 5.2 Funcții

#### `New(interfaceIP)` — Creare route manager
- Inițializare cu IP-ul TUN și lista goală de rute

#### `AddCGNATRoute()` — Rută CGNAT principală
- Delegare la `AddRoute("100.64.0.0", "255.192.0.0")` — range-ul complet RFC 6598 (100.64.0.0/10)

#### `AddRoute(destination, mask)` — Adăugare rută de sistem

1. **Pre-cleanup**: `route delete {destination}` (ignoră erori — curăță rute vechi)
2. **Găsire index interfață TUN**:
   - `waitForInterfaceIndex(interfaceIP, 20 retries, 250ms pause)`
   - Enumerează toate interfețele: `net.Interfaces()`
   - Pentru fiecare interfață: citește adrese → verifică match cu IP-ul TUN
   - Retry-uri necesare deoarece Windows înregistrează IP-ul adaptorului asincron
3. **Adăugare rută**:
   ```
   route add {destination} mask {mask} 0.0.0.0 metric 5 IF {ifIndex}
   ```
   - Gateway: `0.0.0.0` (on-link route)
   - Metric: **5** (prioritate înaltă)
   - `IF {ifIndex}`: legare la interfața TUN specific
4. **Tracking**: Salvare rută pentru cleanup

#### `RemoveAllRoutes()` — Cleanup la shutdown
- Iterează rutele tracked → `route delete {destination}` pentru fiecare
- Golire listă

---

## 6. TCP Proxy / State Machine

### 6.1 Prezentare

Connect App implementează un **proxy TCP userspace complet** — convertește pachetele IP raw de la adaptorul TUN în stream-uri yamux către gateway. Aceasta necesită o mașină de stare TCP care gestionează handshake-ul 3-way, numerele de secvență, segmentarea și generarea pachetelor cu checksum-uri valide.

### 6.2 Structura `Flow`

```go
type Flow struct {
    mu          sync.Mutex

    // Adresare (direcția originală)
    srcIP       net.IP    // IP client TUN (ex. 10.0.0.50)
    srcPort     uint16    // Port efemer client
    dstIP       net.IP    // IP CGNAT resursă (ex. 100.64.1.5)
    dstPort     uint16    // Port serviciu resursă

    // Tracking numere de secvență
    ourSeq      uint32    // Următorul SEQ pe care îl trimitem (start: random)
    clientSeq   uint32    // Următorul SEQ așteptat de la client

    // Stare
    established bool      // Handshake 3-way complet
}
```

### 6.3 Constante TCP

| Constantă | Valoare | Scop |
|-----------|---------|------|
| `FlagFIN` | `0x01` | Închidere conexiune |
| `FlagSYN` | `0x02` | Inițiere conexiune |
| `FlagRST` | `0x04` | Reset conexiune |
| `FlagPSH` | `0x08` | Push (livrare imediată) |
| `FlagACK` | `0x10` | Confirmare |
| `maxSegmentSize` | 1400 bytes | MSS anunțat în SYN-ACK |

### 6.4 Funcțiile mașinii de stare

#### `NewFlow(srcIP, dstIP, srcPort, dstPort)`
- Inițializare cu număr de secvență random pentru partea noastră
- Copiere defensivă a adreselor IP

#### `HandleSYN(clientISN)` — Procesare SYN de la client
1. Extrage ISN-ul clientului
2. Setează `clientSeq = clientISN + 1` (următorul byte așteptat)
3. Generează ISN propriu (deja în `ourSeq`)
4. Incrementează `ourSeq` (SYN consumă un număr de secvență)
5. Construiește și returnează pachet **SYN-ACK** (flags=SYN|ACK, include opțiune MSS=1400)

#### `HandleACK()` — Confirmare handshake
- Setează `established = true` — handshake-ul 3-way este complet
- De acum datele pot curge

#### `HandleData(seq, payload)` — Date de la client
1. **Validare număr de secvență**: Compară `seq` cu `clientSeq` așteptat
2. **Dacă mismatch**: Return duplicate ACK (retransmisie/reordonare)
3. **Dacă în ordine**:
   - `clientSeq += len(payload)`
   - Construiește pachet ACK (flags=ACK, ack=clientSeq)
   - Returnează (pachetul ACK, payload-ul extras)

#### `BuildDataPackets(data)` — Segmentare date de la resursă
- Fragmentează datele în chunk-uri de **1400 bytes** (maxSegmentSize)
- Pentru fiecare chunk:
  - Construiește pachet TCP/IP cu flags=PSH|ACK
  - Setează seq=`ourSeq`, ack=`clientSeq`
  - Incrementează `ourSeq` cu dimensiunea chunk-ului
- Returnează lista de pachete (injectate în TUN de `streamToTUN`)

#### `HandleFIN(seq)` — Închidere de la client
- Setează `clientSeq = seq + 1`
- Construiește pachet FIN-ACK (flags=FIN|ACK)
- Incrementează `ourSeq`

#### `BuildFIN()` — Inițiere închidere de la resursă
- Construiește pachet FIN (incrementează `ourSeq`)
- Trimis spre client la terminarea stream-ului yamux

#### `BuildRST(srcIP, dstIP, srcPort, dstPort, ackSeq)` — Reset conexiune
- Static helper: construiește RST-ACK pentru rejectarea conexiunilor

### 6.5 Construcția pachetelor (`buildPkt`)

**Layout**: Header IPv4 (20 bytes) + Header TCP (20-24 bytes) + Payload

#### Header IPv4 (20 bytes)

| Offset | Câmp | Valoare |
|--------|------|---------|
| 0 | Version/IHL | `0x45` (v4, 5 words = 20 bytes) |
| 2-3 | Total Length | IP + TCP + payload |
| 4-5 | Identification | Random 16-bit |
| 6-7 | Flags/Fragment | DF=1 (Don't Fragment) |
| 8 | TTL | 64 |
| 9 | Protocol | 6 (TCP) |
| 10-11 | Header Checksum | One's complement al sumei one's complement |
| 12-15 | Source IP | IP sursă |
| 16-19 | Destination IP | IP destinație |

#### Header TCP (20-24 bytes)

| Offset | Câmp | Valoare |
|--------|------|---------|
| 0-1 | Source Port | Port swap (reply direction) |
| 2-3 | Destination Port | Port swap |
| 4-7 | Sequence Number | Din starea Flow |
| 8-11 | Acknowledgment | Din starea Flow |
| 12 | Data Offset | 5 (20B) sau 6 (24B cu MSS) |
| 13 | Flags | SYN\|ACK, ACK, PSH\|ACK, FIN\|ACK, RST\|ACK |
| 14-15 | Window | 65535 (full window) |
| 16-17 | Checksum | Pseudo-header + segment |
| 20-23 | MSS Option | kind=2, len=4, value=1400 (doar în SYN-ACK) |

**Algoritm checksum (RFC 1071)**:
- **IP**: Sumă all 16-bit words din header (excluzând câmpul checksum), fold carry-uri, inversare
- **TCP**: Pseudo-header (src IP, dst IP, protocol=6, segment length) + TCP segment complet, același algoritm

### 6.6 Parsarea pachetelor (`ParsePacket`)

- Validează minim 20B IP header + 20B TCP header
- Verifică IP protocol = 6 (TCP)
- Extrage IHL (IP header length) din primul nibble
- Citește IP-uri sursă/destinație (bytes 12-20)
- Citește header TCP la offset IHL: ports, SEQ, ACK, flags, data offset
- Extrage payload-ul după header-ul TCP
- Returnează: `(srcIP, dstIP, srcPort, dstPort, seq, ack, flags, payload, error)`

---

## 7. Procesare Pachete TUN

### 7.1 `tunPacketLoop(dev, tun_, tracker)` — Goroutine principal

Loop infinit care citește pachete de pe adaptorul TUN:

1. **Filtru**: Doar pachete TCP (protocol 6)
2. **Parse**: Extrage srcIP, dstIP, srcPort, dstPort, SEQ, ACK, flags, payload
3. **Dispatch** bazat pe flag-uri TCP:

| Flag-uri | Handler | Acțiune |
|----------|---------|---------|
| RST | direct | Elimină conexiune din tracker |
| SYN (fără ACK) | `handleSYN()` | Deschide stream yamux (async) |
| DATA | `handleTCPData()` | Scrie în stream yamux |
| FIN+DATA | `handleTCPData()` apoi `handleFIN()` | Trimite data + închide |
| FIN | `handleFIN()` | Trimite FIN-ACK |
| Pure ACK | `handleTCPAck()` | Completează 3WHS |

### 7.2 `handleSYN` — Deschidere conexiune nouă

1. Creează sau recuperează `activeConn` din tracker
2. **Deschidere async stream yamux** (`context.WithTimeout(10s)`):
   - `tun_.OpenResourceStream(ctx, dstIP, dstPort)` → gateway deschide conexiune la resursă
3. **Dacă stream reușește**:
   - Stochează stream în `activeConn.stream`
   - `flow.HandleSYN(clientISN)` → generează pachet SYN-ACK
   - Trimite SYN-ACK înapoi la client prin TUN
   - Spawn goroutine `streamToTUN()` (citește răspunsuri gateway → TUN)
4. **Dacă `ErrAuthRequired`**:
   - Setează `pendingAuth=true`, `pendingSyn=true`, `pendingClientISN=clientISN`
   - Declanșează popup browser cu `authURL`
   - Spawn goroutine `waitForAuthAndConnect()`
   - **Nu trimite SYN-ACK** — amânat până la completarea auth
5. **Dacă altă eroare**:
   - Trimite RST la client
   - Elimină flux din tracker

### 7.3 `handleTCPData` — Date de la client

1. Recuperează `activeConn` din tracker
2. `flow.HandleData(seq, payload)` → validare secvență, generare ACK
3. **Dacă stream este nil** (auth pending):
   - Bufferează payload (maxim **1 MB** per flux)
   - Logare bytes buffered
4. **Dacă stream există**:
   - Scrie payload în stream yamux → gateway relay-ul la resursă

### 7.4 `handleTCPAck` — Confirmare handshake

- `flow.HandleACK()` → setează `established = true`

### 7.5 `handleFIN` — Închidere conexiune

1. `flow.HandleFIN(seq)` → generare FIN-ACK
2. Trimite FIN-ACK la client prin TUN
3. Elimină flux din tracker

### 7.6 `streamToTUN` — Goroutine date resursă → client

Goroutine per conexiune care citește de pe stream-ul yamux și injectează în TUN:

1. **Loop infinit**: Citește din stream yamux (buffer **4 KB**)
2. **Construire pachete**: `flow.BuildDataPackets(data)` → împachetează în TCP/IP cu SEQ/ACK/checksums corecte
3. **Scriere în TUN**: Injectează pachetele înapoi spre client
4. **La EOF/eroare**:
   - `flow.BuildFIN()` → trimite FIN la client
   - Elimină flux din tracker

---

## 8. Autentificare OIDC din Tunel

### 8.1 Prezentare

Când gateway-ul returnează `auth_required` (utilizatorul nu este autentificat), connect-app declanșează fluxul OIDC în browser. Particularitatea este că **handshake-ul TCP este amânat** — clientul nu primește SYN-ACK până când autentificarea nu se completează.

### 8.2 Fluxul complet

```
Client App          Connect App           Gateway           Cloud IdP
    │                    │                    │                  │
    │──SYN──────────────→│                    │                  │
    │                    │──connect stream────→│                  │
    │                    │←─auth_required─────│                  │
    │                    │   (authURL)        │                  │
    │                    │                    │                  │
    │  (SYN-ACK amânat)  │──open browser────────────────────────→│
    │                    │                    │                  │
    │                    │  (polling 2s→10s)  │                  │  User authenticates
    │                    │──connect stream────→│                  │  via OIDC + MFA
    │                    │←─connected─────────│                  │
    │                    │                    │                  │
    │←─SYN-ACK──────────│  (deferred)        │                  │
    │──ACK──────────────→│                    │                  │
    │──DATA─────────────→│──buffered data────→│──relay──────────→│ Resursă
    │←─DATA──────────────│←─relay data────────│←────────────────│
```

### 8.3 `waitForAuthAndConnect` — Goroutine de retry

- **Deadline**: `time.Now() + maxAuthWait` (**2 minute**)
- **Retry loop** cu exponential backoff (2s → 4s → 8s → **10s max**):
  - Încearcă deschiderea stream-ului la resursă
  - **Dacă reușește**:
    - Stochează stream în `activeConn`
    - Resetează starea auth
    - Dacă SYN pending → trimite SYN-ACK amânat la client
    - Flush buffer-ul de payload buffered în stream yamux
    - Spawn `streamToTUN()` goroutine
  - **Dacă încă `auth_required`**: continuă loop backoff
  - **Dacă altă eroare**: log + backoff
- **La deadline**: închide fluxul

### 8.4 `triggerAuth(authURL)` — Deschidere browser

- Pattern `sync.Once` — browser-ul se deschide o singură dată per sesiune de auth
- Validare URL: trebuie HTTPS cu host valid
- Deschidere platform-specific:
  - **Windows**: `rundll32 url.dll,FileProtocolHandler {url}`
  - **macOS**: `open {url}`
  - **Linux**: `xdg-open {url}`

### 8.5 `resetAuthOnce()`
- Resetează `sync.Once` pentru a permite trigger-ul următoarei autentificări

---

## 9. Tunel TLS / yamux

### 9.1 Structura `Tunnel`

```go
type Tunnel struct {
    pepAddr   string          // Adresa gateway PEP (host:port)
    tlsConfig *tls.Config     // Config TLS pentru mTLS
    conn      net.Conn        // Conexiune TCP (TLS-wrapped)
    session   *yamux.Session  // Multiplexor yamux
    mu        sync.Mutex
    closed    bool
}
```

### 9.2 Constante

| Constantă | Valoare | Scop |
|-----------|---------|------|
| `streamTimeout` | 10 secunde | Timeout pentru request/response pe stream-uri individuale |

### 9.3 Creare tunel

#### `New(pepAddr, certFile, keyFile, caFile, serverName)` — Mod legacy
- Încarcă cert+key static: `tls.LoadX509KeyPair(certFile, keyFile)`
- Încarcă CA din fișier → `x509.CertPool`
- Config TLS: `MinVersion = TLS 1.3`, cert client, CA pool, ServerName SNI

#### `NewWithSigner(pepAddr, certPEM, caPEM, signer, serverName)` — Mod TPM/Enrollment
- Parsează `certPEM` în block-uri DER (lanț certificat)
- Construiește `tls.Certificate` cu block-uri DER + `signer` ca `PrivateKey`
- Config TLS: `MinVersion = TLS 1.3`, certificates, CA pool, ServerName

### 9.4 Conectare

#### `Connect()` / `connectLocked()`

1. **TLS Dial**: `tls.Dial("tcp", pepAddr, tlsConfig)`
2. **Log TLS**: Versiune (0x0304 = TLS 1.3) și cipher suite
3. **Setup yamux**:
   - Config yamux cu personalizări:
     - `KeepAliveInterval`: **10 secunde**
     - `ConnectionWriteTimeout`: **10 secunde**
   - `yamux.Client(conn, config)` → stabilește multiplexor client
4. **OpenStream()**: Deschide stream nou (`session.Open()` → `net.Conn`)

### 9.5 Reconectare

#### `Reconnect(maxRetries)`
- Exponential backoff: 1s → 2s → 4s → ... → **30s max**
- Per încercare: închide sesiune/conn veche, apelează `connectLocked()`
- La succes: resetează `closed`, return nil
- Returnează eroare dacă toate retry-urile epuizate

### 9.6 Protocol JSON peste stream-uri yamux

Fiecare operație deschide un **stream yamux separat**, trimite un request JSON și primește un response JSON.

#### Request-uri trimise de client

**Rezolvare DNS**:
```json
{
    "type": "dns_resolve",
    "domain": "db.lab.local"
}
```

**Conectare la resursă**:
```json
{
    "type": "connect",
    "remote_addr": "100.64.1.5",
    "remote_port": 3306
}
```

#### Răspunsuri de la gateway

**DNS rezolvat**:
```json
{
    "status": "resolved",
    "cgnat_ip": "100.64.1.5",
    "ttl": 300
}
```

**Conectat la resursă** (stream-ul devine tunel bidirecțional):
```json
{
    "status": "connected"
}
```

**Autentificare necesară**:
```json
{
    "status": "auth_required",
    "auth_url": "https://cloud:8443/auth/authorize?client_id=gateway-oidc-client&..."
}
```

**Eroare**:
```json
{
    "status": "error",
    "message": "resource not accessible"
}
```

### 9.7 Eroare `ErrAuthRequired`

```go
type ErrAuthRequired struct {
    AuthURL string  // URL pentru autentificare utilizator
}
```

Returnată de `OpenResourceStream()` și `ResolveDomain()` când gateway-ul necesită autentificare. Consumată de handler-ul SYN din `main.go` pentru a declanșa fluxul OIDC.

### 9.8 `ResolveDomain(ctx, domain)`
1. Deschide stream yamux nou
2. Setează deadline din context (sau default 10s)
3. Trimite `{"type": "dns_resolve", "domain": "..."}`
4. Decodifică răspuns
5. Return IP CGNAT + TTL sau `ErrAuthRequired`

### 9.9 `OpenResourceStream(ctx, targetHost, targetPort)`
1. Deschide stream yamux nou
2. Trimite `{"type": "connect", "remote_addr": "...", "remote_port": ...}`
3. Așteaptă răspuns JSON
4. **La `auth_required`**: închide stream, returnează `ErrAuthRequired`
5. **La `connected`**: clearează deadline (stream-ul va fi folosit long-lived), returnează stream
6. Stream-ul devine tunel bidirecțional raw bytes

---

## 10. DNS Magic Resolver

### 10.1 Prezentare

Resolver-ul DNS interceptează query-urile pentru domenii interne (ex. `*.lab.local`) și le rezolvă prin tunelul securizat, returnând adrese CGNAT. Domeniile externe sunt forwardare la DNS-ul upstream.

### 10.2 Structura `Resolver`

```go
type Resolver struct {
    listenAddr     string                // UDP/TCP listen (ex. "127.0.0.1:53")
    upstreamDNS    string                // Upstream pentru domenii externe (ex. "1.1.1.1:53")
    internalSuffix string                // Sufix domenii interne (ex. ".lab.local")
    tunnel         TunnelResolver        // Interfață tunel pentru rezolvare CGNAT
    server         *dns.Server           // Server UDP
    serverTCP      *dns.Server           // Server TCP (pentru răspunsuri trunchiate)

    cacheMu        sync.RWMutex
    cache          map[string]*CacheEntry // Cache DNS
}

type CacheEntry struct {
    CGNATIP   string
    ExpiresAt time.Time
}
```

**Interfață `TunnelResolver`**:
```go
type TunnelResolver interface {
    ResolveDomain(ctx context.Context, domain string) (cgnatIP string, ttl int, err error)
}
```

### 10.3 Funcționare

#### `Start()` — Pornire servere DNS
- Creează `dns.ServeMux` cu handler catch-all `.`
- Pornește server UDP + TCP pe adresa configurată
- Două goroutine-uri (UDP și TCP)

#### `handleQuery(w, req)` — Handler DNS

Pentru fiecare întrebare din query:

1. **Verificare tip A** (IPv4) și **match sufix intern**
2. **Dacă domeniu intern**:
   - `resolveInternal(ctx, domain)` cu timeout 10s
   - Construiește record A cu IP CGNAT returnat + TTL
3. **Dacă domeniu extern**:
   - `forwardQuery(req)` → forward la DNS upstream
   - Copiază răspunsul (answer, NS, extra records)

#### `isInternalDomain(name)` — Verificare sufix
- Compară dacă domeniul se termină cu `internalSuffix`
- Case-insensitive

#### `resolveInternal(ctx, name)` — Rezolvare prin tunel

1. **Cache lookup**: Verificare `cache[domain]` (RWMutex-protected)
2. **Cache hit**: Return IP + TTL rămas
3. **Cache miss**:
   - `tunnel.ResolveDomain(ctx, name)` → stream yamux la gateway
   - **Validare IP**: Verifică că IP-ul returnat este în range-ul CGNAT (100.64.0.0/10) — reject IP-uri non-CGNAT
   - **Cache store**: `ExpiresAt = now + TTL`
4. Return IP, TTL

#### `forwardQuery(req)` — Forward extern
- Client UDP cu timeout **5s**: `dns.Client.Exchange(req, upstreamDNS)`
- Dacă răspunsul este trunchiat (flag TC): retry cu client TCP
- Return răspuns complet

#### `FlushCache()` — Golire cache
- Thread-safe via RWMutex
- Șterge toate entry-urile din cache

### 10.4 NRPT (Windows Split DNS)

#### `setupNRPT(suffix, dnsAddr)` — Configurare Registry

Windows Name Resolution Policy Table permite redirecționarea selectivă a query-urilor DNS pe bază de sufix.

**Cheie registry**:
```
HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig\ZTNA-{suffix}
```

**Valori**:

| Valoare | Tip | Conținut | Scop |
|---------|-----|---------|------|
| `Name` | REG_MULTI_SZ | `.{suffix}` | Pattern sufix (ex. `.lab.local`) |
| `GenericDNSServers` | REG_SZ | `{dnsAddr_IP}` | Server DNS pentru acest sufix |
| `ConfigOptions` | REG_DWORD | `0x8` | Bypass cache + server address list |
| `Version` | REG_DWORD | `0x2` | Versiune politică |

**După configurare**: `ipconfig /flushdns` pentru aplicare imediată.

#### `removeNRPT(suffix)` — Cleanup la shutdown
- Șterge cheia registry
- Flush DNS cache

---

## 11. TPM și Enrollment

### 11.1 TPM Signer

```go
type tpmSigner struct {
    tpm    transport.TPMCloser  // Conexiune device TPM deschisă
    handle tpm2.TPMHandle       // Handle obiect în TPM (copil al SRK)
    pub    *ecdsa.PublicKey     // Cheie publică ECDSA P-256
    name   tpm2.TPM2BName      // Nume obiect calculat de TPM (pentru auth)
}
```

**Implementează `crypto.Signer`**:

#### `Sign(rand, digest, opts)` — Semnare TPM
- Comandă TPM Sign: digest = hash SHA-256 pre-calculat (din TLS handshake)
- Scheme: ECDSA cu SHA-256
- Convertire semnătură TPM → format ASN.1 DER (componente r, s)

#### `asn1EncodeECDSASig(r, s)`
- Encodare: `SEQUENCE { INTEGER r, INTEGER s }`
- Adaugă zero bytes de leading dacă bit-ul înalt este setat (evită interpretare negativă)

### 11.2 Managementul cheilor TPM

#### `loadOrCreateTPMKey(dataDir)` — Creare/încărcare cheie TPM

1. **Deschidere TPM**: `transport.OpenTPM()`
2. **Creare Storage Root Key (SRK)**:
   - Cheie primară ECC în ierarhia Owner
   - Template `ECCSRKTemplate` — deterministă (aceeași pe fiecare apel)
3. **Încercare încărcare cheie existentă**:
   - Citire blob-uri din `tpm-key.json`
   - Deserializare + încărcare în TPM sub SRK
   - Extragere cheie publică
   - **Success** → return `tpmSigner`
4. **Dacă nu există sau eșuează**:
   - Creare cheie ECDSA P-256 nouă sub SRK:
     - Template: ECC, SHA-256, ECDSA signing
     - Curbă: P-256 (NIST)
     - Atribute: FixedTPM, FixedParent, SensitiveDataOrigin, UserWithAuth, SignEncrypt
   - Încărcare cheie nouă
   - Salvare blob-uri public/private pe disc (`tpm-key.json`, permisiuni 0600)
   - Return `tpmSigner`

#### `ReadEKPub()` — Citire Endorsement Key
- Cheie primară ECC în ierarhia **Endorsement** (template `ECCEKTemplate`)
- Unică per dispozitiv (fixată de hardware TPM)
- Folosită pentru fingerprinting: `SHA256(DER(EKPUB))`
- Return `*ecdsa.PublicKey` P-256

### 11.3 Key Manager (Fațadă cu fallback)

```go
type KeyManager struct {
    signer crypto.Signer  // TPM signer sau software fallback
    isTPM  bool            // True dacă backed de TPM
}
```

#### `NewKeyManager(dataDir)`

1. Asigură existența directorului (0700)
2. **Încercare TPM**: `loadOrCreateTPMKey(dataDir)`
   - **Success**: return `KeyManager{signer, isTPM: true}`
3. **Fallback software**: `loadOrCreateSoftwareKey(dataDir)`
   - Generare ECDSA P-256 via `ecdsa.GenerateKey(P256, rand.Reader)`
   - Salvare ca PEM `EC PRIVATE KEY` în `client.key` (0600)
   - Return `KeyManager{signer, isTPM: false}`

#### `DeviceFingerprint()` — Identitate stabilă dispozitiv

| Mod | Format | Sursă |
|-----|--------|-------|
| TPM | `"ek-" + SHA256hex(EKPub PKIX DER)` | Endorsement Key hardware — stabil și unic |
| Software | `"sw-" + SHA256hex(Windows MachineGuid)` | Registry `HKLM\SOFTWARE\Microsoft\Cryptography` |

### 11.4 Enrollment și Managementul Certificatelor

#### Structuri

```go
type EnrollmentResult struct {
    CertPEM []byte    // Certificat client X.509 (PEM)
    CAPEM   []byte    // Lanț certificat CA (PEM)
    ID      string    // ID sesiune enrollment
}

type enrollmentRequest struct {
    DeviceID             string  // UUID dispozitiv
    Component            string  // "tunnel" (identifică scopul)
    Hostname             string  // Hostname dispozitiv
    CSRPEM               string  // CSR PEM-encoded
    PublicKeyFingerprint string  // SHA-256(PKIX DER) al cheii de semnare
}
```

#### `CreateCSR(signer, deviceID, hostname)` — Generare Certificate Signing Request
- Subject: `CN=deviceID`, `O="ZeroTrust Device"`
- DNSNames: hostname
- Semnat cu signer-ul furnizat (TPM sau software)
- Return CSR PEM

#### `EnrollAndWait(ctx, km, cloudURL, caFile, deviceID, hostname, dataDir)` — Flux principal

1. **Verificare certificat cached** (`client.crt` în dataDir):
   - Dacă există și valid (NotAfter > now):
     - Verifică fingerprint cheie publică (match cu signer curent)
     - Dacă mismatch: șterge cert-uri vechi → enrollment nou
     - Dacă match și **expirare > 12h**: return cert-ul cached
     - Dacă match și **expirare ≤ 12h**: `renewCertFlow()` proactiv
   - Dacă absent sau expirat → enrollment nou

2. **Generare CSR**:
   - `CreateCSR(km.Signer(), deviceID, hostname)`
   - Calcul fingerprint cheie publică

3. **Start sesiune browser**:
   - `StartEnrollSession(...)` → POST `/api/enroll/start-session`
   - Primește `authURL` + `sessionID`
   - Log URL + deschidere browser

4. **Polling pentru emitere certificat**:
   - `WaitForBrowserAuth(ctx, ..., sessionID, 3s poll interval)`
   - GET `/api/enroll/session-status?session={sessionID}` la fiecare **3 secunde**
   - Stări: `"authenticated"` (certificat emis) → return, `"denied"` → eroare, `"expired"` → eroare, `"pending"` → continuă
   - Timeout din ctx (**5 minute** browser auth)

5. **Cache certificat pe disc**:
   - Scrie certPEM în `client.crt` (0600)
   - Scrie CAPEM în `ca.crt` (0600)

6. **Return `EnrollmentResult`**

#### `RenewCert(cloudURL, caFile, deviceID, csrPEM, fingerprint)`
- POST `/api/enroll/renew` — nou CSR cu fingerprint existent
- Returnează imediat cu certificat nou (fără polling)

#### `StartAutoRenewal(ctx, km, cloudURL, caFile, deviceID, hostname, dataDir)` — Goroutine background
- **Ticker**: verificare la fiecare **1 oră**
- Per tick:
  - Citire `client.crt` cached
  - Parsare dată expirare
  - Dacă expiră în **12 ore**: `renewCertFlow()`
  - La eșec: log warning (continuă cu cert existent)
- Oprire: la anularea context-ului

**Model certificare**: Certificate de scurtă durată (**24 ore**), reînnoire la **12 ore** înainte de expirare.

---

## 12. Logger

### Modul: `logger/logger.go`

**Global**: `Log *slog.Logger`

- **init()**: Inițializare logger default cu `slog.TextHandler`
  - Output: stdout
  - Nivel: Debug (captează toate mesajele)
  - Auto-setat ca default via `slog.SetDefault()`

- **Init(level)**: Reconfigurare opțională la runtime
  - Exemplu: `Init(slog.LevelInfo)` pentru a suprima mesajele debug

---

## 13. Dependențe

### Dependențe principale (`go.mod`)

| Modul | Versiune | Scop |
|-------|----------|------|
| `github.com/hashicorp/yamux` | v0.1.2 | Multiplexare stream-uri peste TCP |
| `github.com/miekg/dns` | v1.1.72 | Protocol handler DNS (RFC 1035) |
| `golang.zx2c4.com/wintun` | latest | Creare/management adaptor TUN Windows |
| `github.com/google/go-tpm` | v0.9.8 | Comenzi TPM 2.0 (generare chei, semnare) |
| `golang.org/x/sys` | v0.39.0 | Syscall-uri Windows (registry, events) |
| `golang.org/x/net` | v0.48.0 | Utilitare rețea |
