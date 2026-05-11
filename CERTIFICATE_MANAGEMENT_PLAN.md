# ZTNA Certificate & Identity Management Plan

## Eliminarea certificatelor statice și implementarea fluxului end-to-end de enrollment dinamic

---

## Cuprins

1. [Sumar Executiv](#1-sumar-executiv)
2. [Analiza Situației Curente](#2-analiza-situației-curente)
3. [Arhitectura Țintă](#3-arhitectura-țintă)
4. [Faze de Implementare](#4-faze-de-implementare)
5. [Modificări Detaliate per Fișier](#5-modificări-detaliate-per-fișier)
6. [Configurație Finală](#6-configurație-finală)
7. [Testare și Validare](#7-testare-și-validare)

---

## 1. Sumar Executiv

Obiectivul acestui plan este **eliminarea completă** a oricărui mecanism de generare sau fallback către certificate statice în toate cele trei componente ale sistemului ZTNA (PDP, Gateway, Agent) și înlocuirea acestora cu un **flux end-to-end de enrollment dinamic**:

- **Cheile private** sunt stocate securizat, la cel mai înalt nivel posibil per platformă:
  - **Agent**: TPM via NCrypt (`Microsoft Platform Crypto Provider`) — cheia nu părăsește niciodată hardware-ul
  - **Gateway (Docker Linux)**: Strategie pe 2 niveluri — Nivel 1: Vault Transit via PDP (securitate 9/10, necesită PDP online la restart); Nivel 2: AES-256-GCM derivat din `/etc/machine-id` (securitate 6/10, autonom). Cheia NU e niciodată în plaintext pe disk
  - **PDP**: Vault Transit Encryption — cheia e criptată prin Vault înainte de a atinge discul; fără Vault Transit, rămâne doar în memorie (re-enroll la restart)
- **Certificatele** sunt obținute dinamic prin enrollment către PA, care intermediază emiterea prin **Vault PKI**
- **Niciun fallback** la certificate auto-semnate sau pre-generate manual nu este permis

### Principii de design

| Principiu | Descriere |
|-----------|-----------|
| **Zero static certs** | Niciun certificat nu este generat manual sau pre-încărcat |
| **Enrollment obligatoriu** | Fiecare componentă trece prin enrollment pentru a primi identitatea mTLS |
| **Chei în hardware (Agent)** | Agentul folosește TPM (`Microsoft Platform Crypto Provider`) — cel mai înalt nivel de securitate |
| **Chei criptate pe disk (PDP)** | PDP criptează cheia cu Vault Transit înainte de a o scrie pe disk; fără Vault Transit, cheia rămâne doar în memorie |
| **Chei criptate pe disk (Gateway)** | Gateway (container Docker Linux) folosește Vault Transit via PDP (Nivel 1) + AES-256-GCM din machine-id (Nivel 2) — cheia nu e niciodată în plaintext |
| **PKI centralizat** | Toate certificatele sunt emise de Vault PKI, via PA |

---

### Strategia de Securizare a Cheilor Private

Problema fundamentală: **unde și cum stocăm cheile private ale PDP-ului și Gateway-urilor** astfel încât să nu fie niciodată în plaintext pe disk?

#### PDP: Vault Transit Encryption

PDP-ul are deja o conexiune autentificată la Vault PKI. Putem folosi și **Vault Transit** pentru a cripta cheia privată înainte de a o persista pe disk:

1. La startup, verifică dacă există `encrypted_key.blob` pe disk
   - DA: Trimite blob-ul la Vault Transit pentru decriptare; dacă reușește, cheia e restaurată
   - NU: Generează cheie ECDSA P-256 nouă, criptează cu Vault Transit, salvează blob
2. Verifică dacă certificatul încă e valid
   - DA: Folosește certificatul existent
   - NU: Self-enroll cu Vault PKI (folosind cheia restaurată sau cea nouă)

**Beneficii**: Cheia privată nu apare niciodată în plaintext pe disk; blob-ul criptat e inutil fără Vault + token valid; dacă token-ul e rotit, blob-ul vechi devine inutil. Fără Vault Transit configurat, cheia rămâne doar în memorie (re-enroll la fiecare restart).

#### Gateway: Analiză Multi-Metodă cu Recomandare Finală

**Context de producție**: Gateway-ul rulează într-un **container Docker Linux** (Alpine, `CGO_ENABLED=0`, non-root), fără `--privileged` sau device passthrough. Accesul la TPM (`/dev/tpm0`), Kernel Keyring (necesită `CAP_IPC_LOCK`), și DPAPI (Windows-only) sunt **indisponibile în container**. Gateway-ul nu are acces direct la Vault — comunică doar cu PDP-ul prin mTLS.

Analizăm **toate metodele viabile**, de la cele posibile în container până la cele care necesită hardware dedicat (pentru referință).

##### Metoda 1: TPM 2.0 Direct (go-tpm) — Nivel 9/10

Gateway-ul poate accesa TPM-ul direct, fără NCrypt (care e Windows-only). Biblioteca [`github.com/google/go-tpm`]() funcționează pe ambele platforme:

```
Flow TPM:
  1. tpm2.CreatePrimary(SRK) → handle persistent
  2. tpm2.Create(srkHandle, ECDSA P-256 template) → key blob (sealed)
  3. tpm2.Load(srkHandle, keyBlob) → keyHandle
  4. La CSR: tpm2.Sign(keyHandle, csrDigest) → semnătură
  5. Key blob-ul e salvat pe disk, dar e useless fără TPM-ul care l-a creat
```

| Avantaje | Dezavantaje |
|---|---|
| Cheia privată nu părăsește niciodată TPM-ul | Necesită TPM 2.0 (standard din 2016, dar nu garantat pe toate VM-urile) |
| Key blob-ul e sealed la PCR-uri (integrity measurement) | Complexitate de implementare mai mare |
| Cross-platform (Linux + Windows) | Necesită `tpm2-abrmd` sau `in-kernel RM` pe Linux |
| Nivel de securitate similar cu Agentul | Nu funcționează în Docker fără device passthrough |
| Fără DPAPI/Kernel Keyring — cod unificat | `go-tpm` e o dependență mare (~1.5 MB compilat) |

**PCR Policy recomandată**: PCR 0 (BIOS), PCR 7 (Secure Boot state), PCR 11 (UKI). Dacă firmware-ul se modifică, cheia devine inaccesibilă → re-enrollment.

##### Metoda 2: DPAPI (Windows) — Nivel 8/10

Deja analizată. Plusuri: API simplu, integrare nativă, TPM-backed master key. Minusuri: Windows-only, necesită rulare ca SYSTEM pentru `CRYPTPROTECT_LOCAL_MACHINE`.

##### Metoda 3: Kernel Key Retention Service (Linux) — Nivel 7/10

Deja analizată. Plusuri: cheia nu atinge discul. Minusuri: nu persistă la restart, necesită kernel 5.4+ cu `CONFIG_KEYS=y`.

##### Metoda 4: AES-256-GCM cu cheie derivată din enrollment_token — Nivel 6/10

Deja analizată. Problemă majoră: după enrollment, token-ul e șters din config (practica curentă). Dacă token-ul e șters, nu mai putem deriva cheia la restart. Soluții:
- **4a**: Păstrăm token-ul criptat pe disk → token criptat + cheie criptată. Circular: cu ce criptăm token-ul?
- **4b**: Derivăm din `machine-id` doar, fără token → oricine citește `/etc/machine-id` poate deriva cheia. E doar cu ~10% mai sigur decât plaintext.
- **4c**: Cheia AES stocată în kernel keyring, iar datele criptate pe disk ca fallback.

##### Metoda 5: Vault Transit via PDP Proxy — Nivel 9/10

Gateway-ul trimite blob-ul criptat la PDP, iar PDP-ul îl decriptează prin Vault Transit și îl returnează prin canalul mTLS deja securizat:

```
Flow:
  1. Gateway are nevoie de cheie → trimite encrypted_blob la PDP
  2. PDP autentifică Gateway-ul (token de enrollment / mTLS)
  3. PDP trimite blob-ul la Vault Transit → primește plaintext
  4. PDP returnează plaintext-ul Gateway-ului prin canal mTLS
```

| Avantaje | Dezavantaje |
|---|---|
| Gateway-ul nu are nevoie de acces direct la Vault | PDP trebuie să fie online la restartul Gateway-ului |
| Securitatea cheii = securitatea Vault + mTLS | Adaugă latență la startup |
| Se poate combina cu caching local (AES-GCM) | Dacă PDP e offline, Gateway-ul nu poate porni |

**Endpoint nou necesar**: `POST /api/gateway/unseal-key` — primește `encrypted_blob`, returnează `key_plaintext` (doar peste mTLS).

##### Metoda 6: Cloud KMS (AWS KMS / Azure Key Vault / GCP KMS) — Nivel 9/10

Dacă Gateway-ul rulează în cloud:

```
Flow AWS KMS:
  1. Gateway generează data key via KMS GenerateDataKey
  2. Criptează cheia ECDSA cu data key (AES-GCM)
  3. Salvează encrypted_key + encrypted_data_key pe disk
  4. La restart: KMS Decrypt(encrypted_data_key) → data key → decriptează cheia ECDSA
```

| Avantaje | Dezavantaje |
|---|---|
| Securitate enterprise-grade | Cost (AWS KMS: ~$1/key/lună + $0.03/10k cereri) |
| Key rotation automată | Necesită IAM roles / managed identities |
| Audit trail complet (CloudTrail) | Vendor lock-in |
| Fără dependență de PDP la restart | Nu funcționează on-premise fără AWS Outposts/Azure Arc |

##### Metoda 7: SoftHSM2 (PKCS#11 software token) — Nivel 7/10

Un HSM software care stochează cheile criptate cu o parolă master:

| Avantaje | Dezavantaje |
|---|---|
| API standardizat (PKCS#11) | Parola master: unde o stocăm? (aceeași problemă) |
| Cross-platform | Proces separat, overhead de administrare |
| Funcționează fără hardware special | PKCS#11 în Go e complex (biblioteci CGo) |

##### Metoda 8: age/rage Encryption — Nivel 5/10

Cheia e criptată cu `age` (X25519) și salvată pe disk. Cheia age privată e stocată... unde? Aceeași problemă circulară.

**Concluzie**: age/rage nu rezolvă problema fundamentală — e doar un alt strat de criptare, dar cheia de decriptare tot trebuie stocată undeva.

##### Metoda 9: PKCS#12 criptat cu parolă — Nivel 4/10

Cheia e ambalată într-un fișier `.p12` protejat cu parolă. Parola e stocată... în fișierul de configurare. Circular.

##### Metoda 10: Shamir's Secret Sharing — Nivel 5/10

Cheia e împărțită în N fragmente, stocate în locații diferite (disk + mediu de rețea + TPM). Necesită M din N pentru reconstrucție. Complexitate mare, câștig marginal.

##### Matricea Decizională

| Metodă | Securitate | Container-compatibil? | Persistă restart | Complexitate | Dependențe externe |
|---|---|---|---|---|---|
| **Vault Transit via PDP** | ⭐⭐⭐⭐⭐ (9) | ✅ Da (HTTP) | ✅ Da | 🟡 Medie | PDP online + Vault Transit |
| **AES-GCM din machine-id** | ⭐⭐⭐ (6) | ✅ Da | ✅ Da | 🟢 Mică | `/etc/machine-id` montat |
| TPM 2.0 (go-tpm) | ⭐⭐⭐⭐⭐ (9) | ❌ (necesită `/dev/tpm0`) | ✅ Da | 🔴 Mare | TPM 2.0 hardware |
| DPAPI (Windows) | ⭐⭐⭐⭐ (8) | ❌ (Windows-only) | ✅ Da | 🟢 Mică | Windows OS |
| Kernel Keyring | ⭐⭐⭐ (7) | ❌ (necesită `CAP_IPC_LOCK`) | ❌ Nu | 🟢 Mică | Kernel 5.4+ |
| Cloud KMS | ⭐⭐⭐⭐⭐ (9) | ✅ Da (HTTP) | ✅ Da | 🟡 Medie | AWS/Azure/GCP |
| SoftHSM2 | ⭐⭐⭐ (7) | ⚠️ (proces separat) | ✅ Da | 🔴 Mare | Proces SoftHSM2 |
| age/rage | ⭐⭐⭐ (5) | ✅ Da | ✅ Da | 🟢 Mică | Nimic (dar circular) |
| PKCS#12 parolă | ⭐⭐ (4) | ✅ Da | ✅ Da | 🟢 Mică | Nimic (dar circular) |

**Legendă**: ✅ = funcționează în container Docker standard | ❌ = imposibil fără `--privileged` / device passthrough | ⚠️ = posibil dar nepractic

**Concluzie**: Doar **2 metode** sunt viabile într-un container Docker Linux standard: **Vault Transit via PDP** (securitate maximă, necesită PDP online) și **AES-GCM din machine-id** (securitate moderată, autonom). Ele sunt complementare și implementate ca Nivel 1 + Nivel 2.

##### Recomandare Finală: Strategie pe 2 Niveluri (Container-Compatibilă)

Într-un container Docker Linux standard (Alpine, `CGO_ENABLED=0`, non-root), metodele hardware (TPM, Kernel Keyring) și specifice Windows (DPAPI) sunt indisponibile. Strategia se reduce la 2 niveluri practice:

```
Gateway Key Storage Strategy (Container Linux):
══════════════════════════════════════════════

Nivel 1 (Primar) ─ Vault Transit via PDP Proxy
├─ La enrollment: Gateway trimite cheia plaintext la PDP POST /api/gateway/seal-key
│   PDP o criptează prin Vault Transit → returnează ciphertext blob
├─ Blob salvat: /app/certs/enrolled/mtls.key.vault (persistent prin Docker volume)
├─ La restart: Gateway trimite blob-ul la PDP POST /api/gateway/unseal-key
│   PDP decriptează prin Vault Transit → returnează cheia plaintext prin mTLS
├─ Cheia rămâne DOAR în memorie după decriptare (nu atinge discul în plaintext)
└─ Dacă PDP e offline → fallback la Nivel 2

Nivel 2 (Fallback) ─ AES-256-GCM cu cheie derivată din machine-id
├─ Cheia AES derivată din /etc/machine-id (unic per container host) + Argon2id
│   NOTĂ: /etc/machine-id trebuie montat read-only în container
├─ La enrollment: criptează cheia ECDSA cu AES-256-GCM → enrolled/mtls.key.gcm
├─ La restart: încearcă Nivel 1; dacă PDP e offline → decriptează local din .key.gcm
├─ Securitate: 6/10 — oricine citește machine-id + blob poate decripta cheia
│   Dar e mult mai bine decât plaintext pe disk
└─ Ambele niveluri eșuează → EROARE FATALĂ (nu există alt fallback)
```

**Motivație**: Într-un container Docker, fără acces hardware sau kernel subsystems, Vault Transit via PDP oferă cel mai înalt nivel de securitate (9/10). Fallback-ul AES-GCM bazat pe machine-id asigură că Gateway-ul pornește și când PDP-ul e temporar indisponibil (ex: restart simultan), deși cu securitate redusă. Cheia NU este niciodată salvată în plaintext pe disk în niciun scenariu.

**Notă pentru deployment-uri non-container**: Dacă Gateway-ul rulează pe metal sau VM (nu container), se poate adăuga un Nivel 0 cu TPM 2.0 sau Kernel Keyring. Aceste metode sunt documentate în secțiunile 1-3 de mai sus pentru referință.


#### Agent: TPM — Deja Implementat (Nivel Maxim de Securitate)

| Strat de securitate | Detaliu |
|---|---|
| TPM Endorsement Key (EK) | Device ID derivat din SHA-256 al EK public — unic, imuabil |
| NCrypt Persistent Key | Cheie ECDSA P-256 în `Microsoft Platform Crypto Provider` |
| NCryptSignHash | Semnarea CSR-ului se face în TPM — cheia privată nu părăsește niciodată TPM-ul |
| CERT_KEY_PROV_INFO_PROP_ID | Certificatul din Windows store e legat de cheia TPM |
| Machine Store | Certificatul + CA chain în `LocalMachine\My` și `LocalMachine\CA` |

Aceasta este **cea mai sigură opțiune posibilă** pe hardware consumer: cheia nu poate fi exportată, copiată, sau folosită pe alt dispozitiv. Chiar și cu acces fizic la mașină, un atacator nu poate extrage cheia din TPM fără vulnerabilități hardware.

### Tabel Comparativ: Securitatea Cheilor per Componentă

| | Agent (Windows) | Gateway (Nivel 1: Vault Transit) | Gateway (Nivel 2: AES-GCM) | PDP |
|---|---|---|---|---|
| Protecție | TPM 2.0 (NCrypt) | Vault Transit via PDP Proxy | AES-256-GCM derivat din machine-id | Vault Transit / Memorie |
| Cheia în plaintext pe disk? | Nu (niciodată) | Nu (blob criptat de Vault) | Nu (AES-GCM criptat) | Nu (Vault criptat / doar RAM) |
| Exportabilă? | Nu (TPM-bound) | Doar cu token Vault + mTLS | Cu machine-id + blob | Doar cu token Vault |
| Supraviețuiește restart? | Da (persistent key) | Da (blob + PDP reachable) | Da (fișier criptat) | Doar cu Vault Transit |
| Rezistent la furt de disk? | Da | Da (blob criptat de Vault) | Parțial (machine-id e lizibil) | Da (blob criptat) |
| Dependență PDP la restart? | Nu | DA (fără PDP → fallback Nivel 2) | Nu (dar mai puțin sigur) | Nu (dar Vault necesar) |
| Container-compatibil? | N/A (Agentul nu rulează în container) | ✅ Da | ✅ Da | N/A (PDP-ul nu rulează în container) |
| Nivel securitate (1-10) | 10/10 | 9/10 | 6/10 | 9/10 |

**Notă**: Gateway-ul încearcă Nivelul 1 (Vault Transit via PDP) la pornire. Dacă PDP-ul e offline, trece automat la Nivelul 2 (AES-GCM local). Cheia NU este salvată niciodată în plaintext pe disk.


## 2. Analiza Situației Curente

### 2.1 PDP — Ce trebuie eliminat

| Fișier / Locație | Problema | Acțiune |
|---|---|---|
| `pdp/certs/gen_server_cert.go` | CLI tool care generează `pdp.crt`/`pdp.key` folosind CA local | **ȘTERGE** |
| `pdp/certs/gen_secret.go` | CLI tool care generează secret hex aleator; `package main` în director `certs` (compilation error) | **ȘTERGE** |
| `pdp/certs/ca.crt` | CA static pe disk | **ȘTERGE** |
| `pdp/certs/ca.key` | Cheie CA statică pe disk | **ȘTERGE** |
| `pdp/certs/pdp.crt` | Certificat TLS static pentru PDP | **ȘTERGE** |
| `pdp/certs/pdp.key` | Cheie TLS statică pentru PDP | **ȘTERGE** |
| `pdp/data/ca-cert.pem` | Copie CA statică în directorul data | **ȘTERGE** |
| `pdp/data/ca-key.pem` | Copie cheie CA statică în directorul data | **ȘTERGE** |
| `pdp/pdp-config.json` | Referințe către fișierele statice `./certs/pdp.crt`, `./certs/pdp.key`, `./certs/ca.crt` | **MODIFICĂ** |
| `pdp/docker-pdp-config.json` | Referințe către fișierele statice `/app/certs/pdp.crt`, `/app/certs/pdp.key` | **MODIFICĂ** |
| `pdp/cmd/pdp/main.go` | Validare că `tls_cert`/`tls_key`/`mtls_ca` există pe disk | **MODIFICĂ** |

### 2.2 Gateway — Ce trebuie eliminat

| Fișier / Locație | Problema | Acțiune |
|---|---|---|
| `gateway/internal/dataplane/server.go:184-191` | `buildServerTLSConfig()`: în `dev_mode`, generează certificat auto-semnat când nu există TLS configurat | **ȘTERGE fallback-ul** |
| `gateway/internal/dataplane/server.go:840-889` | Funcția `generateSelfSignedCert()` — generează certificat ECDSA P-256 auto-semnat | **ȘTERGE funcția** |
| `gateway/gateway-config.json` | Referințe către fișiere statice (`gateway-ssl.crt`, `gateway-ssl.key`, `gateway-mtls.crt`, `gateway-mtls.key`, `gateway-mtls.csr`, `ca.crt`) | **MODIFICĂ** |
| `gateway/gateway-config.local.json` | `dev_mode: true` + referințe către fișiere statice | **MODIFICĂ** |
| `gateway/internal/config/config.go` | Câmpurile pentru fișiere TLS/mTLS statice rămân (vor stoca certificatele obținute prin enrollment) | **PĂSTREAZĂ, dar ajustează logica** |

### 2.3 Agent — Situația (deja corectă)

**Agentul nu necesită modificări pentru eliminarea certificatelor statice.** Tot fluxul este deja implementat corect:

| Componentă | Status | Detalii |
|---|---|---|
| `key_windows.go` | ✅ **Complet** | `EnsureSigningKey()` creează/deschide chei ECDSA P-256 în TPM via NCrypt |
| `provider_windows.go` | ✅ **Complet** | Detectează TPM EK public, derivă `device_id` via SHA-256 |
| `csr.go` | ✅ **Complet** | `CreateCSRWithIdentity()` folosește `crypto.Signer` TPM pentru semnare CSR |
| `est.go` | ✅ **Complet** | `SimpleEnrollWithToken()` — EST enrollment cu Bearer token |
| `renewal.go` | ✅ **Complet** | `RenewWithMTLS()` — reînnoire certificat folosind mTLS existent |
| `certstore_windows.go` | ✅ **Complet** | Instalare certificat în `LocalMachine\My` + `LocalMachine\CA`, legat de cheia TPM |
| `runner.go` | ✅ **Complet** | `Enroll()` + `Renew()` — orchestrează întregul flux |

**Agentul este implementarea de referință** pentru modul corect de gestionare a identității criptografice.

---

## 3. Arhitectura Țintă

### 3.1 Fluxul End-to-End de Enrollment

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        VAULT PKI (HashiCorp Vault)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      │
│  │ ztna-device │  │ ztna-gateway│  │  ztna-pdp   │                      │
│  │    role     │  │    role     │  │    role     │                      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                      │
│         │                │                │                              │
│         └────────────────┼────────────────┘                              │
│                          │ SignCSR / GetCAPEM / RevokeCertificate        │
└──────────────────────────┼──────────────────────────────────────────────┘
                           │
                    ┌──────┴──────┐
                    │     PDP     │
                    │  (PA + PE)  │
                    │             │
                    │ Key: Vault  │
                    │ Transit     │
                    │ encrypted   │
                    │ or RAM-only │
                    │             │
                    │ Cert: self- │
                    │ enrolled    │
                    │ via Vault   │
                    │ PKI         │
                    │             │
                    │ /api/gateway/enroll
                    │ /api/gateway/renew-cert
                    │ /.well-known/est/ztna/simpleenroll
                    │ /api/enroll/renew
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────┴─────┐ ┌───┴──────┐ ┌──┴──────┐
        │  GATEWAY  │ │ GATEWAY  │ │  AGENT  │
        │ (Docker)  │ │ (Docker) │ │ (Win)   │
        │           │ │          │ │         │
        │ Nivel 1:  │ │ Nivel 1: │ │ Key:    │
        │ Vault     │ │ Vault    │ │ TPM     │
        │ Transit   │ │ Transit  │ │ (NCrypt)│
        │ via PDP   │ │ via PDP  │ │         │
        │           │ │          │ │ Cert:   │
        │ Nivel 2:  │ │ Nivel 2: │ │ TPM-    │
        │ AES-GCM   │ │ AES-GCM  │ │ backed  │
        │ (machine- │ │ (machine-│ │         │
        │  id)      │ │  id)     │ │ Renewal:│
        │           │ │          │ │ mTLS    │
        │ Cert:     │ │ Cert:    │ │         │
        │ enrolled  │ │ enrolled │ │         │
        │           │ │          │ │         │
        │ Renewal:  │ │ Renewal: │ │         │
        │ mTLS      │ │ mTLS     │ │         │
        └───────────┘ └──────────┘ └─────────┘
```

### 3.2 PDP Self-Enrollment (Bootstrapping) cu Vault Transit

PDP-ul are o problemă de "chicken-and-egg": pentru a servi HTTPS, are nevoie de un certificat TLS, dar pentru a obține un certificat de la sine însuși, ar trebui să fie deja pornit.

**Soluția**: PDP-ul se auto-înrolează **direct** cu Vault PKI la startup, iar cheia privată este protejată prin **Vault Transit Encryption**:

```
PDP Startup Flow (cu Vault Transit):
────────────────────────────────────
1. Citește configurația (pdp-config.json)
2. Validează Vault PKI + Vault Transit config (url, token, path, role)
3. Verifică dacă există cheie criptată pe disk (encrypted_key.blob)
   ├─ DA → 3a. Trimite blob-ul la Vault Transit pentru decriptare
   │         ├─ SUCCES → Cheia ECDSA P-256 este restaurată
   │         └─ EȘEC  → Blob invalid/expirat, generează cheie nouă
   └─ NU  → 3b. Generează cheie ECDSA P-256 nouă
            3c. Criptează cheia cu Vault Transit → salvează encrypted_key.blob
4. Verifică dacă certificatul salvat (enrolled_cert.pem) încă e valid
   ├─ DA → 4a. Folosește certificatul existent
   └─ NU → 4b. Creează CSR pentru propriul FQDN
            4c. Semnează CSR-ul prin Vault PKI (rolul ztna-pdp)
            4d. Salvează certificatul (enrolled_cert.pem)
5. Obține CA PEM de la Vault PKI
6. Configurează TLS server cu certificatul + cheia
7. Pornește serverul HTTP
8. Pornește bucla de reînnoire (verifică la fiecare 6h, reînnoiește cu 48h înainte de expirare)
```

**Fără Vault Transit** (fallback minimal): cheia rămâne doar în memorie, re-enrollment la fiecare restart. Acesta este un compromis acceptabil pentru medii unde Vault Transit nu e disponibil — downtime-ul unui restart de PDP e de obicei sub 5 secunde.

```

### 3.3 Gateway Enrollment cu Stocare Securizată a Cheii (Container Linux)

Gateway Startup Flow (Container Docker, 2 niveluri):
```
1. Citește configurația (gateway-config.json)
2. Verifică dacă există certificat mTLS salvat pe disk (certs/enrolled/mtls.crt)
   ├─ DA → 2a. Încearcă Nivel 1 (Vault Transit via PDP):
   │         ├─ Trimite certs/enrolled/mtls.key.vault la PDP POST /api/gateway/unseal-key
   │         ├─ PDP decriptează prin Vault Transit → returnează cheia plaintext prin mTLS
   │         ├─ SUCCES → Cheia restaurată în memorie, treci la pasul 8
   │         └─ EȘEC (PDP offline / rețea) → Treci la Nivel 2
   │      2b. Nivel 2 (AES-GCM local):
   │         ├─ Citește /etc/machine-id (montat read-only din host)
   │         ├─ Derivează cheie AES: Argon2id(machine-id, salt="ztna-gateway-kek", iterations=3)
   │         ├─ Decriptează certs/enrolled/mtls.key.gcm cu AES-256-GCM
   │         ├─ SUCCES → Cheia restaurată în memorie, treci la pasul 8
   │         └─ EȘEC → EROARE FATALĂ (ambii vectori de decriptare au eșuat)
   └─ NU  → Continuă cu enrollment (pasul 3)

3. Verifică dacă enrollment_token este configurat
   ├─ DA → Continuă enrollment
   └─ NU  → EROARE FATALĂ: Gateway-ul nu poate porni fără identitate

4. Generează cheie ECDSA P-256

5. Stochează cheia pe ambele niveluri (pentru redundanță):
   ├─ Nivel 1: Trimite cheia la PDP POST /api/gateway/seal-key → primește blob → mtls.key.vault
   └─ Nivel 2: Criptează local cu AES-256-GCM derivat din machine-id → mtls.key.gcm

6. Salvează ambele blobs cu permisiuni 0400

7. Creează CSR, trimite la PDP /api/gateway/enroll

8. Salvează certificatul: certs/enrolled/mtls.crt + certs/enrolled/ca.crt

9. Configurează TLS server cu certificatul + cheia (cheia în memorie doar)

10. Pornește serverul

11. Pornește bucla de reînnoire (la fiecare 6h, reînnoiește cu 48h înainte de expirare)
   ├─ La reînnoire: generează cheie NOUĂ → stochează pe ambele niveluri → CSR nou → PDP /api/gateway/renew-cert
   └─ Dacă Vault Transit eșuează la reînnoire → folosește AES-GCM ca fallback de stocare
```

### 3.4 Agent Enrollment (neschimbat)

```
Agent Enrollment Flow (deja implementat):
─────────────────────────────────────────
1. OIDC Login → obține auth token
2. Obține enrollment token de la PDP /api/enroll/issue-token
3. EnsureSigningKey() → cheie ECDSA P-256 în TPM
4. CreateCSRWithIdentity() → CSR semnat cu cheia TPM
5. SimpleEnrollWithToken() → EST /.../simpleenroll
6. InstallCertificate() → Windows LocalMachine\My + CA
7. Comunicare mTLS cu Gateway și PDP
8. RenewWithMTLS() → reînnoire înainte de expirare
```

---

## 4. Faze de Implementare

### Fază 1: Eliminarea Fallback-urilor și Codului Static
**Prioritate: CRITICĂ | Efort: 2-3 ore**

#### 1.1 Ștergere fișiere statice PDP
- [ ] Șterge `pdp/certs/gen_server_cert.go`
- [ ] Șterge `pdp/certs/gen_secret.go`
- [ ] Șterge `pdp/certs/ca.crt`
- [ ] Șterge `pdp/certs/ca.key`
- [ ] Șterge `pdp/certs/pdp.crt`
- [ ] Șterge `pdp/certs/pdp.key`
- [ ] Șterge `pdp/data/ca-cert.pem`
- [ ] Șterge `pdp/data/ca-key.pem`

#### 1.2 Eliminare fallback Gateway
- [ ] Șterge `generateSelfSignedCert()` din [`gateway/internal/dataplane/server.go:840-889`](gateway/internal/dataplane/server.go:840)
- [ ] Elimină blocul `dev_mode` self-signed cert din [`gateway/internal/dataplane/server.go:184-191`](gateway/internal/dataplane/server.go:184)
- [ ] Gateway-ul **refuză pornirea** dacă nu are nici certificat salvat, nici enrollment token

#### 1.3 Curățare configurări Gateway
- [ ] Elimină `dev_mode` din [`gateway/internal/config/config.go`](gateway/internal/config/config.go) (sau îl face inofensiv — fără generare de certificate)
- [ ] Actualizează [`gateway/gateway-config.json`](gateway/gateway-config.json) — șterge referințele la fișiere inexistente
- [ ] Actualizează [`gateway/gateway-config.local.json`](gateway/gateway-config.local.json) — șterge `dev_mode` și referințele statice

### Fază 2: PDP Self-Enrollment cu Vault Transit
**Prioritate: ÎNALTĂ | Efort: 6-8 ore**

#### 2.1 Modul nou: `pdp/pki/self_enroll.go`
- [ ] Funcția `SelfEnroll(ctx, vaultConfig) (*tls.Certificate, []byte, error)`:
  - Generează cheie ECDSA P-256
  - Creează CSR cu CN = FQDN configurat
  - Conectează la Vault PKI
  - Semnează CSR-ul propriu
  - Obține CA PEM
  - Returnează `tls.Certificate` + CA PEM
- [ ] Funcția `SelfEnrollLoop(ctx, vaultConfig, renewThreshold)`:
  - Verifică periodic expirarea certificatului
  - Reînnoiește înainte de expirare

#### 2.1b Modul nou: `pdp/pki/transit_key.go` (Vault Transit Encryption)
- [ ] Funcția `EncryptKeyViaTransit(ctx, vaultConfig, keyPEM []byte) ([]byte, error)`:
  - Conectează la Vault Transit engine
  - Trimite plaintext-ul (cheia PEM) la `/v1/transit/encrypt/ztna-pdp-key`
  - Primește ciphertext-ul
  - Salvează ciphertext-ul ca `data/pdp_key.enc` (permisiuni 0600)
- [ ] Funcția `DecryptKeyViaTransit(ctx, vaultConfig, ciphertext []byte) ([]byte, error)`:
  - Trimite ciphertext-ul la `/v1/transit/decrypt/ztna-pdp-key`
  - Primește plaintext-ul (cheia PEM originală)
- [ ] Funcția `RestoreOrCreateKey(ctx, vaultConfig) (*ecdsa.PrivateKey, []byte, error)`:
  - Încearcă să restaureze cheia din `data/pdp_key.enc` via Vault Transit
  - Dacă eșuează sau fișierul nu există: generează cheie nouă, criptează și salvează
  - Returnează cheia + cheia PEM (pentru TLS config)
- [ ] Configurare Vault Transit:
  - Admin-ul trebuie să creeze key: `vault write -f transit/keys/ztna-pdp-key`
  - Policy minimă: `update` pe `transit/encrypt/ztna-pdp-key` și `transit/decrypt/ztna-pdp-key`

#### 2.2 Modificare `pdp/cmd/pdp/main.go`
- [ ] Elimină validarea `tls_cert`/`tls_key`/`mtls_ca` ca fișiere pe disk
- [ ] Adaugă logica de self-enrollment înainte de `server.Start()`
- [ ] Dacă self-enrollment eșuează → **EROARE FATALĂ**, PDP-ul nu pornește
- [ ] Construiește `*tls.Config` din certificatul enrolled + CA PEM
- [ ] Adaugă parametru `pdp_fqdn` în config

#### 2.3 Modificare `pdp/config/config.go`
- [ ] Adaugă câmpul `PDPFQDN string` pentru auto-enrollment CSR
- [ ] Adaugă câmpul `PKIRolePDP string` (rolul Vault pentru certificatul PDP-ului)
- [ ] Elimină câmpurile `TLSCert`, `TLSKey`, `MTLSCA` (sau le face opționale, completate dinamic)

### Fază 3: Gateway Enrollment Obligatoriu cu Stocare Securizată (Container Linux)
**Prioritate: ÎNALTĂ | Efort: 5-7 ore**

#### 3.0 Modul nou: `gateway/internal/crypto/vault_transit.go` (Nivel 1 — Vault Transit via PDP)
- [ ] Funcția `SealKeyViaPDP(ctx, pdpURL string, keyPEM []byte) ([]byte, error)`:
  - Conectează la PDP prin HTTPS (fără mTLS — enrollment token în header)
  - Trimite `POST /api/gateway/seal-key` cu cheia în plaintext + `Authorization: Bearer <enrollment_token>`
  - PDP criptează prin Vault Transit și returnează ciphertext blob
  - Salvează blob-ul ca `/app/certs/enrolled/mtls.key.vault`
- [ ] Funcția `UnsealKeyViaPDP(ctx, pdpURL string, blob []byte) ([]byte, error)`:
  - La restart: Gateway-ul NU are încă certificat mTLS → folosește enrollment token pentru auth
  - Trimite `POST /api/gateway/unseal-key` cu blob + `Authorization: Bearer <enrollment_token>`
  - PDP decriptează prin Vault Transit → returnează cheia plaintext
  - Cheia rămâne **doar în memorie** după decriptare
- [ ] NOTĂ: După enrollment, enrollment_token-ul rămâne în config pentru unseal la restart

#### 3.0b Modul nou: `gateway/internal/crypto/aesgcm_key.go` (Nivel 2 — AES-256-GCM local)
- [ ] Funcția `DeriveKeyEncryptionKey(machineID string) ([]byte, error)`:
  - Citește `/etc/machine-id` (trebuie montat read-only din host în container)
  - Aplică Argon2id: salt=`"ztna-gateway-kek-v1"`, iterations=3, memory=64MB, keyLen=32
  - Returnează cheia AES-256 (32 bytes)
- [ ] Funcția `EncryptKeyLocal(keyPEM, kek []byte) ([]byte, error)`:
  - Generează nonce aleator (12 bytes)
  - Criptează cheia PEM cu AES-256-GCM
  - Returnează nonce || ciphertext
- [ ] Funcția `DecryptKeyLocal(blob, kek []byte) ([]byte, error)`:
  - Extrage nonce-ul (primele 12 bytes), restul e ciphertext
  - Decriptează cu AES-256-GCM
  - Returnează cheia PEM

#### 3.0c Modul nou: `gateway/internal/crypto/keystore.go` (Orchestrator 2-niveluri)
- [ ] Funcția `StoreKey(keyPEM, pdpURL, machineID, enrollmentToken string) error`:
  - Pas 1: `SealKeyViaPDP(keyPEM, pdpURL)` → salvează `mtls.key.vault`
  - Pas 2: `DeriveKeyEncryptionKey(machineID)` + `EncryptKeyLocal(keyPEM, kek)` → salvează `mtls.key.gcm`
  - Ambele fișiere cu permisiuni `0400`
- [ ] Funcția `RestoreKey(certsDir, pdpURL, machineID, enrollmentToken string) (*ecdsa.PrivateKey, error)`:
  - Pas 1: Încearcă `UnsealKeyViaPDP(mtls.key.vault, pdpURL)` → returnează cheia
  - Pas 2 (fallback): `DeriveKeyEncryptionKey(machineID)` + `DecryptKeyLocal(mtls.key.gcm, kek)` → returnează cheia
  - Dacă ambele eșuează → `ErrKeyRestorationFailed`

#### 3.0d Endpoint-uri noi pe PDP: `/api/gateway/seal-key` + `/api/gateway/unseal-key`
- [ ] `POST /api/gateway/seal-key`:
  - Primește `{"key_pem": "<base64>"}` + `Authorization: Bearer <enrollment_token>`
  - Validează enrollment token-ul
  - Apelează Vault Transit: `POST /v1/transit/encrypt/ztna-gateway-key`
  - Returnează `{"ciphertext": "vault:v1:...", "key_version": 1}`
- [ ] `POST /api/gateway/unseal-key`:
  - Primește `{"ciphertext": "vault:v1:..."}` + `Authorization: Bearer <enrollment_token>`
  - Validează enrollment token-ul
  - Apelează Vault Transit: `POST /v1/transit/decrypt/ztna-gateway-key`
  - Returnează `{"key_pem": "<base64>"}`
- [ ] Rate limiting: max 1 request/sec per enrollment token
- [ ] Configurare Vault Transit key: `vault write -f transit/keys/ztna-gateway-key`

#### 3.1 Modificare `gateway/internal/enrollment/enrollment.go`
- [ ] `Ensure()` să returneze eroare fatală dacă nu există nici certificat salvat, nici enrollment token
- [ ] Elimină orice fallback la generare auto-semnată
- [ ] După enrollment: `keystore.StoreKey()` — salvează pe ambele niveluri
- [ ] La startup: `keystore.RestoreKey()` — încearcă Vault Transit, apoi AES-GCM

#### 3.2 Modificare `gateway/internal/dataplane/server.go`
- [ ] `buildServerTLSConfig()` să ceară explicit certificat + cheie
- [ ] Fără `dev_mode` self-signed cert
- [ ] Eroare clară dacă certificatul lipsește

#### 3.3 Modificare `gateway/cmd/gateway/main.go`
- [ ] Dacă enrollment-ul eșuează → **EROARE FATALĂ**
- [ ] Logare clară a motivului (token invalid, PDP unreachable, etc.)
- [ ] Logare a nivelului de decriptare folosit: `key_source=vault_transit` sau `key_source=aes_gcm_local`
- [ ] NOTĂ: `enrollment_token` rămâne în config (necesar pentru unseal la restart)

#### 3.4 Modificare `gateway/docker-compose.yml` + `gateway/Dockerfile.gateway`
- [ ] Montează `/etc/machine-id` read-only: `- /etc/machine-id:/etc/machine-id:ro`
- [ ] Montează volumul `gateway-certs` în `/app/certs/enrolled` pentru persistență
- [ ] Variabila de mediu `GATEWAY_ENROLLMENT_TOKEN` rămâne obligatorie

### Fază 4: Configurare și Deployment
**Prioritate: MEDIE | Efort: 2-3 ore**

#### 4.1 Actualizare fișiere de configurare
- [ ] `pdp/pdp-config.json` — elimină `tls_cert`/`tls_key`/`mtls_ca`, adaugă `pdp_fqdn`, `pki_role_pdp`
- [ ] `pdp/docker-pdp-config.json` — aceleași modificări
- [ ] `gateway/gateway-config.json` — elimină referințele la fișiere statice
- [ ] `gateway/gateway-config.local.json` — elimină `dev_mode`

#### 4.2 Actualizare Docker
- [ ] `pdp/Dockerfile` — nu mai copiază `certs/` (sau doar `certs/certs.go` rămâne)
- [ ] `gateway/Dockerfile.gateway` — nu mai include fișiere de certificat statice
- [ ] `docker-compose.yml` — actualizează volume mounts și variabile de mediu

---

## 5. Modificări Detaliate per Fișier

### 5.1 Fișiere de ȘTERS

```
pdp/certs/gen_server_cert.go     # CLI tool generare certificat static
pdp/certs/gen_secret.go           # CLI tool generare secret
pdp/certs/ca.crt                  # CA static
pdp/certs/ca.key                  # Cheie CA statică
pdp/certs/pdp.crt                 # Certificat PDP static
pdp/certs/pdp.key                 # Cheie PDP statică
pdp/data/ca-cert.pem              # Copie CA statică
pdp/data/ca-key.pem               # Copie cheie CA statică
```

**Notă**: `pdp/certs/certs.go` **rămâne** — conține funcții utilitare (`CertFingerprint`, `BuildResourceCSR`, `ParseCertPEM`) folosite de enrollment, resources, și gateway services.

### 5.2 `pdp/pki/self_enroll.go` (FIȘIER NOU)

```go
package pki

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "log"
    "net"
    "time"
)

// SelfEnrollResult holds the TLS certificate and CA PEM obtained via
// direct Vault PKI enrollment at PDP startup.
type SelfEnrollResult struct {
    Certificate tls.Certificate
    CAPEM       []byte
    ExpiresAt   time.Time
}

// SelfEnroll connects directly to Vault PKI, generates an ECDSA P-256 keypair,
// creates a CSR for the configured FQDN, signs it via the PDP PKI role,
// and returns a tls.Certificate ready for use as the server's TLS identity.
//
// This replaces the old static pdp.crt/pdp.key files.
func SelfEnroll(ctx context.Context, cfg VaultConfig, fqdn string) (*SelfEnrollResult, error) {
    // 1. Generate ECDSA P-256 keypair
    key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        return nil, fmt.Errorf("generate PDP key: %w", err)
    }

    // 2. Create CSR
    tmpl := &x509.CertificateRequest{
        Subject: pkix.Name{
            CommonName: fqdn,
            Organization: []string{"ZTNA PDP"},
        },
        DNSNames: []string{fqdn},
    }
    // Also add localhost for development
    if fqdn != "localhost" {
        tmpl.DNSNames = append(tmpl.DNSNames, "localhost")
    }
    tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

    csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
    if err != nil {
        return nil, fmt.Errorf("create PDP CSR: %w", err)
    }
    csrPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE REQUEST",
        Bytes: csrDER,
    })

    // 3. Connect to Vault PKI
    client, err := NewVaultClient(cfg)
    if err != nil {
        return nil, fmt.Errorf("connect to Vault PKI: %w", err)
    }

    // 4. Sign CSR via Vault PKI (using the PDP role)
    certPEM, err := client.SignCSR(csrPEM, cfg.PKIRolePDP, "168h") // 7 days
    if err != nil {
        return nil, fmt.Errorf("sign PDP CSR via Vault: %w", err)
    }

    // 5. Get CA PEM for mTLS client validation
    caPEM, err := client.GetCAPEM()
    if err != nil {
        return nil, fmt.Errorf("get CA PEM from Vault: %w", err)
    }

    // 6. Build tls.Certificate
    keyDER, err := x509.MarshalECPrivateKey(key)
    if err != nil {
        return nil, fmt.Errorf("marshal PDP key: %w", err)
    }
    keyPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: keyDER,
    })

    tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
    if err != nil {
        return nil, fmt.Errorf("build TLS certificate: %w", err)
    }

    // 7. Parse expiration
    block, _ := pem.Decode(certPEM)
    parsed, _ := x509.ParseCertificate(block.Bytes)
    expiresAt := time.Now().Add(168 * time.Hour)
    if parsed != nil {
        expiresAt = parsed.NotAfter
    }

    log.Printf("[PDP-SELF-ENROLL] Identity obtained: fqdn=%s serial=%s expires=%s",
        fqdn, serialFromCert(parsed), expiresAt.Format(time.RFC3339))

    return &SelfEnrollResult{
        Certificate: tlsCert,
        CAPEM:       caPEM,
        ExpiresAt:   expiresAt,
    }, nil
}

// StartSelfEnrollLoop periodically renews the PDP's TLS certificate
// before it expires. It blocks until ctx is cancelled.
func StartSelfEnrollLoop(ctx context.Context, cfg VaultConfig, fqdn string, current *SelfEnrollResult, onRenew func(*SelfEnrollResult)) {
    const checkInterval = 6 * time.Hour
    const renewThreshold = 48 * time.Hour

    ticker := time.NewTicker(checkInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            remaining := time.Until(current.ExpiresAt)
            if remaining > renewThreshold {
                continue
            }
            log.Printf("[PDP-SELF-ENROLL] Renewing certificate (expires in %s)", remaining.Round(time.Minute))
            result, err := SelfEnroll(ctx, cfg, fqdn)
            if err != nil {
                log.Printf("[PDP-SELF-ENROLL] Renewal failed: %v", err)
                continue
            }
            current = result
            if onRenew != nil {
                onRenew(result)
            }
        }
    }
}

func serialFromCert(cert *x509.Certificate) string {
    if cert == nil {
        return "unknown"
    }
    return cert.SerialNumber.String()
}
```

### 5.3 `pdp/config/config.go` — Modificări

```go
// ADAUGĂ în structura Config:
type Config struct {
    // ... câmpuri existente ...

    // PDP identity — înlocuiește tls_cert / tls_key / mtls_ca statice
    PDPFQDN string `json:"pdp_fqdn"` // FQDN-ul PDP-ului pentru CSR (ex: "pdp.lab.local")

    // Vault PKI — extinde configurația existentă
    PKIURL        string `json:"pki_url"`
    PKIToken      string `json:"pki_token"`
    PKIPath       string `json:"pki_path"`
    PKIRoleDevice string `json:"pki_role_device"`
    PKIRoleGateway string `json:"pki_role_gateway"`
    PKIRolePDP    string `json:"pki_role_pdp"`    // NOU: rolul Vault pentru certificatul PDP

    // Câmpurile de mai jos devin INTERNE (completate dinamic la startup)
    // tls_cert, tls_key, mtls_ca — eliminate din config file
}
```

### 5.4 `pdp/cmd/pdp/main.go` — Modificări

```go
// ÎNLOCUIEȘTE logica de validare TLS statică cu self-enrollment:

func main() {
    // ... parse flags, load config ...

    // ── PDP Self-Enrollment (înlocuiește validarea fișierelor statice) ──
    vaultCfg := pki.VaultConfig{
        URL:          cfg.PKIURL,
        Token:        cfg.PKIToken,
        Path:         cfg.PKIPath,
        PKIRolePDP:   cfg.PKIRolePDP,
        CACertFile:   cfg.PKICACertFile,
        InsecureSkipVerify: cfg.PKIInsecureSkipVerify,
    }
    if cfg.PKIRolePDP == "" {
        vaultCfg.PKIRolePDP = "ztna-pdp" // default
    }

    enrollResult, err := pki.SelfEnroll(ctx, vaultCfg, cfg.PDPFQDN)
    if err != nil {
        log.Fatalf("[PDP] Self-enrollment failed: %v", err)
    }

    // Construiește TLS config din certificatul enrolled
    tlsConfig := &tls.Config{
        Certificates: []tls.Certificate{enrollResult.Certificate},
        MinVersion:   tls.VersionTLS13,
    }

    // CA pool pentru mTLS client validation
    caPool := x509.NewCertPool()
    if !caPool.AppendCertsFromPEM(enrollResult.CAPEM) {
        log.Fatal("[PDP] Failed to parse CA PEM for mTLS client validation")
    }
    tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
    tlsConfig.ClientCAs = caPool

    // Pornește bucla de reînnoire în background
    go pki.StartSelfEnrollLoop(ctx, vaultCfg, cfg.PDPFQDN, enrollResult, func(newResult *pki.SelfEnrollResult) {
        // Actualizează TLS config la reînnoire (necesită sincronizare thread-safe)
    })

    // ... restul inițializării ...
}
```

### 5.5 `gateway/internal/dataplane/server.go` — Modificări

```go
// ȘTERGE liniile 184-191 (blocul dev_mode self-signed cert)
// ȘTERGE liniile 840-889 (funcția generateSelfSignedCert)

// buildServerTLSConfig — varianta curățată:
func (gateway *Gateway) buildServerTLSConfig() (*tls.Config, error) {
    certPath := strings.TrimSpace(gateway.cfg.TLSCert)
    keyPath := strings.TrimSpace(gateway.cfg.TLSKey)
    
    // Fără fallback la auto-semnat
    if certPath == "" || keyPath == "" {
        return nil, fmt.Errorf("TLS certificate and key are required; gateway must be enrolled before starting")
    }

    cert, err := tls.LoadX509KeyPair(certPath, keyPath)
    if err != nil {
        return nil, fmt.Errorf("failed to load TLS certificate: %w", err)
    }
    // ... restul logicii neschimbate ...
}
```

### 5.6 `gateway/internal/enrollment/enrollment.go` — Modificări

```go
// Ensure() — varianta fără fallback:
func Ensure(ctx context.Context, cfg *config.Config) (*Result, error) {
    // Verifică dacă există deja certificat salvat
    if fileExists(cfg.MTLSCert) && fileExists(cfg.MTLSKey) {
        // Certificatul există — Gateway-ul este deja înrolat
        return &Result{AlreadyEnrolled: true}, nil
    }

    // Verifică dacă avem enrollment token
    token := strings.TrimSpace(cfg.EnrollmentToken)
    if token == "" {
        // FĂRĂ FALLBACK — eroare fatală
        return nil, fmt.Errorf("gateway is not enrolled and no enrollment token is configured; "+
            "generate an enrollment token from the PDP dashboard (Gateways → Create Gateway)")
    }

    // ... restul logicii de enrollment neschimbată ...
}
```

### 5.7 `gateway/internal/config/config.go` — Modificări

```go
// Elimină câmpul DevMode sau îl face inofensiv:
type Config struct {
    // ... câmpuri existente ...
    
    // DevMode NU mai permite generare de certificate auto-semnate.
    // Poate fi păstrat pentru alte scopuri (ex: logging verbose, CORS permisiv).
    DevMode bool `json:"dev_mode"`
    
    // NOTĂ: câmpurile TLSCert, TLSKey, MTLSCert, MTLSKey, MTLSKey, MTLSCSR, CloudCA
    // rămân — ele stochează căile unde se salvează certificatele OBȚINUTE PRIN ENROLLMENT.
}
```

### 5.8 Fișiere de Configurare — Modificări

#### `pdp/pdp-config.json` (înainte → după)

```json
// ÎNAINTE (static):
{
  "listen_addr": ":8443",
  "tls_cert": "./certs/pdp.crt",
  "tls_key": "./certs/pdp.key",
  "mtls_ca": "./certs/ca.crt",
  "pki_url": "https://vault.lab.local:8200",
  "pki_token": "s.xxxxxxxxxxxx",
  "pki_path": "pki_int",
  "pki_role_device": "ztna-device",
  "pki_role_gateway": "ztna-gateway"
}

// DUPĂ (enrollment dinamic):
{
  "listen_addr": ":8443",
  "pdp_fqdn": "pdp.lab.local",
  "pki_url": "https://vault.lab.local:8200",
  "pki_token": "s.xxxxxxxxxxxx",
  "pki_path": "pki_int",
  "pki_role_device": "ztna-device",
  "pki_role_gateway": "ztna-gateway",
  "pki_role_pdp": "ztna-pdp"
}
```

#### `gateway/gateway-config.json` (înainte → după)

```json
// ÎNAINTE (static):
{
  "fqdn": "gateway.lab.local",
  "cloud_url": "https://localhost:8443",
  "tls_cert_file": "gateway-ssl.crt",
  "tls_key_file": "gateway-ssl.key",
  "mtls_cert_file": "gateway-mtls.crt",
  "mtls_key_file": "gateway-mtls.key",
  "mtls_csr_file": "gateway-mtls.csr",
  "cloud_ca_file": "ca.crt",
  "enrollment_token": ""
}

// DUPĂ (enrollment dinamic):
{
  "fqdn": "gateway.lab.local",
  "cloud_url": "https://pdp.lab.local:8443",
  "tls_cert_file": "enrolled/tls.crt",
  "tls_key_file": "enrolled/tls.key",
  "mtls_cert_file": "enrolled/mtls.crt",
  "mtls_key_file": "enrolled/mtls.key",
  "cloud_ca_file": "enrolled/ca.crt",
  "enrollment_token": ""
}
```

---

## 6. Configurație Finală

### 6.1 Structura de directoare (după implementare)

```
pdp/
├── certs/
│   └── certs.go              # Singurul fișier rămas — funcții utilitare
├── config/
│   └── config.go             # Actualizat cu PDPFQDN, PKIRolePDP
├── cmd/pdp/
│   └── main.go               # Self-enrollment la startup
├── pki/
│   ├── vault.go              # Client Vault PKI (existent)
│   ├── self_enroll.go        # NOU — PDP self-enrollment
│   └── transit_key.go        # NOU — Vault Transit encryption/decryption
├── pdp-config.json           # Fără tls_cert/tls_key/mtls_ca
└── docker-pdp-config.json    # Fără referințe statice

gateway/
├── internal/
│   ├── config/
│   │   └── config.go              # DevMode fără generare de certificate
│   ├── crypto/
│   │   ├── vault_transit.go       # NOU — Nivel 1: SealKeyViaPDP(), UnsealKeyViaPDP()
│   │   ├── aesgcm_key.go          # NOU — Nivel 2: DeriveKeyEncryptionKey(), EncryptKeyLocal(), DecryptKeyLocal()
│   │   └── keystore.go            # NOU — Orchestrator: StoreKey(), RestoreKey() (2-niveluri)
│   ├── enrollment/
│   │   └── enrollment.go          # Fără fallback; keystore.StoreKey() după enrollment
│   └── dataplane/
│       └── server.go              # Fără generateSelfSignedCert()
├── docker-compose.yml             # MODIFICAT — mount /etc/machine-id:ro, volume gateway-certs
├── Dockerfile.gateway             # MODIFICAT — mkdir /app/certs/enrolled
├── docker-config.json             # MODIFICAT — paths sub /app/certs/enrolled/
├── gateway-config.json            # Fără referințe la fișiere statice; doar paths
└── gateway-config.local.json      # Fără dev_mode
```

### 6.2 Variabile de Mediu

| Variabilă | Componentă | Descriere |
|---|---|---|
| `PDP_FQDN` | PDP | FQDN-ul pentru CSR-ul de auto-enrollment |
| `PDP_PKI_URL` | PDP | Adresa Vault PKI |
| `PDP_PKI_TOKEN` | PDP | Token Vault pentru autentificare |
| `PDP_PKI_ROLE_PDP` | PDP | Rolul Vault pentru certificatul PDP |
| `GATEWAY_ENROLLMENT_TOKEN` | Gateway | Token de enrollment (primit din dashboard) |
| `GATEWAY_CLOUD_URL` | Gateway | URL-ul PDP-ului pentru enrollment |

### 6.3 Roluri Vault PKI Necesare

| Rol | Componentă | CN Pattern | TTL |
|---|---|---|---|
| `ztna-pdp` | PDP | `pdp.lab.local` | 168h (7 zile) |
| `ztna-gateway` | Gateway | `gateway-*.lab.local` | 168h (7 zile) |
| `ztna-device` | Agent | `device-*` (din TPM EK) | 720h (30 zile) |
| `ztna-resource` | Resurse | `*.lab.local` | 2160h (90 zile) |

---

## 7. Testare și Validare

### 7.1 Teste Unitare

| Test | Descriere |
|---|---|
| `TestSelfEnroll_Success` | PDP se înrolează cu Vault PKI configurat corect |
| `TestSelfEnroll_VaultUnreachable` | PDP refuză pornirea când Vault e inaccesibil |
| `TestSelfEnroll_InvalidToken` | PDP refuză pornirea cu token Vault invalid |
| `TestGatewayEnsure_NoCertNoToken` | Gateway refuză pornirea fără certificat și fără token |
| `TestGatewayEnsure_WithToken` | Gateway se înrolează cu token valid |
| `TestGatewayEnsure_AlreadyEnrolled` | Gateway pornește direct cu certificat existent |
| `TestBuildServerTLSConfig_NoCert` | Eroare când certificatul TLS lipsește |

### 7.2 Teste de Integrare

| Test | Descriere |
|---|---|
| `TestPDPStartupFlow` | PDP pornește complet din Vault PKI, fără fișiere statice |
| `TestGatewayEnrollmentFlow` | Gateway se înrolează → obține certificat → pornește |
| `TestGatewayRenewalFlow` | Gateway reînnoiește certificatul înainte de expirare |
| `TestAgentEnrollmentFlow` | Agentul se înrolează prin EST → certificat în TPM |
| `TestEndToEndMTLS` | Agent → Gateway → PDP, toate cu certificate enrolled |

### 7.3 Procedură de Validare Manuală

1. **Pornește Vault PKI** cu rolurile configurate
2. **Șterge toate fișierele statice** (`pdp/certs/*.crt`, `pdp/certs/*.key`, `gateway/*.crt`, `gateway/*.key`)
3. **Configurează PDP** cu Vault URL, token, și roluri
4. **Pornește PDP** — trebuie să se auto-înroleze și să pornească
5. **Verifică** `curl -k https://localhost:8443/api/health` — trebuie să răspundă
6. **Creează Gateway în dashboard** → copiază enrollment token
7. **Configurează Gateway** cu enrollment token
8. **Pornește Gateway** — trebuie să se înroleze și să pornească
9. **Verifică** conectivitatea mTLS între Gateway și PDP
10. **Pornește Agentul** — trebuie să se înroleze prin EST
11. **Testează** o conexiune completă Agent → Gateway → Resursă

---

## Anexa A: Codul care RĂMÂNE

### `pdp/certs/certs.go` — PĂSTRAT (funcții utilitare)

```go
// Aceste funcții sunt folosite de:
// - enrollment/service.go (ComputeCSRFingerprint, certificateSerial)
// - resources/service.go (BuildResourceCSR)
// - gateway/service.go (validare CSR)
// - transport/router.go (CertFingerprint)

func CertFingerprint(certPEM []byte) (string, error)  // ✅ PĂSTRAT
func BuildResourceCSR(domain string) (...)              // ✅ PĂSTRAT
func ParseCertPEM(certPEM []byte) (*x509.Certificate, error) // ✅ PĂSTRAT
```

### `pdp/pki/vault.go` — PĂSTRAT (client Vault PKI)

```go
// Folosit de:
// - self_enroll.go (NOU) — PDP self-enrollment
// - transport/router.go (signCSR, revokeCertificate)
// - enrollment/service.go (prin signer interface)

func NewVaultClient(cfg VaultConfig) (*VaultClient, error)    // ✅ PĂSTRAT
func (v *VaultClient) SignCSR(...) ([]byte, error)             // ✅ PĂSTRAT
func (v *VaultClient) GetCAPEM() ([]byte, error)               // ✅ PĂSTRAT
func (v *VaultClient) RevokeCertificate(...) error             // ✅ PĂSTRAT
```

---

## Anexa B: Rezumat al Modificărilor

| Categorie | Acțiune | Număr fișiere |
|---|---|---|
| **ȘTERSE** | Fișiere de certificat static și tool-uri CLI | 8 |
| **NOU** | `pdp/pki/self_enroll.go` | 1 |
| **MODIFICAT** | `pdp/cmd/pdp/main.go` — self-enrollment startup | 1 |
| **MODIFICAT** | `pdp/config/config.go` — câmpuri noi | 1 |
| **MODIFICAT** | `gateway/internal/dataplane/server.go` — eliminare self-signed | 1 |
| **MODIFICAT** | `gateway/internal/enrollment/enrollment.go` — eroare fatală | 1 |
| **MODIFICAT** | `gateway/internal/config/config.go` — DevMode inofensiv | 1 |
| **MODIFICAT** | `pdp/pdp-config.json` — eliminare referințe statice | 1 |
| **MODIFICAT** | `pdp/docker-pdp-config.json` — eliminare referințe statice | 1 |
| **MODIFICAT** | `gateway/gateway-config.json` — paths curățate | 1 |
| **MODIFICAT** | `gateway/gateway-config.local.json` — fără dev_mode | 1 |

---

*Plan generat pe 10 Mai 2026 | ZTNA System | Laura's Bachelor Thesis*
