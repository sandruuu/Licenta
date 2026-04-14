# ZTNA — Copilot Instructions

## Project Overview

This project is a thesis-grade **Zero Trust Network Access (ZTNA)** platform with multifactor authentication, dynamic risk-based policy enforcement, device health compliance, and secure tunneled access to internal resources.

- **Language**: Go (all backend services), JavaScript/React (cloud dashboard, device-health frontend)
- **Modules**: 4 independent Go modules (`cloud/`, `connect-app/`, `gateway/`, `device-health-app/`)
- **Desktop framework**: Wails v2 for the device-health-app (Go + React embedded)
- **Database**: SQLite (pure Go via `modernc.org/sqlite`) in cloud and gateway session store
- **Deployment**: Docker Compose (multi-network: public, dmz, private)

## Directory Layout

```
cloud/
  main.go              Control plane — IdP, Policy Engine, Policy Administrator
  admin/               Admin handlers (users, audit, sessions)
  api/                 HTTP router + middleware (JWT auth, mTLS, CORS)
  certs/               Internal CA management (sign CSRs, revoke certs)
  config/              JSON config loader + validation
  idp/                 Identity Provider (login, OIDC, JWT ES256, TOTP HMAC-SHA256)
  models/              Domain models (User, PolicyRule, Session, DeviceHealth, etc.)
  policy/              Policy engine + risk scoring + rule evaluation
  store/               SQLite persistence layer
  web/                 Login HTML template
  dashboard/           React 19 + Vite 7 admin SPA
    src/               Pages: Login, Dashboard, Users, Policies, Sessions, Audit,
                        Gateways, DeviceHealth, ProtectApp, Resources

connect-app/
  main.go              Windows client — TUN adapter, DNS interception, yamux tunnel
  config/              JSON config loader
  dns/                 Magic DNS resolver (internal domains → CGNAT IPs via tunnel)
  logger/              Structured logging
  routing/             Windows route table management
  tcpproxy/            TCP state machine (SYN/ACK/FIN) over TUN packets
  tpmauth/             TPM 2.0 device enrollment, key management, CSR generation
  tun/                 Wintun adapter (Windows TUN driver)
  tunnel/              TLS 1.3 + yamux multiplexed tunnel to gateway

gateway/
  cmd/
    portal/            Data plane PEP — TLS listener (:9443), OIDC callback (:443)
    admin/             Management plane — REST API + web UI (:8444)
    sessionstore/      Centralized session store — HTTP/JSON API (:6380)
    syslog/            Structured log aggregator — TCP JSON (:5514)
  admin/               Admin handlers, setup wizard, static UI, secrets management
  portal/              OIDC callback, yamux session handler, access enforcement
  sessionstore/        SQLite-backed session CRUD + cleanup
  store/               Gateway config persistence (SQLite)
  syslog/              Client + server for structured logging
  internal/
    anomaly/           Anomaly detection for access patterns
    auth/              Cloud client (mTLS + API key) — authorize, validate, report
    cgnat/             Dynamic CGNAT IP allocation (100.64.0.0/10 pool)
    config/            Gateway configuration + validation
    dns/               DNS resolution for internal resources
    models/            Gateway domain models (Resource, Session, etc.)
    relay/             Bidirectional TCP relay to internal resources

device-health-app/
  main.go              Windows desktop app (Wails) — continuous health monitoring
  app.go               Application lifecycle, enrollment, health coordination
  monitor.go           Health collection scheduler (30s cycle)
  reporter.go          Cloud reporter (mTLS, 5-min interval)
  localapi.go          Local HTTP API (:12080/health) for portal verification
  models.go            HealthCheck, DeviceHealth models
  config.go            JSON config loader
  collectors/
    antivirus.go       Windows Defender status (WMI + registry)
    firewall.go        3-profile firewall check (netsh)
    disk_encryption.go BitLocker status per drive
    os_info.go         OS version, hostname, uptime
    password.go        Password policy (registry)
  tpmauth/             TPM 2.0 enrollment (shared pattern with connect-app)
  frontend/            React 18 + Vite — health gauge, expandable check cards

infrastructure/
  docker-lab.md        Network topology documentation
  dns/                 CoreDNS configurations
  private-dns/         Internal zone definitions
  public-dns/          External DNS zones
  rdp-desktop/         Sample RDP backend resource
  ssh-server/          Sample SSH backend resource
```

## Documentation Index

| Document | Content |
|----------|---------|
| `doc.md` | Thesis specification — objectives, chapters, bibliography requirements |
| `architecture_oidc_flow.md` | OIDC Authorization Code flow, gateway enrollment, sequence diagrams (Mermaid) |
| `cloud/dashboard/README.md` | Dashboard setup and development guide |
| `connect-app/CONNECT_APP_DOCUMENTATION.md` | Connect-app architecture, TUN, DNS, TPM enrollment |
| `device-health-app/DEVICE_HEALTH_APP_DOCUMENTATION.md` | Health collectors, scoring algorithm, reporting |
| `gateway/GATEWAY_DOCUMENTATION.md` | Gateway microservices, portal, admin, session store, syslog |
| `infrastructure/docker-lab.md` | Docker lab topology (public/dmz/private networks) |

## Collaboration

- **Language**: User communicates in Romanian. All code, comments, documentation, and commit messages must be in **English**.
- **Domain**: Academic network security research (thesis project). Zero Trust architecture, MFA, device compliance, policy enforcement, TLS/mTLS, OIDC, and tunnel mechanisms are the core domain — implement them with full rigor.
- **Workflow**: Prefer implementation over asking permission — if the intent is clear, proceed. Test changes by running `go build ./...` in the affected module directory.
- **Documentation discipline**: After **every** codebase change, update the relevant documentation files **and** this file (`ztna-flow-docs.instructions.md`) to reflect the current state. This is mandatory — not optional, not "only for major refactors." Keeping docs in sync eliminates the need to re-analyze the codebase on each session start and ensures productive collaboration from the first message.

## Quality Standards

This is a **thesis-grade** project — all contributions must meet the highest professional bar:

- **SOTA (State of the Art)**: Every implementation should reflect current best practices (OIDC/OAuth2, PKCE, mTLS, Zero Trust principles). Research before implementing; prefer RFC-compliant, proven approaches over ad-hoc solutions.
- **Professional**: Production-quality code — no shortcuts, no TODOs left behind, no dead code. Every commit should be deployable.
- **Efficient**: Minimize allocations, avoid unnecessary copies, prefer streaming over buffering. Profile before optimizing, but design for performance from the start.
- **Logical**: Clear control flow, single responsibility, explicit over implicit. Code should read top-to-bottom without mental gymnastics. Group related functionality; separate unrelated concerns.
- **Elegant**: Concise without being cryptic. Favor idiomatic Go patterns (accept interfaces/return structs, error wrapping, context propagation). Name things precisely — if a name needs a comment, rename it.

### Quality Checklist

- [ ] `go vet` clean in all modules
- [ ] All tests pass with race detector (`-race`)
- [ ] Error paths are tested, not just happy paths
- [ ] Security implications considered (input validation, crypto misuse, TOCTOU, injection)
- [ ] No hardcoded secrets, paths, or magic numbers
- [ ] mTLS and certificate validation enforced on all inter-component channels
- [ ] Documentation updated if behavior changes

## Key Conventions

- **No external test libraries** — stdlib `testing` + `httptest` only
- **Error handling**: Return `error`, never `panic` in library code
- **Crypto & TLS**: TLS 1.3 minimum for all connections. mTLS between gateway ↔ cloud and device ↔ cloud. JWT signing uses ES256 (ECDSA P-256). TOTP uses HMAC-SHA256 with 6-digit codes and 30-second time steps (±1 skew window).
- **JWT**: Auto-generated ECDSA P-256 keys at cloud startup (`data/jwt-signing.key` + `jwt-signing.pub`). Public key exposed via `/.well-known/jwks.json`. Claims include `UserID`, `Username`, `Role`, `DeviceID`, `MFADone`. Access token TTL: 1 hour.
- **OIDC flow**: Authorization Code + PKCE (S256). Per-gateway `client_id`/`client_secret` generated at enrollment. Auth codes are one-time use with 60-second TTL. Refresh tokens rotated on use.
- **Device identity**: TPM 2.0 ECDSA P-256 key (software fallback if TPM unavailable). Device ID = SHA-256 of Endorsement Key public key (or `MachineGuid` fallback). Certificates are 24-hour validity with auto-renewal at 12-hour mark.
- **CGNAT**: Dynamic IP allocation from 100.64.0.0/10 pool. TTL-based expiration (5 min default). Garbage collection every 30 seconds. LRU eviction on pool exhaustion (aggressive GC + evict oldest mapping by `LastAccess`).
- **Magic DNS**: connect-app intercepts DNS for internal domains (e.g., `*.lab.local`) → sends `dns_resolve` over yamux → gateway allocates CGNAT IP → synthetic DNS response returned to Windows.
- **Tunnel protocol**: TLS 1.3 + yamux multiplexing (10s keepalive). Stream 1 = JSON control channel (`auth`, `dns_resolve`, `dns_resolve_response`, `tunnel_data`). Streams 2+ = TCP data relay.
- **TCP state machine**: connect-app implements full SYN/SYN-ACK/ACK handshake + data transfer + FIN/RST over raw TUN packets. Max segment size: 1400 bytes.
- **Policy engine**: Rules evaluated in priority order (lower = higher precedence), first match wins. Conditions: roles, users, IPs, time windows, days, blocked dates, health scores, required checks, target resources/ports, max risk score. Default fallback: risk-based decision.
- **Risk scoring**: Contextual factors — `UserID`, `SourceIP`, `DeviceHealth`, `FailedAttempts`, `TimeOfDay`, `Protocol`. Score range 0–100.
- **Health scoring**: Weighted collectors — Firewall (25%), Antivirus (25%), Disk Encryption (20%), Password Policy (15%), OS Info (15%). Status values: `"good"` = 1.0, `"warning"` = 0.5, `"critical"` = 0.
- **Gateway microservices**: 4 independent Docker containers — Portal (PEP, :9443/:443), Admin (:8444), Session Store (:6380), Syslog (:5514). Portal depends on Session Store health and Cloud connectivity. Syslog has TCP healthcheck (`nc -z localhost 5514`); Admin and Portal depend on both SessionStore and Syslog being healthy.
- **Gateway session cache**: Cloud session cache with 5-min cleanup goroutine, 15-min TTL cap, and 5-min max staleness bound (circuit breaker fallback won't serve arbitrarily old cached sessions).
- **Gateway connection limiter**: Max 1000 concurrent connections on portal (atomic counter). Excess connections refused with warning log.
- **Gateway resource sync**: Portal syncs resources from cloud every 2 minutes via `GET /api/gateway/resources`. Upsert changed, delete removed, preserve local-only fields (TunnelIP, Protocol, CertPEM).
- **Gateway OIDC health**: Atomic `oidcHealthy` flag — blocks OIDC redirects if callback server is down. OIDC state capped at 500 pending entries.
- **Gateway syslog client**: Ring buffer (1000 messages) for offline buffering. Auto-flush on reconnect. Server fsync after each entry for audit durability.
- **Gateway DNS cache**: 60-second TTL cache in DNS resolver. Reduces upstream queries and protects against DNS flood.
- **Gateway device identity enforcement**: Portal rejects connections where `certDeviceID` is empty but request claims a `DeviceID` (prevents spoofing without mTLS proof).
- **Gateway admin improvements**: FQDN regex validation at setup, cert expiry check on upload (reject expired, warn <24h), CORS validated with `url.Parse()`, admin email redacted from startup logs, log cleanup goroutine (1h, max 10000 entries).
- **Gateway circuit breaker observability**: State transition logging at all 4 transition points. Public `State()` and `Metrics()` methods for monitoring.
- **Gateway enrollment**: Cloud generates one-time enrollment token (1h TTL) → gateway sends CSR + token → receives mTLS cert + CA + OIDC client credentials. mTLS cert is short-lived and renewble via CSR.
- **Gateway admin**: Setup wizard (2 steps: validate token, configure hostname + SSL). Admin auth via HttpOnly cookie (Secure, SameSiteStrict) + CSRF double-submit pattern.
- **Password policy**: Min 8 chars (upper + lower + digit + special). bcrypt cost factor 12. Setup token expires after 30 minutes.
- **Account lockout**: 5 failed attempts → 15-minute lockout.
- **Session management**: Max 5 concurrent sessions per user. Session TTL: 8 hours. Automatic cleanup every 5 minutes (cloud) / 60 seconds (session store).
- **Dashboard (cloud/dashboard)**: React 19 + Vite 7 + TailwindCSS + Lucide Icons. Pages: Login, Dashboard, Users, Policies, Sessions, Audit, Gateways, DeviceHealth, ProtectApp, Resources. Layout with sidebar navigation.
- **Device Health App**: Wails v2 desktop app. React frontend with animated score gauge and expandable health cards. Backend emits `health:updated` Wails events. Local API at `:12080/health`.
- **Configuration**: JSON config files per component (`cloud-config.json`, `connect-config.json`, `gateway-config.json`, `health-config.json`). Environment variable overrides supported. Secrets validated at startup (fail-fast in production, warn in dev mode). Gateway config saved with fsync before atomic rename. Gateway `InternalDNS` defaults to empty string (no hardcoded external DNS).
- **Docker lab**: 3 networks — public (172.30.0.0/24), dmz (172.22.0.0/24), private (10.10.0.0/24). Services: ztna-cloud (:8443), ztna-public-dns (:1053), ztna-gateway-portal (:9443/:9444), ztna-gateway-admin (:8444), ztna-sessionstore (:6380), ztna-syslog (:5514).
- **connect-app TLS**: Can run without local cert/key files by using server certificate pinning (`server_cert_sha256`) and optional client cert loading. Requires Administrator rights on Windows for TUN adapter creation.
- **Identity Broker (per-gateway federation)**: Cloud acts as an identity broker. Each gateway has an `auth_mode` field (`"builtin"` or `"federated"`). When `"builtin"`, cloud shows its own login page. When `"federated"`, cloud redirects the user to an external OIDC IdP (e.g. Keycloak) configured via `FederationConfig` (issuer, client_id, client_secret, scopes, claim_mapping). External IdP discovery uses `.well-known/openid-configuration` with 6-hour cache. PKCE S256 is mandatory for external exchanges. After external authentication, cloud maps claims, auto-provisions federated users, and issues its own JWT (MFADone=false). Gateway code is unchanged — it always talks to cloud's OIDC endpoints.
- **Federated users**: Users provisioned via federation have `ExternalSubject` (external `sub` claim) and `AuthSource` (issuer URL). They have no local password. MFA methods (TOTP/WebAuthn/Push) can still be enrolled in cloud for step-up at access time.
- **MFA at access time (Conditional Access)**: MFA is never required at login. Login always produces a JWT with `MFADone=false`. MFA is triggered only when the policy engine returns `"mfa_required"` during resource access. The gateway sends `"auth_required"` + OIDC URL with `mfa_step=true`, and the browser opens the MFA step-up flow.
- **MFA methods**: Three methods supported — TOTP (HMAC-SHA256, 6-digit, 30s), WebAuthn/Passkeys (go-webauthn v0.16.4, ECDSA P-256), Push Approval (device-health-app polls every 3s, 2-min TTL, Windows toast notification). Method selection is dynamic based on user's configured methods.
- **Geo-velocity / Impossible travel**: IP geolocation via MaxMind GeoLite2-City (.mmdb). Haversine distance calculation between consecutive logins. Speed thresholds: <500 km/h normal (0 risk pts), 500–900 km/h suspicious (15 pts), >900 km/h impossible travel (30 pts). Last 50 login locations stored per user.

## Key Authentication & Authorization Flows

### Device Enrollment (connect-app / device-health-app)
1. Derive `device_id` from TPM EK (or MachineGuid)
2. Generate CSR signed by TPM key
3. `POST /api/enroll/start-session` → receive `auth_url` + `session_id`
4. Open browser for user authentication at cloud
5. Poll `GET /api/enroll/session-status` every 2s (5-min timeout)
6. Receive `cert_pem` + `ca_pem` → save to `data/`
7. Background auto-renewal at 12-hour mark

### OIDC Authorization Code Flow (resource access)
1. User accesses internal resource via connect-app (CGNAT IP)
2. connect-app sends yamux stream → gateway detects no session
3. Gateway returns `auth_required` + `auth_url` to connect-app
4. connect-app opens browser at cloud `/auth/authorize?client_id=gw-<id>&...`
5. Cloud looks up gateway by `client_id` → checks `auth_mode`:
   - **builtin**: serves login page (password → JWT with MFADone=false)
   - **federated**: redirects browser to external IdP (PKCE S256, state=oidc_session_id)
6. After authentication (builtin login or external IdP callback), cloud issues authorization code
7. Cloud redirects browser to gateway callback with authorization code + state
8. Gateway exchanges code for JWT (`POST /auth/token`, backend-to-backend)
9. Gateway creates session in session store → user reconnects → traffic flows

### Identity Broker — Federated Authentication Flow
1. Browser arrives at `/auth/authorize` with gateway's `client_id`
2. Cloud creates OIDC authorize session, then looks up gateway by `client_id` → `auth_mode` is `"federated"`
3. Cloud generates PKCE (S256) verifier/challenge + nonce, creates `FederationSession` (5-min TTL, one-time use)
4. Cloud redirects browser to external IdP's authorization endpoint (discovered via `.well-known/openid-configuration`)
5. User authenticates at external IdP (e.g. Keycloak login page)
6. External IdP redirects to `GET /auth/federated/callback?code=xxx&state=oidc_session_id`
7. Cloud retrieves `FederationSession` by state (delete-on-read — one-time use)
8. Cloud exchanges authorization code at external IdP's token endpoint (sends PKCE verifier + client_secret)
9. Cloud parses external `id_token` (JWT `ParseUnverified` — trusted, received directly from IdP over TLS)
10. Cloud maps external claims via configurable `ClaimMapping` (default: `sub`, `preferred_username`, `email`)
11. Cloud calls `FindOrCreateFederatedUser` — looks up by `external_subject` + `auth_source`, auto-provisions if new
12. Cloud issues its own JWT (`MFADone=false`), completes the OIDC authorize session → generates authorization code
13. Cloud redirects browser to gateway's callback URL with authorization code
14. Gateway exchanges code normally via `POST /auth/token` — completely unaware that federation occurred

### MFA Step-Up Flow (at access time)
1. User connects to resource via connect-app → gateway calls cloud `POST /api/gateway/authorize`
2. Policy engine evaluates risk → returns `"mfa_required"` (e.g. high risk score, sensitive resource)
3. Gateway sends `"auth_required"` + OIDC URL with `?mfa_step=true` back to connect-app
4. connect-app opens browser → cloud login page detects `mfa_step=true` + existing `auth_token`
5. Login page skips password, shows MFA method selection (TOTP / WebAuthn / Push)
6. User completes MFA → cloud issues new JWT with `MFADone=true`
7. OIDC session completes → gateway receives new JWT → creates session → user reconnects

### Policy Evaluation (per-request)
1. Gateway receives access request with JWT + device health
2. Gateway calls cloud `POST /api/gateway/authorize` (mTLS + API key)
3. Cloud policy engine calculates risk score from contextual factors
4. Rules evaluated in priority order; first match wins
5. Decision returned: `allow` / `deny` / `mfa_required` / `restrict`
6. Gateway enforces decision — creates session or rejects

## API Surface Summary

### Cloud Public Endpoints
```
POST   /api/auth/login              Login (returns mfa_token or auth_token)
POST   /api/auth/verify-mfa         MFA verification (TOTP / WebAuthn / Push)
POST   /api/auth/mfa-step-up        MFA step-up (access-time conditional MFA)
GET    /health                      Health check
GET    /api/ca/cert                 CA certificate (PEM)
GET    /.well-known/jwks.json       JWT public keys
```

### Cloud OIDC Endpoints
```
GET    /auth/authorize              Authorization endpoint (routes builtin vs federated)
GET    /auth/federated/callback     External IdP callback (code exchange + user provisioning)
POST   /auth/token                  Token exchange (code → JWT)
GET    /auth/userinfo               User identity (Bearer token)
```

### Cloud MFA Endpoints
```
POST   /api/auth/mfa-step-up                  Initiate MFA step-up (returns mfa_token + methods)
POST   /api/auth/verify-mfa                   Verify MFA (dispatches to TOTP/WebAuthn/Push)
POST   /api/webauthn/register/begin           Start WebAuthn credential registration
POST   /api/webauthn/register/finish          Complete WebAuthn credential registration
POST   /api/webauthn/authenticate/begin       Start WebAuthn authentication challenge
POST   /api/webauthn/authenticate/finish      Complete WebAuthn authentication
POST   /api/auth/push/begin                   Start push MFA challenge
GET    /api/auth/push/status                   Poll push challenge status
```

### Cloud Device Push Endpoints (mTLS)
```
GET    /api/device/push-challenges             Pending push challenges for device
POST   /api/device/push-challenges/respond     Approve or deny a push challenge
```

### Cloud Gateway Endpoints (mTLS + API Key)
```
POST   /api/gateway/authorize       Access decision request
POST   /api/gateway/validate-token  JWT validation
POST   /api/gateway/device-report   Forward device health
POST   /api/gateway/session-validate Session check
POST   /api/gateway/revoked-serials Revoked certificate list
POST   /api/gateway/enroll          Gateway enrollment (token + CSR)
POST   /api/gateway/renew-cert      Certificate renewal
GET    /api/gateway/resources       Synced resource list
```

### Cloud Admin Endpoints (JWT + admin role)
```
GET/POST   /api/admin/users         User management
GET/POST   /api/admin/rules         Policy rule management
GET/POST   /api/admin/sessions      Session oversight
GET        /api/admin/audit         Audit log
GET/POST   /api/admin/gateways      Gateway lifecycle
```

### Gateway Session Store (:6380)
```
POST   /sessions/create             Create session
POST   /sessions/get                Retrieve session
POST   /sessions/touch              Update activity
POST   /sessions/revoke             Revoke session
GET    /sessions                    List active sessions
GET    /health                      Health check
```

### Device Health Local API (:12080)
```
GET    /health                      Status + device_id + last_report
```

## Remaining Work

- End-to-end integration testing script (`test-oidc-flow.ps1`) needs update for latest enrollment flow.

## Commands

```bash
# Build all components
cd cloud && go build ./...
cd connect-app && go build ./...
cd gateway && go build ./...
cd device-health-app && go build ./...

# Run Docker lab
docker-compose up --build

# Run cloud dashboard dev server
cd cloud/dashboard && npm install && npm run dev

# Run device-health-app frontend dev
cd device-health-app/frontend && npm install && npm run dev

# Test OIDC flow (PowerShell)
.\test-oidc-flow.ps1
```