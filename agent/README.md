# ZTNA Agent

`agent/` contains the final endpoint-side executable. It is independent from `endpoint-agent/` and does not import `endpoint-agent/internal` packages.

## Milestone 1

The first milestone proves the Windows process boundary and IPC transport:

- one physical executable: `ztna-agent.exe`
- one LocalSystem service process launched by Windows SCM
- one user-context tray process launched from the interactive session
- strict Windows Named Pipe IPC with an authorized user SID in the pipe ACL
- a simple `Ping` message from tray to service and a `PingResponse` from service to tray

The initial proof milestone intentionally excluded Wails UI, catalog sync, tunnel ownership, renewal, and privileged traffic routing. Later slices have added the enrollment trust gate, service-owned posture collection, Cloud posture reporting, startup enrollment restore, endpoint certificate renewal, gRPC/mTLS device catalog synchronization, persistent catalog cache, catalog backoff, tray-to-service access-token refresh, the service-owned synthetic DNS catalog resolver with a local UDP/TCP DNS listener, the service-owned TUN adapter plus CGNAT route baseline, a Gateway mTLS/yamux tunnel manager, the first TUN-to-yamux TCP bridge, optional per-flow process identity, and the Wails/React tray dashboard while preserving the same service/tray boundary.

## Enrollment Trust Gate

The agent now has the first enrollment handoff slice:

- Cloud registers a dedicated native OIDC public client: `ztna-agent`
- tray can run browser OIDC login with Authorization Code + PKCE S256 and a loopback callback
- tray exchanges the OIDC access token at Cloud `POST /api/enroll/token`
- tray submits the returned short-lived enrollment JWT to the service through `SubmitEnrollmentToken`
- service validates the enrollment JWT locally through configured Cloud JWKS before accepting the handoff
- service applies per-SID submission rate limiting and never logs raw tokens
- when the service is installed with `--cloud-url`, it creates or loads the machine-scope NCrypt ECDSA P-256 key `ZTNA_DeviceKey_{SID}`, builds a CSR with `CN=device_id`, calls Cloud EST `/.well-known/est/ztna/simpleenroll`, and installs the returned certificate material into Windows Machine Store

The service-side TPM and EST work is gated behind the verified token step. The service resolves the active Windows user SID, probes the machine-scope NCrypt key through the Microsoft Platform Crypto Provider, derives `device_id` from SHA-256 of TPM EK public bytes when the platform exposes `PCP_EKPUB`, creates the persisted machine key if absent, signs the CSR through NCrypt, and records the enrolled certificate SHA-256 and expiry in IPC status. EST enrollment remains HTTPS/REST through the RFC 7030 endpoints. After enrollment, steady-state posture reports, heartbeats, catalog synchronization, and the service-owned Gateway tunnel use the matching `CN=device_id` certificate from `LocalMachine\My`, paired with the existing machine-scope NCrypt signer and issuer material from `LocalMachine\CA` when present. MFA/step-up remains intentionally outside the current implementation slice; `mfa_required` is surfaced as a structured Gateway challenge/denial event until the Tray step-up flow is implemented.

After successful EST enrollment, the service persists only non-secret enrollment metadata to `agent-enrollment-state.json` in the endpoint state folder. State directory resolution is `ZTNA_AGENT_STATE_DIR`, then `ZTNA_ENDPOINT_DIR`, then the legacy `ZTNA_TPM_DIR` alias, then the machine-wide endpoint default (`%PROGRAMDATA%\ztna\endpoint` on Windows or `/var/lib/ztna/endpoint` elsewhere). The state file stores device ID, user SID, key name/provider, certificate SHA-256, certificate expiry, and timestamps; it does not store enrollment tokens, OIDC access tokens, refresh tokens, or private key material. On service startup, the agent reloads this metadata and marks the endpoint `ENROLLED` only if the matching Machine Store certificate can be loaded and its SHA-256 fingerprint matches the persisted value. The service also persists the service-private catalog cache to `agent-catalog-cache.json` when Cloud catalog sync is configured; that cache stores device ID, catalog version, policy epoch, DNS suffixes, catalog resource entries, TTL, and timestamps, but no tokens or private key material.

## Certificate Renewal

Endpoint certificate renewal is owned by the LocalSystem service. When the enrolled Machine Store certificate expires within the renewal window, the service reloads the certificate and machine-scope NCrypt signer, creates a new CSR with the same `CN=device_id`, and calls Cloud `POST /api/enroll/renew` using the current endpoint certificate as the mTLS client credential. Cloud validates the mTLS identity and CSR public key fingerprint before issuing the replacement certificate.

The default renewal scheduler checks once per hour and renews certificates that expire within 12 hours. Successful renewals install the replacement leaf and CA material through the same certificate installer path, update IPC status with the new SHA-256 and expiry, and refresh the non-secret state file. Renewal never uses a user OIDC token and never persists private key material.

## Device Catalog Synchronization

The service now owns the final-agent catalog transport. When enrollment is `ENROLLED`, a Cloud URL is configured, and the service has the current user access token in memory, it loads the endpoint Machine Store certificate and calls Cloud `ztna.catalog.v1.DeviceCatalogService/GetCatalog` over HTTP/2 gRPC with device mTLS. The access token is sent as gRPC `authorization` metadata so Cloud can keep user and role filtering while the device identity is authenticated by the certificate. The tray updates this in-memory token through `UpdateAccessToken`; the service validates authorized SID, device ID, JWT shape, and expiry, and never persists the token.

Catalog responses carry a version, DNS suffix list, private resource entries (`fqdn`, `resource_id`, `protocol`, `port`), TTL, not-modified flag, and policy epoch. The agent normalizes and de-duplicates suffixes/resources, handles not-modified responses without replacing the local view, and applies returned suffixes through the service-owned DNS configurator/NRPT path. Successful live syncs persist the service-private cache, and startup restore reapplies cached NRPT suffixes plus the synthetic DNS policy after enrollment state is restored and the device ID matches the Machine Store certificate. The scheduler tracks TTL, next sync time, transient-error backoff, token-required state, stale cache state, and last error. Catalog data remains service-private; IPC exposes status metadata and counts rather than FQDNs or resource identifiers.

The synthetic DNS baseline lives in `internal/dnsresolver`. It maintains an exact FQDN catalog, allocates stable synthetic addresses from RFC 6598 CGNAT space (`100.64.0.0/10`) only for catalog resources, rejects suffix-only or unknown domains, tracks TTL/expiry, and keeps a reverse mapping from synthetic IP to resource context for the TUN data plane. It also exposes a service-owned UDP/TCP DNS listener on the configured DNS server address (default `127.0.0.1:53` when Cloud/catalog sync is configured): A queries for catalog resources return synthetic CGNAT records, unknown catalog names return NXDOMAIN, and AAAA queries return an empty successful response. Cloud `GetCatalog` returns the private resource entries needed for this check.

## Service-Owned TUN And Gateway Tunnel

The service now has an explicit opt-in TUN baseline for the data plane. When installed or run with `--tun`, the LocalSystem service creates or reopens the Wintun adapter, configures the adapter IP/DNS settings, adds the CGNAT route (`100.64.0.0/10` by default), starts reading packets from the adapter, and removes the route plus closes the adapter when the service context is cancelled. The default values are `ZTNA-TUN`, `100.64.0.1`, `255.192.0.0`, and `100.64.0.0/10`; they can be overridden with `--tun-name`, `--tun-ip`, `--tun-netmask`, and `--tun-route-cidr`.

The packet loop parses IPv4/TCP packets, checks the destination synthetic IP against the service-private DNS resolver reverse map, verifies the catalog port when present, and dispatches matched packets to the Gateway relay when `--gateway-tunnel` or `--gateway-address` is configured. Without a relay forwarder, matched packets are still counted and dropped locally so the TUN baseline remains observable during staged rollout. `GetStatus` exposes metadata and counters such as network state, TUN adapter name, TUN IP, route CIDR, packets read, TCP packets, matched/unmatched/dropped packets, whether a forwarder is configured, last packet time, and last packet error without exposing catalog resource identifiers.

The Gateway tunnel manager dials the configured Gateway with TLS 1.3, device mTLS, and yamux, sends the protocol `hello` frame, reconnects with bounded exponential backoff, and opens one yamux stream per TCP flow. When `--cloud-url` and the Gateway tunnel are configured, the TUN relay asks Cloud `ztna.agent.v1.AgentAuthorizationService/AuthorizeResource` over gRPC HTTP/2 with endpoint mTLS and the volatile device-bound user bearer token before opening the Gateway stream. On `allow`, Cloud creates the PA session, provisions the connected Gateway, and returns strict `session_id`, `session_token`, `resource_id`, protocol, port, Gateway metadata, and expiry. The relay includes those fields, the enrolled `device_id`, and optional process identity in the yamux `connect` frame and omits the legacy bearer token whenever strict session material is present. `POST /api/agent/authorize` remains a compatibility surface over the same PA logic. If Cloud returns `deny`/`mfa_required` or Gateway returns `session_invalid`, policy denial, or another structured error, the service records an access event for the tray and sends a TCP RST to the client flow. MFA retry orchestration is still deferred.

## Tray Wails Dashboard

The default `tray` mode now launches the final-agent Wails v2 + React dashboard from `internal/tray/frontend`. The legacy pipe proof remains available with `tray --proof` for diagnostics and tests. The GUI talks only to the LocalSystem service through `\\.\pipe\ztna-agent`; it does not add localhost component APIs and does not read privileged device state directly.

The service exposes GUI-specific IPC views for agent connection state, enrollment and certificate metadata, authenticated user identity, raw posture checks, catalog resources, active Gateway relay sessions, and local/Gateway access-denial messages. Current posture display includes firewall, antivirus, disk encryption, Windows updates, connectivity, OS, and password/lock checks. Active sessions are populated from the service-owned relay, and Gateway connect denials are recorded as access events. MFA/push UI is intentionally not migrated in this slice.

## Layout

```text
main.go                Root Wails-compatible entry point for Wails CLI builds
cmd/ztna-agent/        Primary single executable entry point
internal/app/          Command parsing and mode dispatch
internal/bootstrap/    First-run orchestration, UAC helper, service start, tray launch
internal/ipc/          Named Pipe transport, ACLs, frame codec, client/server, contracts
internal/deviceidentity/ Active user SID, NCrypt key create/load, TPM EK device ID foundation, Machine Store mTLS credential loading
internal/deviceposture/ Service-owned raw device posture collectors and gRPC Cloud reporter without local scoring
internal/catalog/     Service-owned gRPC/mTLS device catalog client and suffix normalization
internal/dnscontrol/  Service-owned DNS/NRPT configuration seam for catalog suffixes
internal/dnsresolver/ Service-owned synthetic DNS server, FQDN-to-CGNAT mapping, and reverse lookup baseline
internal/network/     Service-owned TUN adapter, CGNAT route lifecycle, and packet classification orchestration
internal/routing/     Windows route-table ownership for the synthetic CGNAT range
internal/tun/         Windows Wintun adapter wrapper plus non-Windows unsupported stubs
internal/tunnel/      Service-owned TLS 1.3/mTLS/yamux Gateway tunnel client and protocol DTOs
internal/tcpproxy/    TCP state machine for SYN/ACK/data/FIN/RST packets over TUN
internal/relay/       TUN packet to Gateway yamux stream bridge and active session snapshots
internal/appid/       Optional Windows process identity lookup for TCP flows
internal/jwtverify/    Local ES256/JWKS verifier for Cloud enrollment JWTs
internal/enrollment/   Cloud token client, CSR generation, EST simpleenroll, mTLS renewal, certificate install seam
internal/oidc/         Native public-client OIDC Authorization Code + PKCE flow
internal/process/      Process identity, user, SID, elevation helpers
internal/service/      LocalSystem service runtime, IPC handler, enrollment state persistence, and catalog cache persistence
internal/service/scm/  Windows SCM install/start/stop/status/uninstall integration
internal/tray/         User-context Wails dashboard and legacy IPC proof
```

## Commands

```powershell
go test ./...
go build -o ztna-agent.exe ./cmd/ztna-agent

.\ztna-agent.exe bootstrap --demo-message "hello from tray"
.\ztna-agent.exe bootstrap --login --cloud-url https://localhost:8443 --issuer-url https://localhost:8443 --cloud-issuer https://localhost:8443 --jwks-url https://localhost:8443/.well-known/jwks.json
.\ztna-agent.exe bootstrap --tun --cloud-url https://localhost:8443 --cloud-issuer https://localhost:8443 --jwks-url https://localhost:8443/.well-known/jwks.json
.\ztna-agent.exe bootstrap --tun --gateway-tunnel --gateway-address gateway.local:9443 --gateway-server-name gateway.local --process-identity --cloud-url https://localhost:8443 --cloud-issuer https://localhost:8443 --jwks-url https://localhost:8443/.well-known/jwks.json
.\ztna-agent.exe tray
.\ztna-agent.exe tray --proof
.\ztna-agent.exe status
.\ztna-agent.exe stop
.\ztna-agent.exe start
.\ztna-agent.exe uninstall
```

No-argument execution defaults to `bootstrap` on Windows.

Generated executables and build backup artifacts (`*.exe`, `*.exe~`) are local outputs and are ignored by this module.

`bootstrap` captures the current interactive user's SID, asks UAC to run the transient `install-service` helper, installs or updates the `ZTNAAgent` Windows service with the same executable in `service` mode, starts the service as LocalSystem, waits for the Named Pipe to answer, then launches the same executable in `tray` mode in the original user context.

## IPC Security

The pipe is:

```text
\\.\pipe\ztna-agent
```

The default security descriptor grants full access only to LocalSystem and Builtin Administrators. During bootstrap, the current interactive user SID is added with read/write access so the tray can connect without broad local TCP listeners or world-accessible IPC.

Current IPC operations are:

- `Ping`
- `GetStatus`
- `GetDevicePosture`
- `GetDashboard`
- `GetCatalogResources`
- `GetActiveSessions`
- `GetAccessEvents`
- `SubmitEnrollmentToken`
- `UpdateAccessToken`

`SubmitEnrollmentToken` carries the short-lived enrollment JWT only over the strict local pipe. The service requires a configured JWKS URL, validates the token signature and claims locally, checks nonce/device/SID/key-name binding, and applies rate limiting before any NCrypt or EST call. Without `--cloud-url`, a valid token moves the service to `PENDING` for development. With `--cloud-url`, the service performs NCrypt key create/load, CSR generation, EST `simpleenroll`, Windows Machine Store installation, writes non-secret enrollment metadata to the endpoint state folder, and moves to `ENROLLED` or `FAILED`. When the tray includes an access token, the service copies it into volatile session state only.

`UpdateAccessToken` lets the tray refresh the volatile access token after login/enrollment. The service accepts the update only when the SID and device ID match service state, the token is JWT-shaped, and the expiry is in the future. `GetStatus` reports session state and token expiry metadata, never the token value.

`GetStatus` also reports service-owned identity metadata used by the tray enrollment flow: active user SID, machine-scope TPM key name, whether that NCrypt key already exists, TPM-derived `device_id` when available, restored certificate SHA-256 and expiry when startup rediscovery succeeds, session/catalog/synthetic DNS/network/Gateway tunnel status metadata, and any non-fatal identity refresh error. A `--device-id` tray/bootstrap override remains useful only for development machines where TPM EK material is unavailable.

`GetDevicePosture` returns raw, structured posture data collected by the LocalSystem service. The service collects operating system, firewall, antivirus, disk encryption, Windows updates, connectivity, and password/screen-lock checks with bounded execution and exposes per-check status/details without calculating a local aggregate score. When the service is configured with `--cloud-url`, it creates gRPC posture and catalog clients that load the endpoint mTLS credential lazily from Windows Machine Store after enrollment. Once enrollment is `ENROLLED`, it sends raw reports to Cloud `ztna.device.v1.DeviceTelemetryService/ReportPosture`, polls every five minutes, sends immediately when firewall or antivirus transitions to `critical`, sends steady-state heartbeats through `DeviceTelemetryService/Heartbeat`, and syncs the versioned DNS/resource catalog through `ztna.catalog.v1.DeviceCatalogService/GetCatalog`. The service applies returned suffixes to NRPT and returned resource entries to the synthetic DNS resolver; the local DNS listener answers catalog-backed A queries with CGNAT addresses and refuses unknown resources. `GetStatus` exposes only counts/status for these views. `GetDashboard`, `GetCatalogResources`, `GetActiveSessions`, and `GetAccessEvents` expose display-oriented snapshots for the Wails tray while keeping privileged collection and policy state in the service. Cloud accepts final-agent raw posture and catalog sync through gRPC/mTLS services. The tray remains a read-only IPC client for this data.

## Expected Proof

The default tray opens the Wails dashboard and periodically refreshes service-owned dashboard data through the named pipe. With `--proof`, the tray prints its PID/user/SID and a JSON response from the service. The response includes the echoed message, protocol, pipe name, service PID, service Windows account, service state, and authorized SID. With `--login`, the tray opens the browser, completes public-client OIDC, requests an enrollment token from Cloud, submits the enrollment JWT, and updates the service's volatile access token through IPC. With `--stay`, the tray remains resident and refreshes the access token before expiry through the same IPC operation. Raw posture collection, gRPC/mTLS Cloud reporting, gRPC/mTLS catalog sync, catalog cache, NRPT suffix application, local DNS serving, catalog-backed synthetic DNS mapping, TUN packet classification, and Gateway mTLS/yamux relay state are service-owned, and Cloud stores raw posture separately from legacy scored health reports.