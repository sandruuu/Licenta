# ZTNA Agent

`agent/` contains the final endpoint-side executable. It is independent from `endpoint-agent/` and does not import `endpoint-agent/internal` packages.

## Platform Support

The agent is Windows-only. It is built around Windows SCM, LocalSystem, Named Pipes, NCrypt/TPM keys, Windows Machine Store certificates, Wintun, NRPT, and Windows device posture signals.

## Milestone 1

The first milestone proves the Windows process boundary and IPC transport:

- one runtime executable: `ztna-agent.exe`
- one LocalSystem service process launched by Windows SCM
- one user-context tray process launched from the interactive session
- strict Windows Named Pipe IPC with an authorized user SID in the pipe ACL
- a simple `Ping` message from tray to service and a `PingResponse` from service to tray

The initial proof milestone intentionally excluded Wails UI, catalog sync, tunnel ownership, renewal, and privileged traffic routing. Later slices have added the enrollment trust gate, service-owned posture collection, Cloud posture reporting, startup enrollment restore, endpoint certificate renewal, gRPC/mTLS device catalog synchronization, persistent catalog cache, catalog backoff, tray-to-service access-token refresh, the service-owned synthetic DNS catalog resolver with a local UDP/TCP DNS listener, the service-owned TUN adapter plus CGNAT route baseline, a Gateway mTLS/yamux tunnel manager, the first TUN-to-yamux TCP bridge, optional per-flow process identity, and the Wails/React tray dashboard while preserving the same service/tray boundary.

## Enrollment Trust Gate

The agent now has the first enrollment handoff slice:

- Cloud registers a dedicated native OIDC public client: `ztna-agent`
- tray can run browser OIDC login with Authorization Code + PKCE S256 and a loopback callback
- tray sends the OIDC access token to the service through the local `StartEnrollment` IPC operation
- service validates that access token through PA gRPC before accepting the handoff
- service applies per verified local SID submission rate limiting and never logs raw tokens
- when the service is installed with a configured PA URL, it creates or loads the machine-scope NCrypt ECDSA P-256 device key `ZTNA_DeviceKey`, builds a CSR with `CN=device_id`, calls PA enrollment over gRPC, and installs the returned certificate material into Windows Machine Store

The service-side TPM and gRPC enrollment work is gated behind the verified local SID and PA validation step. The service resolves the active Windows user SID, probes the machine-scope NCrypt key through the Microsoft Platform Crypto Provider, derives `device_id` from SHA-256 of TPM EK public bytes when the platform exposes `PCP_EKPUB`, creates the persisted machine key if absent, signs the CSR through NCrypt, and records the enrolled certificate SHA-256 and expiry in IPC status. After enrollment, steady-state posture reports, heartbeats, catalog synchronization, authorization, enrollment renewal, and the service-owned Gateway tunnel use PA gRPC and the matching `CN=device_id` certificate from `LocalMachine\My`, paired with the existing machine-scope NCrypt signer and issuer material from `LocalMachine\CA` when present. MFA/step-up remains intentionally outside the current implementation slice; `mfa_required` is surfaced as a structured Gateway challenge/denial event until the Tray step-up flow is implemented.

After successful gRPC enrollment, the service persists only non-secret enrollment metadata to `agent-enrollment-state.json` in the endpoint state folder. State directory resolution is `ZTNA_AGENT_STATE_DIR`, then `ZTNA_ENDPOINT_DIR`, then the legacy `ZTNA_TPM_DIR` alias, then the machine-wide endpoint default (`%PROGRAMDATA%\ztna\endpoint`, falling back to `C:\ProgramData\ztna\endpoint`). The state file stores device ID, user SID, key name/provider, certificate SHA-256, certificate expiry, and timestamps; it does not store OIDC access tokens, refresh tokens, or private key material. On service startup, the agent reloads this metadata and marks the endpoint `ENROLLED` only if the matching Machine Store certificate can be loaded and its SHA-256 fingerprint matches the persisted value. The service also persists the service-private catalog cache to `agent-catalog-cache.json` when Cloud catalog sync is configured; that cache stores device ID, catalog version, policy epoch, DNS suffixes, catalog resource entries, TTL, and timestamps, but no tokens or private key material.

## Certificate Renewal

Endpoint certificate renewal is owned by the LocalSystem service. When the enrolled Machine Store certificate expires within the renewal window, the service reloads the certificate and machine-scope NCrypt signer, creates a new CSR with the same `CN=device_id`, and calls PA gRPC renewal using the current endpoint certificate as the mTLS client credential. PA validates the mTLS identity and CSR public key fingerprint before issuing the replacement certificate.

The configured renewal scheduler checks on `certificate_renewal_interval` and renews certificates that expire within `certificate_renew_before`. Successful renewals install the replacement leaf and CA material through the same certificate installer path, update IPC status with the new SHA-256 and expiry, and refresh the non-secret state file. Renewal never uses a user OIDC token and never persists private key material.

## Device Catalog Synchronization

The service now owns the final-agent catalog transport. When enrollment is `ENROLLED`, a PA URL is configured, and the service has the current user access token in memory, it loads the endpoint Machine Store certificate and calls Cloud `ztna.catalog.v1.DeviceCatalogService/GetCatalog` over HTTP/2 gRPC with device mTLS. The access token is sent as gRPC `authorization` metadata so Cloud can keep user and role filtering while the device identity is authenticated by the certificate. The tray updates this in-memory token through `UpdateAccessToken`; the service validates authorized SID, device ID, JWT shape, and expiry, and never persists the token.

Catalog responses carry a version, DNS suffix list, private resource entries (`fqdn`, `resource_id`, `protocol`, `port`), TTL, not-modified flag, and policy epoch. The agent normalizes and de-duplicates suffixes/resources, handles not-modified responses without replacing the local view, and applies returned suffixes through the service-owned DNS configurator/NRPT path. Successful live syncs persist the service-private cache, and startup restore reapplies cached NRPT suffixes plus the synthetic DNS policy after enrollment state is restored and the device ID matches the Machine Store certificate. The scheduler tracks TTL, next sync time, transient-error backoff, token-required state, stale cache state, and last error. Catalog data remains service-private; IPC exposes status metadata and counts rather than FQDNs or resource identifiers.

The synthetic DNS baseline lives in `internal/dnsresolver`. It maintains an exact FQDN catalog, allocates stable synthetic addresses from RFC 6598 CGNAT space (`100.64.0.0/10`) only for catalog resources, rejects suffix-only or unknown domains, tracks TTL/expiry, and keeps a reverse mapping from synthetic IP to resource context for the TUN data plane. It also exposes a service-owned UDP/TCP DNS listener on the configured DNS server address (default `127.0.0.1:53` when Cloud/catalog sync is configured): A queries for catalog resources return synthetic CGNAT records, unknown catalog names return NXDOMAIN, and AAAA queries return an empty successful response. Cloud `GetCatalog` returns the private resource entries needed for this check.

## Service-Owned TUN And Gateway Tunnel

The service now has an explicit opt-in TUN baseline for the data plane. When `tun` is enabled in config, the LocalSystem service creates or reopens the Wintun adapter, configures the adapter IP/DNS settings, adds the CGNAT route (`100.64.0.0/10` by default), starts reading packets from the adapter, and removes the route plus closes the adapter when the service context is cancelled. The defaults can be overridden with `tun_name`, `tun_ip`, `tun_netmask`, and `tun_route_cidr`.

The packet loop parses IPv4/TCP packets, checks the destination synthetic IP against the service-private DNS resolver reverse map, verifies the catalog port when present, and dispatches matched packets to the Gateway relay when `tun` is enabled and a PA URL is configured. Without a relay forwarder, matched packets are still counted and dropped locally so the TUN baseline remains observable during staged rollout. `GetStatus` exposes metadata and counters such as network state, TUN adapter name, TUN IP, route CIDR, packets read, TCP packets, matched/unmatched/dropped packets, whether a forwarder is configured, last packet time, and last packet error without exposing catalog resource identifiers.

The Gateway tunnel manager dials the Gateway returned by PA authorization with TLS 1.3, device mTLS, and yamux, sends the protocol `hello` frame, reconnects with bounded exponential backoff, and opens one yamux stream per TCP flow. When `tun` and PA are configured, the TUN relay asks Cloud `ztna.agent.v1.AgentAuthorizationService/AuthorizeResource` over gRPC HTTP/2 with endpoint mTLS and the volatile device-bound user bearer token before opening the Gateway stream. On `allow`, Cloud creates the PA session, provisions the connected Gateway, and returns strict `session_id`, `session_token`, `resource_id`, protocol, port, Gateway metadata, and expiry. The relay includes those fields, the enrolled `device_id`, and optional process identity in the yamux `connect` frame and omits the legacy bearer token whenever strict session material is present. If Cloud returns `deny`/`mfa_required` or Gateway returns `session_invalid`, policy denial, or another structured error, the service records an access event for the tray and sends a TCP RST to the client flow. MFA retry orchestration is still deferred.

## Tray Wails Dashboard

Interactive execution launches the final-agent Wails v2 + React dashboard from `internal/tray/frontend`. The GUI talks only to the LocalSystem service through `\\.\pipe\ztna-agent`; it does not add localhost component APIs and does not read privileged device state directly.

Service installation is owned by the separate `ztna-agent-installer.exe` entry point. The installer requests Windows administrator approval through UAC, installs or updates the LocalSystem service, starts it, waits for IPC readiness, and exits. The installed Windows service points at `ztna-agent.exe` without command-line arguments and reads the same `config.json` as the tray.

The GUI does not install the service. If the service is unavailable, it shows the disconnected state until the installer or enterprise deployment tooling installs and starts the service.

Enterprise packaging lives under `packaging/windows`. The package installs binaries and `config.json` into `%ProgramFiles%\ZTNA Agent`, installs the LocalSystem service, and adds an HKLM Run entry so the tray starts for users at logon. The service pipe allows interactive users to connect, while enrollment and access-token IPC operations verify the actual named-pipe peer SID before accepting user-bound state.

The service exposes GUI-specific IPC views for agent connection state, enrollment and certificate metadata, authenticated user identity, raw posture checks, catalog resources, active Gateway relay sessions, and local/Gateway access-denial messages. Current posture display includes firewall, antivirus, disk encryption, Windows updates, connectivity, OS, and password/lock checks. Active sessions are populated from the service-owned relay, and Gateway connect denials are recorded as access events. MFA/push UI is intentionally not migrated in this slice.

## Layout

```text
cmd/agent/             Primary runtime executable entry point
cmd/agent-installer/   Installer executable entry point for service setup
internal/app/          Runtime config loading and automatic service/GUI dispatch
internal/bootstrap/    First-run orchestration, UAC helper, service install/start
internal/ipc/          Named Pipe transport, ACLs, frame codec, client/server, contracts
internal/deviceidentity/ Active user SID, NCrypt key create/load, TPM EK device ID foundation, Machine Store mTLS credential loading
internal/deviceposture/ Service-owned raw device posture collectors without local scoring
internal/catalog/     Service-owned catalog DTOs and suffix/resource normalization
internal/dnscontrol/  Service-owned DNS/NRPT configuration seam for catalog suffixes
internal/dnsresolver/ Service-owned synthetic DNS server, FQDN-to-CGNAT mapping, and reverse lookup baseline
internal/network/     Service-owned TUN adapter, CGNAT route lifecycle, and packet classification orchestration
internal/routing/     Windows route-table ownership for the synthetic CGNAT range
internal/tun/         Windows Wintun adapter wrapper
internal/tunnel/      Service-owned TLS 1.3/mTLS/yamux Gateway tunnel client and protocol DTOs
internal/tcpproxy/    TCP state machine for SYN/ACK/data/FIN/RST packets over TUN
internal/relay/       TUN packet to Gateway yamux stream bridge and active session snapshots
internal/appid/       Optional Windows process identity lookup for TCP flows
internal/pa/          Single PA gRPC client for validation, enrollment, posture, catalog, and authorization
internal/enrollment/  CSR generation, gRPC enrollment runner, mTLS renewal, certificate install seam
internal/oidc/         Native public-client OIDC Authorization Code + PKCE flow
internal/process/      Process identity, user, SID, elevation helpers
internal/service/      LocalSystem service runtime, IPC handler, enrollment state persistence, and catalog cache persistence
internal/service/scm/  Windows SCM install/start/stop/status/uninstall integration
internal/tray/         User-context Wails dashboard and enrollment flow
packaging/windows/     Enterprise install, uninstall, and package build scripts
```

There is intentionally no root `main.go`; enterprise binaries are built only from
the explicit `cmd/` entry points.

## Run

The runtime agent runs without user-supplied arguments:

```powershell
.\ztna-agent.exe
```

When Windows SCM starts the same executable, it automatically enters service mode. When a user starts it interactively, it opens the Wails tray GUI. If the LocalSystem service is missing, the GUI stays in a disconnected state until the installer or enterprise deployment tooling installs and starts it.

The agent reads PA defaults from `config.json` next to `ztna-agent.exe`. A minimal local lab config is:

```json
{
  "pa_url": "https://localhost:8443",
  "dns_server": "127.0.0.1",
  "posture_interval": "5m",
  "critical_interval": "1m",
  "heartbeat_interval": "1m",
  "posture_report_timeout": "30s",
  "catalog_interval": "5m",
  "catalog_cache_ttl": "5m",
  "catalog_retry_backoff": ["5m", "10m", "15m", "30m"],
  "access_token_expiry_skew": "30s",
  "certificate_renewal_interval": "1h",
  "certificate_renew_before": "12h",
  "certificate_renewal_timeout": "30s",
  "pa_request_timeout": "10s",
  "enrollment_rate_limit_max": 3,
  "enrollment_rate_limit_window": "1m",
  "tray_timeout": "10s",
  "tray_enrollment_timeout": "10m",
  "token_refresh_interval": "1m",
  "token_refresh_margin": "5m",
  "dashboard_refresh_interval": "30s",
  "install_timeout": "30s",
  "service_recovery_restart_delays": ["10s", "30s", "1m"],
  "tun": false
}
```

`pa_url` is the PA gRPC endpoint used by the service and the default OIDC issuer URL used by the tray. Set `issuer_url` only when the interactive OIDC issuer differs from PA.

```powershell
.\packaging\windows\build-enterprise-package.ps1
.\build\install.ps1
```

Generated executables and build backup artifacts (`*.exe`, `*.exe~`) are local outputs and are ignored by this module.

The installer must be placed next to `ztna-agent.exe`. It asks UAC when run manually, installs or updates the `ZTNAAgent` Windows service with `ztna-agent.exe` and no service command-line arguments, starts the service as LocalSystem, waits for the Named Pipe to answer, then exits. In managed deployments, Intune/SCCM/GPO can run `install.ps1` elevated or as `SYSTEM`; the service is not bound to the installer process SID. After that, interactive startup of `ztna-agent.exe` opens the Wails tray GUI and can begin enrollment when the device is not enrolled.

## IPC Security

The pipe is:

```text
\\.\pipe\ztna-agent
```

The default security descriptor grants full access to LocalSystem and Builtin Administrators, and read/write access to interactive Windows users so the tray can connect without broad local TCP listeners or world-accessible IPC. A deployment can still set `authorized_user_sid` to restrict the pipe to one SID when needed.

On Windows, the service also resolves the connected named-pipe client's user SID from the pipe peer process and uses that verified local SID for enrollment start and access-token refresh. Any `user_sid` field carried by local IPC requests is compatibility metadata and must match the verified pipe peer when peer verification is available.

Current IPC operations are:

- `Ping`
- `GetStatus`
- `GetDevicePosture`
- `GetDashboard`
- `GetCatalogResources`
- `GetActiveSessions`
- `GetAccessEvents`
- `StartEnrollment`
- `UpdateAccessToken`

`StartEnrollment` carries the OIDC access token only over the strict local pipe. The service validates the verified local pipe SID, checks nonce/device/key-name binding, applies rate limiting, and asks PA gRPC to validate the access token before any NCrypt or enrollment work. With a configured PA URL, the service performs NCrypt key create/load, CSR generation, PA gRPC enrollment, Windows Machine Store installation, writes non-secret enrollment metadata to the endpoint state folder, and moves to `ENROLLED` or `FAILED`. The service stores the access token only in volatile session state.

`UpdateAccessToken` lets the tray refresh the volatile access token after login/enrollment. The service accepts the update only when the verified local pipe SID and device ID match service state, the token is JWT-shaped, and the expiry is in the future. `GetStatus` reports session state and token expiry metadata, never the token value.

`GetStatus` also reports service-owned identity metadata used by the tray enrollment flow: active user SID, machine-scope TPM key name, whether that NCrypt key already exists, TPM-derived `device_id` when available, restored certificate SHA-256 and expiry when startup rediscovery succeeds, session/catalog/synthetic DNS/network/Gateway tunnel status metadata, and any non-fatal identity refresh error. A config-provided `device_id` override remains useful only for development machines where TPM EK material is unavailable.

`GetDevicePosture` returns raw, structured posture data collected by the LocalSystem service. The service collects operating system, firewall, antivirus, disk encryption, Windows updates, connectivity, and password/screen-lock checks with bounded execution and exposes per-check status/details without calculating a local aggregate score. When the service has a configured PA URL, it creates gRPC posture and catalog clients that load the endpoint mTLS credential lazily from Windows Machine Store after enrollment. Once enrollment is `ENROLLED`, it sends raw reports to Cloud `ztna.device.v1.DeviceTelemetryService/ReportPosture`, polls every five minutes, sends immediately when firewall or antivirus transitions to `critical`, sends steady-state heartbeats through `DeviceTelemetryService/Heartbeat`, and syncs the versioned DNS/resource catalog through `ztna.catalog.v1.DeviceCatalogService/GetCatalog`. The service applies returned suffixes to NRPT and returned resource entries to the synthetic DNS resolver; the local DNS listener answers catalog-backed A queries with CGNAT addresses and refuses unknown resources. `GetStatus` exposes only counts/status for these views. `GetDashboard`, `GetCatalogResources`, `GetActiveSessions`, and `GetAccessEvents` expose display-oriented snapshots for the Wails tray while keeping privileged collection and policy state in the service. Cloud accepts final-agent raw posture and catalog sync through gRPC/mTLS services. The tray remains a read-only IPC client for this data.

## Expected Proof

The default interactive process opens the Wails dashboard and periodically refreshes service-owned dashboard data through the named pipe. During enrollment, the tray opens the browser, completes public-client OIDC, and sends the access token to the service through `StartEnrollment`. The service validates that token with PA over gRPC, creates the machine key and CSR, enrolls the endpoint certificate over gRPC, and keeps the access token only in memory. The tray remains resident and refreshes the access token before expiry through `UpdateAccessToken`. Raw posture collection, PA gRPC/mTLS reporting, gRPC/mTLS catalog sync, catalog cache, NRPT suffix application, local DNS serving, catalog-backed synthetic DNS mapping, TUN packet classification, and Gateway mTLS/yamux relay state are service-owned.
