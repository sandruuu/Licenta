# Device-Agent Architecture

This document defines the production target architecture for the endpoint-side component of the ZTNA platform. The final installed endpoint component now lives in `../agent`; the existing `endpoint-agent/` folder remains the transitional source umbrella for `connect-app`, `device-health-app`, and shared endpoint identity code.

The transitional implementation is intentionally preserved during migration: `connect-app` still carries network access source material and `device-health-app` keeps legacy posture UI/reporting plus push/MFA compatibility. The target architecture replaces that split runtime model with a privileged Windows service plus a user-context tray application connected only through strict Named Pipes IPC. The current final milestone in `../agent` proves that split with one `ztna-agent.exe` running as service and tray process instances, and the tray now hosts the primary Wails/React dashboard.

## Target Process Model

Device-Agent is composed of two processes:

| Process | Account | Responsibility |
| --- | --- | --- |
| Device-Agent Service | LocalSystem | TPM key operations, certificate access, machine certificate store, TUN route ownership, DNS policy, catalog sync, health collection, posture reporting, gateway tunnel, and service lifecycle. |
| Device-Agent Tray | Interactive user | OIDC login, enrollment/user prompts, health/status display, notifications, and user-initiated commands sent to the service over IPC. |

The service is the only trust-sensitive endpoint runtime. The tray is a companion UI and must not hold private keys, install machine certificates, modify routes, collect privileged posture state directly, or expose privileged listeners.

## Current State Versus Target

| Area | Current implementation | Target architecture |
| --- | --- | --- |
| Process boundary | `agent/ztna-agent.exe` now proves LocalSystem service plus user tray for the first milestone; `connect-app` and `device-health-app` remain transitional production runtimes. | LocalSystem service plus user tray. |
| Component IPC | `agent` uses a strict Named Pipe for `Ping`; legacy runtimes still have localhost compatibility APIs. | Named Pipes only, with explicit ACLs. |
| Enrollment | `agent` validates tray-submitted enrollment JWTs locally, creates/loads the per-SID machine NCrypt key, signs a CSR, and calls Cloud EST when the service has `--cloud-url`; legacy browser enrollment remains in transitional runtimes. | Tray obtains short-lived enrollment token; service performs EST enrollment. |
| Certificate storage | `agent` can install the EST leaf into `LocalMachine\My` and CA bundle into `LocalMachine\CA`, persist non-secret enrollment metadata in the endpoint state folder, restore `ENROLLED` on startup only after the matching `CN=device_id` Machine Store leaf plus NCrypt signer are reloaded and fingerprint-checked, and renew the endpoint certificate through Cloud `/api/enroll/renew` using the current certificate as the mTLS client credential. | Windows Machine Store for production; endpoint folder stores metadata/state only. |
| Catalog transport | `agent` now owns the first final-agent catalog sync path: Cloud `ztna.catalog.v1.DeviceCatalogService/GetCatalog` over HTTP/2 gRPC with device mTLS, bearer metadata for user/role filtering, version/not-modified handling, private resource entries, DNS/NRPT suffix application, service-private catalog cache, token-required state, transient-error backoff, catalog-backed synthetic DNS mapping from FQDN to CGNAT IP, and a local UDP/TCP DNS listener for catalog-backed A responses. | gRPC over HTTP/2 with device mTLS and versioned local cache. |
| Health reporting | `agent` now has service-owned raw posture collection, `GetDevicePosture` IPC, a gRPC/mTLS reporter scheduler for five-minute polling plus critical-change triggers, Machine Store mTLS credential loading for posture reports and heartbeats, and a Wails/React tray dashboard that reads display data through named pipe IPC. Cloud stores final-agent raw posture from `ztna.device.v1.DeviceTelemetryService` only; the legacy Device Health App remains for scored-health HTTP reporting and push/MFA compatibility. | Service collects raw device posture and transmits it over gRPC/mTLS for Cloud-side visualization; tray renders read-only status through IPC. |
| Traffic interception | Synthetic DNS, TUN route ownership, IPv4/TCP packet classification, the first TCP state machine, Gateway mTLS/yamux tunnel manager, and TUN-to-yamux relay are now service-owned; legacy `connect-app` remains the reference for compatibility and MFA retry behavior. | TUN data plane with DNS/NRPT controls, CGNAT routing, and TLS/yamux gateway tunnel. |

The current final-agent milestone in `../agent` includes a standalone Go module and one executable with `bootstrap`, `service`, `tray`, `install-service`, `start`, `stop`, `status`, and `uninstall` modes. `bootstrap` captures the current interactive user SID, elevates only the transient service installation/start helper, installs or updates the `ZTNAAgent` Windows service, starts it as LocalSystem through SCM, waits for the strict Named Pipe to answer, and launches the tray process in the user context. The service and tray exchange framed JSON over `\\.\pipe\ztna-agent` for `Ping`, `GetStatus`, `GetDevicePosture`, `GetDashboard`, `GetCatalogResources`, `GetActiveSessions`, `GetAccessEvents`, `SubmitEnrollmentToken`, and `UpdateAccessToken`. The tray can perform native OIDC as `ztna-agent`; the service can validate the enrollment JWT locally and, when configured with Cloud URL/JWKS, perform the service-owned NCrypt/CSR/EST enrollment path over HTTPS/REST. After successful EST enrollment, the service writes only non-secret device/key/certificate metadata to the endpoint state folder and, on restart, restores `ENROLLED` only if the Machine Store certificate still matches that metadata. The service also checks endpoint certificate expiry hourly and renews within the 12-hour window by calling Cloud `/api/enroll/renew` over mTLS with the current device certificate. The service now collects raw posture checks locally without aggregate scoring, reports posture/heartbeats through gRPC/mTLS, and syncs the versioned resource catalog through Cloud `ztna.catalog.v1.DeviceCatalogService/GetCatalog` using the same Machine Store endpoint credential plus the current in-memory user access token. The catalog now includes DNS suffixes plus private resource entries; the service persists this service-private catalog cache, reapplies cached NRPT suffixes and synthetic DNS policy after startup restore, runs the local synthetic DNS listener when catalog sync is configured, and exposes display snapshots to the Wails tray for connection/enrollment/certificate/user/posture/resource/session/access-denial views. With `--gateway-tunnel` or `--gateway-address`, the service opens a TLS 1.3/mTLS/yamux Gateway tunnel, performs the protocol hello handshake, opens per-flow `connect` streams, forwards TUN TCP payloads through those streams, records Gateway denial events, and exposes active relay sessions in IPC snapshots. Cloud accepts steady-state posture reports and heartbeats through `ztna.device.v1.DeviceTelemetryService`, serves the catalog through `ztna.catalog.v1.DeviceCatalogService`, and exposes stored raw posture through dashboard posture APIs.

## Named Pipes IPC

All service-to-tray communication must use a versioned IPC contract over a Windows Named Pipe. Localhost TCP must not be introduced for internal Device-Agent IPC. The OAuth/OIDC loopback redirect can remain during migration as browser callback plumbing only; it is not a component IPC channel.

Default pipe name:

```text
\\.\pipe\ztna-agent
```

The service owns the pipe. The Windows security descriptor must allow LocalSystem and Builtin Administrators full access, and only the enrolled interactive user SID read/write access where user interaction is required. World/Everyone access is not allowed.

Current final-agent request operations:

- `Ping`
- `GetStatus`
- `GetDevicePosture`
- `GetDashboard`
- `GetCatalogResources`
- `GetActiveSessions`
- `GetAccessEvents`
- `SubmitEnrollmentToken`
- `UpdateAccessToken`

Future minimum request operations:

- `StreamEvents`
- `StartLogin`
- `RequestReconnect`
- `GetNetworkState`
- `GetDeviceIdentity`

Minimum event families:

- service state transitions
- authentication and enrollment state
- health/posture updates
- network tunnel state
- catalog version changes
- user notifications

The current `agent/internal/ipc` transport uses length-prefixed JSON frames over the named pipe for integration speed with the existing Go code. It provides request/response models, frame encoding, a client, a server loop, Windows pipe listener/dialer support, and the strict security descriptor builder. If binary compatibility, schema evolution, or cross-language clients become important, the same operations should be migrated to protobuf messages without changing the trust boundary.

## Privileged Service

The Device-Agent service runs as LocalSystem and is installed through Windows Service Control Manager. Its lifecycle requirements are:

- boot autostart
- recovery restart policy
- graceful shutdown on SCM stop/shutdown
- event log logging
- explicit state transitions: `starting`, `running`, `degraded`, `stopping`, `stopped`
- non-Windows compile stubs for development tests

The service owns:

- TPM 2.0 key generation/loading and software fallback declaration
- endpoint certificate lookup, renewal, and Machine Store installation
- network routes, TUN adapter lifecycle, CGNAT route ownership, and DNS policy
- gRPC/mTLS catalog synchronization and local policy cache
- health collectors and posture change detection
- posture report streaming and offline buffering
- TLS 1.3/mTLS/yamux gateway tunnel

The current `agent` service shell can run in console mode for development or under Windows SCM. Its CLI supports `run-service`, `install-service`, `uninstall`, `start`, `stop`, and `status`; Windows install creates or updates the service for delayed automatic startup under the default LocalSystem account, configures restart recovery actions, registers the Application Event Log source, and logs SCM lifecycle start/stop/failure events. At runtime it starts the strict Named Pipe IPC server and handles `Ping`, `GetStatus`, `GetDevicePosture`, `GetDashboard`, `GetCatalogResources`, `GetActiveSessions`, `GetAccessEvents`, `SubmitEnrollmentToken`, and `UpdateAccessToken`. `GetDevicePosture` runs service-owned raw checks for operating system, firewall, antivirus, disk encryption, Windows updates, connectivity, and password/screen-lock posture with bounded execution and no local aggregate score. With `--cloud-url`, the service configures a gRPC posture reporter that loads a valid Machine Store endpoint certificate whose public key matches `ZTNA_DeviceKey_{SID}`, sends an initial report after enrollment, polls every five minutes, immediately reports new firewall/antivirus `critical` transitions, and sends heartbeats to Cloud `ztna.device.v1.DeviceTelemetryService` over HTTP/2 + mTLS. `SubmitEnrollmentToken` requires service-owned Cloud JWKS configuration, validates the Cloud-signed enrollment JWT locally, checks nonce/device/SID/key-name binding, rate-limits submissions, then creates/loads `ZTNA_DeviceKey_{SID}` through NCrypt, signs an endpoint CSR, calls EST `simpleenroll` over HTTPS/REST, installs returned certificate material into Machine Store when `--cloud-url` is configured, and persists non-secret enrollment metadata for startup rediscovery. `UpdateAccessToken` accepts only authorized SID/device-bound, JWT-shaped, unexpired access tokens and keeps them in volatile service session state for catalog filtering and Gateway connect frames. The service owns endpoint certificate renewal as well: it reloads the current Machine Store credential, signs a replacement CSR with the same device key, calls Cloud `/api/enroll/renew` over device mTLS, installs the renewed certificate, and updates non-secret metadata. Catalog sync is now service-owned through gRPC/mTLS, applies DNS suffixes through the service DNS/NRPT configurator, persists a service-private catalog cache with DNS suffixes and resource entries, reapplies cached suffixes and synthetic DNS policy after startup restore, and tracks TTL/backoff/token-required status. The synthetic resolver allocates CGNAT addresses only for exact FQDNs present in the catalog, answers local UDP/TCP DNS A queries for those resources, refuses unknown catalog names with NXDOMAIN, and keeps reverse IP-to-resource mappings for the TUN data plane. With `--tun`, the service also owns Wintun adapter creation/reopen, adapter IP/DNS configuration, CGNAT route installation, TUN packet reads, IPv4/TCP parsing, reverse synthetic-IP classification, cleanup on shutdown, and metadata-only IPC status/counters. With `--gateway-tunnel` or `--gateway-address`, it owns the TLS 1.3/mTLS/yamux Gateway tunnel, reconnect loop, per-flow `connect` streams, TCP SYN/ACK/data/FIN/RST synthesis, optional Windows process identity lookup, active relay session snapshots, and access events for structured Gateway errors. MFA/step-up retry orchestration remains pending.

## User Tray

The tray runs in the interactive user session. It is a UI client of the service, not a privileged agent. It owns:

- launching browser OIDC login
- receiving enrollment/login results from the Cloud-facing browser flow
- sending short-lived enrollment tokens to the service over IPC
- sending refreshed user access tokens to the service over IPC
- showing service status, enrollment state, certificate metadata, authenticated user, posture state, catalog resources, active sessions, access denial messages, notifications, and later MFA/push prompts
- requesting reconnect or refresh actions through IPC

The tray must not read private key material, write machine certificate stores, alter routes, collect privileged device state directly, or communicate with the service over localhost HTTP.

The current `agent` tray launches a Wails v2 + React dashboard by default. It reads display snapshots from the service with `GetDashboard`, listens for periodic dashboard updates, and can still run the original pipe proof with `--proof` for diagnostics. With `--login`, it reads service enrollment status, opens browser OIDC as the native public client `ztna-agent`, calls Cloud `/api/enroll/token`, submits the short-lived enrollment JWT to the service with `SubmitEnrollmentToken`, and pushes the access token expiry to service volatile state through `UpdateAccessToken`. With `--stay`, it uses the OIDC refresh token in memory to refresh and resend access tokens before expiry. The tray never handles the TPM key or CSR. MFA prompts and push approval are not part of the current implementation slice.

## Enrollment Target Flow

1. User starts enrollment/login from the tray.
2. The tray opens the Cloud OIDC flow.
3. Cloud authenticates the user, then `/api/enroll/token` exchanges the device-bound OIDC token for a short-lived Enrollment Token JWT with `aud=ztna-enrollment`, `purpose=device_enrollment`, `device_id`, nonce, five-minute expiry, and one-time JTI replay protection.
4. The tray sends the token to the service with `SubmitEnrollmentToken` over the named pipe.
5. The service validates the JWT locally through trusted Cloud JWKS/public-key material and rejects invalid tokens before touching TPM/CNG APIs.
6. The service generates or loads the machine-scope, non-exportable TPM ECDSA P-256 key named `ZTNA_DeviceKey_{SID}`. Software fallback is allowed only when TPM is unavailable and must be visible in posture/risk.
7. The service builds a CSR with `CN=device_id`, a user email SAN, and an optional hostname SAN.
8. The service calls `/.well-known/est/ztna/simpleenroll` with the enrollment token.
9. Cloud validates the token audience/purpose, CSR common-name binding, optional email SAN binding to the token username, nonce/replay state, and user/device policy.
10. The service receives the device certificate and CA chain.
11. The service installs the certificate into Windows Machine Store and records metadata in the endpoint state folder.
12. Renewals use the existing device certificate over mTLS, not a user token.

Current implementation note: Cloud exposes `/api/enroll/token` for authenticated OIDC clients whose parent token is already bound to a `device_id`. It returns a dedicated enrollment token, nonce, expiry, and email hint when the username is an email address. EST simpleenroll rejects gateway-audience tokens, enforces the enrollment nonce when present, consumes each token JTI exactly once through the store, and rejects CSR email SANs that do not match the enrollment identity. The final `agent` service uses its own independent `internal/enrollment` implementation, not `endpoint-agent/shared`: when `--cloud-url` is present, a validated `SubmitEnrollmentToken` creates or opens the machine-scope NCrypt ECDSA P-256 key, signs a CSR with `CN=device_id`, optional hostname DNS SAN, optional user email SAN, sends the EST HTTPS/REST request with the tray-submitted token and nonce, records the returned leaf certificate SHA-256 and expiry, installs leaf/CA material into `LocalMachine\My` and `LocalMachine\CA` on Windows, and persists only non-secret enrollment metadata in the endpoint state folder. The service reloads that metadata on startup and restores `ENROLLED` only after the matching Machine Store certificate can be loaded and fingerprint-checked against the persisted SHA-256. Renewals use the existing device certificate over mTLS, not a user token, and update the same Machine Store/state path. Catalog credential usage now relies on the tray-owned OIDC session refreshing access tokens into volatile service state through `UpdateAccessToken`.

Final-agent hardening note: `agent/internal/service` now implements the `SubmitEnrollmentToken` trust gate and the first privileged enrollment execution path. The request requires JWT-shaped token input, nonce, device ID, user SID, key name, optional RFC822 email, expiry metadata, service-side Cloud JWKS validation, and per-user submission rate limiting. The service also resolves active SID, probes `ZTNA_DeviceKey_{SID}`, derives TPM EK public SHA-256 `device_id` when Windows exposes platform EK bytes, creates/loads the key through NCrypt with `NCRYPT_MACHINE_KEY_FLAG`, signs CSR material through a CNG-backed signer, and transitions IPC state to `ENROLLED` or `FAILED`.

## gRPC/mTLS Catalog And Posture

After enrollment, the service authenticates to Cloud using device mTLS and opens HTTP/2 gRPC channels.

Current implementation note: the service has a credential provider that reloads the active endpoint certificate and TPM/software signer before steady-state Cloud calls. On Windows it prefers a valid Machine Store certificate whose `CN=device_id` and public key match the active endpoint signer and includes the issuer CA from `LocalMachine\\CA` when present. Posture reports now use gRPC over HTTP/2 (`ztna.device.v1.DeviceTelemetryService/ReportPosture`) with the same device mTLS credentials, and the service sends heartbeats through `ztna.device.v1.DeviceTelemetryService/Heartbeat`. Catalog sync now uses Cloud `ztna.catalog.v1.DeviceCatalogService/GetCatalog` over HTTP/2 gRPC with device mTLS, carries the current volatile user access token as `authorization` metadata for Cloud-side user/role filtering, handles version/not-modified responses, applies returned DNS suffixes through service-owned DNS/NRPT configuration, persists `agent-catalog-cache.json`, and restores/reapplies cached suffixes on service restart after enrollment certificate validation. Cloud enforces enrollment/fingerprint checks through the same gRPC auth interceptor, rejects `overall_score` on raw posture payloads, stores the reports in `device_posture`, and does not expose a final-agent raw-posture HTTP fallback.

Catalog responsibilities:

- Cloud exposes a Device-Agent catalog service authenticated by device mTLS.
- The service receives allowed FQDNs, resource identifiers, protocol/port metadata, DNS suffixes, and policy metadata derived from IdP groups and PDP decisions.
- Catalog updates are versioned, cached locally inside the service-owned endpoint state path, and exposed through metadata-only IPC status.
- DNS/NRPT, synthetic DNS resolver views, TUN route ownership, packet classification counters, Gateway tunnel status, and active relay sessions are updated together; MFA/step-up retries and deeper session-refresh orchestration remain later integration points.

Posture responsibilities:

- Health collectors run inside the service.
- Reports and heartbeats are sent periodically to Cloud over gRPC/mTLS through `ztna.device.v1.DeviceTelemetryService`.
- Offline buffering is still pending.
- The tray reads health state and dashboard display data only through service IPC/events.

## DNS, DoH, TUN, And Gateway Tunnel

The migration keeps TUN/yamux as the selected data-plane baseline. The final `agent` service now has the catalog-backed synthetic DNS runtime plus the first service-owned TUN-to-Gateway relay path: it accepts only exact catalog FQDNs, serves local UDP/TCP DNS, allocates addresses from `100.64.0.0/10`, configures or reopens a Wintun adapter when `--tun` is enabled, routes the CGNAT range to that adapter, expires mappings with catalog TTLs, reads IPv4/TCP packets from TUN, classifies synthetic destinations through the reverse mapping metadata, and can bridge matched TCP flows to Gateway yamux streams when the Gateway tunnel is configured.

Target traffic path:

1. Catalog sync provides allowed FQDN/IP policy.
2. DNS policy resolves protected names and mitigates known browser/resolver DoH bypass paths where feasible.
3. The local route table sends traffic for the synthetic CGNAT range to the service-owned TUN adapter.
4. The service reads packets from TUN, parses IPv4/TCP headers, maps the synthetic destination back to the catalog resource, and dispatches matched packets to the forwarding layer.
5. The Gateway tunnel manager establishes TLS 1.3 with device mTLS, wraps the connection in yamux, performs the `hello` handshake, and opens one `connect` stream per intercepted TCP SYN.
6. The relay sends the volatile user access token, device ID, target synthetic IP/port, and optional process identity to Gateway; Gateway remains responsible for Cloud PDP authorization and internal-resource relay.
7. The service synthesizes TCP SYN-ACK/data/FIN/RST packets back into the TUN adapter and records structured Gateway denials for the tray. MFA challenges are surfaced as structured denial events until Tray step-up is implemented.
8. Process attribution from the existing App-ID code remains contextual policy input, not cryptographic process attestation.

## Migration Slices

1. Document the target and keep current binaries working. Complete.
2. Add final `agent/` module with service/tray/bootstrap boundaries. Complete for the first single-exe milestone.
3. Introduce the service shell, tray shell, bootstrap, and framed JSON Named Pipes transport. Complete for `Ping` proof messaging.
4. Move endpoint identity loading into the service shell. In progress in `agent`; key/device-id/enrollment, Machine Store mTLS posture/catalog credentials, enrollment metadata startup restore, and endpoint certificate renewal are service-owned.
5. Replace localhost component watchdog/local API with Named Pipes IPC. In progress; legacy runtimes still expose transitional localhost APIs.
6. Move health collectors into service-owned packages. In progress in `agent`; raw posture collection, IPC exposure, gRPC/mTLS reporter scheduling, Machine Store mTLS credential loading, heartbeat, and Cloud raw-posture storage/dashboard APIs are implemented. Offline buffering remains pending.
7. Add token-driven EST enrollment and Machine Store installation. Complete for the first `SubmitEnrollmentToken` path in `agent`; non-secret metadata persistence, startup certificate rediscovery, and mTLS certificate renewal are implemented.
8. Add gRPC catalog and posture streams. Posture report, heartbeat, catalog gRPC transport, private resource entries, persistent catalog cache, catalog retry backoff, access-token refresh IPC, and catalog-backed synthetic DNS mapping are implemented in `agent`; offline buffering and streaming hardening remain pending.
9. Harden Windows service lifecycle. Complete for first milestone CLI command dispatch, SCM install/update/uninstall/start/stop/status, delayed automatic startup, restart recovery policy, Event Log source registration, SCM lifecycle event logging, and non-Windows command stubs.
10. Move traffic interception into the final service-owned TUN data plane. In progress: synthetic DNS mapping, local DNS serving, reverse CGNAT lookup, TUN adapter lifecycle, CGNAT route ownership, TUN packet reads, IPv4/TCP parsing, packet classification, Gateway mTLS/yamux tunnel management, TCP stream forwarding, and optional process identity exist in `agent`; MFA step-up retry orchestration and advanced session-refresh behavior remain pending.
11. Move Wails tray status UI into final `agent/`. In progress: the Wails/React dashboard is hosted by `agent tray`, reads service-owned dashboard/resources/sessions/access-event snapshots over Named Pipes IPC, excludes MFA/push, and now receives active relay sessions plus structured Gateway denial events from the service-owned bridge.
12. Merge split configs into a Device-Agent config and migrate existing endpoint identity state.
13. Deprecate and remove legacy coupling once the service/tray path is complete.

## Verification Requirements

- Documentation clearly distinguishes current runtime behavior from the production target.
- `go test ./...` passes in `agent` after each final-agent slice. Transitional modules should still be tested when touched.
- Wails frontend builds when tray UI code is touched.
- IPC tests validate message versioning, frame transport, event streaming, Windows pipe ACL construction, and a real Windows Named Pipe round trip using a test pipe scoped to the current user SID.
- Windows integration tests prove unauthorized users cannot access the pipe.
- Service validation proves SCM install/start/stop/recovery behavior under LocalSystem; current unit coverage validates CLI command parsing and build compatibility, while privileged SCM integration remains a Windows installation test.
- Enrollment tests cover dedicated enrollment token audience/purpose, one-time JTI consumption, shared EST simpleenroll request shape, nonce forwarding, service token handoff success/failure, CSR SANs, email SAN identity binding, TPM-backed signing, cache reuse, certificate thumbprints, service propagation of Machine Store metadata, startup certificate metadata enrichment without writing LocalMachine stores, service-owned renewal cache/install behavior, and mTLS renewal client/server enforcement; later tests must cover token expiry/replay prevention end-to-end and privileged Machine Store integration.
- Catalog tests cover mTLS credential enforcement, Cloud device catalog identity/fingerprint checks, direct gRPC sync semantics (including not-modified responses), resource-entry parsing, versioned cache updates, private metadata-only IPC exposure, PDP group behavior, and reconnect/backoff.
- Health/posture tests cover raw collector timeout behavior, IPC posture delivery without local aggregate scoring, critical-change triggers, service-owned gRPC/mTLS posture delivery, heartbeat behavior, and Cloud raw-data storage/visualization; later posture-stream tests must cover offline buffering.
- Traffic tests cover DNS policy, DoH mitigation, TUN route ownership, process attribution, allow/deny behavior, and gateway forwarding.
- Migration tests prove existing `%PROGRAMDATA%\ztna\endpoint` state remains usable where possible.