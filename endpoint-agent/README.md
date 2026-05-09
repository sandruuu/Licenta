# Device-Agent

This folder keeps the transitional endpoint-side runtimes and shared endpoint identity code for the ZTNA platform. The final installed endpoint component now lives in [`../agent`](../agent).

The production target is documented in [DEVICE_AGENT_ARCHITECTURE.md](DEVICE_AGENT_ARCHITECTURE.md): a privileged Windows LocalSystem service plus a user-context tray/UI app, connected only through strict Named Pipes IPC. The first final single-exe milestone is implemented in [`../agent`](../agent); this folder remains the migration baseline for the legacy network, posture, and shared identity code.

## Current Implementation

The codebase still contains the transitional two-runtime implementation:

- `connect-app/` remains the transitional network access runtime and compatibility reference: TUN adapter, DNS interception, OIDC public-client flow, TLS/yamux tunnel, and per-flow process context.
- `device-health-app/` is the transitional posture runtime: Windows health collectors, legacy Wails UI, local posture API, legacy Cloud reporting, and push/MFA support.
- `shared/endpointidentity/` is the current shared identity layer used by both runtimes: TPM/software endpoint key, CSR generation, browser/EST enrollment, cached `device.crt` / `ca.crt`, and auto-renewal.

The final single-exe milestone has moved out of this folder into [`../agent`](../agent). That module builds one `ztna-agent.exe` with `bootstrap`, `service`, `tray`, `install-service`, `start`, `stop`, `status`, and `uninstall` modes. Bootstrap captures the current interactive user SID, elevates only the transient service installation/start helper, starts a LocalSystem Windows service through SCM, then launches the tray in the user context. The service and tray communicate through `\\.\pipe\ztna-agent` with a strict ACL and versioned JSON IPC. The old `device-agent-service/` and `device-agent-tray/` source modules were removed after this migration. The legacy `connect-app` and `device-health-app` runtimes still carry compatibility behavior, advanced network-access reference code, legacy Wails posture UI, and push/MFA behavior while the final agent takes over enrollment, raw posture collection, gRPC/mTLS steady-state posture/heartbeat transport, gRPC catalog sync, catalog-backed synthetic DNS mapping, local DNS serving for catalog resources, service-owned TUN adapter plus CGNAT route lifecycle, IPv4/TCP packet classification, the first Gateway mTLS/yamux TCP relay bridge, optional per-flow process identity, Gateway denial events, active relay session snapshots, and the primary Wails/React tray dashboard.

## Target Layout

New final Device-Agent work should happen in [`../agent`](../agent). This folder now preserves transitional runtime code that still needs to be migrated:

- `connect-app/` remains the transitional network access runtime.
- `device-health-app/` remains the transitional posture/Wails UI compatibility runtime; the primary final-agent tray dashboard now lives under [`../agent/internal/tray/frontend`](../agent/internal/tray/frontend).
- `shared/endpointidentity/` remains the shared TPM/software endpoint identity implementation used by transitional runtimes.
- `internal/ipc/`, `internal/health/`, and `internal/catalog/` are retained only as migration source material for later phases; the first final `agent/` milestone has its own local IPC implementation and does not import these packages.
- `connect-app/` and `device-health-app/` remain implementation references and compatibility runtimes until their responsibilities are extracted into service-owned packages.

## Endpoint State

During the transition, both current endpoint runtimes still share the same unified endpoint folder:

1. `ZTNA_ENDPOINT_DIR`, when set.
2. `ZTNA_TPM_DIR`, as a legacy alias when `ZTNA_ENDPOINT_DIR` is not set.
3. `%PROGRAMDATA%\ztna\endpoint` on Windows, or `/var/lib/ztna/endpoint` elsewhere.
4. The component `data_dir` fallback.

That folder currently contains shared endpoint identity and enrollment artifacts: `client.key`, `tpm-key.json`, `device.crt`, `ca.crt`, `enroll-state.json`, and `enroll.lock`.

The production target moves device certificates into Windows Machine Store and keeps only required metadata/state in the endpoint folder. Service-owned EST enrollment now writes the leaf certificate to `LocalMachine\\My` and the CA bundle to `LocalMachine\\CA` on Windows when permissions allow. EST remains HTTPS/REST; after enrollment, the final `agent` service loads a valid `CN=device_id` certificate whose public key matches the active Machine Store NCrypt signer and includes the matching issuer CA from `LocalMachine\\CA` for gRPC/mTLS posture reports and heartbeats. Transitional shared helpers still use the endpoint file cache for current `connect-app` / `device-health-app` compatibility, non-Windows development, and migration. Existing `%PROGRAMDATA%\ztna\endpoint` state should be migrated without re-enrollment where possible.

## Source Hygiene

Local runtime state does not belong in the source tree. The endpoint umbrella ignores generated binaries, runtime logs, and local certificate/key caches such as `connect-app/data/`, `device-health-app/data/`, and `device-health-app/certs/`. The final `agent/` module also ignores generated `.exe` files and local runtime data. Those artifacts should live in the unified endpoint state directory or be regenerated by builds/runs.

## Process Ownership Rules

- The service owns all privileged and trust-sensitive operations: TPM, machine certificate store, network interception, catalog policy, health collection, cloud reporting, and gateway tunnel control.
- The tray owns user interaction only: OIDC login, enrollment token handoff, status display, notifications, and commands over IPC.
- Internal component IPC must use Named Pipes with ACLs. Do not add new localhost TCP APIs for Device-Agent service/tray communication.
- Enrollment token handoff over IPC is migrating into `agent/`: final-agent `SubmitEnrollmentToken` now requires JWT-shaped token input, nonce, device ID, user SID, key name, strict user email format when present, service-owned JWKS validation, and per-user rate limiting before TPM/EST work is allowed.
- The current TUN/yamux path is the selected migration baseline; final `agent` now owns the service-private FQDN-to-CGNAT mapping core, local DNS listener, Wintun adapter lifecycle, CGNAT route ownership, IPv4/TCP packet classification, the first TCP state machine to Gateway yamux stream bridge, and optional Windows process identity on connect frames. Legacy `connect-app` remains the reference for MFA retry/step-up refinements and compatibility behavior.
- Final `agent` tray UI work belongs in `agent/internal/tray` and must continue to use the named pipe IPC contract; do not reintroduce `device-health-app` localhost APIs into the final service/tray path.