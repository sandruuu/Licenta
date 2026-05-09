# ZTNA Copilot Instructions

## Project Overview

This project is a thesis-grade Zero Trust Network Access platform with a PDP control plane, a final installed endpoint Agent, a strict Gateway PEP, and transitional endpoint runtimes kept only while responsibilities are migrated.

- User-facing conversation is Romanian.
- Code, comments, documentation, and commit messages must be English.
- Prefer implementation when intent is clear.
- After every codebase change, update the relevant documentation and this file.
- Validate affected Go modules with `go test ./...` and `go vet ./...`.

## Modules

```text
pdp/                   PDP runtime: physical PA/PE folders plus external IdP, MFA, PKI, store, events
agent/                 final installed endpoint Agent: service/tray, IPC, enrollment, posture, catalog, TUN, Gateway tunnel
gateway/               strict single-process Gateway PEP
endpoint-agent/        transitional connect-app and device-health-app migration source
infrastructure/        lab DNS and sample protected resources
```

## Gateway Rules

Gateway must remain a data-plane Policy Enforcement Point only.

Allowed Gateway responsibilities:

- one-time token enrollment, local ECDSA P-256 key generation, CSR submission, mTLS cert/CA install
- TLS 1.3 plus mTLS Agent listener
- yamux multiplexing
- `hello` and strict `connect` data-plane messages
- local validation of PA-provisioned sessions
- outbound PA/Gateway `ztna.gateway.v1.GatewayControlService/ControlStream` over HTTP/2 gRPC with mTLS
- `provision_session`, `revoke_session`, and `heartbeat` command handling
- direct TCP relay to the PA-provisioned internal host/port
- active relay termination on expiry, revocation, or shutdown
- Gateway mTLS renewal and revoked certificate serial sync
- minimal health endpoint and Docker service

Forbidden Gateway responsibilities:

- local user authentication or OIDC browser callback
- MFA orchestration
- policy evaluation or risk/anomaly scoring
- Cloud PDP calls from the relay path
- user JWT/JWKS validation for relay admission
- local resource catalog database
- Gateway DNS resolver or synthetic address allocation
- Admin UI, SessionStore, Syslog, SQLite resource store, or local management plane
- `auth_request`, bearer-token-only relay admission, `dns_resolve`, or raw tunnel data compatibility flows

Current Gateway structure:

```text
gateway/
  cmd/gateway/              single runtime entry point
  internal/auth/            PDP/PKI client, renewal, revocation feed
  internal/config/          strict PEP config only
  internal/controlplane/    PA/Gateway outbound gRPC stream
  internal/dataplane/       Agent mTLS/yamux listener and strict connect relay
  internal/enrollment/      enrollment token, keypair, CSR, cert install
  internal/provisioning/    PA-provisioned session store and validator
  internal/relay/           direct TCP dialer to provisioned internal targets
```

Gateway docs: `gateway/GATEWAY_DOCUMENTATION.md`.

## Agent Rules

The final endpoint component is `agent/`.

- The final Agent stays TUN-based.
- Do not introduce WFP.
- Service/tray IPC uses Windows Named Pipes under `agent/internal/ipc` with strict ACLs.
- MFA/step-up UI orchestration remains deferred unless explicitly requested.
- The service owns endpoint identity, Machine Store mTLS credentials, posture reporting, catalog sync, synthetic DNS/NRPT, TUN routing, Gateway tunnel, TUN-to-yamux relay, and optional process identity context.

## Strict Access Flow

1. Agent maps a TUN TCP flow to a catalog resource.
2. Agent asks PDP/PA to authorize the resource over gRPC/HTTP/2 with endpoint mTLS and the volatile user bearer token.
3. PDP/PA prepares normalized context and PDP/PE evaluates policy centrally.
4. On `allow`, PA creates a session and provisions the assigned Gateway through the PA/Gateway control stream.
5. Agent receives `gateway_endpoint`, `session_id`, raw `session_token`, `resource_id`, protocol, port, and expiry.
6. Agent opens/reuses the Gateway mTLS/yamux tunnel and sends strict `connect`.
7. Gateway validates local PA-provisioned session bindings and relays only to the internal host/port stored in that session.
8. PA revocation closes active Gateway relay streams through `revoke_session`.

## PDP Rules

- `pdp/` is the renamed control-plane component and represents the Policy Decision Point.
- `pdp/pa/` is the physical Policy Administrator boundary. Transport adapters live under `pdp/pa/transport`, PA sessions under `pdp/pa/sessions`, audit under `pdp/pa/audit`, policy administration under `pdp/pa/policies`, Gateway admin/enrollment/certificate lifecycle/control state under `pdp/pa/gateway`, resource administration under `pdp/pa/resources`, device catalog assembly under `pdp/pa/catalog`, device telemetry under `pdp/pa/devices`, enrollment CSR rules under `pdp/pa/enrollment`, and the admin UI under `pdp/pa/dashboard`.
- `pdp/pe/` is the physical Policy Engine boundary. Deterministic evaluation lives under `pdp/pe/evaluation`, and risk scoring lives under `pdp/pe/risk`.
- External/shared PDP services such as `pdp/pki`, `pdp/mfa`, `pdp/idp`, `pdp/store`, `pdp/events`, `pdp/models`, and `pdp/config` stay outside `pa` and `pe`.
- PA owns IdP/OIDC, MFA orchestration, enrollment, mTLS coordination, sessions, Gateway enrollment records, Gateway control stream server, Agent authorization, catalog distribution, posture storage, CAEP/security event propagation, Vault PKI mediation, admin APIs, dashboard, and audit.
- PE owns deterministic policy and risk evaluation only. PE returns `allow`, `deny`, or `mfa_required` from a normalized context and must not issue tokens, create sessions, provision Gateways, sign certificates, or write audit records.
- The runtime PA-to-PE boundary is `pa.PolicyAdministrator.EvaluateAccess` -> `pe/evaluation.Engine.Evaluate` with `evaluation.AccessContext`.
- Agent authorization orchestration belongs to PA through `pa.PolicyAdministrator.AuthorizeAgentResource`; `pa/transport` handlers should stay thin transport adapters.
- Gateway admin create/list/detail/update/delete, enrollment token regeneration, administrative revocation, one-time enrollment, enrollment token validation, Gateway certificate renewal, old Gateway certificate revocation, control registry, and command construction belong to `pdp/pa/gateway`; `pa/transport` keeps only endpoint method checks, rate limiting, request decoding, mTLS context extraction, CA response loading, gRPC stream handshake, wire I/O, IdP federation discovery probes, and PA error mapping.
- Resource admin create/list/detail/update/delete, per-app credential generation, resource secret regeneration, Vault-backed resource certificate CSR/signing, resource certificate metadata persistence, and resource CAEP update emission belong to `pdp/pa/resources`; `pa/transport` should only decode admin payloads, call PA resources, log, and map PA errors to HTTP status codes.
- Device catalog snapshot construction belongs to `pdp/pa/catalog`; `pa/transport` should only authenticate the device/user, call PA catalog assembly, and encode HTTP/gRPC responses.
- Device health, raw posture, heartbeat state updates, telemetry audit records, and health CAEP events belong to `pdp/pa/devices`; `pa/transport` should only authenticate the device, decode payloads, call PA telemetry methods, and map PA errors to wire status codes.
- Endpoint enrollment component canonicalization, CSR normalization, CSR public-key fingerprinting, CSR identity validation, pending enrollment request creation, browser enrollment session creation/completion/status polling, classic enrollment status polling, admin enrollment listing, admin approval/revocation actions, device-bound enrollment token issuance, device-bound EST enrollment, EST one-time token consumption, certificate issuance, certificate renewal, same-key reuse, changed-key revocation, old-certificate revocation during renewal, and owner device-user binding belong to `pdp/pa/enrollment`; `pa/transport` may keep temporary compatibility wrappers, rate limiting, IdP token parsing, admin authentication, admin audit emission, auth URL construction, mTLS context extraction, CA response loading, and endpoint orchestration but should not own these rules.
- Production code under `pdp/pe` must not import `store`, `pa`, `pa/transport`, `idp`, `pki`, `mfa`, or `events`; PA must load store-backed state before evaluation.
- Gateway enrollment endpoint is `POST /api/gateway/enroll` with token plus CSR.
- Gateway renewal endpoint is `POST /api/gateway/renew-cert` over Gateway mTLS.
- Gateway revoked serial fallback is `GET /api/gateway/revoked-serials`.
- Agent resource authorization is `ztna.agent.v1.AgentAuthorizationService/AuthorizeResource`; REST `/api/agent/authorize` remains compatibility over the same PA logic.

## Security Conventions

- TLS 1.3 minimum for inter-component channels.
- mTLS is mandatory for Gateway-to-PDP, Agent-to-PDP steady-state APIs, and Agent-to-Gateway data plane in production.
- Vault PKI is the certificate signing backend for Gateway and endpoint certificates.
- JWT signing uses ECDSA P-256 / ES256.
- Do not hardcode secrets or keep generated cert/key/runtime state in source directories.
- Library code returns errors instead of panicking.
- Use stdlib `testing` and `httptest`; do not add external test libraries.

## Validation Commands

Gateway:

```powershell
cd gateway
go test ./...
go vet ./...
```

PDP:

```powershell
cd pdp
go test ./...
go vet ./...
```

Agent validation may require generated frontend assets for tray builds and Windows-specific behavior for service/TUN/Named Pipe paths.