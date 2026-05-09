# PDP Documentation

The `pdp/` component is the Zero Trust Policy Decision Point. It replaces the previous `cloud/` component name and keeps the same external Agent, Gateway, OIDC, and admin API contracts while separating the internal Policy Administrator (PA) and Policy Engine (PE) boundaries.

## Current Runtime

The runtime is a single Go process with explicit PA and PE boundaries:

- Go module: `pdp`
- Runtime entrypoint: `cmd/pdp`
- PA coordination: `pa/`
- PA transport adapters: `pa/transport/`
- PA capability packages: `pa/sessions/`, `pa/audit/`, `pa/policies/`, `pa/gateway/`, `pa/resources/`, `pa/catalog/`, `pa/devices/`, `pa/enrollment/`
- PA admin dashboard: `pa/dashboard/`
- PE evaluator: `pe/evaluation/`
- PE risk scoring: `pe/risk/`
- External/shared services: `idp/`, `mfa/`, `pki/`, `store/`, `events/`, `models/`, `config/`
- Docker image entrypoint: `/app/pdp`
- Default config file: `pdp-config.json`
- Docker config file: `docker-pdp-config.json`

PA calls PE through `pa.PolicyAdministrator.EvaluateAccess`. This method loads policy rules, user role, failed-attempt count, posture, and geo-risk context, then passes a normalized `evaluation.AccessContext` into `pe/evaluation.Engine.Evaluate`.

Agent authorization is coordinated by `pa.PolicyAdministrator.AuthorizeAgentResource`. HTTP and gRPC handlers in `pa/transport` only decode transport input, provide the mTLS device identity and bearer token, call PA, and encode the response. PA validates the user token, resolves and checks the resource, evaluates policy, creates PA sessions, builds the Gateway provisioning payload, and audits the decision. Gateway admin create/list/detail/update/delete, enrollment token regeneration, administrative revocation, one-time enrollment, enrollment token validation, Gateway certificate renewal, old Gateway certificate revocation, control stream state, and `provision_session` / `revoke_session` command construction live in `pa/gateway`; the transport package only performs HTTP/gRPC decoding, mTLS context extraction, CA response loading, stream handshake, message I/O, IdP federation discovery probes, and PA error mapping. Resource administration, per-app credential generation, resource certificate CSR creation/signing through Vault PKI, resource secret regeneration, patch-style resource updates, deletion, and resource CAEP update emission live in `pa/resources`; `pa/transport` only decodes admin payloads, calls PA, logs, and maps PA errors to HTTP status codes. Device catalog assembly lives in `pa/catalog`, where PA builds versioned resource snapshots, DNS suffixes, resource FQDN/protocol/port entries, and TTL metadata for authenticated device users. Device health, raw posture, heartbeat state updates, audit records, and health-related CAEP events live in `pa/devices`; `pa/transport` only authenticates the mTLS device identity, decodes wire payloads, calls PA, and maps PA errors to HTTP/gRPC status codes. Endpoint enrollment CSR normalization, CSR public-key fingerprinting, component canonicalization, CSR email identity checks, pending enrollment request creation, browser enrollment session creation/completion/status polling, classic enrollment status polling, admin listing, admin approval/revocation, device-bound enrollment token issuance, device-bound EST enrollment, EST one-time token consumption, certificate issuance, certificate renewal, same-key reuse, changed-key revocation, old-certificate revocation during renewal, and owner binding live in `pa/enrollment`.

## Policy Administrator

PA coordinates the PDP control plane. It owns operational workflows and side effects:

- Agent resource authorization intake
- User token validation for device-bound Agent catalog and authorization calls
- Device catalog distribution and versioned catalog snapshot construction
- Device posture and heartbeat intake through `pa/devices`
- Session lifecycle and revocation
- Gateway admin management, enrollment, certificate renewal, old certificate revocation, and control-plane stream registry through `pa/gateway`
- Resource administration, per-app credentials, resource certificate generation, and resource CAEP update emission through `pa/resources`
- Gateway session provisioning and revocation commands
- Agent enrollment and certificate renewal, with endpoint certificate issuance rules in `pa/enrollment`
- OIDC, federation, MFA, and identity brokerage
- Vault PKI mediation for CSR signing, CA retrieval, renewal, and revocation
- CAEP/security event propagation
- Audit logging and admin APIs
- React admin dashboard

PA prepares normalized context and calls PE for a decision. PA applies the decision to operational flows. Agent authorization, session creation, Gateway provisioning payload construction, audit logging, certificate operations, IdP/OIDC work, and CAEP propagation remain outside PE.

Vault/PKI and MFA are not physically inside `pa/` or `pe/`. They remain external PDP services under `pki/` and `mfa/`; PA coordinates them as part of operational workflows.

## Policy Engine

PE is the deterministic evaluator. Its boundary is intentionally narrower than PA:

- Evaluate normalized access context against policy rules
- Compute contextual risk from supplied inputs
- Return `allow`, `deny`, or `mfa_required`
- Report matched rule, risk score, and decision reason

PE must not create sessions, issue tokens, sign certificates, provision Gateways, publish events, or write audit records.

The production `pe/` packages must not import `store`, `pa`, `pa/transport`, `idp`, `pki`, `mfa`, or `events`. Store-backed state is loaded by PA before evaluation.

## Stable External Contracts

The rename does not change the external protocol surface:

- `ztna.agent.v1.AgentAuthorizationService/AuthorizeResource`
- `ztna.catalog.v1.DeviceCatalogService/GetCatalog`
- `ztna.device.v1.DeviceTelemetryService/ReportPosture`
- `ztna.device.v1.DeviceTelemetryService/Heartbeat`
- `ztna.gateway.v1.GatewayControlService/ControlStream`
- `POST /api/gateway/enroll`
- `POST /api/gateway/renew-cert`
- `GET /api/gateway/revoked-serials`
- `POST /api/agent/authorize`
- `/api/admin/*`
- OIDC endpoints under `/auth/*`

## Compatibility Notes

Agent and Gateway consumers still use `cloud_url` / `CLOUD_URL` config names pointing to the PDP URL. These are external consumer config keys and are intentionally preserved for backward compatibility.

The root Docker Compose service is named `pdp`, with `pdp.ztna.local` as the sole network alias.

## Migration Status (completed May 2026)

The PDP has been fully migrated from the legacy `cloud` naming convention:

- All Go source comments and log messages renamed: "cloud" → "PDP"
- `isAllowedCloudOrigin` renamed to `isAllowedPDPOrigin`
- Legacy `filepath.Join("..", "cloud", "web", filename)` path fallback removed
- Legacy `LoadFromDisk()`/`importJSON()` store.json migration removed
- Legacy `PKIRoleHealth` config field removed
- `cloud.ztna.local` Docker alias removed; Gateway `depends_on` updated from `cloud:` → `pdp:`
- TLS cert references in config files updated: `cloud.crt`/`cloud.key` → `pdp.crt`/`pdp.key`

## Validation

Run from `pdp/` after backend changes:

```powershell
go test ./...
go vet ./...
```

Run from `pdp/pa/dashboard/` after dashboard changes:

```powershell
npm run lint
npm run build
```

The dashboard lint baseline currently has pre-existing React/ESLint issues; the production build succeeds.
