# Gateway PEP Documentation

## Purpose

The Gateway is a strict Zero Trust Policy Enforcement Point placed in front of internal resources. It does not authenticate users, evaluate policies, store resource catalogs, allocate synthetic DNS addresses, or expose an administration plane. Those responsibilities belong to PDP/PA/PE and the endpoint Agent.

Gateway accepts traffic only after PDP/PA has authorized a resource request and provisioned a short-lived session through the PA/Gateway control plane.

## Current Structure

```text
gateway/
  cmd/gateway/              single Gateway process entry point
  internal/auth/            PDP/PKI client, cert renewal, revoked serial sync
  internal/config/          strict PEP JSON config and environment overrides
  internal/controlplane/    outbound PA gRPC ControlStream client
  internal/dataplane/       mTLS/yamux Agent endpoint and strict connect handler
  internal/enrollment/      one-time token enrollment, key generation, CSR submit
  internal/provisioning/    PA-provisioned session store and validator
  internal/relay/           direct TCP connection to provisioned internal targets
```

Removed legacy surfaces: Gateway Admin UI, SessionStore microservice, Syslog service, SQLite resource store, Gateway DNS resolver, CGNAT allocator, local anomaly/risk engine, local user JWT/JWKS validation, `auth_request`, and `dns_resolve`.

## Runtime Flow

1. Gateway starts from `cmd/gateway` with `gateway-config.json`.
2. If `enrollment_token` is set and the mTLS cert/key are missing, `internal/enrollment` generates an ECDSA P-256 key, creates a CSR, posts it to Cloud `/api/gateway/enroll`, writes the signed Gateway mTLS certificate and CA, clears the token, and saves the config.
3. `internal/auth.CloudClient` starts with TLS 1.3 and Gateway mTLS for PDP/PKI calls.
4. If `control_plane.enabled=true`, `internal/controlplane` opens `ztna.gateway.v1.GatewayControlService/ControlStream` over HTTP/2 gRPC with mTLS, sends `gateway_hello`, and receives PA commands.
5. `provision_session` commands are stored in `internal/provisioning` with SHA-256 token hashes.
6. Agents connect to `internal/dataplane` through TLS 1.3 plus mTLS and yamux.
7. Each yamux stream may send `hello` or strict `connect`. `connect` must include `session_id`, `session_token`, `device_id`, `resource_id`, `protocol`, and `remote_port`.
8. Gateway validates the frame locally against the PA-provisioned session, including token, device, resource, protocol, port, expiry, and revocation state.
9. Gateway ignores client-controlled target addresses for strict relay. The actual internal target is `Session.InternalHost:Session.InternalPort`, provisioned by PA.
10. `internal/relay` opens a direct TCP connection to that target and `internal/dataplane` bridges bytes between the yamux stream and the resource until EOF, expiry, shutdown, or revocation.
11. `revoke_session` marks the session revoked and closes active relays for that session immediately.

## Data Plane Messages

### `hello`

Used for lightweight protocol negotiation. Gateway responds with `hello_ack` and advertises `pa-provisioned-connect`, `yamux`, and `mtls`.

### `connect`

Required fields:

```json
{
  "type": "connect",
  "session_id": "pa-session-id",
  "session_token": "raw-token-returned-to-agent",
  "device_id": "device-id",
  "resource_id": "resource-id",
  "protocol": "tcp",
  "remote_port": 443,
  "process": {
    "pid": 1234,
    "name": "client.exe",
    "path": "C:/Program Files/App/client.exe",
    "sha256": "optional",
    "signer": "optional"
  }
}
```

Bearer-token-only `connect` requests are rejected with `session_invalid`. `dns_resolve` is not part of the Gateway protocol anymore and is treated as an unsupported request type.

## Control Plane

The PA/Gateway channel is outbound from Gateway to PDP/PA:

- protocol: `ztna.gateway.v1.GatewayControlService/ControlStream`
- transport: HTTP/2 gRPC over TLS 1.3 with Gateway mTLS
- commands: `provision_session`, `revoke_session`, `heartbeat`
- handler: `internal/dataplane.Gateway` implements `ProvisionSession` and `RevokeProvisionedSession`

PDP/PA remains authoritative for authentication, MFA/step-up orchestration, policy evaluation, session creation, and resource-to-Gateway assignment.

## Enrollment And PKI

Gateway enrollment is non-interactive and does not require a local Admin UI:

1. Cloud admin creates a one-time Gateway enrollment token.
2. Gateway receives it through `enrollment_token` or `GATEWAY_ENROLLMENT_TOKEN`.
3. Gateway generates an ECDSA P-256 key and CSR locally.
4. Gateway calls `POST /api/gateway/enroll` with token, CSR, FQDN, and name.
5. Cloud signs the CSR through the configured PKI role and returns the Gateway mTLS certificate plus CA bundle.
6. Gateway writes `mtls_cert`, `mtls_key`, `mtls_csr`, and `cloud_ca`, then clears the token.

Certificate renewal uses `POST /api/gateway/renew-cert` over existing Gateway mTLS. Revoked certificate serials are synchronized from Vault CRL first, with Cloud revoked-serial feed fallback.

## Configuration

Primary JSON fields:

- `listen_addr`, `fqdn`
- `tls_cert`, `tls_key`, `tls_ca`, `client_ca`, `cloud_ca`, `require_client_cert`
- `mtls_cert`, `mtls_key`, `mtls_csr`
- `cloud_url`, `cloud_cert_sha256`, `enrollment_token`
- `control_plane.enabled`, `control_plane.pa_url`, `control_plane.gateway_id`, `control_plane.gateway_endpoint`, `control_plane.ca_file`, `control_plane.cert_file`, `control_plane.key_file`
- `pki_url`, `pki_token`, `pki_path`, `pki_role_gateway`
- `max_relay_bandwidth_mbps`, `dev_mode`

There are no Gateway `resources`, `internal_dns`, `cgnat`, `session_timeout`, Admin, SessionStore, or Syslog config sections.

## Deployment

The Docker deployment contains one Gateway service built from `Dockerfile.gateway`:

```text
gateway -> cmd/gateway -> internal/dataplane + internal/controlplane + internal/provisioning + internal/relay
```

Ports:

- `9443`: Agent mTLS/yamux data plane
- `8080`: local health endpoint
- `80`: optional ACME HTTP-01 challenge listener when Let's Encrypt is enabled

## Validation

Run from `gateway/`:

```powershell
go test ./...
go vet ./...
```

Current focused tests cover:

- PA-provisioned session acceptance
- bearer-token-only strict `connect` rejection
- revocation denial
- `dns_resolve` unsupported behavior
- control-plane command parsing and mTLS stream behavior
- provisioning token hash, binding, expiry, and revocation checks
- Vault CRL parsing and Cloud fallback for revoked serial sync