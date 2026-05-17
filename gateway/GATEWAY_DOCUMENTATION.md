# Gateway PEP Documentation

## Purpose

The Gateway is a strict Zero Trust Policy Enforcement Point placed in front of internal resources. It does not authenticate users, evaluate policies, store resource catalogs, allocate synthetic DNS addresses, or expose an administration plane. Those responsibilities belong to PDP/PA/PE and the endpoint Agent.

Gateway accepts traffic only after PDP/PA has authorized a resource request and provisioned a short-lived session through the PA/Gateway control plane.

## Current Structure

```text
gateway/
  cmd/gateway/              single Gateway process entry point
  internal/config/          strict PEP JSON config loader and validation
  internal/controlplane/    PA gRPC client, mTLS, trust calls, control stream, command handler
  internal/dataplane/       mTLS/yamux Agent endpoint, relay, messages, and strict connect handler
  internal/enrollment/      one-time token enrollment, key generation, CSR submit
  internal/provisioning/    PA-provisioned session store and validator
```

Removed legacy surfaces: Gateway Admin UI, SessionStore microservice, Syslog service, SQLite resource store, Gateway DNS resolver, CGNAT allocator, local anomaly/risk engine, local user JWT/JWKS validation, `auth_request`, and `dns_resolve`.

## Runtime Flow

1. Gateway starts from `cmd/gateway` and reads `config.json` from its working directory.
2. If `GATEWAY_ENROLLMENT_TOKEN` is set and the Gateway cert/key are missing, `internal/enrollment` generates an ECDSA P-256 private key, creates a CSR for the public key, calls PA `gateway.GatewayEnrollmentService/Enroll` over gRPC, and writes the signed Gateway certificate plus PA CA. PA marks the token as used and issues Gateway identity from the token-bound Gateway record.
3. The same Gateway certificate and key from `certs/gateway.crt` and `certs/gateway.key` are used for Agent-facing server TLS and PA-facing client mTLS. Gateway rejects certificates that do not include both `serverAuth` and `clientAuth` extended key usages.
4. `internal/controlplane.Client` starts with TLS 1.3 and Gateway mTLS for all PA calls.
5. `internal/controlplane` opens the required `gateway.GatewayControlService/ControlStream` over HTTP/2 gRPC with mTLS, builds `gateway_hello`, parses PA commands, and returns acknowledgements.
6. `provision_session` commands are stored in `internal/provisioning` with SHA-256 token hashes.
7. When PA allows access, it sends the selected Gateway address to the Agent.
8. Agents connect to `internal/dataplane` through TLS 1.3 plus mTLS and yamux.
9. Each yamux stream may send `hello` or strict `connect`. `connect` must include `session_id`, `session_token`, `device_id`, `resource_id`, `protocol`, and `remote_port`.
10. Gateway validates the frame locally against the PA-provisioned session, including token, device, resource, protocol, port, expiry, and revocation state.
11. Gateway ignores client-controlled target addresses for strict relay. The actual internal target is `Session.InternalHost:Session.InternalPort`, provisioned by PA.
12. `internal/dataplane` opens a direct TCP connection to that target and bridges bytes between the yamux stream and the resource until EOF, expiry, shutdown, or revocation.
13. `revoke_session` marks the session revoked and closes active relays for that session immediately.

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

- protocol: `gateway.GatewayControlService/ControlStream`
- transport: HTTP/2 gRPC over TLS 1.3 with Gateway mTLS
- commands: `provision_session`, `revoke_session`, `heartbeat`
- handler: `internal/dataplane.Gateway` implements `ProvisionSession` and `RevokeProvisionedSession`

PDP/PA remains authoritative for authentication, MFA/step-up orchestration, policy evaluation, session creation, and resource-to-Gateway assignment.

## Enrollment And PKI

Gateway enrollment is non-interactive and does not require a local Admin UI:

1. PA creates a one-time Gateway enrollment token through its administration interface.
2. Gateway receives it through the `GATEWAY_ENROLLMENT_TOKEN` environment variable.
3. Gateway generates an ECDSA P-256 private key and CSR locally. The CSR requests both `serverAuth` and `clientAuth` extended key usages.
4. Gateway calls the gRPC method `gateway.GatewayEnrollmentService/Enroll` on PA with token and CSR.
5. PA validates the token, uses its own Gateway record for organization/address/SAN identity, signs the CSR through the configured PKI role, and returns one Gateway certificate with both `serverAuth` and `clientAuth`.
6. The certificate carries Gateway identity: `gateway_id` and `organization_id` in URI SAN, and FQDN in DNS SAN. Gateway extracts those values from the certificate, writes `certs/gateway.crt`, `certs/gateway.key`, `certs/gateway.csr`, and `certs/pa-ca.crt`, then uses the same certificate identity on later restarts.

Certificate renewal uses `gateway.GatewayEnrollmentService/RenewCertificate` over existing Gateway mTLS. PA authenticates the current certificate and its stored Gateway identity, rejects mismatched CSR SAN requests, and signs the renewed certificate with the Gateway identity from its own record. PA CA retrieval and revoked certificate serial sync use `gateway.GatewayTrustService/GetCACertificate` and `gateway.GatewayTrustService/GetRevokedSerials` over the same mTLS gRPC channel.

## Configuration

Primary JSON fields:

- `pa_url`
- `control_plane.server_name`

Gateway deployment values are read from `config.json`. Timeout, retry, circuit breaker, connection limit, yamux, certificate renewal, revocation sync, and relay bandwidth behavior are internal Gateway policies, not deployment configuration.

There are no Gateway `resources`, `internal_dns`, `cgnat`, `session_timeout`, Admin, SessionStore, or Syslog config sections.

## Deployment

The Docker deployment contains one Gateway service built from `Dockerfile.gateway`:

```text
gateway -> cmd/gateway -> internal/dataplane + internal/controlplane + internal/provisioning
```

Ports:

- `9443`: Agent mTLS/yamux data plane

Runtime mounts:

- `./config.json:/app/config.json:ro`
- `gateway-certs:/app/certs`

Runtime environment:

- `GATEWAY_ENROLLMENT_TOKEN`: one-time token generated in PA for first enrollment

Certificates are runtime artifacts. They are not kept in the repository; the Gateway reads and writes them through the Docker `gateway-certs` volume according to the certificate paths from `config.json`. The config file is mounted read-only because enrollment state is enforced by PA, not by rewriting local config.

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
- PA revoked-serial sync
