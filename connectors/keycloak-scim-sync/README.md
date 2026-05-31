# Keycloak SCIM sync connector

This connector is a lab adapter for Keycloak deployments that do not push SCIM
to TrustCloud directly.

Flow:

```text
Keycloak Admin API -> keycloak-scim-sync -> TrustCloud PDP SCIM API
```

The PDP remains the SCIM service provider. This connector is only an IdP-specific
source adapter.

## Required configuration

```text
KEYCLOAK_BASE_URL=http://keycloak:8080
KEYCLOAK_REALM=trustcloud-lab
KEYCLOAK_AUTH_REALM=master
KEYCLOAK_CLIENT_ID=admin-cli
KEYCLOAK_ADMIN_USERNAME=admin
KEYCLOAK_ADMIN_PASSWORD=admin
# alternatively:
# KEYCLOAK_CLIENT_SECRET=<service-account-secret>

PDP_BASE_URL=https://pdp:8443
PDP_TENANT_ID=<organization id>
# alternatively, set the SCIM base URL directly:
# PDP_SCIM_BASE_URL=https://pdp:8443/scim/v2/<organization id>
PDP_SCIM_TOKEN=<token configured on the IdP in PDP>
PDP_TLS_SKIP_VERIFY=true

SYNC_INTERVAL=60s
SYNC_ONCE=false
DISABLE_MISSING_USERS=true
DELETE_MISSING_GROUPS=true
SKIP_SERVICE_ACCOUNTS=true
PAGE_SIZE=100
```

For production-like setups, prefer `KEYCLOAK_CLIENT_ID` +
`KEYCLOAK_CLIENT_SECRET` with a Keycloak service account that can read users and
groups.

`PDP_TENANT_ID` is used to derive the SCIM URL as
`{PDP_BASE_URL}/scim/v2/{PDP_TENANT_ID}`. Use `PDP_SCIM_BASE_URL` when the
connector must target a custom SCIM base path.

## Behavior

- Reads Keycloak users, groups, and group memberships.
- Upserts SCIM users and groups into PDP.
- Uses Keycloak object IDs as SCIM `externalId`.
- By default disables SCIM users missing from Keycloak and deletes missing
  groups.
- Skips Keycloak service accounts by default.
- Runs once at startup, then repeats every `SYNC_INTERVAL` unless
  `SYNC_ONCE=true`.
- Uses `application/scim+json` payloads against the PDP SCIM API. PDP remains
  authoritative for the SCIM token and organization context.
