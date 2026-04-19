# ZTNA Docker Lab

This lab simulates:

- `cloud` (IdP + policy decision point) in a public segment
- `gateway-*` services in a DMZ segment
- internal resources (`rdp-desktop`, `web-app`) in a private segment
- `private-dns` used by gateway to resolve `internal_url` targets
- `public-dns` that resolves external resource FQDNs to gateway

## Start

```powershell
docker compose up -d --build
```

## Start With External PKI (Vault profile)

```powershell
$env:PKI_URL = "http://vault:8200"
$env:PKI_TOKEN = "ztna-dev-root-token"
docker compose --profile vault up -d --build
```

Clear custom Vault PKI overrides:

```powershell
Remove-Item Env:PKI_URL -ErrorAction SilentlyContinue
Remove-Item Env:PKI_TOKEN -ErrorAction SilentlyContinue
```

## Stop

```powershell
docker compose down
```

## Quick checks

```powershell
docker compose ps
nslookup rdp-desktop.ztna.test 127.0.0.1 -port=1053
nslookup web.internal.lab.local 127.0.0.1 -port=1053
```

Notes:

- `connect-app` still runs on the Windows host (not in Docker).
- OIDC browser endpoints are exposed on `https://localhost:8443` (cloud) and callback on `https://localhost:9444`.
- Gateway tunnel endpoint for `connect-app` is `localhost:9443`.
- `PKI_URL` and `PKI_TOKEN` are consumed by both cloud and gateway services during Vault-profile runs.
- Vault in Docker lab runs in dev mode only (profile `vault`) and is intended for migration/testing, not production hardening.
