# Public PDP Dashboard

This overlay publishes the PDP/PA web interface through Caddy with a public
Let's Encrypt certificate. The PDP still listens internally on `8443`; Caddy is
the only public HTTP(S) entrypoint.

## DNS

Create a Cloudflare DNS record for the PA dashboard hostname:

```text
A  policy-admin.remote-access-demo.xyz  <server-public-ip>
```

Keep the record as **DNS only** while Caddy obtains the Let's Encrypt
certificate. You can later enable Cloudflare proxying if you want, but the first
certificate issuance is simplest with direct DNS.

## Firewall

Allow only:

```text
80/tcp
443/tcp
443/udp
```

Do not expose `8443`, `8200`, `8080`, or `1053` publicly. The base compose file
binds those local lab ports to `127.0.0.1`.

## Environment

Set the public hostname in `.env`:

```text
PDP_PUBLIC_HOST=policy-admin.remote-access-demo.xyz
PDP_ADMIN_REQUIRE_MFA=true
```

`PDP_PUBLIC_HOST` updates the public callback URL, WebAuthn origin, and CORS
origin inside the PDP process through environment overrides.

Optional WebAuthn override if you want passkeys scoped to the root domain:

```text
PDP_WEBAUTHN_RP_ID=remote-access-demo.xyz
PDP_WEBAUTHN_RP_ORIGINS=https://policy-admin.remote-access-demo.xyz
```

## Start

Build the dashboard and start the public overlay:

```powershell
cd pdp\pa\dashboard
npm install
npm run build
cd ..\..\..
docker compose -f docker-compose.yml -f docker-compose.public.yml up -d --build pdp public-proxy
```

Then open:

```text
https://policy-admin.remote-access-demo.xyz
```

## First administrator

Create the first administrator locally before publishing DNS or opening the
firewall. Public registration is blocked by Caddy at `/api/auth/register`.

Use the local PDP endpoint:

```text
https://localhost:8443
```

The PDP uses its internal Vault-issued certificate there, so the browser may ask
you to accept the local lab certificate.
