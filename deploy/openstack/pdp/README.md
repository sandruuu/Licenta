# PDP OpenStack Deployment

This deployment runs PDP from a prebuilt Docker image.

## Build The Image

From the repository root:

```sh
docker build -t trustcloud-pdp:latest ./pdp
```

The PDP Dockerfile expects the dashboard build to exist at `pdp/pa/dashboard/dist`.
If it is missing, build it first:

```sh
cd pdp/pa/dashboard
npm install
npm run build
cd ../../..
```

## Move The Image To The PDP VM

Option A: save and copy the image:

```sh
docker save trustcloud-pdp:latest -o trustcloud-pdp.tar
scp trustcloud-pdp.tar ubuntu@<pdp-vm-ip>:/tmp/
ssh ubuntu@<pdp-vm-ip>
docker load -i /tmp/trustcloud-pdp.tar
rm /tmp/trustcloud-pdp.tar
```

Option B: push it to a registry and set `PDP_IMAGE` in `.env` to that registry image.

## Configure The VM

Copy this folder to the PDP VM, then create `.env`:

```sh
cp .env.example .env
```

Set:

```env
PDP_IMAGE=trustcloud-pdp:latest
PDP_PUBLIC_HOST=<pdp-public-domain>
PDP_FQDN=pdp
VAULT_PRIVATE_IP=<vault-private-ip>
PDP_PKI_TOKEN=<token-created-by-vault-bootstrap>
POSTGRES_PASSWORD=<strong-postgres-password>
PDP_REDIS_URL=redis://redis:6379/0
```

`vault-ca.crt` must be present in this folder. It is the public CA certificate used by PDP to verify Vault HTTPS.

The compose stack starts PostgreSQL for persistent PDP data and Redis for shared runtime state used by multiple PDP replicas.

## Start

```sh
docker compose up -d
docker compose logs -f pdp
```

Check through the public proxy:

```sh
curl https://$PDP_PUBLIC_HOST/health
```
