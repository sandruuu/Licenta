#!/bin/sh
set -eu

: "${VAULT_ADDR:?Set VAULT_ADDR, for example https://vault:8200}"
: "${TRUSTCLOUD_VAULT_STATE_DIR:?Set TRUSTCLOUD_VAULT_STATE_DIR, for example ./state}"
: "${TRUSTCLOUD_VAULT_TOKEN_FILE:?Set TRUSTCLOUD_VAULT_TOKEN_FILE, for example ./state/pdp-token.env}"

VAULT_ADDR="$VAULT_ADDR"
STATE_DIR="$TRUSTCLOUD_VAULT_STATE_DIR"
APP_TOKEN_FILE="$TRUSTCLOUD_VAULT_TOKEN_FILE"

TRANSIT_MOUNT="transit"
TRANSIT_KEY="trustcloud-key"
PKI_MOUNT="pki_int"
PKI_CA_COMMON_NAME="TrustCloud"
PKI_CA_TTL="8760h"
PDP_POLICY="trustcloud-pki"
PDP_TOKEN_TTL="720h"
CERT_ROLE_MAX_TTL="720h"
PDP_ROLE="trustcloud"
PDP_ROLE_ALLOWED_DOMAINS="pdp"
DEVICE_ROLE="trustagent"
DEVICE_ROLE_URI_SANS="trustagent://device/*"
GATEWAY_ROLE="trustgateway"
GATEWAY_ROLE_URI_SANS="spiffe://gateway/organization/*/gateway/*"

export VAULT_ADDR
mkdir -p "$STATE_DIR"

require_vault_ready() {
  if [ -z "${VAULT_TOKEN:-}" ]; then
    echo "VAULT_TOKEN must be set for OpenStack Vault bootstrap." >&2
    echo "Initialize and unseal Vault manually, then rerun this script with an admin/root token." >&2
    exit 1
  fi

  set +e
  vault status >/tmp/vault-status.txt 2>&1
  code=$?
  set -e
  if [ "$code" -ne 0 ]; then
    cat /tmp/vault-status.txt >&2 || true
    echo "Vault must be initialized and unsealed before bootstrap." >&2
    exit 1
  fi

  if ! vault token lookup >/dev/null 2>&1; then
    echo "VAULT_TOKEN is not valid or does not have permission to configure Vault." >&2
    exit 1
  fi
}

load_app_token_file() {
  if [ ! -f "$APP_TOKEN_FILE" ]; then
    return
  fi

  # shellcheck disable=SC1090
  . "$APP_TOKEN_FILE"
  APP_TOKEN="${PDP_PKI_TOKEN:-}"
}

ensure_secret_engine() {
  mount="$1"
  type="$2"
  if ! vault secrets list | grep -q "^${mount}/"; then
    vault secrets enable -path="$mount" "$type" >/dev/null
  fi
}

ensure_pki_ca() {
  if ! vault read "$PKI_MOUNT/cert/ca" >/dev/null 2>&1; then
    vault secrets tune -max-lease-ttl="$PKI_CA_TTL" "$PKI_MOUNT" >/dev/null
    vault write -field=certificate "$PKI_MOUNT/root/generate/internal" \
      common_name="$PKI_CA_COMMON_NAME" \
      ttl="$PKI_CA_TTL" > "$STATE_DIR/trustcloud-ca.pem"
    chmod 600 "$STATE_DIR/trustcloud-ca.pem"
  fi
}

ensure_transit_key() {
  if ! vault read "$TRANSIT_MOUNT/keys/$TRANSIT_KEY" >/dev/null 2>&1; then
    vault write -f "$TRANSIT_MOUNT/keys/$TRANSIT_KEY" >/dev/null
  fi
}

write_pki_roles() {
  vault write "$PKI_MOUNT/roles/$PDP_ROLE" \
    allowed_domains="$PDP_ROLE_ALLOWED_DOMAINS" \
    key_type=ec \
    allow_bare_domains=true \
    allow_subdomains=true \
    allow_localhost=true \
    allow_ip_sans=true \
    client_flag=true \
    server_flag=true \
    max_ttl="$CERT_ROLE_MAX_TTL" >/dev/null

  vault write "$PKI_MOUNT/roles/$DEVICE_ROLE" \
    allow_any_name=true \
    key_type=ec \
    enforce_hostnames=false \
    allowed_uri_sans="$DEVICE_ROLE_URI_SANS" \
    client_flag=true \
    server_flag=false \
    max_ttl="$CERT_ROLE_MAX_TTL" >/dev/null

  vault write "$PKI_MOUNT/roles/$GATEWAY_ROLE" \
    allow_any_name=true \
    key_type=any \
    enforce_hostnames=false \
    use_csr_common_name=false \
    use_csr_sans=false \
    allowed_uri_sans="$GATEWAY_ROLE_URI_SANS" \
    allow_ip_sans=true \
    client_flag=true \
    server_flag=true \
    max_ttl="$CERT_ROLE_MAX_TTL" >/dev/null
}

write_pdp_policy() {
  cat > /tmp/trustcloud-pki-policy.hcl <<POLICY
path "$TRANSIT_MOUNT/encrypt/$TRANSIT_KEY" {
  capabilities = ["update"]
}

path "$TRANSIT_MOUNT/decrypt/$TRANSIT_KEY" {
  capabilities = ["update"]
}

path "$TRANSIT_MOUNT/keys/$TRANSIT_KEY" {
  capabilities = ["read"]
}

path "$PKI_MOUNT/cert/ca" {
  capabilities = ["read"]
}

path "$PKI_MOUNT/ca/pem" {
  capabilities = ["read"]
}

path "$PKI_MOUNT/sign/*" {
  capabilities = ["update"]
}

path "$PKI_MOUNT/sign-verbatim/*" {
  capabilities = ["update"]
}

path "$PKI_MOUNT/revoke" {
  capabilities = ["update"]
}
POLICY
  vault policy write "$PDP_POLICY" /tmp/trustcloud-pki-policy.hcl >/dev/null
}

ensure_app_token() {
  APP_TOKEN=""
  load_app_token_file

  if [ -n "$APP_TOKEN" ]; then
    if vault token lookup "$APP_TOKEN" >/dev/null 2>&1; then
      return
    fi
  fi

  APP_TOKEN="$(vault token create \
    -policy="$PDP_POLICY" \
    -ttl="$PDP_TOKEN_TTL" \
    -renewable=true \
    -field=token)"
  umask 077
  printf "PDP_PKI_TOKEN='%s'\n" "$APP_TOKEN" > "$APP_TOKEN_FILE"
  echo "Vault PDP token written to $APP_TOKEN_FILE"
}

require_vault_ready
ensure_secret_engine "$TRANSIT_MOUNT" "transit"
ensure_transit_key
ensure_secret_engine "$PKI_MOUNT" "pki"
ensure_pki_ca
write_pki_roles
write_pdp_policy
ensure_app_token

echo "Vault PKI and Transit bootstrap completed."
