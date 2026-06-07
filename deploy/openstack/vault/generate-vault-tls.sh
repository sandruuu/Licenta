#!/bin/sh
set -eu

if [ "${1:-}" = "" ]; then
  echo "Usage: $0 <vault-private-ip>" >&2
  echo "Example: $0 10.20.40.10" >&2
  exit 1
fi

VAULT_PRIVATE_IP="$1"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
TLS_DIR="$SCRIPT_DIR/tls"
CA_OPENSSL_CNF="$TLS_DIR/vault-ca-openssl.cnf"
OPENSSL_CNF="$TLS_DIR/vault-openssl.cnf"

mkdir -p "$TLS_DIR"

cat > "$CA_OPENSSL_CNF" <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
CN = TrustCloud Vault Internal CA
O = TrustCloud Demo

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cat > "$OPENSSL_CNF" <<EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = vault
O = TrustCloud Demo

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = vault
IP.1 = $VAULT_PRIVATE_IP
EOF

openssl genrsa -out "$TLS_DIR/vault-ca.key" 4096
openssl req -x509 -new -nodes \
  -key "$TLS_DIR/vault-ca.key" \
  -sha256 \
  -days 3650 \
  -config "$CA_OPENSSL_CNF" \
  -out "$TLS_DIR/vault-ca.crt"

openssl genrsa -out "$TLS_DIR/vault.key" 4096
openssl req -new \
  -key "$TLS_DIR/vault.key" \
  -out "$TLS_DIR/vault.csr" \
  -config "$OPENSSL_CNF"

openssl x509 -req \
  -in "$TLS_DIR/vault.csr" \
  -CA "$TLS_DIR/vault-ca.crt" \
  -CAkey "$TLS_DIR/vault-ca.key" \
  -CAcreateserial \
  -out "$TLS_DIR/vault.crt" \
  -days 825 \
  -sha256 \
  -extensions req_ext \
  -extfile "$OPENSSL_CNF"

chmod 600 "$TLS_DIR/vault.key" "$TLS_DIR/vault-ca.key"
chmod 644 "$TLS_DIR/vault.crt" "$TLS_DIR/vault-ca.crt"

echo "Vault TLS material generated under $TLS_DIR"
echo "Copy vault.crt and vault.key to vault-vm under /etc/vault.d/tls/"
echo "Copy vault-ca.crt to vault-vm under /etc/vault.d/tls/ and to pdp-vm as deploy/openstack/pdp/vault-ca.crt"
