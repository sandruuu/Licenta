#!/bin/sh
set -eu

mkdir -p /etc/nginx/tls

if [ ! -f /etc/nginx/tls/web-app.crt ] || [ ! -f /etc/nginx/tls/web-app.key ]; then
  cat > /tmp/web-app-openssl.cnf <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no

[dn]
CN = web.demo.trustcloud.test

[v3_req]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[alt_names]
DNS.1 = web.demo.trustcloud.test
DNS.2 = web-app.trustcloud.test
DNS.3 = web.internal.lab.local
DNS.4 = web-app
IP.1 = 10.10.0.20
EOF
  openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
    -keyout /etc/nginx/tls/web-app.key \
    -out /etc/nginx/tls/web-app.crt \
    -config /tmp/web-app-openssl.cnf >/dev/null 2>&1
fi

exec nginx -g "daemon off;"
