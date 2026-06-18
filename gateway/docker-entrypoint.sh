#!/bin/sh
set -eu

mkdir -p /app/certs

if [ ! -f /app/certs/pa-ca.crt ]; then
  if [ ! -f /bootstrap/pa-ca.crt ]; then
    echo "missing PDP CA certificate: mount it at /bootstrap/pa-ca.crt" >&2
    exit 1
  fi
  cp /bootstrap/pa-ca.crt /app/certs/pa-ca.crt
fi

chown -R appuser:appuser /app/certs

exec su-exec appuser:appuser ./gateway
