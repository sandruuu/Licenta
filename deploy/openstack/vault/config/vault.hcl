ui = true
disable_mlock = true
api_addr = "https://vault:8200"
cluster_addr = "https://vault:8201"

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault.d/tls/vault.crt"
  tls_key_file  = "/etc/vault.d/tls/vault.key"
  tls_min_version = "tls13"
}

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "vault-1"
}
