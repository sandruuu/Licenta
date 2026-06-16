# Vault on Kubernetes

Acest overlay ruleaza HashiCorp Vault pentru PDP. Vault este intern clusterului si este expus prin Service-ul `vault.vault.svc.cluster.local:8200`.

Vault furnizeaza:

- Transit key `trustcloud-key` pentru cheile PDP/JWT/MFA.
- PKI mount `pki_int`.
- Roluri PKI `trustcloud`, `trustagent` si `trustgateway`.
- Token PDP cu policy `trustcloud-pki`.

## Configurare TLS

Vault ruleaza cu TLS. Creeaza secretul real:

```powershell
Copy-Item deploy\kubernetes\vault\tls-secret.example.yaml deploy\kubernetes\vault\tls-secret.yaml
```

Inlocuieste:

- `tls.crt`: certificatul serverului Vault.
- `tls.key`: cheia privata a serverului Vault.
- `ca.crt`: CA-ul care a emis certificatul Vault.

Certificatul serverului Vault trebuie sa fie valid pentru:

```text
vault.vault.svc.cluster.local
vault.vault.svc
vault
localhost
127.0.0.1
```

## Deploy

```powershell
kubectl apply -f deploy\kubernetes\vault\tls-secret.yaml
kubectl apply -k deploy\kubernetes\vault
kubectl -n vault rollout status statefulset/vault
kubectl -n vault rollout status deployment/vault-bootstrap
```

`vault-bootstrap` initializeaza si desigileaza Vault, configureaza Transit/PKI, genereaza tokenul PDP si il scrie in PVC-ul `vault-bootstrap-state`, in fisierul:

```text
/vault/state/pdp-token.env
```

CA-ul PKI generat pentru certificatele PDP/gateway/agent este scris informativ in:

```text
/vault/state/trustcloud-ca.pem
```

## Preluare token si CA pentru PDP

Citeste tokenul PDP generat de `vault-bootstrap`:

```powershell
kubectl -n vault exec deploy/vault-bootstrap -- cat /vault/state/pdp-token.env
```

Pune valoarea `PDP_PKI_TOKEN` in `deploy/kubernetes/pdp/secret.yaml`.

Pentru secretul `vault-ca` al PDP-ului foloseste CA-ul TLS care a semnat certificatul HTTPS al Vault. Daca ai generat certificatele cu instructiunile din acest overlay, acesta este fisierul local:

```powershell
deploy\kubernetes\vault\tls\vault-ca.crt
```

Pune continutul in `deploy/kubernetes/pdp/vault-ca-secret.yaml`, la `vault-ca.crt`. Nu folosi aici `trustcloud-ca.pem`: acela este CA-ul PKI intern folosit pentru certificatele emise de Vault, nu pentru validarea conexiunii HTTPS dintre PDP si Vault.

## Verificare

```powershell
kubectl -n vault get pods
kubectl -n vault get svc vault
kubectl -n vault logs deploy/vault-bootstrap
```

## Observatii

- Acest overlay este simplu si potrivit pentru demo/licenta. Pentru productie reala, foloseste un deployment Vault HA cu storage Raft, init/unseal gestionat operational si tokenuri scurte/rotite.
- `vault-bootstrap` ruleaza ca watcher pentru a redesigila Vault dupa restart folosind cheia salvata in PVC. Protejeaza PVC-ul `vault-bootstrap-state`, deoarece contine cheia de unseal si tokenul operator.
- Rolul PKI `trustcloud` permite SAN-uri sub `trust-cloud.dev`, inclusiv `trust-cloud.dev` si `mtls.trust-cloud.dev`.
