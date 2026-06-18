# TrustCloud Kubernetes Deploy

Fiecare componenta are overlay separat:

- `vault/`: HashiCorp Vault pentru PKI si Transit.
- `postgres/`: PostgreSQL pentru date persistente.
- `redis/`: Redis pentru state runtime distribuit.
- `pdp/`: PDP scalabil, UI/API/OIDC si endpoint mTLS.
- `cert-manager/`: exemplu pentru `ClusterIssuer` Let's Encrypt folosit de Ingress.

Pentru DigitalOcean Kubernetes, endpoint-ul mTLS al PDP-ului este expus prin `Service type: LoadBalancer` in `pdp/service-mtls.yaml`. UI/API/OIDC raman expuse prin Ingress normal, iar gateway-urile folosesc `https://mtls.trust-cloud.dev` pe portul standard `443`.

Gateway-ul din DMZ si resursele interne nu sunt definite aici. Pentru acea zona foloseste `deploy/digitalocean/edge-private`, unde gateway-ul si resursele sunt create in acelasi VPC privat DigitalOcean.

Ordinea recomandata de deploy:

```powershell
kubectl apply -f deploy\kubernetes\vault\tls-secret.yaml
kubectl apply -k deploy\kubernetes\vault

kubectl apply -f deploy\kubernetes\postgres\secret.yaml
kubectl apply -k deploy\kubernetes\postgres

kubectl apply -f deploy\kubernetes\redis\secret.yaml
kubectl apply -k deploy\kubernetes\redis

kubectl apply -f deploy\kubernetes\pdp\secret.yaml
kubectl apply -f deploy\kubernetes\pdp\vault-ca-secret.yaml
kubectl apply -k deploy\kubernetes\pdp
```

Pregateste fisierele reale pornind de la exemple:

```powershell
Copy-Item deploy\kubernetes\vault\tls-secret.example.yaml deploy\kubernetes\vault\tls-secret.yaml
Copy-Item deploy\kubernetes\postgres\secret.example.yaml deploy\kubernetes\postgres\secret.yaml
Copy-Item deploy\kubernetes\redis\secret.example.yaml deploy\kubernetes\redis\secret.yaml
Copy-Item deploy\kubernetes\pdp\secret.example.yaml deploy\kubernetes\pdp\secret.yaml
Copy-Item deploy\kubernetes\pdp\vault-ca-secret.example.yaml deploy\kubernetes\pdp\vault-ca-secret.yaml
```

Citeste README-ul fiecarei componente inainte de aplicare, pentru valorile care trebuie completate manual.
