# Redis on Kubernetes

Acest overlay ruleaza Redis in Kubernetes pentru starea runtime a PDP. Redis ruleaza in acelasi namespace cu PDP (`trustcloud`) si este expus prin Service-ul `redis.trustcloud.svc.cluster.local:6379`.

## Configurare

1. Creeaza secretul real:

```powershell
Copy-Item deploy\kubernetes\redis\secret.example.yaml deploy\kubernetes\redis\secret.yaml
```

Inlocuieste `REDIS_PASSWORD` cu o parola reala.

2. Aplica secretul si manifestele:

```powershell
kubectl apply -f deploy\kubernetes\redis\secret.yaml
kubectl apply -k deploy\kubernetes\redis
kubectl -n trustcloud rollout status deployment/redis
```

3. Configureaza PDP sa foloseasca Redis:

```text
redis://:<REDIS_PASSWORD>@redis.trustcloud.svc.cluster.local:6379/0
```

Aceasta valoare trebuie pusa in `deploy/kubernetes/pdp/secret.yaml` la `PDP_REDIS_URL`.

## Verificare

```powershell
kubectl -n trustcloud get pods -l app.kubernetes.io/name=redis
kubectl -n trustcloud get svc redis
```

## Observatii

- Redis tine doar state runtime cu TTL: MFA/WebAuthn/OIDC/step-up, lockout, rate limit, lock-uri distribuite si gateway control.
- Nu folosim persistenta Redis pentru date permanente. Datele permanente sunt in PostgreSQL.
- `NetworkPolicy` permite conexiuni catre Redis doar din podurile PDP din acelasi namespace, daca CNI-ul clusterului aplica NetworkPolicy.
