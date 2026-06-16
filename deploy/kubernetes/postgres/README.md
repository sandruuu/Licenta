# PostgreSQL on Kubernetes

Acest overlay ruleaza PostgreSQL in Kubernetes pentru PDP. Baza este interna clusterului, ruleaza in acelasi namespace cu PDP (`trustcloud`) si este expusa prin Service-ul `postgres.trustcloud.svc.cluster.local:5432`.

## Configurare

1. Creeaza secretul real:

```powershell
Copy-Item deploy\kubernetes\postgres\secret.example.yaml deploy\kubernetes\postgres\secret.yaml
```

Inlocuieste `POSTGRES_PASSWORD` cu o parola reala.

2. Aplica secretul si manifestele:

```powershell
kubectl apply -f deploy\kubernetes\postgres\secret.yaml
kubectl apply -k deploy\kubernetes\postgres
kubectl -n trustcloud rollout status statefulset/postgres
```

3. Configureaza PDP sa foloseasca baza:

```text
postgres://trustcloud:<POSTGRES_PASSWORD>@postgres.trustcloud.svc.cluster.local:5432/trustcloud?sslmode=disable
```

Aceasta valoare trebuie pusa in `deploy/kubernetes/pdp/secret.yaml` la `PDP_DATABASE_URL`.

## Verificare

```powershell
kubectl -n trustcloud get pods -l app.kubernetes.io/name=postgres
kubectl -n trustcloud get svc postgres
kubectl -n trustcloud get pvc
```

## Observatii

- Manifestul foloseste `StatefulSet`, nu `Deployment`, pentru ca PostgreSQL are date persistente.
- PVC-ul este `ReadWriteOnce`; o singura instanta PostgreSQL scrie in volum.
- `NetworkPolicy` permite conexiuni catre PostgreSQL doar din podurile PDP din acelasi namespace, daca CNI-ul clusterului aplica NetworkPolicy.
- Pentru productie reala cu failover automat si backup-uri gestionate, foloseste un operator PostgreSQL. Pentru demo/licenta, acest StatefulSet este varianta simpla si predictibila.
