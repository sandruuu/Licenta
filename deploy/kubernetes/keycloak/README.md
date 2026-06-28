# Keycloak IdP on Kubernetes

Acest overlay ruleaza IdP-ul separat de PDP, in namespace-ul `trustcloud-idp`.
Keycloak este expus public prin Ingress la `https://idp.trust-cloud.dev`, iar
datele sale persistente sunt stocate intr-un PostgreSQL separat de baza PDP.

## Cerinte

- `ingress-nginx` instalat in cluster.
- `cert-manager` instalat si `ClusterIssuer`-ul `letsencrypt` aplicat.
- DNS pentru `idp.trust-cloud.dev` catre LoadBalancer-ul controllerului Ingress.

## Configurare

1. Creeaza secretul real pornind de la exemplu:

```powershell
Copy-Item deploy\kubernetes\keycloak\secret.example.yaml deploy\kubernetes\keycloak\secret.yaml
Copy-Item deploy\kubernetes\keycloak\scim-sync-secret.example.yaml deploy\kubernetes\keycloak\scim-sync-secret.yaml
```

Actualizeaza valorile:

```yaml
KEYCLOAK_ADMIN_USERNAME: "admin"
KEYCLOAK_ADMIN_PASSWORD: "parola-admin"
KEYCLOAK_DATABASE_PASSWORD: "parola-postgres-keycloak"
```

In `scim-sync-secret.yaml`, completeaza valorile generate de PDP pentru IdP-ul
asociat organizatiei:

```yaml
PDP_ORGANIZATION_ID: "id-organizatie"
PDP_SCIM_TOKEN: "token-scim"
```

2. Verifica hostname-ul public in `configmap.yaml`:

```yaml
KEYCLOAK_HOSTNAME: "https://idp.trust-cloud.dev"
```

3. Publica imaginea connectorului SCIM, daca nu exista deja in registry:

```powershell
docker build -t laurasandru/trustcloud-keycloak-scim-sync:latest deploy\docker\keycloak-scim-sync
docker push laurasandru/trustcloud-keycloak-scim-sync:latest
```

4. Creeaza namespace-ul si secretele:

```powershell
kubectl apply -f deploy\kubernetes\keycloak\namespace.yaml
kubectl apply -f deploy\kubernetes\keycloak\secret.yaml
kubectl apply -f deploy\kubernetes\keycloak\scim-sync-secret.yaml
```

5. Creeaza `ConfigMap`-ul pentru importul realm-ului:

```powershell
kubectl -n trustcloud-idp create configmap keycloak-realm-import `
  --from-file=trustcloud-lab-realm.json=deploy\docker\keycloak\import\trustcloud-lab-realm.json `
  --dry-run=client -o yaml | kubectl apply -f -
```

6. Aplica manifesturile:

```powershell
kubectl apply -k deploy\kubernetes\keycloak
kubectl -n trustcloud-idp rollout status deployment/keycloak
kubectl -n trustcloud-idp rollout status deployment/keycloak-scim-sync
```

7. Verifica Ingress-ul, certificatul si connectorul:

```powershell
kubectl -n trustcloud-idp get ingress keycloak
kubectl -n trustcloud-idp get certificate
kubectl -n trustcloud-idp logs deploy/keycloak-scim-sync
```

## Configurare in PDP

Pentru organizatia care foloseste acest IdP, issuer-ul OIDC este:

```text
https://idp.trust-cloud.dev/realms/trustcloud-lab
```

Clientul importat in realm este:

```text
client_id: trustcloud
client_secret: trustcloud-dev-secret
redirect_uri: https://trust-cloud.dev/auth/federated/callback
```

Realm-ul importat este citit din:

```text
deploy/docker/keycloak/import/trustcloud-lab-realm.json
```
