# PDP on Kubernetes

Acest overlay ruleaza PDP in Kubernetes cu doua replici, fara profil local separat. Datele persistente sunt in PostgreSQL, starea runtime este in Redis, iar fisierele criptate locale ramase pentru chei sunt tinute pe un PVC partajat.

## Cerinte

- O imagine PDP publicata intr-un registry accesibil de cluster.
- PostgreSQL disponibil pentru `PDP_DATABASE_URL`. Daca baza ruleaza in acelasi cluster, foloseste overlay-ul `deploy/kubernetes/postgres`.
- Redis disponibil pentru `PDP_REDIS_URL`.
- Vault PKI si Transit disponibile pentru emitere certificate si criptarea cheilor locale.
- Rolul Vault PKI pentru PDP trebuie sa permita SAN-urile `pdp.apps.fsisc.ro` si `pdp-mtls.apps.fsisc.ro` sau hosturile echivalente alese de tine.
- Un volum `ReadWriteMany` pentru `pdp-data`. Toate replicile trebuie sa vada aceleasi fisiere:
  - `/app/data/pdp_key.enc`
  - `/app/data/jwt_signing_key.enc`
  - `/app/data/mfa_secret.key.enc`
  - certificatele PDP emise de Vault

Fara un PVC partajat, fiecare replica poate genera alta cheie JWT/PDP si tokenurile sau certificatele pot deveni inconsistente intre poduri. Codul PDP serializeaza initializarea acestor fisiere cu lock-uri distribuite in Redis, dar PVC-ul comun ramane necesar pentru ca toate replicile sa incarce aceleasi chei si certificate.

## Configurare

1. Inlocuieste `trustcloud-pdp:latest` din `deployment.yaml` cu imaginea reala publicata intr-un registry accesibil clusterului.
2. Verifica hosturile publice in `configmap.yaml`. Overlay-ul este pregatit pentru:
   - UI/API/OIDC: `pdp.apps.fsisc.ro`
   - gateway/agent mTLS: `pdp-mtls.apps.fsisc.ro`
3. Daca folosesti alte hosturi, actualizeaza:
   - `PDP_FQDN`
   - `PDP_TLS_DNS_NAMES`
   - `PDP_PUBLIC_ORIGIN`
   - `PDP_CORS_ORIGINS`
   - `PDP_FEDERATED_CALLBACK_URL`
   - `PDP_WEBAUTHN_RP_ID`
   - `PDP_WEBAUTHN_RP_ORIGINS`
4. Actualizeaza setarile Vault din `configmap.yaml`:
   - `PDP_PKI_URL`
   - `PDP_PKI_SERVER_NAME`
   - `PDP_PKI_PATH`
   - rolurile PKI
5. Creeaza secretul real pentru PDP:

```powershell
Copy-Item deploy\kubernetes\pdp\secret.example.yaml deploy\kubernetes\pdp\secret.yaml
```

Completeaza in `secret.yaml` valorile reale pentru `PDP_DATABASE_URL`, `PDP_REDIS_URL`, `PDP_PKI_TOKEN` si `PDP_TRANSIT_KEY`.
Pentru PostgreSQL-ul din `deploy/kubernetes/postgres`, formatul este:

```text
postgres://trustcloud:<POSTGRES_PASSWORD>@postgres.database.svc.cluster.local:5432/trustcloud?sslmode=disable
```

6. Creeaza secretul real pentru CA-ul Vault:

```powershell
Copy-Item deploy\kubernetes\pdp\vault-ca-secret.example.yaml deploy\kubernetes\pdp\vault-ca-secret.yaml
```

Inlocuieste continutul `vault-ca.crt` cu certificatul CA real folosit pentru conexiunea TLS catre Vault.

## Deploy

```powershell
kubectl apply -f deploy\kubernetes\postgres\secret.yaml
kubectl apply -k deploy\kubernetes\postgres
kubectl apply -f deploy\kubernetes\pdp\secret.yaml
kubectl apply -f deploy\kubernetes\pdp\vault-ca-secret.yaml
kubectl apply -k deploy\kubernetes\pdp
kubectl -n trustcloud rollout status deployment/pdp
```

Deployment-ul porneste cu `replicas: 2`. HPA-ul pastreaza minim 2 replici si poate creste pana la 5, daca exista metrics-server in cluster.

La oprire, PDP marcheaza `/ready` ca indisponibil, asteapta `readiness_drain_delay`, apoi inchide serverul HTTP/gRPC prin graceful shutdown. Manifestul seteaza `terminationGracePeriodSeconds: 45`.

## Expunere publica

Overlay-ul separa traficul public in doua endpoint-uri:

- `ingress-ui.yaml`: expune `https://pdp.apps.fsisc.ro` prin Ingress normal, cu TLS terminat in Ingress si certificat emis de cert-manager prin `cert-manager.io/cluster-issuer: letsencrypt`.
- `service-mtls.yaml`: expune `pdp-mtls.apps.fsisc.ro` prin `Service type: LoadBalancer`, port `443 -> 8443`, ca TLS-ul si certificatul client mTLS sa ajunga direct la PDP.

DNS-ul trebuie configurat astfel:

```text
pdp.apps.fsisc.ro      -> IP/hostname al Ingress controllerului
pdp-mtls.apps.fsisc.ro -> EXTERNAL-IP/hostname al Service-ului pdp-mtls
```

Daca `kubectl -n trustcloud get svc pdp-mtls` ramane cu `EXTERNAL-IP` in `Pending`, clusterul nu ofera LoadBalancer L4 pentru namespace-ul tau. In acel caz foloseste fallback-ul `ingress-mtls-passthrough.example.yaml`, dar doar daca ingress-nginx este pornit cu `--enable-ssl-passthrough`. Fallback-ul nu foloseste cert-manager pentru `pdp-mtls.apps.fsisc.ro`, deoarece certificatul servit gateway-ului este certificatul PDP emis de Vault.

Important: `PDP_TLS_DNS_NAMES` trebuie sa contina atat `pdp.apps.fsisc.ro`, cat si `pdp-mtls.apps.fsisc.ro`. Astfel certificatul PDP emis de Vault ramane valid pentru endpoint-ul mTLS si pentru orice acces direct la serverul PDP.

## Verificare

```powershell
kubectl -n trustcloud get pods -l app.kubernetes.io/name=pdp
kubectl -n trustcloud get hpa pdp
kubectl -n trustcloud get ingress pdp-ui
kubectl -n trustcloud get svc pdp-mtls
kubectl -n trustcloud describe pvc pdp-data
```

Probe expuse de PDP:

- `/live` verifica doar ca procesul HTTP/TLS raspunde.
- `/ready` intoarce 503 in timpul drain-ului si verifica PostgreSQL, Redis, CA-ul incarcat si JWKS/auth.
- `/health` ramane endpoint operational si verifica aceleasi dependinte principale: PostgreSQL, Redis, CA si JWKS/auth.

## Cod runtime relevant pentru replici

- `cmd/pdp/main.go` este doar orchestratorul; bootstrap-ul este impartit in `config.go`, `identity.go`, `runtime.go` si `shutdown.go`.
- Cheile PDP, JWT si MFA folosesc Vault Transit, fisiere criptate pe `/app/data` si lock-uri Redis; nu exista varianta locala in memoria unei singure replici.
- Clientii OIDC sunt persistenti in PostgreSQL, nu in memoria unei singure replici.
- Initializarea cheilor si a certificatului PDP foloseste lock-uri Redis.
- Certificatul PDP este reincarcat periodic de pe `/app/data`, astfel incat o replica poate prelua certificatul reinnoit de alta replica.
- Scrierile de chei/certificate sunt atomice pe filesystem.
- Redis tine state runtime cu TTL: sesiuni OIDC/WebAuthn/MFA/step-up, rate limit, lockout, enrollment interactiv, Pub/Sub intern si gateway control.
- PostgreSQL tine datele persistente: useri, organizatii, IdP-uri, SCIM directory, gateway-uri, resurse, politici, sesiuni, audit, revocari si clientii OIDC.

## Structura manifesturilor

- `namespace.yaml`: namespace-ul `trustcloud`.
- `configmap.yaml`: `config.json` si valorile publice/non-secrete pentru host, WebAuthn, CORS si Vault endpoint.
- `secret.example.yaml`: exemplu pentru `PDP_DATABASE_URL`, `PDP_REDIS_URL`, `PDP_PKI_TOKEN` si `PDP_TRANSIT_KEY`.
- `vault-ca-secret.example.yaml`: exemplu pentru CA-ul TLS folosit la conexiunea catre Vault.
- `pvc.yaml`: PVC `ReadWriteMany` montat la `/app/data`.
- `deployment.yaml`: doua replici PDP, probes, graceful shutdown, volume mounts si anti-affinity.
- `service.yaml`: Service intern `ClusterIP` pe portul `8443`.
- `service-mtls.yaml`: Service public L4 pentru `pdp-mtls.apps.fsisc.ro`, folosit de gateway/agent mTLS.
- `ingress-ui.yaml`: Ingress public normal pentru UI/API/OIDC pe `pdp.apps.fsisc.ro`, cu cert-manager/Let's Encrypt.
- `ingress-mtls-passthrough.example.yaml`: fallback pentru mTLS prin NGINX TLS passthrough, neaplicat implicit de kustomize.
- `hpa.yaml`: autoscaling intre 2 si 5 replici pe CPU.
- `pdb.yaml`: pastreaza cel putin o replica disponibila la disruption.
