# PDP on Kubernetes

Acest overlay ruleaza PDP in Kubernetes fara profil local separat. Datele persistente sunt in PostgreSQL, starea runtime este in Redis, iar fisierele criptate locale ramase pentru chei sunt tinute pe PVC.

Configuratia curenta este ajustata pentru testul DigitalOcean fara NFS/ReadWriteMany: PDP ruleaza cu o singura replica si PVC `ReadWriteOnce`. Pentru scalare reala la mai multe replici, `pdp-data` trebuie sa fie un volum `ReadWriteMany`, apoi `deployment.yaml` si `hpa.yaml` pot reveni la minimum 2 replici.

## Cerinte

- O imagine PDP publicata intr-un registry accesibil de cluster.
- PostgreSQL disponibil pentru `PDP_DATABASE_URL`. Daca baza ruleaza in acelasi cluster, foloseste overlay-ul `deploy/kubernetes/postgres`.
- Redis disponibil pentru `PDP_REDIS_URL`. Daca Redis ruleaza in acelasi cluster, foloseste overlay-ul `deploy/kubernetes/redis`.
- Vault PKI si Transit disponibile pentru emitere certificate si criptarea cheilor locale. Daca Vault ruleaza in acelasi cluster, foloseste overlay-ul `deploy/kubernetes/vault`.
- Rolul Vault PKI pentru PDP trebuie sa permita SAN-urile `trust-cloud.dev` si `mtls.trust-cloud.dev` sau hosturile echivalente alese de tine.
- Pentru o singura replica, un volum `ReadWriteOnce` pentru `pdp-data` este suficient. Pentru mai multe replici, este necesar un volum `ReadWriteMany`, astfel incat toate replicile sa vada aceleasi fisiere:
  - `/app/data/pdp_key.enc`
  - `/app/data/jwt_signing_key.enc`
  - `/app/data/mfa_secret.key.enc`
  - certificatele PDP emise de Vault

Fara un PVC partajat `ReadWriteMany`, fiecare replica poate genera alta cheie JWT/PDP si tokenurile sau certificatele pot deveni inconsistente intre poduri. Codul PDP serializeaza initializarea acestor fisiere cu lock-uri distribuite in Redis, dar PVC-ul comun ramane necesar pentru ca toate replicile sa incarce aceleasi chei si certificate.

## Configurare

1. Inlocuieste `trustcloud-pdp:latest` din `deployment.yaml` cu imaginea reala publicata intr-un registry accesibil clusterului.
2. Verifica hosturile publice in `configmap.yaml`. Overlay-ul este pregatit pentru:
   - UI/API/OIDC: `trust-cloud.dev`
   - gateway/agent mTLS: `mtls.trust-cloud.dev`
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
`PDP_PKI_TOKEN` se citeste din Vault dupa ce `vault-bootstrap` ruleaza cu succes:

```powershell
kubectl -n vault exec deploy/vault-bootstrap -- cat /vault/state/pdp-token.env
```

Pentru PostgreSQL-ul din `deploy/kubernetes/postgres`, formatul este:

```text
postgres://trustcloud:<POSTGRES_PASSWORD>@postgres.trustcloud.svc.cluster.local:5432/trustcloud?sslmode=disable
```

Pentru Redis-ul din `deploy/kubernetes/redis`, formatul este:

```text
redis://:<REDIS_PASSWORD>@redis.trustcloud.svc.cluster.local:6379/0
```

6. Creeaza secretul real pentru CA-ul TLS al Vault:

```powershell
Copy-Item deploy\kubernetes\pdp\vault-ca-secret.example.yaml deploy\kubernetes\pdp\vault-ca-secret.yaml
```

Inlocuieste continutul `vault-ca.crt` cu certificatul CA real folosit pentru conexiunea TLS catre Vault. Daca ai generat certificatele cu overlay-ul Vault, continutul vine din `deploy/kubernetes/vault/tls/vault-ca.crt`.

## Deploy

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
kubectl -n trustcloud rollout status deployment/pdp
```

Deployment-ul curent porneste cu `replicas: 1`. HPA-ul este blocat temporar la o singura replica pentru a evita scalarea pe un PVC `ReadWriteOnce`. Dupa configurarea unui volum `ReadWriteMany`, seteaza `replicas: 2`, `minReplicas: 2` si `maxReplicas` peste `2`.

La oprire, PDP marcheaza `/ready` ca indisponibil, asteapta `readiness_drain_delay`, apoi inchide serverul HTTP/gRPC prin graceful shutdown. Manifestul seteaza `terminationGracePeriodSeconds: 45`. Strategia de rollout curenta este `Recreate`, ca noul pod sa nu incerce sa monteze acelasi volum `ReadWriteOnce` in timp ce podul vechi inca ruleaza.

## Expunere publica

Overlay-ul separa traficul public in doua endpoint-uri:

- `ingress-ui.yaml`: expune `https://trust-cloud.dev` prin Ingress normal, cu TLS terminat in Ingress si certificat emis de cert-manager prin `cert-manager.io/cluster-issuer: letsencrypt`.
- `service-mtls.yaml`: expune endpoint-ul mTLS prin `Service type: LoadBalancer`, port extern `443 -> 8443`, ca TLS-ul si certificatul client mTLS sa ajunga direct la PDP.

DNS-ul trebuie configurat astfel:

```text
trust-cloud.dev      -> IP/hostname al Ingress controllerului
mtls.trust-cloud.dev -> IP-ul/hostname-ul LoadBalancer-ului creat pentru service-ul pdp-mtls
```

Gateway-ul trebuie configurat cu URL-ul `https://mtls.trust-cloud.dev`. LoadBalancer-ul DigitalOcean trebuie sa publice portul `443/TCP` si sa trimita traficul catre service-ul `pdp-mtls`.

Daca LoadBalancer-ul nu poate fi creat, foloseste fallback-ul `ingress-mtls-passthrough.example.yaml`, dar doar daca ingress-nginx este pornit cu `--enable-ssl-passthrough`. Fallback-ul nu foloseste cert-manager pentru `mtls.trust-cloud.dev`, deoarece certificatul servit gateway-ului este certificatul PDP emis de Vault.

Important: `PDP_TLS_DNS_NAMES` trebuie sa contina atat `trust-cloud.dev`, cat si `mtls.trust-cloud.dev`. Astfel certificatul PDP emis de Vault ramane valid pentru endpoint-ul mTLS si pentru orice acces direct la serverul PDP.

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
- `pvc.yaml`: PVC `ReadWriteOnce` montat la `/app/data` pentru testul DigitalOcean fara NFS. Pentru scalare la mai multe replici trebuie schimbat la `ReadWriteMany`.
- `deployment.yaml`: o replica PDP, probes, graceful shutdown, volume mounts si rollout `Recreate` pentru PVC `ReadWriteOnce`.
- `service.yaml`: Service intern `ClusterIP` pe portul `8443`.
- `service-mtls.yaml`: Service `LoadBalancer` public pentru `mtls.trust-cloud.dev:443`, folosit de gateway/agent mTLS.
- `ingress-ui.yaml`: Ingress public normal pentru UI/API/OIDC pe `trust-cloud.dev`, cu cert-manager/Let's Encrypt.
- `ingress-mtls-passthrough.example.yaml`: fallback pentru mTLS prin NGINX TLS passthrough, neaplicat implicit de kustomize.
- `hpa.yaml`: blocat temporar la o replica. Pentru scalare, revino la minimum 2 replici dupa ce exista storage `ReadWriteMany`.
- `pdb.yaml`: pastreaza cel putin o replica disponibila la disruption.

