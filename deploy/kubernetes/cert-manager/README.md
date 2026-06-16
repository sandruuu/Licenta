# cert-manager pentru DigitalOcean

Ingress-ul PDP foloseste adnotarea:

```yaml
cert-manager.io/cluster-issuer: letsencrypt
```

Intr-un cluster DigitalOcean nou trebuie sa existe un `ClusterIssuer` cu numele `letsencrypt`.

Instalarea controllerului `cert-manager` se face o singura data in cluster. Dupa ce controllerul ruleaza, creeaza issuer-ul:

```powershell
Copy-Item deploy\kubernetes\cert-manager\clusterissuer-letsencrypt.example.yaml deploy\kubernetes\cert-manager\clusterissuer-letsencrypt.yaml
```

Inlocuieste `<EMAIL_FOR_LETS_ENCRYPT_NOTICES>` cu adresa ta de email, apoi aplica:

```powershell
kubectl apply -f deploy\kubernetes\cert-manager\clusterissuer-letsencrypt.yaml
kubectl get clusterissuer letsencrypt
```

Acest issuer este folosit doar pentru TLS-ul public al UI/API/OIDC prin Ingress. Endpoint-ul mTLS `mtls.trust-cloud.dev` nu foloseste cert-manager, deoarece certificatul lui este certificatul PDP emis de Vault si trebuie sa ajunga direct la gateway.
