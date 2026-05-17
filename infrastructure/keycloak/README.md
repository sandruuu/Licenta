# Keycloak IdP pentru lab

Acest director configureaza un IdP OIDC gratuit pentru integrarea mai multor organizatii din ZTNA.

## Pornire

```powershell
docker compose --profile idp up -d keycloak
```

Adauga numele local in hosts, ca issuer-ul sa fie accesibil si din browser:

```text
127.0.0.1 keycloak
```

Pe Windows, fisierul este:

```text
C:\Windows\System32\drivers\etc\hosts
```

Consola Keycloak:

```text
http://keycloak:8080
```

Credenitiale admin implicite:

```text
admin / admin
```

Pot fi schimbate prin `.env`:

```text
KEYCLOAK_ADMIN=admin
KEYCLOAK_ADMIN_PASSWORD=change-me
```

## Configurare in organizatii

In dashboard, deschide `Tenants`, alege organizatia, apoi `Identity Providers` si adauga una dintre configuratiile de mai jos.

### Organizatia demo

```text
Name: Keycloak Lab
Issuer URL: http://keycloak:8080/realms/ztna-lab
OIDC Client ID: ztna-pdp
OIDC Client Secret: ztna-pdp-dev-secret
Scopes: openid profile email
HRD Domains: demo.ztna.test
Enabled: true
Default for tenant: true
Auto-discovery: true
```

Claim mapping:

```text
Username: preferred_username
Email: email
Groups: groups
```

Group to role mapping:

```text
ZTNA-Admins -> admin
ZTNA-Users  -> user
```

### Organizatia partner

```text
Name: Keycloak Partner
Issuer URL: http://keycloak:8080/realms/ztna-partner
OIDC Client ID: ztna-pdp-partner
OIDC Client Secret: ztna-pdp-partner-dev-secret
Scopes: openid profile email
HRD Domains: partner.ztna.test
Enabled: true
Default for tenant: true
Auto-discovery: true
```

Claim mapping:

```text
Username: preferred_username
Email: email
Groups: groups
```

Group to role mapping:

```text
PARTNER-Admins -> admin
PARTNER-Users  -> user
```

Foloseste exact issuer-ul realm-ului configurat, nu `http://localhost:8080/...`. Keycloak emite token-uri cu issuer
`http://keycloak:8080/realms/<realm>`, iar aplicatia trebuie sa valideze acelasi issuer.

## Utilizatori demo

Organizatia demo:

```text
admin@demo.ztna.test / Admin123!
user@demo.ztna.test  / User123!
```

Organizatia partner:

```text
admin@partner.ztna.test / PartnerAdmin123!
user@partner.ztna.test  / PartnerUser123!
```

## Observatii

Realm-urile importate sunt `ztna-lab` si `ztna-partner`. Clientul OIDC reprezinta PA/Auth Broker-ul aplicatiei, nu organizatia, gateway-ul sau resursa. Pentru fiecare organizatie reala ar trebui creat un client OIDC separat in IdP-ul ei.

Importul realm-urilor se face la prima initializare a volumului `keycloak-data`. Daca modifici fisierele de import dupa prima pornire, recreeaza volumul Keycloak pentru un import curat sau importa realm-ul nou cu `kcadm.sh`.

Redirect URI-uri incluse in clientul demo:

```text
https://localhost:8443/auth/federated/callback
https://pdp:8443/auth/federated/callback
```
