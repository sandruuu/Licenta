# Gateway PEP

Gateway-ul este Policy Enforcement Point-ul TrustCloud. Sta in fata resurselor private, accepta conexiuni mTLS de la agenti si releaza TCP doar pentru sesiuni provisionate de PDP/PA.

Gateway-ul nu autentifica utilizatori, nu evalueaza politici, nu face MFA, nu tine catalog de resurse si nu expune UI. Toate acestea raman in PDP/PA/PE si in agent. Gateway-ul aplica strict decizia primita de la PA.

Comportamentul este fail-closed: fara configuratie valida, certificat gateway, CA PA, sesiune provisionata, token de sesiune valid sau control plane functional, accesul este refuzat.

## Structura

```text
gateway/
  cmd/gateway/              entrypoint proces gateway
  internal/config/          env vars, validari, path-uri certificate, PA URL
  internal/cert/            chei, certificate, profil gateway, identitate SPIFFE
  internal/enrollment/      enrollment initial si certificate renewal la startup
  internal/controlplane/    client gRPC mTLS spre PA si control stream
  internal/dataplane/       listener mTLS/yamux, connect validation, relay TCP
  internal/provisioning/    sesiuni PA-provisioned in memorie
```

Fisiere dataplane:

- `server.go`: tipul `Gateway`, bootstrap listener, shutdown si operatii publice.
- `tls.go`: TLS listener, PA CA, certificate gateway.
- `streams.go`: conexiuni agent, yamux, `hello`, `connect`.
- `sessions.go`: revocari, cleanup, revalidare sesiuni cu PA.
- `cert_renewal.go`: verificare expirare si renewal certificat gateway.
- `helpers.go`: relay lifecycle, limite IP, seriale certificate, copy throttling.
- `constants.go`: timeout-uri, limite si intervale interne.
- `protocol.go`: mesajele JSON agent-gateway.
- `relay.go`: dial TCP strict spre tinta interna.

## Configurare

Gateway-ul nu foloseste fisier local de configurare. Configurarea runtime se face exclusiv prin variabile de mediu.

Variabile obligatorii:

- `GATEWAY_PA_URL`: URL-ul PDP/PA pentru gRPC mTLS, de forma `https://mtls.trust-cloud.dev`.
- `GATEWAY_PUBLIC_ENDPOINT`: endpoint-ul `host:port` anuntat la PA, de forma `gateway.example.com:9443`.
- `GATEWAY_ENROLLMENT_TOKEN`: token one-time folosit la prima inrolare, cand lipseste certificatul gateway.

Variabile optionale:

- `GATEWAY_SESSION_REVALIDATION_INTERVAL`: Go duration pentru revalidarea sesiunilor locale, default `30s`.

`GATEWAY_ENROLLMENT_TOKEN` poate fi si `file:/path/to/token`; continutul fisierului este citit si trimuit.

Validari:

- `GATEWAY_PA_URL` trebuie sa fie `https` si sa includa host.
- Daca `GATEWAY_PA_URL` nu are port, se foloseste `443`.
- `GATEWAY_PUBLIC_ENDPOINT` trebuie sa fie strict `host:port`, fara schema `https://`.
- Portul public trebuie sa fie intre `1` si `65535`.
- `GATEWAY_SESSION_REVALIDATION_INTERVAL`, daca este setat, trebuie sa fie acceptat de `time.ParseDuration`, de exemplu `30s` sau `1m`.

Path-uri locale fixe:

- `certs/pa-ca.crt`
- `certs/gateway.crt`
- `certs/gateway.key`
- `certs/gateway.csr`

Cheia privata se scrie cu `0600`; certificatele si CA-ul cu `0644`.

## Enrollment

La prima pornire, gateway-ul are nevoie de `GATEWAY_ENROLLMENT_TOKEN`.

Flux:

1. Genereaza cheie privata ECDSA P-256.
2. Creeaza CSR cu EKU `serverAuth` si `clientAuth`.
3. Apeleaza `/gateway.GatewayEnrollmentService/Enroll`.
4. Primeste certificatul gateway si CA-ul PA.
5. Valideaza certificatul gateway.
6. Scrie `gateway.crt`, `gateway.key`, `pa-ca.crt`.
7. Extrage identitatea gateway din URI SAN SPIFFE.

Identitatea asteptata in certificat:

```text
spiffe://trustcloud/organization/{organization_id}/gateway/{gateway_id}
```

Certificatul gateway trebuie:

- sa nu fie CA;
- sa permita `digitalSignature`;
- sa includa EKU `serverAuth` si `clientAuth`;
- sa fie valid temporal;
- sa contina URI SAN SPIFFE si DNS SAN/FQDN.

## Certificate Renewal

Gateway-ul reinnoieste certificatul in doua momente:

- la startup, daca certificatul local exista dar este expirat;
- periodic, daca certificatul expira in mai putin de `48h`.

Intervalul de verificare runtime este `6h`. Renewal-ul se face prin `/gateway.GatewayEnrollmentService/RenewCertificate`, folosind mTLS cu certificatul gateway curent.

Dupa renewal:

- cheia si certificatul local sunt rescrise atomic;
- CA-ul PA este actualizat daca PA trimite un CA nou;
- clientul gRPC catre PA reincarca certificatul;
- listener-ul agent-facing foloseste `GetCertificate`, deci noile handshake-uri primesc certificatul nou fara restart.

## Control Plane

Gateway se conecteaza outbound la PA prin gRPC mTLS, TLS 1.3.

Control stream:

- serviciu: `gateway.GatewayControlService`
- metoda: `/gateway.GatewayControlService/ControlStream`
- reconnect backoff: `1s` pana la `30s`

La conectare, gateway trimite `gateway_hello`:

```json
{
  "type": "gateway_hello",
  "gateway_id": "gw-1",
  "gateway_endpoint": "gateway.example.com:9443",
  "sent_at": "2026-05-08T12:00:00Z"
}
```

Comenzi acceptate:

- `provision_session`
- `revoke_session`
- `heartbeat`

Comenzile necunoscute primesc ack cu `unsupported_command`.

## Sesiuni Provisionate

PA trimite sesiunile prin `provision_session`. Gateway le tine doar in memorie.

Campuri relevante:

- `session_id`
- `session_token`
- `device_id`
- `user_id`
- `username`
- `resource_id`
- `resource_name`
- `internal_host`
- `external_port`
- `internal_port`
- `protocol`
- `expires_at`
- `constraints`
- `policy_version`
- `max_bandwidth_mbps`

Gateway salveaza doar hash SHA-256 al `session_token`, nu tokenul raw.

La `connect`, gateway valideaza:

- `session_id` si `session_token`;
- device binding;
- resource binding;
- protocol binding;
- port extern;
- expirare/revocare.

Portul extern este folosit pentru binding-ul clientului. Relay-ul catre resursa privata foloseste mereu `internal_host:internal_port`.

Sesiunile sunt:

- sterse local cand expira;
- revocate imediat la comanda PA;
- revalidate periodic cu PA la `GATEWAY_SESSION_REVALIDATION_INTERVAL`.

Daca o sesiune activa este revocata sau expira, toate relay-urile active pentru acea sesiune sunt inchise.

## Dataplane Agent

Gateway asculta hard-coded pe:

```text
:9443
```

Acest port nu este configurabil.

TLS agent-facing:

- TLS minim 1.3;
- client cert obligatoriu;
- client cert verificat cu `certs/pa-ca.crt`;
- serialele revocate sunt sincronizate periodic de la PA.

Protocolul agent-gateway ruleaza peste yamux.

Mesaje acceptate:

- `hello`
- `connect`

`hello` primeste `hello_ack` cu versiunea protocolului si feature-uri.

`connect` trebuie sa includa:

- `session_id`
- `session_token`
- `device_id`
- `resource_id`
- `protocol`
- `remote_port`

La succes, gateway raspunde `connected`, apoi copiaza bidirectional traficul intre stream-ul agentului si resursa interna.

Limite interne:

- maximum conexiuni active global: `1000`;
- maximum conexiuni per IP: `100`;
- buffer relay: `64 KiB`;
- max bandwidth global: `400 Mbps`;
- dial timeout resursa: `10s`.

## Docker

`Dockerfile.gateway`:

- construieste binarul Go;
- copiaza `docker-entrypoint.sh`;
- ruleaza ca user non-root;
- expune `9443`;
- nu copiaza fisiere locale de configurare.

`docker-compose.yml` asteapta:

- `GATEWAY_PA_URL`;
- `GATEWAY_PUBLIC_ENDPOINT`;
- `GATEWAY_ENROLLMENT_TOKEN`;
- optional `GATEWAY_SESSION_REVALIDATION_INTERVAL`;
- mount explicit pentru `./pa-ca.crt:/bootstrap/pa-ca.crt:ro`;
- volume persistent pentru `certs/`.

La startup, entrypoint-ul copiaza CA-ul PA din `/bootstrap/pa-ca.crt` doar daca lipseste `certs/pa-ca.crt`.

## Fail-Closed

Gateway refuza accesul cand:

- lipseste `GATEWAY_PA_URL`;
- `GATEWAY_PA_URL` nu este `https`;
- lipseste sau este invalid `GATEWAY_PUBLIC_ENDPOINT`;
- lipseste tokenul la prima inrolare;
- lipsesc certificatul sau cheia gateway;
- lipseste PA CA pentru listenerul agent;
- certificatul agentului nu este valid;
- serialul certificatului agent este revocat;
- lipsesc `session_id` sau `session_token`;
- sesiunea este expirata, revocata sau invalida;
- device/resource/protocol/port binding nu se potriveste;
- resursa interna nu poate fi dialata;
- control stream-ul PA se opreste in afara unui shutdown intentionat.

## Functionalitati Neincluse

Gateway nu include:

- UI admin;
- autentificare utilizatori;
- evaluare politici;
- MFA;
- store persistent local de sesiuni;
- SQLite;
- catalog local de resurse;
- DNS sintetic;
- CGNAT;
- syslog service;
- JWT/JWKS validation local;
- `dns_resolve`;
- `auth_request`;

## Testare

Din `gateway/`:

```powershell
go test ./...
go vet ./...
```

Testele acopera:

- validarea env vars;
- enrollment si renewal;
- certificate gateway;
- identitate SPIFFE;
- control stream;
- provision/revoke session;
- trust calls;
- connect validation;
- revocare relay-uri;
- cleanup sesiuni expirate;
- token hash;
- binding device/resource/protocol/port;
- respingere request-uri nesuportate.

## Checklist Modificari

Cand schimbi gateway-ul, verifica:

- env vars noi documentate aici;
- protocol `hello`/`connect` documentat;
- comenzi PA noi documentate;
- validari de sesiune actualizate;
- Dockerfile si compose actualizate;
- teste pentru comportamentul fail-closed;
- lipsa modurilor locale temporare sau dev.
