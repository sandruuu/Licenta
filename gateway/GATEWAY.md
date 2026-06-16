# Gateway PEP

## 1. Rolul gateway-ului

Gateway-ul este Policy Enforcement Point-ul strict al sistemului TrustCloud. El sta in fata resurselor interne si accepta trafic doar pentru sesiuni provisionate de PDP/PA.

Gateway-ul nu face:

- autentificare user;
- evaluare politici;
- MFA sau step-up orchestration;
- catalog de resurse;
- rezolvare DNS sintetica;
- alocare CGNAT;
- local JWT/JWKS validation pentru utilizatori;
- UI admin;
- local SessionStore persistent;
- syslog service;
- store SQLite de resurse;
- motor local de risc/anomalii.

Aceste responsabilitati raman la PDP/PA/PE si la agentul endpoint. Gateway-ul aplica doar decizia primita de la PA: accepta o conexiune mTLS de la agent, verifica o sesiune provisionata local prin control plane si releaza TCP catre tinta interna exacta trimisa de PA.

Comportamentul este fail-closed: fara certificat gateway valid, fara CA PA, fara sesiune provisionata, fara token de sesiune valid, fara device binding corect sau fara control plane functional pentru intretinere, gateway-ul refuza accesul.

## 2. Structura codului

```text
gateway/
  cmd/gateway/              entry point unic al procesului gateway
  internal/config/          incarcare config.json, env overrides, validari, utilitare PA URL
  internal/cert/            cheie P-256, parsare certificat, validare profil gateway, identitate SPIFFE
  internal/enrollment/      enrollment initial cu token one-time si renewal la startup pentru cert expirat
  internal/controlplane/    client gRPC mTLS spre PA, control stream, trust calls, circuit breaker
  internal/dataplane/       listener mTLS/yamux pe :9443, protocol agent, relay TCP strict
  internal/provisioning/    store in-memory pentru sesiuni PA-provisioned si validarea connect
```

Fisiere importante:

- `gateway/cmd/gateway/main.go`: bootstrap, enrollment, control plane, dataplane, shutdown.
- `gateway/internal/config/config.go`: `config.json`, env vars, path-uri certificate.
- `gateway/internal/config/pa.go`: validare `pa_url` si transformare in target gRPC.
- `gateway/internal/cert/certificate.go`: profil certificat gateway si extragere identitate.
- `gateway/internal/enrollment/enrollment.go`: enrollment initial si renewal la startup pentru certificat expirat.
- `gateway/internal/controlplane/client.go`: client PA cu TLS 1.3, mTLS si circuit breaker.
- `gateway/internal/controlplane/handler.go`: protocolul bidirectional `ControlStream`.
- `gateway/internal/controlplane/trust.go`: CA, seriale revocate, revalidare sesiuni, renewal cert.
- `gateway/internal/dataplane/server.go`: TLS listener, yamux, connect validation, relay, cleanup.
- `gateway/internal/dataplane/protocol.go`: mesajele JSON agent-gateway.
- `gateway/internal/dataplane/relay.go`: dial TCP strict catre tinta interna.
- `gateway/internal/provisioning/sessions.go`: store-ul local de sesiuni provisionate.

## 3. Configuratie

Gateway-ul citeste intotdeauna `config.json` din working directory. Constanta din cod este:

```text
FileName = config.json
```

Config-ul curent din repository este:

```json
{
  "pa_url": "https://mtls.trust-cloud.dev",
  "public_endpoint": "localhost:9443",
  "session_revalidation_interval": 30000000000
}
```

`session_revalidation_interval` este serializat ca `time.Duration`, deci valoarea numerica este in nanosecunde. `30000000000` inseamna `30s`.

### 3.1 Campuri JSON

Campurile JSON acceptate de `Config` sunt:

- `pa_url`: URL-ul PDP/PA folosit pentru gRPC. Este obligatoriu.
- `public_endpoint`: endpoint-ul host:port anuntat catre PA in `gateway_hello`, pentru ca PA sa-l transmita agentilor.
- `session_revalidation_interval`: intervalul la care gateway-ul cere PA sa revalideze sesiunile provisionate local.
- `control_plane`: exista ca struct intern in `Config`, dar campurile sale (`gateway_id`, `organization_id`, `fqdn`) au tag `json:"-"` si nu se configureaza din JSON. Ele sunt populate din certificatul gateway.
- `enrollment_token`: are tag `json:"-"` si nu se citeste din fisier. Este citit doar din env.

Nu exista campuri de configurare pentru:

- portul dataplane;
- certificate paths;
- relay timeout;
- connection limits;
- yamux settings;
- bandwidth global;
- revocation sync;
- certificate renewal interval;
- admin UI;
- resources;
- internal DNS;
- CGNAT;
- syslog;
- local session timeout.

Acestea sunt politici interne hard-coded in codul gateway-ului.

### 3.2 Validari config

`pa_url`:

- este obligatoriu;
- trebuie sa aiba schema `https`;
- trebuie sa includa host;
- daca nu include port, target-ul gRPC foloseste portul default `443`;
- `ServerName` TLS este hostname-ul din URL, fara port.

Exemple:

- `https://pdp:8443` devine target gRPC `pdp:8443`, ServerName `pdp`.
- `https://pdp.example.com` devine target gRPC `pdp.example.com:443`, ServerName `pdp.example.com`.
- `http://pdp:8443` este respins.
- un URL fara host este respins.

`public_endpoint`:

- este optional;
- daca este setat, trebuie sa fie strict `host:port`;
- host-ul nu poate fi gol;
- portul trebuie sa fie integer intre `1` si `65535`;
- nu accepta schema `https://`; valoarea asteptata este de forma `gateway.example.com:9443`.

`session_revalidation_interval`:

- daca lipseste sau este `<= 0`, se seteaza la `30s`;
- daca este valid, valoarea este folosita de loop-ul de revalidare sesiuni.

### 3.3 Variabile de mediu

Gateway-ul citeste explicit:

- `GATEWAY_ENROLLMENT_TOKEN`
- `GATEWAY_PA_URL`
- `GATEWAY_PUBLIC_ENDPOINT`

`GATEWAY_PA_URL` suprascrie `pa_url` din JSON. In deployment-ul cu PDP pe Kubernetes prin LoadBalancer L4, valoarea folosita de gateway trebuie sa fie endpoint-ul mTLS al PDP-ului, de exemplu `https://mtls.trust-cloud.dev`.

`GATEWAY_PUBLIC_ENDPOINT` suprascrie `public_endpoint` din JSON.

`GATEWAY_ENROLLMENT_TOKEN` este folosit doar pentru enrollment initial, cand lipseste certificatul gateway sau cheia gateway. Daca valoarea incepe cu `file:`, gateway-ul citeste tokenul din fisierul indicat si face `TrimSpace`.

Exemple:

- `GATEWAY_ENROLLMENT_TOKEN=raw-token`
- `GATEWAY_ENROLLMENT_TOKEN=file:/run/secrets/gateway-token`
- `GATEWAY_PA_URL=https://mtls.trust-cloud.dev`
- `GATEWAY_PUBLIC_ENDPOINT=gateway.example.com:9443`

### 3.4 Path-uri certificate si artefacte locale

Path-urile sunt constante, nu campuri de config:

- `certs/pa-ca.crt`: CA-ul PA/PKI folosit pentru verificarea PA si a certificatelor agent.
- `certs/gateway.crt`: certificatul gateway.
- `certs/gateway.key`: cheia privata gateway.
- `certs/gateway.csr`: CSR-ul generat la enrollment initial.

Scrierea fisierelor este atomica:

- se creeaza directorul cu `0700`;
- se scrie intr-un fisier temporar in acelasi director;
- se seteaza permisiunile;
- se inchide fisierul;
- se face rename atomic peste destinatie.

Permisiuni folosite:

- `gateway.key`: `0600`;
- `gateway.csr`: `0600`;
- `gateway.crt`: `0644`;
- `pa-ca.crt`: `0644`.

## 4. Bootstrap runtime

Fluxul din `cmd/gateway/main.go`:

1. Incarca `config.json`.
2. Aplica env overrides.
3. Valideaza config-ul.
4. Ruleaza `enrollment.Ensure`.
5. Daca enrollment-ul creeaza cert nou, logheaza status `created`.
6. Daca exista deja cert valid, logheaza status `existing`.
7. Daca certificatul existent era expirat si a fost reinnoit, logheaza status `renewed`.
8. Creeaza `controlplane.Client`.
9. Creeaza `dataplane.Gateway`.
10. Creeaza context de semnal pentru `os.Interrupt` si `SIGTERM`.
11. Porneste `GatewayControlService/ControlStream` intr-un goroutine.
12. Porneste loop-ul de certificate renewal intr-un goroutine.
13. Porneste listener-ul dataplane intr-un goroutine.
14. Asteapta fie oprirea serverului, fie oprirea control plane-ului, fie semnal de shutdown.
15. La shutdown, cheama `gateway.Shutdown()` si asteapta pana la `5s` ca listener-ul sa se opreasca.

`shutdownWait` este `5s`.

Daca serverul dataplane se opreste cu eroare, procesul face `log.Fatalf`. Daca stream-ul de control se opreste in timp ce contextul nu este anulat, procesul face tot `log.Fatalf`, deoarece gateway-ul nu trebuie sa functioneze fara control plane.

## 5. Enrollment si PKI

### 5.1 Starile enrollment-ului

`enrollment.Ensure` intoarce una dintre starile:

- `created`: nu exista cert/key local, s-a facut enrollment cu token.
- `existing`: exista cert/key local si certificatul este valid.
- `renewed`: exista cert/key local, profilul certificatului este utilizabil, certificatul este expirat si a fost reinnoit prin PA.

### 5.2 Enrollment initial

Enrollment initial se face cand lipseste `certs/gateway.crt` sau `certs/gateway.key`.

Cerinte:

- `GATEWAY_ENROLLMENT_TOKEN` trebuie sa fie prezent;
- `pa_url` trebuie sa fie configurat;
- PA trebuie sa fie accesibil pe gRPC TLS.

Pasii exacti:

1. Genereaza cheie privata ECDSA P-256.
2. Construieste extensia EKU pentru `serverAuth` si `clientAuth`.
3. Creeaza CSR PEM cu extensia EKU.
4. Scrie cheia in `certs/gateway.key` cu `0600`.
5. Scrie CSR-ul in `certs/gateway.csr` cu `0600`.
6. Apeleaza gRPC unary `/gateway.GatewayEnrollmentService/Enroll`.
7. Payload-ul este `structpb.Struct` cu:
   - `token`
   - `csr_pem`
8. Primeste raspuns cu:
   - `status`
   - `cert_pem`
   - `ca_pem`
   - `message`
9. Accepta raspunsul doar daca `status == "enrolled"`.
10. Parseaza `cert_pem`.
11. Valideaza profilul certificatului gateway.
12. Extrage identitatea gateway din certificat.
13. Scrie certificatul in `certs/gateway.crt`.
14. Daca `ca_pem` este prezent, scrie `certs/pa-ca.crt`.
15. Populeaza in config `ControlPlane.GatewayID`, `OrganizationID` si `FQDN`.

Enrollment initial foloseste TLS 1.3. Daca `certs/pa-ca.crt` exista deja, este folosit ca Root CA pentru conexiunea catre PA. Daca nu exista, `RootCAs` ramane nil si Go foloseste root-urile implicite ale sistemului.

### 5.3 Renewal la startup pentru certificat expirat

Daca exista cert/key local:

1. Gateway incarca perechea `certs/gateway.crt` si `certs/gateway.key`.
2. Valideaza profilul certificatului pentru renewal.
3. Daca certificatul este expirat, ruleaza `renewExistingEnrollment`.
4. Genereaza o noua cheie ECDSA P-256.
5. Creeaza CSR de renewal care copiaza din certificatul curent:
   - DNS SANs;
   - IP SANs;
   - URI SANs;
   - EKU serverAuth/clientAuth.
6. Apeleaza `/gateway.GatewayEnrollmentService/RenewCertificate` folosind certificatul gateway curent ca mTLS client cert.
7. Trimite payload `csr_pem`.
8. Accepta raspuns doar daca `status == "renewed"`.
9. Parseaza si valideaza certificatul nou.
10. Extrage identitatea.
11. Scrie cheia noua in `certs/gateway.key`.
12. Scrie certificatul nou in `certs/gateway.crt`.
13. Scrie CA-ul daca PA trimite `ca_pem`.

Validarea pentru renewal permite certificat expirat, dar cere profil gateway corect.

### 5.4 Renewal periodic la runtime

Gateway-ul mai porneste si `StartCertRenewalLoop`.

Valori interne:

- verificare imediata la pornirea loop-ului;
- interval verificare renewal: `6h`;
- fereastra de renewal: `48h`;
- timeout request renewal PA: `20s`.

Daca certificatul expira in mai putin de `48h`:

1. Gateway genereaza o cheie ECDSA P-256 noua.
2. Determina `gateway_id` din `cfg.ControlPlane.GatewayID`.
3. Creeaza CSR cu `Subject.CommonName = gateway_id`.
4. Copiaza DNS SANs, IP SANs si URI SANs din certificatul curent.
5. Include EKU serverAuth/clientAuth.
6. Apeleaza `controlPlane.RenewCert`, adica `/gateway.GatewayEnrollmentService/RenewCertificate`.
7. Cere `status == "renewed"`.
8. Valideaza certificatul primit.
9. Scrie cheia si certificatul local.
10. Scrie PA CA daca raspunsul include `ca_pem`.
11. Cheama `controlPlane.ReloadTLSCert`, astfel incat clientul gRPC PA sa foloseasca noul certificat.

Serverul TLS agent-facing foloseste `GetCertificate` si reincarca `certs/gateway.crt` + `certs/gateway.key` la fiecare handshake, deci noile conexiuni agent pot folosi certificatul reinnoit fara restart.

### 5.5 Profil certificat gateway

Certificatul gateway trebuie:

- sa nu fie CA;
- sa permita `digitalSignature` daca `KeyUsage` este setat;
- sa aiba EKU explicit;
- sa includa `serverAuth`;
- sa includa `clientAuth`;
- sa fie deja valid temporal (`NotBefore <= now`);
- sa nu fie expirat (`now <= NotAfter`) pentru utilizare normala.

Pentru renewal se valideaza profilul, dar nu se respinge expirarea temporala inainte de a chema PA.

### 5.6 Identitatea gateway din certificat

Identitatea se extrage din URI SAN cu schema `spiffe`.

Forma path-ului asteptat este:

```text
/organization/{organization_id}/gateway/{gateway_id}
```

Exemplu conceptual:

```text
spiffe://trustcloud/organization/org-1/gateway/gw-1
```

Conditii:

- schema trebuie sa fie `spiffe`;
- path-ul trebuie sa aiba exact segmentele `organization/{id}/gateway/{id}`;
- `organization_id` nu poate fi gol;
- `gateway_id` nu poate fi gol;
- certificatul trebuie sa contina cel putin un DNS SAN nevid, folosit ca `FQDN`.

Identitatea extrasa este folosita in:

- `gateway_hello`;
- renewal certificate;
- loguri;
- control plane state.

## 6. Clientul control plane

### 6.1 TLS si gRPC

`controlplane.NewClient`:

- transforma `pa_url` in target gRPC;
- seteaza TLS minim `TLS 1.3`;
- seteaza `ServerName` din hostname-ul `pa_url`;
- citeste `certs/pa-ca.crt` ca Root CA;
- incarca `certs/gateway.crt` si `certs/gateway.key`;
- valideaza certificatul gateway;
- configureaza certificatul ca mTLS client cert.

Toate apelurile PA post-enrollment folosesc mTLS gateway.

### 6.2 Conexiuni gRPC

Apelurile unary folosesc:

- dial nou per request;
- `grpc.DialContext`;
- `credentials.NewTLS`;
- raspuns `structpb.Struct`;
- circuit breaker.

Control stream-ul foloseste:

- stream bidirectional;
- `grpc.NewStream`;
- path exact `/gateway.GatewayControlService/ControlStream`;
- reconnect loop separat.

### 6.3 Timeout-uri si circuit breaker

Valori interne:

- request timeout trust/unary: `10s`;
- certificate renewal timeout: `20s`;
- circuit breaker max failures: `5`;
- circuit breaker open timeout: `30s`;
- half-open probe max latency: `2s`.

Circuit breaker-ul se aplica apelurilor unary prin `invokeUnary`, adica:

- `GetCACertificate`;
- `GetRevokedSerials`;
- `RevalidateSessions`;
- `RenewCertificate` facut prin `controlPlane.RenewCert`.

Stari:

- `closed`: request-urile trec normal.
- `open`: dupa 5 esecuri consecutive sau un esec in half-open; request-urile primesc `ErrCircuitOpen`.
- `half-open`: dupa ce open timeout-ul a trecut, permite un probe.

Daca probe-ul half-open dureaza peste `2s`, circuitul revine in `open` si creste contorul de timeout-uri half-open.

Metricile interne tin:

- total trips;
- total successes;
- total failures;
- total half-open timeouts.

Aceste metrici exista in struct, dar nu sunt expuse prin endpoint.

## 7. Control stream PA -> Gateway

### 7.1 Reconnect

`RunControlStream` ruleaza pana cand contextul se inchide.

Reconnect backoff:

- minim: `1s`;
- se dubleaza dupa fiecare stream incheiat;
- maxim: `30s`.

Backoff-ul nu este resetat explicit dupa un stream reusit; loop-ul continua sa il mareasca pana la plafon.

### 7.2 Hello gateway

La deschiderea stream-ului, gateway-ul trimite:

```json
{
  "type": "gateway_hello",
  "gateway_id": "gw-1",
  "gateway_endpoint": "localhost:9443",
  "sent_at": "2026-05-08T12:00:00Z"
}
```

Campuri:

- `type`: mereu `gateway_hello`;
- `gateway_id`: identitatea din certificatul gateway;
- `sent_at`: timestamp UTC RFC3339Nano;
- `gateway_endpoint`: optional, apare doar daca `public_endpoint` / `GATEWAY_PUBLIC_ENDPOINT` este setat.

### 7.3 Comenzi acceptate

Gateway-ul accepta comenzi cu `type`:

- `provision_session`;
- `revoke_session`;
- `heartbeat`.

Orice alta comanda primeste ack cu:

- `status = "error"`;
- `code = "unsupported_command"`.

### 7.4 Ack

Pentru fiecare comanda primita, gateway-ul trimite:

```json
{
  "type": "ack",
  "gateway_id": "gw-1",
  "command_id": "cmd-1",
  "status": "ok",
  "message": "session provisioned",
  "sent_at": "2026-05-08T12:00:00Z"
}
```

La eroare, include si `code`.

Coduri posibile din handler:

- `invalid_argument`;
- `provision_failed`;
- `session_not_found`;
- `unsupported_command`.

### 7.5 `provision_session`

Comanda cere obiect `session`.

Campuri citite:

- `session_id` sau `id`;
- `session_token`;
- `device_id`;
- `user_id`;
- `username`;
- `resource_id`;
- `resource_name`;
- `internal_host`;
- `internal_port`;
- `protocol`;
- `expires_at`;
- `constraints`;
- `policy_version`;
- `max_bandwidth_mbps`.

Validari la parsare comanda:

- `session` trebuie sa existe;
- `expires_at` trebuie sa existe si sa fie RFC3339/RFC3339Nano;
- `internal_port` trebuie sa fie integer pozitiv;
- `max_bandwidth_mbps`, daca exista, trebuie sa fie integer nenegativ;
- `constraints`, daca exista, trebuie sa fie lista.

Dupa parsare, `dataplane.Gateway.ProvisionSession` salveaza sesiunea in store-ul local si reinnoieste expiry-ul relay-urilor active pentru acelasi `session_id`.

### 7.6 `revoke_session`

Gateway accepta `session_id` din:

- top-level `session_id`;
- `session.session_id`;
- `session.id`.

Motivul se citeste din:

- top-level `reason`;
- `session.reason`.

Daca `session_id` lipseste, ack-ul are `invalid_argument`.

Daca sesiunea nu exista local, ack-ul are `session_not_found`.

Daca exista, sesiunea este marcata revoked si toate relay-urile active pentru acel `session_id` sunt inchise imediat cu motiv intern `session.revoked`.

### 7.7 `heartbeat`

`heartbeat` primeste ack `ok` cu mesaj `heartbeat received`. Nu modifica state local.

## 8. Trust service si intretinere cu PA

Gateway foloseste serviciul:

```text
gateway.GatewayTrustService
```

Metode exacte:

- `/gateway.GatewayTrustService/GetCACertificate`
- `/gateway.GatewayTrustService/GetRevokedSerials`
- `/gateway.GatewayTrustService/RevalidateSessions`

### 8.1 GetCACertificate

`GetCACert`:

- trimite request gol;
- asteapta camp `ca_pem`;
- intoarce eroare daca raspunsul nu include `ca_pem`;
- timeout implicit prin `requestTimeout = 10s`;
- apelul trece prin circuit breaker.

Dataplane-ul incearca sa adauge CA-ul primit de la PA peste CA-ul local. Totusi, listener-ul cere citirea locala a `certs/pa-ca.crt`; daca fisierul local lipseste, `clientCAPool` esueaza inainte ca pool-ul sa poata fi util pentru mTLS agent-facing.

### 8.2 GetRevokedSerials

`GetRevokedSerials`:

- trimite request gol;
- asteapta `revoked_serials` ca lista;
- parseaza doar string-uri nevida;
- ruleaza prin circuit breaker.

Gateway sincronizeaza serialele:

- imediat la pornirea listener-ului;
- apoi la fiecare `1m`.

Serialele sunt normalizate in mai multe chei:

- valoarea originala lowercase;
- forma decimal;
- forma hexadecimal lowercase;
- forma fara prefix `0x`, cand este cazul.

La handshake TLS agent-facing, gateway verifica serialul certificatului client impotriva map-ului local de seriale revocate.

Detaliu important: daca PA intoarce lista goala, codul curent iese fara sa goleasca map-ul local. Asta inseamna ca serialele revocate deja memorate raman in cache pana cand procesul se restarteaza sau PA trimite o lista nenula care declanseaza rescrierea cache-ului.

### 8.3 RevalidateSessions

Loop-ul de revalidare:

- ruleaza la `session_revalidation_interval`;
- default/config curent: `30s`;
- foloseste timeout intern `10s`.

Gateway trimite catre PA pentru fiecare sesiune locala:

- `session_id`;
- `device_id`;
- `resource_id`;
- `protocol`;
- `expires_at` in RFC3339Nano UTC.

Raspunsul asteptat poate include:

```json
{
  "invalid_sessions": [
    {
      "session_id": "sess-1",
      "status": "revoked",
      "reason": "policy.updated"
    }
  ]
}
```

Pentru fiecare intrare invalida, gateway cheama `RevokeProvisionedSession`. Motivul de revocare este primul non-empty dintre:

- `reason`;
- `status`;
- `pa_revalidation_failed`.

Daca nu exista sesiuni locale, gateway nu trimite request.

## 9. Dataplane agent-facing

### 9.1 Listener

Gateway asculta hard-coded pe:

```text
:9443
```

Acest port nu este configurabil din `config.json`.

TLS server:

- minim `TLS 1.3`;
- cere certificat client;
- `ClientAuth = RequireAndVerifyClientCert`;
- `ClientCAs` este construit din `certs/pa-ca.crt` si optional CA-ul obtinut prin PA;
- certificatul server gateway este incarcat din `certs/gateway.crt` si `certs/gateway.key`.

Certificatul gateway server este reincarcat prin `GetCertificate` la fiecare handshake.

### 9.2 Limite conexiuni

Valori interne:

- maxim conexiuni active global: `1000`;
- maxim conexiuni active per IP: `100`;

Ordine:

1. Gateway extrage IP-ul remote.
2. Daca `activeConns >= 1000`, inchide conexiunea.
3. Incrementeaza counter-ul per IP.
4. Daca valoarea devine `> 100`, decrementeaza inapoi si inchide conexiunea.
5. Incrementeaza `activeConns`.
6. La final, decrementeaza global si per IP.

### 9.3 Handshake TLS si identitate device

Dupa accept:

1. Ruleaza TLS handshake.
2. Daca handshake-ul esueaza, conexiunea se inchide.
3. Gateway citeste primul certificat client.
4. `certDeviceID` este `Subject.CommonName` al certificatului agent/device.
5. La `connect`, daca `certDeviceID` exista si difera de `request.device_id`, request-ul este refuzat cu `auth_invalid`.

Verificarea lantului certificatului este facuta de TLS folosind CA-ul configurat. Verificarea serialelor revocate este facuta in `VerifyConnection`.

### 9.4 Yamux

Dupa TLS, gateway creeaza server yamux peste conexiune.

Valori yamux:

- `MaxStreamWindowSize = 256 KiB`;
- `StreamOpenTimeout = 30s`;
- `StreamCloseTimeout = 5m`.

Fiecare stream yamux trimite un singur frame JSON initial. Gateway decodeaza `type`, apoi ruteaza:

- `hello`;
- `connect`;
- orice alt type este refuzat.

## 10. Protocol agent-gateway

### 10.1 Versiune protocol

Constante:

- `ProtocolVersion = "1.0"`;
- `ProtocolMinClientVersion = "1.0"`;
- `ProtocolMaxClientVersion = "1.0"`.

### 10.2 `hello`

Request:

```json
{
  "type": "hello",
  "client_version": "1.0",
  "client_app": "trustagent",
  "client_build": "build-id",
  "features": ["yamux", "mtls"]
}
```

Response:

```json
{
  "type": "hello_ack",
  "code": "ok",
  "server_version": "1.0",
  "min_client_version": "1.0",
  "max_client_version": "1.0",
  "features": ["pa-provisioned-connect", "yamux", "mtls"]
}
```

Daca `client_version` lipseste sau este gol, gateway raspunde cu:

- `type = "hello_ack"`;
- `code = "bad_request"`;
- `message = "client_version is required"`.

### 10.3 `connect`

Request:

```json
{
  "type": "connect",
  "session_id": "pa-session-id",
  "session_token": "raw-token-returned-to-agent",
  "device_id": "device-id",
  "resource_id": "resource-id",
  "protocol": "ssh",
  "remote_port": 22,
  "remote_addr": "ignored-by-strict-gateway",
  "token": "legacy-token-ignored",
  "process": {
    "pid": 1234,
    "name": "ssh.exe",
    "path": "C:/Windows/System32/OpenSSH/ssh.exe",
    "sha256": "optional",
    "signer": "optional"
  }
}
```

Campuri obligatorii in strict connect:

- `session_id`;
- `session_token`;
- `device_id`;
- `resource_id`;
- `protocol`;
- `remote_port`.

Campuri legacy/auxiliare:

- `remote_addr` exista in struct, dar gateway-ul strict nu o foloseste pentru dial.
- `token` exista pentru compatibilitate struct, dar bearer-token-only connect este refuzat.
- `process` este folosit doar in loguri.

Response la succes:

```json
{
  "type": "connect_response",
  "status": "connected",
  "code": "ok",
  "message": "connected"
}
```

Response la deny:

```json
{
  "type": "connect_response",
  "status": "denied",
  "code": "session_invalid",
  "message": "connect requires a PA-provisioned session_id and session_token"
}
```

### 10.4 Coduri protocol

Coduri definite:

- `ok`;
- `auth_invalid`;
- `session_invalid`;
- `session_expired`;
- `resource_unavailable`;
- `internal_error`;
- `bad_request`.

Mapari importante:

- JSON invalid: `bad_request`.
- Type necunoscut, inclusiv `dns_resolve`: `bad_request`.
- Lipsa `session_id` sau `session_token`: `session_invalid`.
- Certificatul device nu corespunde cu `device_id`: `auth_invalid`.
- Store fara sesiuni provisionate: `session_invalid`.
- Sesiune expirata: `session_expired`.
- Eroare dial catre resource intern: `resource_unavailable`.

## 11. Store-ul de sesiuni provisionate

Store-ul este in-memory si nu are persistenta pe disk. Daca procesul gateway restarteaza, sesiunile provisionate local dispar si trebuie reprovisionate de PA prin control stream.

### 11.1 Model sesiune

`provisioning.Session` contine:

- `ID`;
- `TokenHash`;
- `DeviceID`;
- `UserID`;
- `Username`;
- `ResourceID`;
- `ResourceName`;
- `InternalHost`;
- `InternalPort`;
- `Protocol`;
- `ExpiresAt`;
- `Constraints`;
- `PolicyVersion`;
- `MaxBandwidthMbps`;
- `CreatedAt`;
- `Revoked`;
- `RevokedAt`;
- `RevocationReason`.

`provisioning.ConnectCheck` este input-ul local pentru validarea unui request `connect` si contine:

- `SessionID`;
- `SessionToken`;
- `DeviceID`;
- `ResourceID`;
- `Protocol`;
- `Port`.

`provisioning.ValidationError` contine:

- `Code`;
- `Message`.

Metoda `Error()` intoarce `Message`; daca receiver-ul este nil, intoarce string gol.

`provisioning.Store` tine:

- mutex `sync.RWMutex`;
- functia de timp `now`;
- map-ul in-memory `sessions`.

`Store` nu este serializat si nu se salveaza pe disk.

### 11.2 Provision

La `Provision`, gateway:

- trimite `TrimSpace` pe ID-uri si string-uri relevante;
- normalizeaza protocolul cu lowercase + trim;
- cere `session_id`;
- cere token raw sau `TokenHash`;
- cere `device_id`;
- cere `resource_id`;
- cere `internal_host` si `internal_port > 0`;
- cere `expires_at` in viitor;
- daca protocolul este gol, il seteaza la `tcp`;
- daca exista token raw, salveaza doar SHA-256 hex;
- daca `CreatedAt` lipseste, il seteaza la `now`;
- copiaza lista de constraints ca sa evite mutatii externe;
- suprascrie sesiunea existenta cu acelasi ID.

Tokenul raw nu este pastrat in memorie. Se pastreaza doar hash SHA-256 hex.

### 11.3 Validate

La `Validate`, gateway cere:

- `session_id`;
- `session_token`;
- `device_id`;
- `resource_id`;
- `protocol`;
- `port > 0`.

Apoi verifica:

1. sesiunea exista;
2. sesiunea nu este revoked;
3. `ExpiresAt` este in viitor;
4. SHA-256(session_token) este egal constant-time cu `TokenHash`;
5. `device_id` este identic cu `Session.DeviceID`;
6. `resource_id` este identic cu `Session.ResourceID`;
7. `protocol` normalizat este identic cu `Session.Protocol`;
8. `remote_port` este identic cu `Session.InternalPort`.

La succes, intoarce o copie a sesiunii.

### 11.4 Coduri de validare provisioning

Coduri interne:

- `missing_session_id`;
- `session_not_found`;
- `session_expired`;
- `session_revoked`;
- `invalid_session_token`;
- `device_mismatch`;
- `resource_mismatch`;
- `protocol_mismatch`;
- `bad_request`.

In raspunsul public `connect_response`, majoritatea erorilor provisioning sunt transformate in `session_invalid`, cu exceptii:

- `bad_request` ramane `bad_request`;
- `session_expired` devine `session_expired`.

### 11.5 Revocare, delete si purge

`Revoke`:

- marcheaza sesiunea `Revoked = true`;
- seteaza `RevokedAt = now`;
- seteaza `RevocationReason`;
- pastreaza sesiunea in store;
- intoarce copie.

`Delete` sterge sesiunea complet.

`PurgeExpired`:

- sterge din store sesiunile expirate;
- intoarce copiile sesiunilor sterse;
- este chemat de dataplane la startup si la fiecare `1m`.

`ListSessions` intoarce copii, inclusiv copii ale listelor `Constraints`.

### 11.6 Functii auxiliare din sessions.go

`NewStore()` creeaza store cu `time.Now`.

`NewStoreWithClock(now)` creeaza store cu clock injectat. Daca `now` este nil, foloseste `time.Now`. Testele folosesc aceasta functie ca sa controleze expirarea.

`Count()` intoarce numarul curent de sesiuni din map sub read lock.

`hashToken(token)` calculeaza `sha256.Sum256` peste tokenul raw si intoarce hex lowercase.

`normalizeProtocol(protocol)` face `strings.TrimSpace` si lowercase.

`validationError(code, message)` creeaza `*ValidationError` cu codul si mesajul date.

`AsValidationError(err)` are trei comportamente:

- daca `err == nil`, intoarce `(nil, false)`;
- daca eroarea este deja `*ValidationError`, intoarce eroarea si `true`;
- pentru alte erori, construieste un `ValidationError` cu `CodeBadRequest` si mesaj `invalid session: ...`, dar intoarce flag `false`.

### 11.7 Detalii fine de implementare in Store

Ordinea si detaliile conteaza:

- `Provision` nu are guard pentru `store == nil`; presupune ca apelantul a creat store-ul prin `NewStore` sau `NewStoreWithClock`.
- `Validate`, `Revoke`, `Delete` si `Count` presupun si ele receiver valid; doar `ListSessions` si `PurgeExpired` verifica explicit `store == nil` si intorc `nil`.
- `Provision` foloseste `strings.TrimSpace` pe `ID`, `DeviceID`, `UserID`, `Username`, `ResourceID`, `ResourceName`, `InternalHost` si `PolicyVersion`.
- `Provision` normalizeaza `Protocol` prin `normalizeProtocol`, adica trim + lowercase.
- `Provision` testeaza prezenta tokenului raw cu `strings.TrimSpace(rawToken)`, dar daca raw token-ul exista, `hashToken(rawToken)` calculeaza SHA-256 peste valoarea raw originala, nu peste valoarea trimuita. Daca PA ar trimite token cu spatii la capete, hash-ul salvat ar include spatiile.
- Daca `rawToken` lipseste, `Provision` accepta un `TokenHash` existent si il salveaza dupa `strings.TrimSpace(session.TokenHash)`.
- Defaultul de protocol este atribuit exact prin `session.Protocol = "tcp"`.
- `Validate` trimuieste `SessionID`, `SessionToken`, `DeviceID`, `ResourceID` si normalizeaza `Protocol` inainte de verificari.
- `Validate` calculeaza hash-ul peste `SessionToken` deja trimuit.
- Comparatia tokenului se face cu `subtle.ConstantTimeCompare([]byte(session.TokenHash), []byte(hashToken(check.SessionToken)))`.
- `Provision` seteaza `CreatedAt = store.now()` doar cand `CreatedAt.IsZero()`.
- `Provision` refuza `ExpiresAt` zero sau orice expiry care nu este strict dupa `store.now()`.
- `Validate` considera sesiunea expirata cand `!session.ExpiresAt.After(store.now())`, deci o sesiune cu expiry egal cu momentul curent este expirata.
- `PurgeExpired` sterge doar sesiuni cu `ExpiresAt` nenul si care nu mai sunt dupa `now`; o sesiune cu `ExpiresAt.IsZero()` este ignorata de purge, desi `Provision` nu ar permite crearea unei astfel de sesiuni prin calea normala.
- `ListSessions`, `Validate`, `PurgeExpired` si `Revoke` intorc copii ale sesiunii si copiaza `Constraints` cu `append([]string(nil), session.Constraints...)`.
- `Delete` sterge direct intrarea din map si intoarce doar boolean, fara copie.
- `Revoke` face `strings.TrimSpace(sessionID)` si `strings.TrimSpace(reason)`. Pentru `sessionID` gol intoarce `(nil, false)`.
- `Delete` face `strings.TrimSpace(sessionID)`. Pentru ID gol sau inexistent intoarce `false`.
- `Count` intoarce direct `len(store.sessions)` sub read lock.

## 12. Relay TCP

### 12.1 Alegerea tintei

Gateway nu foloseste tinta ceruta de client.

Clientul trimite `remote_addr`, dar gateway-ul strict deschide TCP doar catre:

```text
Session.InternalHost:Session.InternalPort
```

Aceste valori vin exclusiv din comanda PA `provision_session`.

### 12.2 Dial

Relay-ul foloseste:

- protocol TCP;
- `net.DialTimeout`;
- timeout intern `10s`;
- validare host nevid;
- validare port `1..65535`.

Daca host-ul lipseste, portul e invalid sau timeout-ul este `<= 0`, dial-ul esueaza.

### 12.3 Conectare si bridging

Dupa validarea `connect`:

1. Gateway face TCP dial catre tinta interna.
2. Daca dial esueaza, raspunde `resource_unavailable`.
3. Daca dial reuseste, raspunde `connected`.
4. Creeaza `relayID` random de 8 bytes hex. Daca random esueaza, fallback-ul este `relay-{UnixNano}`.
5. Inregistreaza relay-ul activ in `activeRelays`.
6. Porneste watcher de expiry.
7. Porneste doua goroutine-uri de copy:
   - client -> target;
   - target -> client.
8. La EOF, eroare, expiry, revocare sau shutdown, inchide stream-ul si target connection.

### 12.4 Expiry si renewal pe relay activ

La deschiderea relay-ului, `watchRelayExpiry` seteaza timer pana la `Session.ExpiresAt`.

Daca PA reprovisioneaza aceeasi sesiune cu un `ExpiresAt` nou:

- `ProvisionSession` gaseste relay-uri active cu acelasi `session_id`;
- trimite noul expiry prin channel-ul `renew`;
- watcher-ul reseteaza timerul.

Daca noul expiry este deja trecut, relay-ul se inchide cu motiv `session.expired`.

### 12.5 Revocare relay activ

La `RevokeProvisionedSession`, gateway:

- marcheaza sesiunea revoked in store;
- cauta relay-uri active cu acelasi `session_id`;
- cheama cancel pe fiecare;
- inchide stream-ul si conexiunea target;
- logheaza cate relay-uri au fost terminate.

Motive interne folosite:

- `session.revoked`;
- `session.expired`;
- `gateway.shutdown`;
- `client.closed`;
- `target.closed`;
- `complete`.

### 12.6 Bandwidth limit

Valori:

- plafon global intern: `400 Mbps`;
- plafon per sesiune: `Session.MaxBandwidthMbps`, daca PA il seteaza;
- buffer relay: `64 KiB`.

Calcul:

```text
bytes_per_second = Mbps * 1024 * 1024 / 8
```

Daca `MaxBandwidthMbps > 0`, se foloseste acel plafon. Altfel se foloseste plafonul global `400 Mbps`.

Rate limit-ul este aplicat in fiecare directie de copy. Cand bytes copiati in fereastra curenta ating plafonul pe secunda, goroutine-ul doarme pana se implineste o secunda.

## 13. Loop-uri runtime dataplane

La pornirea listener-ului:

1. Sincronizeaza serialele revocate.
2. Curata sesiunile expirate.
3. Porneste revocation sync loop.
4. Porneste provisioned session cleanup loop.
5. Porneste session revalidation loop.
6. Porneste certificate expiry loop.

Valori interne:

- `revocationSyncInterval = 1m`;
- `sessionCleanupInterval = 1m`;
- `sessionRevalidationTimeout = 10s`;
- `certExpiryCheckInterval = 12h`;
- `certExpiryCriticalWindow = 7d`;
- `certExpiryWarningWindow = 30d`;
- `certRenewalCheckInterval = 6h`;
- `certRenewalWindow = 48h`.

### 13.1 Cert expiry monitor

Gateway monitorizeaza:

- `certs/gateway.crt`;
- `certs/pa-ca.crt`.

Loguri:

- daca fisierul nu poate fi citit, logheaza eroare;
- daca certificatul este expirat, logheaza data expirarii;
- daca expira in mai putin de `7d`, logheaza critic/s soon;
- daca expira in mai putin de `30d`, logheaza cate zile au ramas.

Acest loop doar logheaza; renewal-ul propriu-zis este in `StartCertRenewalLoop`.

## 14. Docker si deployment

### 14.1 Dockerfile

`Dockerfile.gateway`:

- build stage: `golang:1.25-alpine`;
- `WORKDIR /build`;
- ruleaza `go mod download`;
- compileaza cu `CGO_ENABLED=0 go build -o gateway ./cmd/gateway`;
- runtime stage: `alpine:3.20`;
- instaleaza `ca-certificates`;
- creeaza user non-root `appuser` cu UID/GID `1000`;
- `WORKDIR /app`;
- creeaza `/app/certs`;
- copiaza binarul;
- binarul este copiat din `/build/gateway`;
- copiaza `config.json`;
- ruleaza ca `appuser`;
- ownership-ul directorului `/app` este setat cu `chown -R appuser:appuser /app`;
- expune port `9443`;
- declara volume `/app/certs`;
- entrypoint `./gateway`.

### 14.2 docker-compose gateway local

`gateway/docker-compose.yml` defineste:

- network `gateway-net`;
- network extern `truststack-private`, mapat la `truststack_private`;
- volume `gateway-certs`, cu nume override prin `GATEWAY_CERT_VOLUME`;
- serviciu `gateway`;
- container name default `trustgateway`, override prin `GATEWAY_CONTAINER_NAME`;
- restart `unless-stopped`;
- port host default `9443`, override prin `GATEWAY_HOST_PORT`;
- env `GATEWAY_PA_URL`, default `https://mtls.trust-cloud.dev`;
- env `GATEWAY_ENROLLMENT_TOKEN`;
- env `GATEWAY_PUBLIC_ENDPOINT`, default `localhost:9443`, prin sintaxa compose `${GATEWAY_PUBLIC_ENDPOINT:-localhost:9443}`.

Comanda de startup din compose:

1. Daca `/app/certs/pa-ca.crt` lipseste si `/bootstrap/vault-pki-ca-cert.pem` exista, copiaza CA-ul din bootstrap.
2. Ruleaza `./gateway`.

Volume-uri:

- `./config.json:/app/config.json:ro`;
- `../pdp/data:/bootstrap:ro`;
- `gateway-certs:/app/certs`.

Config-ul este read-only. Enrollment state nu se salveaza in config, ci in certificatele din volume si in state-ul PA.

## 15. Suprafata gRPC folosita

Gateway apeleaza PA prin gRPC folosind `structpb.Struct`, nu mesaje generate local din `.proto`.

Metode exacte:

- `/gateway.GatewayEnrollmentService/Enroll`
- `/gateway.GatewayEnrollmentService/RenewCertificate`
- `/gateway.GatewayTrustService/GetCACertificate`
- `/gateway.GatewayTrustService/GetRevokedSerials`
- `/gateway.GatewayTrustService/RevalidateSessions`
- `/gateway.GatewayControlService/ControlStream`

`ControlStream` este stream bidirectional. Celelalte sunt unary.

## 16. Suprafata network expusa de gateway

Gateway expune catre agenti:

- TCP/TLS pe `:9443`;
- mTLS obligatoriu;
- yamux peste TLS;
- frame-uri JSON initiale per stream.

Gateway nu expune:

- HTTP admin API;
- dashboard;
- metrics endpoint;
- health endpoint;
- OIDC endpoint;
- SCIM endpoint;
- DNS endpoint;
- gRPC server public pentru administrare.

Comunicarea cu PA este outbound din gateway.

## 17. Fail-closed si erori importante

Gateway refuza sau opreste accesul cand:

- `config.json` lipseste;
- `pa_url` lipseste;
- `pa_url` nu este `https`;
- `public_endpoint` este invalid;
- lipseste tokenul de enrollment la prima pornire;
- lipsesc `gateway.crt`/`gateway.key` dupa enrollment;
- lipseste `pa-ca.crt` pentru listener agent-facing;
- certificatul gateway nu are EKU `serverAuth` si `clientAuth`;
- certificatul gateway este CA;
- certificatul gateway nu are identitate SPIFFE gateway;
- certificatul gateway nu are FQDN in DNS SAN;
- certificatul client agent este revocat;
- certificatul agent nu se potriveste cu `device_id`;
- `connect` nu include `session_id` si `session_token`;
- session token-ul nu se potriveste;
- device/resource/protocol/port nu se potrivesc cu sesiunea PA;
- sesiunea este expirata;
- sesiunea este revoked;
- resursa interna nu poate fi dialata;
- control stream-ul PA se opreste fara shutdown intentionat.

## 18. Functionalitati eliminate fata de variante legacy

Documentatia si codul curent confirma ca au fost eliminate:

- Gateway Admin UI;
- SessionStore microservice;
- Syslog service;
- SQLite resource store;
- Gateway DNS resolver;
- CGNAT allocator;
- local anomaly/risk engine;
- local user JWT/JWKS validation;
- `auth_request`;
- `dns_resolve`;
- bearer-token-only connect;
- configuratii locale `resources`, `internal_dns`, `cgnat`, `session_timeout`, `admin`, `sessionstore`, `syslog`.

`dns_resolve` este tratat ca request type nesuportat si primeste `bad_request`.

## 19. Constante, coduri si mesaje exacte

Aceasta sectiune listeaza numele exacte ale constantelor din cod, ca documentatia sa poata fi folosita si prin cautare directa dupa identifier.

### 19.1 Constante config

In `internal/config/config.go`:

- `FileName = "config.json"`;
- `EnrollmentTokenEnv = "GATEWAY_ENROLLMENT_TOKEN"`;
- `PublicEndpointEnv = "GATEWAY_PUBLIC_ENDPOINT"`;
- `PACAPath = "certs/pa-ca.crt"`;
- `GatewayCertPath = "certs/gateway.crt"`;
- `GatewayKeyPath = "certs/gateway.key"`;
- `GatewayCSRPath = "certs/gateway.csr"`.

### 19.2 Constante control plane

In `internal/controlplane/handler.go`:

- `ServiceName = "gateway.GatewayControlService"`;
- `ControlStreamPath = "/gateway.GatewayControlService/ControlStream"`;
- `CommandProvisionSession = "provision_session"`;
- `CommandRevokeSession = "revoke_session"`;
- `CommandHeartbeat = "heartbeat"`;
- `MessageGatewayHello = "gateway_hello"`;
- `MessageAck = "ack"`;
- `ackStatusOK = "ok"`;
- `ackStatusError = "error"`.

In `internal/controlplane/stream.go`:

- `controlReconnectMin = 1s`;
- `controlReconnectMax = 30s`.

In `internal/controlplane/client.go`:

- `requestTimeout = 10s`;
- `certRenewalTimeout = 20s`;
- `circuitMaxFailures = 5`;
- `circuitOpenTimeout = 30s`;
- `circuitProbeMaxDelay = 2s`.

In `internal/controlplane/trust.go`:

- `gatewayTrustGRPCGetCACertificate = "/gateway.GatewayTrustService/GetCACertificate"`;
- `gatewayTrustGRPCGetRevokedSerials = "/gateway.GatewayTrustService/GetRevokedSerials"`;
- `gatewayTrustGRPCRevalidateSessions = "/gateway.GatewayTrustService/RevalidateSessions"`;
- `gatewayEnrollmentGRPCRenewCert = "/gateway.GatewayEnrollmentService/RenewCertificate"`.

In `internal/enrollment/enrollment.go`:

- `gatewayEnrollmentGRPCEnroll = "/gateway.GatewayEnrollmentService/Enroll"`;
- `gatewayEnrollmentGRPCRenewCert = "/gateway.GatewayEnrollmentService/RenewCertificate"`.

### 19.3 Constante dataplane

In `internal/dataplane/server.go`:

- `agentListenAddr = ":9443"`;
- `relayDialTimeout = 10s`;
- `maxConnections = 1000`;
- `maxConnectionsPerIP = 100`;
- `relayBufferSizeBytes = 64 * 1024`;
- `yamuxMaxStreamWindowSize = 256 * 1024`;
- `yamuxStreamOpenTimeout = 30s`;
- `yamuxStreamCloseTimeout = 5m`;
- `revocationSyncInterval = 1m`;
- `sessionCleanupInterval = 1m`;
- `sessionRevalidationTimeout = 10s`;
- `certExpiryCheckInterval = 12h`;
- `certExpiryCriticalWindow = 7d`;
- `certExpiryWarningWindow = 30d`;
- `certRenewalCheckInterval = 6h`;
- `certRenewalWindow = 48h`;
- `maxRelayBandwidthMbps = 400`.

In `cmd/gateway/main.go`:

- `shutdownWait = 5s`.

### 19.4 Constante protocol agent-gateway

In `internal/dataplane/protocol.go`:

- `ProtocolVersion = "1.0"`;
- `ProtocolMinClientVersion = "1.0"`;
- `ProtocolMaxClientVersion = "1.0"`;
- `CodeOK = "ok"`;
- `CodeAuthInvalid = "auth_invalid"`;
- `CodeSessionInvalid = "session_invalid"`;
- `CodeSessionExpired = "session_expired"`;
- `CodeResourceUnavailable = "resource_unavailable"`;
- `CodeInternalError = "internal_error"`;
- `CodeBadRequest = "bad_request"`.

`CodeInternalError` este definit in protocol, dar codul curent de dataplane nu il foloseste intr-o ramura explicita de raspuns.

### 19.5 Coduri interne provisioning

In `internal/provisioning/sessions.go`:

- `CodeMissingSessionID = "missing_session_id"`;
- `CodeSessionNotFound = "session_not_found"`;
- `CodeSessionExpired = "session_expired"`;
- `CodeSessionRevoked = "session_revoked"`;
- `CodeInvalidToken = "invalid_session_token"`;
- `CodeDeviceMismatch = "device_mismatch"`;
- `CodeResourceMismatch = "resource_mismatch"`;
- `CodeProtocolMismatch = "protocol_mismatch"`;
- `CodeBadRequest = "bad_request"`.

Aceste coduri sunt interne store-ului de provisioning. La raspunsul public `connect_response`, `validateProvisionedConnect` le transforma in coduri de protocol mai generale, de obicei `session_invalid`.

### 19.6 Mesaje runtime relevante

Mesaje exacte care pot aparea in raspunsuri, erori sau loguri:

- `gateway certificate and key are required`;
- `Agent mTLS requires PA CA or a reachable PA CA endpoint`;
- `client certificate is required`;
- `invalid JSON frame`;
- `invalid hello frame`;
- `invalid connect frame`;
- `unsupported gateway request type`;
- `client_version is required`;
- `connect request is required`;
- `connect requires a PA-provisioned session_id and session_token`;
- `device certificate does not match connect request`;
- `no PA-provisioned sessions are available`;
- `internal resource is unavailable`;
- `session_id is required`;
- `session token is required`;
- `session_token is required`;
- `device_id is required`;
- `device identity is required`;
- `resource_id is required`;
- `protocol is required`;
- `internal resource host and port are required`;
- `session expiry must be in the future`;
- `session was not provisioned by the Policy Administrator`;
- `session was revoked`;
- `session expired`;
- `session token is invalid`;
- `session device binding mismatch`;
- `session resource binding mismatch`;
- `session protocol binding mismatch`;
- `session port binding mismatch`;
- `remote_port is required`;
- `PA gRPC response did not include ca_pem`;
- `pa_url must use https for gateway gRPC`;
- `pa_url must include a host`;
- `public_endpoint must be host:port`;
- `public_endpoint host is required`;
- `public_endpoint port must be between 1 and 65535`;
- `gateway_id is required`;
- `session handler is required`;
- `gateway control handler is nil`;
- `gateway control stream is nil`;
- `session object is required`;
- `current gateway certificate is required`;
- `gateway certificate is required`;
- `gateway certificate PEM is required`;
- `gateway certificate chain is empty`;
- `gateway certificate must allow digitalSignature key usage`;
- `gateway certificate must include both serverAuth and clientAuth extended key usages`;
- `gateway certificate does not contain gateway identity`;
- `gateway certificate does not contain gateway FQDN`.

### 19.7 Fixture-uri si valori de test

Unele string-uri apar doar in teste si nu reprezinta configuratie de productie:

- `gateway.example.test`;
- `gateway.internal.test`;
- `gateway.example.test:9443`;
- `spiffe://gateway/organization/org-1/gateway/gw-1`;
- `spiffe://gateway/account/organization-1/gateway/gw-1`;
- `device-1`;
- `device-2`;
- `session-secret`;
- `rotated-session-secret`;
- `stream-token`;
- `admin_revoked`;
- `policy.updated`;
- `managed_device`;
- `healthy_device_data`;
- `gateway_control.proto`.

Ele valideaza comportamente precum identitate SPIFFE, endpoint public, token hash, revocare si parsare control stream.

### 19.8 Simboluri Go exportate

Simboluri exportate din codul gateway, grupate pe pachet:

`internal/config`:

- tipuri: `Config`, `ControlPlaneConfig`;
- functii/metode: `DefaultConfig`, `Load`, `Validate`, `ApplyEnvironment`, `AtomicWriteFile`, `PATargetFromURL`.
- campuri `Config`: `PAURL`, `PublicEndpoint`, `SessionRevalidationInterval`, `EnrollmentToken`, `ControlPlane`.
- campuri `ControlPlaneConfig`: `GatewayID`, `OrganizationID`, `FQDN`.

`internal/cert`:

- tipuri: `GatewayIdentity`;
- functii: `GenerateGatewayPrivateKey`, `EncodePrivateKeyPEM`, `LoadGatewayKeyPair`, `LoadGatewayKeyPairAndValidateCert`, `ValidateGatewayCertificateForRenewal`, `ValidateGatewayCertificate`, `GatewayCertificateExpired`, `GatewayExtendedKeyUsageExtension`, `ParseGatewayCertificatePEM`, `GatewayIdentityFromCertificate`.

`internal/enrollment`:

- tipuri: `Result`, `EnrollmentStatus`;
- functii: `Ensure`.

`internal/controlplane`:

- tipuri: `Client`, `CircuitState`, `CircuitBreaker`, `CircuitBreakerConfig`, `RevalidationSession`, `SessionRevalidationResult`, `CertRenewalResponse`, `SessionHandler`, `Stream`, `Handler`, `HandlerOptions`;
- functii/metode: `NewClient`, `ReloadTLSCert`, `Close`, `Execute`, `State`, `Metrics`, `HalfOpenTimeouts`, `NewCircuitBreaker`, `RunControlStream`, `NewHandler`, `NewHandlerWithOptions`, `Run`, `HandleCommand`, `GetCACert`, `GetRevokedSerials`, `RevalidateSessions`, `RenewCert`.
- campuri `CircuitBreaker`: `state`, `failures`, `lastFailure`, `lastSuccess`, `maxFailures`, `timeout`, `halfOpenMaxLatency`, `totalTrips`, `totalSuccess`, `totalFailure`, `totalHalfOpenTimeout`.
- campuri `CircuitBreakerConfig`: `MaxFailures`, `OpenTimeout`, `HalfOpenMaxLatency`.
- campuri `RevalidationSession`: `SessionID`, `DeviceID`, `ResourceID`, `Protocol`, `ExpiresAt`.
- campuri `SessionRevalidationResult`: `SessionID`, `Status`, `Reason`.
- campuri `CertRenewalResponse`: `GatewayID`, `Status`, `CertPEM`, `CAPEM`, `Message`.
- campuri `HandlerOptions`: `PublicEndpoint`, `Now`.

`internal/dataplane`:

- tipuri: `ConnectRequest`, `ProcessIdentity`, `ConnectResponse`, `HelloRequest`, `HelloResponse`, `Gateway`, `Relay`;
- functii/metode: `New`, `ProvisionSession`, `RevokeProvisionedSession`, `ProvisionedSessionCount`, `ListenAndServe`, `StartCertRenewalLoop`, `Shutdown`, `NewRelay`, `Connect`.
- campuri `ConnectRequest`: `Type`, `RemoteAddr`, `RemotePort`, `Token`, `SessionID`, `SessionToken`, `ResourceID`, `Protocol`, `DeviceID`, `Process`.
- campuri `ProcessIdentity`: `PID`, `Name`, `Path`, `SHA256`, `Signer`.
- campuri `ConnectResponse`: `Type`, `Status`, `Code`, `Message`.
- campuri `HelloRequest`: `Type`, `ClientVersion`, `ClientApp`, `ClientBuild`, `Features`.
- campuri `HelloResponse`: `Type`, `Code`, `ServerVersion`, `MinClientVersion`, `MaxClientVersion`, `Features`, `Message`.
- campuri interne `Gateway`: `cfg`, `controlPlane`, `relay`, `provisioned`, `ctx`, `cancel`, `activeConns`, `perIPConns`, `revokedSerials`, `activeRelays`.
- campuri `Relay`: `DialTimeout`.

`internal/provisioning`:

- tipuri: `ValidationError`, `Session`, `ConnectCheck`, `Store`;
- functii/metode: `Error`, `NewStore`, `NewStoreWithClock`, `Provision`, `Validate`, `ListSessions`, `PurgeExpired`, `Revoke`, `Delete`, `Count`, `AsValidationError`.

### 19.9 Helper-e Go neexportate

Simboluri neexportate relevante, grupate pe pachet/fisier:

`cmd/gateway/main.go`:

- `main`: incarca config-ul, ruleaza enrollment, porneste control plane-ul, dataplane-ul si renewal loop-ul.
- `shutdownGateway`: cheama `Gateway.Shutdown()` si asteapta maximum `shutdownWait` dupa `serverErr`.

`internal/config/config.go`:

- `resolveSecretRef`: intoarce valoarea raw daca nu incepe cu `file:`; altfel citeste fisierul indicat si intoarce continutul trimuit.
- `validatePublicEndpoint`: verifica formatul strict `host:port`, host nevid si port in intervalul `1..65535`.

`internal/cert/certificate.go`:

- `validateGatewayCertificateProfile`: valideaza profilul structural al certificatului gateway fara verificarea ferestrei temporale pentru renewal.
- `gatewayIdentityFromURI`: parseaza URI SAN `spiffe` de forma `/organization/{organization_id}/gateway/{gateway_id}`.
- `hasExtKeyUsage`: verifica daca lista EKU contine `ExtKeyUsageAny` sau EKU-ul cerut.

`internal/enrollment/enrollment.go`:

- `enrollRequest`: struct intern cu `Token` si `CSRPEM`.
- `enrollResponse`: struct intern cu `Status`, `CertPEM`, `CAPEM` si `Message`.
- `loadExistingEnrollment`: incarca certificatul local, decide daca este existing sau trebuie renewal.
- `enrollWithToken`: ruleaza enrollment initial cu tokenul din env.
- `renewExistingEnrollment`: ruleaza renewal la startup pentru certificat expirat.
- `writeEnrollmentKeyAndCSR`: scrie cheia si CSR-ul initial.
- `writeRenewedCertificateAndKey`: scrie cheia noua si certificatul reinnoit.
- `writeEnrollmentCertificate`: scrie `gateway.crt` si, daca exista, `pa-ca.crt`.
- `applyGatewayIdentity`: copiaza identitatea extrasa in `cfg.ControlPlane`.
- `resultFromIdentity`: construieste `Result` din identitatea gateway.
- `createCSR`: genereaza cheia P-256 si CSR-ul initial cu EKU gateway.
- `createRenewalCSR`: genereaza cheia P-256 noua si CSR-ul de renewal copiind SAN-urile certificatului curent.
- `enrollGateway`: apeleaza `/gateway.GatewayEnrollmentService/Enroll`.
- `renewGatewayGRPC`: apeleaza `/gateway.GatewayEnrollmentService/RenewCertificate` in fluxul de enrollment package.
- `enrollResponseFromStruct`: converteste `structpb.Struct` in `enrollResponse`.
- `enrollmentTLSConfig`: creeaza TLS 1.3 pentru enrollment si adauga `pa-ca.crt` daca exista.
- `enrollmentRenewalTLSConfig`: extinde TLS config-ul cu certificatul gateway pentru mTLS renewal.
- `structFieldString`: citeste string trimuit din `structpb.Struct`.
- `hasFile`: verifica daca path-ul exista si nu este director.

`internal/controlplane/client.go`:

- `buildTLSConfig`: creeaza TLS 1.3, Root CA din `pa-ca.crt` si certificatul gateway mTLS.
- `paRootCAPool`: citeste si parseaza `certs/pa-ca.crt`.
- `invokeUnary`: ruleaza apel unary prin circuit breaker.
- `invokeUnaryOnce`: deschide conexiune gRPC, invoca metoda si inchide conexiunea.
- `dial`: creeaza `grpc.ClientConn` cu TLS config clonat.
- `grpcTLSConfig`: cloneaza TLS config-ul curent sub read lock.

`internal/controlplane/fields.go`:

- `structFieldString`: citeste string trimuit din `structpb.Struct`.
- `nestedString`: citeste string trimuit dintr-un obiect nested.
- `intField`: citeste integer pozitiv obligatoriu.
- `optionalIntField`: citeste integer nenegativ optional.
- `timeField`: parseaza timestamp RFC3339/RFC3339Nano obligatoriu.
- `stringListField`: parseaza lista de string-uri, cu optiune `required`.
- `firstNonEmpty`: intoarce prima valoare nevida dupa trim.

`internal/controlplane/handler.go`:

- `helloMessage`: construieste mesajul initial `gateway_hello`.
- `ack`: construieste raspunsul `ack` cu status, code optional si timestamp.
- `sessionFromCommand`: parseaza obiectul `session` din comanda `provision_session`.

`internal/controlplane/stream.go`:

- `runControlStreamOnce`: deschide o conexiune si un stream `ControlStream`, apoi ruleaza handler-ul pana la EOF sau eroare.

`internal/dataplane/server.go`:

- `connectionState`: tine `remoteAddr` si `certDeviceID` pentru conexiunea agent.
- `activeRelay`: tine `id`, `sessionID`, `deviceID`, `resourceID`, canalul `renew` si callback-ul `cancel`.
- `listen`: creeaza listener TCP si il infasoara in TLS.
- `buildServerTLSConfig`: creeaza TLS server config cu mTLS agent si verificare seriale revocate.
- `loadGatewayServerCertificate`: incarca si valideaza `gateway.crt` + `gateway.key`.
- `clientCAPool`: construieste pool-ul CA pentru certificate agent din `pa-ca.crt` si, optional, CA obtinut prin PA.
- `handleConnection`: aplica limitele de conexiuni, face TLS handshake si porneste yamux.
- `handleStream`: decodeaza frame-ul JSON initial si ruteaza `hello`/`connect`.
- `handleHello`: raspunde cu `hello_ack`.
- `handleConnectRequest`: valideaza sesiunea, conecteaza relay-ul si porneste copy bidirectional.
- `validateProvisionedConnect`: mapeaza request-ul `connect` catre validarea store-ului provisioning si codurile de protocol.
- `syncRevokedSerials`: cere serialele revocate de la PA si actualizeaza cache-ul local.
- `revocationSyncLoop`: ruleaza `syncRevokedSerials` la `revocationSyncInterval`.
- `sessionRevalidationLoop`: ruleaza `revalidateProvisionedSessions` la intervalul configurat.
- `provisionedSessionCleanupLoop`: ruleaza cleanup pentru sesiuni expirate la `sessionCleanupInterval`.
- `cleanupExpiredProvisionedSessions`: sterge sesiuni expirate si inchide relay-urile lor.
- `revalidateProvisionedSessions`: trimite lista de sesiuni catre PA si revoca local ce PA considera invalid.
- `certExpiryLoop`: ruleaza verificarea de expirare certificate la `certExpiryCheckInterval`.
- `checkCertExpiry`: logheaza certificate expirate sau aproape de expirare.
- `renewCertIfNeeded`: face renewal daca certificatul gateway expira in fereastra de `certRenewalWindow`.
- `identityForCertificateRenewal`: citeste gateway ID-ul din `cfg.ControlPlane`.
- `terminateRelays`: inchide relay-uri active care satisfac predicatul primit.
- `renewActiveRelays`: trimite un nou expiry catre relay-urile active pentru aceeasi sesiune.
- `watchRelayExpiry`: inchide relay-ul la expiry sau reseteaza timerul la renewal.
- `incIP`: incrementeaza counter-ul per IP.
- `decIP`: decrementeaza counter-ul per IP si sterge intrarea cand ajunge la zero.
- `relayLimitBytesPerSecond`: converteste Mbps in bytes/secunda, preferand limita de sesiune peste cea globala.
- `processLogName`: alege numele de proces pentru log din `Name`, apoi `Path`, apoi `PID`.
- `remoteIPOnly`: extrage host-ul din remote address.
- `firstNonEmptyString`: intoarce primul string nevid dupa trim.
- `newRelayID`: genereaza 8 bytes random hex, cu fallback `relay-{UnixNano}`.
- `serialLookupKeys`: construieste chei de lookup pentru serialul certificatului client.
- `normalizedSerialKeys`: normalizeaza serialele in forme decimal/hex/lowercase.
- `rateLimitedCopy`: copiaza bytes cu buffer fix si throttle pe fereastra de o secunda.
- `atoi`: parseaza integer dupa trim; in codul curent nu este folosit de fluxul principal.

`internal/provisioning/sessions.go`:

- `hashToken`: SHA-256 peste token si output hex lowercase.
- `normalizeProtocol`: trim + lowercase.
- `validationError`: creeaza `ValidationError`.

## 20. Teste existente

Din `gateway/`, comenzile recomandate sunt:

```powershell
go test ./...
go vet ./...
```

Testele existente acopera:

- validarea `public_endpoint`;
- override `GATEWAY_PUBLIC_ENDPOINT`;
- default `session_revalidation_interval = 30s`;
- parsarea `pa_url`;
- enrollment initial si renewal;
- profil certificat gateway;
- identitate SPIFFE gateway;
- comanda `provision_session`;
- includerea `gateway_endpoint` in hello;
- comanda `revoke_session`;
- comenzi malformed;
- circuit breaker;
- trust calls;
- control stream;
- sesiuni provisionate PA;
- respingere bearer-token-only connect;
- revocare sesiuni;
- terminare relay-uri la revocare;
- reinnoire expiry pentru relay-uri active;
- cleanup sesiuni expirate;
- respingere `dns_resolve`;
- store token hash;
- binding device/resource/protocol/port;
- copii defensive pentru constraints;
- relay dial validation.

Nume exacte de teste prezente in gateway:

- `TestValidateAcceptsPublicEndpointWithPort`;
- `TestValidateRejectsPublicEndpointWithoutPort`;
- `TestApplyEnvironmentOverridesPublicEndpoint`;
- `TestValidateDefaultsSessionRevalidationInterval`;
- `TestGenerateGatewayPrivateKeyUsesECDSAP256`;
- `TestValidateGatewayCertificateAcceptsDualUseCertificate`;
- `TestValidateGatewayCertificateRejectsSingleUseCertificate`;
- `TestValidateGatewayCertificateRejectsExpiredCertificate`;
- `TestValidateGatewayCertificateRejectsNotYetValidCertificate`;
- `TestGatewayIdentityFromCertificateReadsPAIdentity`;
- `TestGatewayIdentityFromCertificateRequiresFQDN`;
- `TestGatewayIdentityFromCertificateRejectsInvalidOrganizationPath`;
- `TestHandleProvisionSessionCommand`;
- `TestHelloMessageIncludesPublicEndpoint`;
- `TestHandleRevokeSessionCommand`;
- `TestHandleProvisionSessionRejectsMalformedCommand`;
- `TestRunControlStreamOnceUsesMTLSAndAppliesCommands`;
- `TestStringListFieldReadsRevokedSerials`;
- `TestStringListFieldRejectsMalformedResponse`;
- `TestValidateProvisionedConnectAcceptsPASession`;
- `TestValidateProvisionedConnectRejectsLegacyBearerOnly`;
- `TestRevokeProvisionedSessionDeniesConnect`;
- `TestRevokeProvisionedSessionTerminatesActiveRelays`;
- `TestProvisionSessionRenewsActiveRelays`;
- `TestCleanupExpiredProvisionedSessionsRemovesSessionsAndTerminatesRelays`;
- `TestDNSResolveIsNotAcceptedByStrictGateway`;
- `TestStoreValidatesProvisionedSession`;
- `TestStoreRejectsInvalidBindings`;
- `TestStoreRejectsExpiredAndRevokedSessions`;
- `TestStoreListSessionsReturnsCopies`;
- `TestStorePurgeExpiredRemovesExpiredSessions`.

## 21. Checklist de operare

Cand se modifica gateway-ul, verifica explicit:

- daca s-a adaugat un camp JSON in `internal/config`, documenteaza-l aici;
- daca s-a adaugat o env var, documenteaza override-ul si prioritatea;
- daca se schimba path-uri de certificate, actualizeaza sectiunea PKI;
- daca se schimba constante de timeout/interval, actualizeaza valorile exacte;
- daca se schimba protocolul `hello` sau `connect`, actualizeaza JSON-ul;
- daca se adauga o comanda control plane, documenteaza payload-ul si ack-ul;
- daca se schimba validarea sesiunilor, actualizeaza codurile fail-closed;
- daca se schimba Docker compose, actualizeaza porturile, env-urile si volume-urile;
- daca se introduce persistenta, documenteaza cum interactioneaza cu PA si cu revocarea;
- daca se introduce vreun endpoint inbound nou, documenteaza suprafata expusa si autentificarea.
