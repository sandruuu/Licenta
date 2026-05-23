# TrustAgent WFP Driver

`trustagent_wfp.sys` este componenta nativa Windows care face doar redirectarea conexiunilor TCP IPv4 catre spatiul sintetic `100.64.0.0/10`.

Driverul nu decide accesul la resurse si nu comunica direct cu PDP. Service-ul Go ramane singura componenta care:

- primeste catalogul autentificat;
- instaleaza regulile de interceptare;
- rezolva `synthetic_ip -> resource_id`;
- cere decizia de acces;
- deschide stream-ul catre Gateway.

## Contract cu service-ul Go

Device object:

```text
\\.\TrustAgentWfp
```

IOCTL-uri:

- `IOCTL_TRUSTAGENT_WFP_APPLY_RULES`
- `IOCTL_TRUSTAGENT_WFP_CLEAR_RULES`
- `IOCTL_TRUSTAGENT_WFP_QUERY_ORIGINAL_TARGET`

Payload-ul pentru `APPLY_RULES` este binar little-endian:

```text
TRUSTAGENT_WFP_APPLY_RULES
  Magic        uint32  // "TAWF"
  Version      uint16  // 1
  Flags        uint16  // bit 0 = fail closed
  ProxyIpv4    uint32
  ProxyPort    uint16
  Reserved     uint16
  ProxyPid     uint32
  RuleCount    uint32
  Rules[]      TRUSTAGENT_WFP_RULE

TRUSTAGENT_WFP_RULE
  SyntheticIpv4 uint32
  Port          uint16 // 0 = orice port
  Protocol      uint8  // 6 = TCP
  Reserved      uint8
```

Driverul implementeaza doar redirectarea conexiunilor TCP IPv4. IPv6 si UDP nu fac parte din designul curent al TrustAgent.

## Flux asteptat

1. Service-ul primeste catalogul de la PDP.
2. Resolverul local prealoca IP-urile sintetice pentru FQDN-urile din catalog.
3. Service-ul porneste proxy-ul local pe `127.0.0.1:<port>`.
4. Service-ul trimite regulile catre `trustagent_wfp.sys`.
5. Driverul instaleaza provider, sublayer, callout si filtru WFP pe `ALE_CONNECT_REDIRECT_V4`.
6. Aplicatia face `connect(100.64.x.y:port)`.
7. Driverul redirectioneaza conexiunea catre proxy-ul local.
8. Driverul ataseaza destinatia originala ca WFP redirect context.
9. Proxy-ul citeste contextul prin `SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT`.
10. Service-ul mapeaza destinatia la `resource_id` si continua cu autorizarea/tunelul.

## Build

Driverul se construieste separat de binarul Go, cu Visual Studio Build Tools si Windows Driver Kit instalate:

```powershell
cd agent\wfp-driver
.\build-driver.ps1 -Configuration Release -Platform x64
```

Output-ul WDK contine:

- `trustagent_wfp.sys`;
- `trustagent_wfp.inf`;
- `trustagent_wfp.cat`.

Pentru instalare pe un endpoint normal, driverul trebuie semnat. Pentru test local se poate folosi test-signing pe o masina de dezvoltare:

```powershell
bcdedit /set testsigning on
```

dupa care sistemul trebuie repornit.

Instalare locala pe masina de dezvoltare, din PowerShell Administrator:

```powershell
cd C:\Users\laura\Desktop\Licenta\agent\wfp-driver
& "C:\Program Files (x86)\Windows Kits\10\Tools\10.0.26100.0\x64\devcon.exe" install `
  ".\x64\Release\trustagent_wfp\trustagent_wfp.inf" Root\TrustAgentWfp
sc.exe start trustagent_wfp
```

Pana cand driverul este instalat si validat, `traffic_interception_enabled` trebuie lasat `false` in `config.json`.
