# Gateway DMZ si Resurse Private

Acest pachet creeaza o zona simpla pentru demo/licenta:

```text
Internet
  |
  | agenti -> gateway:9443
  v
Gateway Droplet
  | acelasi VPC privat
  v
Resurse interne Droplets
```

Toate Droplet-urile sunt in acelasi VPC DigitalOcean. Gateway-ul are endpoint public controlat prin firewall, iar resursele interne accepta trafic doar de la IP-ul privat al gateway-ului.

## Structura

- `terraform/`: creeaza VPC, Droplets si firewall-uri.
- `cloud-init/`: scripturi de initializare pentru gateway, resurse web interne si resurse RDP interne.
- `gateway/`: runtime Docker Compose pentru gateway.

## Pregatire

1. Creeaza un token DigitalOcean.
2. Adauga cheia ta SSH in DigitalOcean si noteaza fingerprint-ul.
3. Extrage CA-ul public al PDP-ului:

```powershell
kubectl --kubeconfig C:\Users\laura\Desktop\config.yaml -n trustcloud exec deploy/pdp -- cat /app/data/vault-pki-ca-cert.pem > gateway-pa-ca.crt
```

4. Converteste CA-ul in base64 pentru Terraform:

```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("gateway-pa-ca.crt"))
```

5. Copiaza exemplul de variabile:

```powershell
Copy-Item deploy\digitalocean\edge-private\terraform\terraform.tfvars.example deploy\digitalocean\edge-private\terraform\terraform.tfvars
```

6. Completeaza `terraform.tfvars` cu:

- `do_token`
- `ssh_key_fingerprints`
- `ssh_allowed_cidrs`
- `gateway_enrollment_token`
- `pdp_ca_pem_base64`

## Creare infrastructura

```powershell
cd deploy\digitalocean\edge-private\terraform
terraform init
terraform plan
terraform apply
```

## Dupa creare

Terraform va afisa:

- IP-ul public al gateway-ului;
- IP-ul privat al gateway-ului;
- IP-urile private ale resurselor web interne;
- IP-urile private ale resurselor RDP interne.

In PDP, pentru fiecare resursa interna foloseste:

- `Host`: IP-ul privat al resursei;
- `Port`: `8080`;
- `Gateway`: gateway-ul inrolat.

Exemplu:

```text
Resource host: 10.40.0.12
Resource port: 8080
```

Pentru resursa RDP foloseste output-ul `rdp_resource_private_ips`:

```text
Resource host: 10.40.0.13
Resource port: 3389
```

Credentialele RDP demo sunt configurate prin `rdp_user` si `rdp_password` in `terraform.tfvars`.

## Stergere

Ca sa nu consumi credit DigitalOcean:

```powershell
cd deploy\digitalocean\edge-private\terraform
terraform destroy
```
