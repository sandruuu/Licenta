# TrustCloud Deploy

Deployment-ul este impartit pe medii si responsabilitati:

- `kubernetes/`: componentele care ruleaza in Kubernetes: Vault, PostgreSQL, Redis, PDP si suportul pentru Ingress/cert-manager.
- `digitalocean/edge-private/`: infrastructura pentru gateway-ul din DMZ si resursele interne din aceeasi retea privata DigitalOcean.

PDP-ul ramane componenta publica de control. Gateway-ul si resursele interne se creeaza separat, ca sa fie mai clar ce este control plane si ce este zona privata de acces.
