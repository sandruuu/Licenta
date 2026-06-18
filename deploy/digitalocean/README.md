# TrustCloud DigitalOcean Deploy

Acest director contine deployment-uri DigitalOcean care nu fac parte direct din manifestele Kubernetes.

- `edge-private/`: creeaza un VPC, un gateway expus controlat catre internet si resurse interne accesibile doar prin reteaua privata.

Pentru PDP in Kubernetes foloseste in continuare `deploy/kubernetes`.
