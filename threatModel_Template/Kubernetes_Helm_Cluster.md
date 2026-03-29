# Kubernetes / Helm Cluster — Quick Reference

See the full model with GDAF context in `Kubernetes_Helm_Cluster/model.md`.

## Architecture Summary
- **Ingress / DMZ**: Cloud LB → Nginx ingress controller (internet-facing)
- **Frontend Namespace**: React SPA pods (stateless, HPA)
- **Backend Namespace**: Node.js API + async workers (Vault sidecar for secrets)
- **Data Namespace**: PostgreSQL StatefulSet, Redis, Kafka (all TLS + auth)
- **Platform Namespace**: HashiCorp Vault, cert-manager, Harbor registry
- **Observability Namespace**: Prometheus, Grafana (OIDC SSO)
- **Control Plane**: kube-apiserver + etcd (highest trust boundary)

## Key Threats Covered
- Container escape via privileged pod → host compromise
- ServiceAccount token theft → lateral movement to kube-apiserver
- RBAC misconfiguration → privilege escalation to cluster-admin
- Supply chain attack via malicious container image (Harbor / CI/CD)
- SSRF from backend pod → EC2/GCP metadata API → IAM credential theft
- Lateral movement via service mesh (Istio sidecar bypass)
- etcd direct access → Kubernetes Secret exfiltration
- Helm chart injection via compromised CI/CD runner

## Usage
```bash
secopstm --model-file threatModel_Template/Kubernetes_Helm_Cluster/model.md \
         --output-format all --navigator
```
