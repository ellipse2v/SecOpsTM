# Threat Model: Kubernetes / Helm Cluster

## Description
Production Kubernetes cluster deployed via Helm, with three application namespaces
(frontend, backend, data), a shared observability namespace, and a dedicated platform
namespace for cluster-wide services (ingress controller, cert-manager, Vault).
The control plane (kube-apiserver, etcd) is isolated in its own trust boundary.
Pod-to-pod communication is governed by NetworkPolicy; mTLS is enforced in the
service mesh (Istio sidecar). External traffic enters via an Nginx ingress controller
fronted by a cloud load balancer.

## Context
gdaf_context = context/gdaf_context.yaml

## Boundaries
- **Internet**: color=lightcoral, isTrusted=False
- **Ingress / DMZ**: color=orange, isTrusted=False, traversal_difficulty=medium
- **Frontend Namespace**: color=lightyellow, isTrusted=True, traversal_difficulty=medium
- **Backend Namespace**: color=lightgreen, isTrusted=True, traversal_difficulty=high
- **Data Namespace**: color=lightblue, isTrusted=True, traversal_difficulty=high
- **Platform Namespace**: color=mediumpurple, isTrusted=True, traversal_difficulty=high
- **Observability Namespace**: color=lightgray, isTrusted=True, traversal_difficulty=medium
- **Control Plane**: color=darkred, isTrusted=True, traversal_difficulty=high

## Actors
- **End User**: boundary="Internet", description="External user accessing the application"
- **Developer**: boundary="Internet", description="Operator using kubectl / Helm to deploy workloads"
- **CI/CD Pipeline**: boundary="Internet", description="GitHub Actions / GitLab CI runner deploying Helm releases"
- **Attacker**: boundary="Internet", description="Threat actor attempting cluster compromise"

## Servers
- **Cloud Load Balancer**: boundary="Ingress / DMZ", type="load_balancer",
  description="Cloud LB (AWS NLB / GCP GLB) — terminates TLS, forwards to ingress"
- **Ingress Controller (Nginx)**: boundary="Ingress / DMZ", type="web_server",
  description="Nginx ingress controller — routes HTTP/S traffic to services via Ingress objects",
  internet_facing=True
- **Frontend Pod (React SPA)**: boundary="Frontend Namespace", type="web_server",
  description="Stateless React frontend served via Nginx container, HPA enabled"
- **Backend API Pod (Node.js)**: boundary="Backend Namespace", type="api_server",
  description="REST/GraphQL API, reads secrets from Vault via sidecar injector",
  credentials_stored=True
- **Worker Pod (async jobs)**: boundary="Backend Namespace", type="microservice",
  description="Celery/BullMQ worker consuming tasks from message broker"
- **PostgreSQL (StatefulSet)**: boundary="Data Namespace", type="database",
  description="Primary PostgreSQL with streaming replication; PVCs on encrypted EBS",
  credentials_stored=True
- **Redis (StatefulSet)**: boundary="Data Namespace", type="cache",
  description="Session store and job queue; AUTH enabled, TLS in-cluster"
- **Message Broker (Kafka)**: boundary="Data Namespace", type="message_broker",
  description="Kafka cluster (Strimzi operator); SASL/SCRAM auth, TLS between brokers"
- **Vault (Platform)**: boundary="Platform Namespace", type="secrets_manager",
  description="HashiCorp Vault — Kubernetes auth method, dynamic DB credentials",
  credentials_stored=True
- **Cert-Manager**: boundary="Platform Namespace", type="pki",
  description="Issues and rotates TLS certificates via ACME / internal CA"
- **Container Registry (Harbor)**: boundary="Platform Namespace", type="registry",
  description="Private OCI registry with vulnerability scanning; push requires OIDC token"
- **Prometheus + Alertmanager**: boundary="Observability Namespace", type="monitoring",
  description="Metrics collection via ServiceMonitor CRDs; Alertmanager sends PagerDuty alerts"
- **Grafana**: boundary="Observability Namespace", type="web_server",
  description="Dashboards; SSO via OIDC, read-only datasource credentials in Secret"
- **kube-apiserver**: boundary="Control Plane", type="api_server",
  description="Kubernetes API server — RBAC enforced, audit logging enabled, no anonymous auth",
  credentials_stored=True
- **etcd**: boundary="Control Plane", type="database",
  description="etcd cluster; client cert auth, encrypted at rest, not exposed outside control plane",
  credentials_stored=True

## Data
- **JWT / OIDC Tokens**: credentialsLife=SHORT, classification=SECRET,
  description="Short-lived tokens issued by OIDC provider for user and service authentication"
- **Database Credentials (Vault dynamic)**: credentialsLife=SHORTLIVED, classification=SECRET,
  description="Vault-issued Postgres credentials with TTL ≤ 1h"
- **Kubernetes Secrets**: credentialsLife=UNKNOWN, classification=SECRET,
  description="Base64-encoded secrets mounted as env vars or volumes in pods"
- **TLS Certificates**: credentialsLife=LONG, classification=RESTRICTED,
  description="Cluster-internal and external TLS certs managed by cert-manager"
- **Container Images**: credentialsLife=NONE, classification=RESTRICTED,
  description="OCI images stored in Harbor; signed with cosign, scanned on push"
- **Application Logs**: credentialsLife=NONE, classification=INTERNAL,
  description="Structured JSON logs shipped to Loki; may contain PII if not filtered"
- **Metrics**: credentialsLife=NONE, classification=INTERNAL,
  description="Prometheus time-series metrics, no credentials"
- **User PII**: credentialsLife=NONE, classification=SENSITIVE,
  description="User profile data stored in PostgreSQL, encrypted columns for PII fields"

## Dataflows
- **User HTTPS Request**: from="End User", to="Cloud Load Balancer", protocol="HTTPS"
- **LB to Ingress**: from="Cloud Load Balancer", to="Ingress Controller (Nginx)", protocol="HTTPS"
- **Ingress to Frontend**: from="Ingress Controller (Nginx)", to="Frontend Pod (React SPA)", protocol="HTTP"
- **Ingress to Backend API**: from="Ingress Controller (Nginx)", to="Backend API Pod (Node.js)", protocol="HTTP"
- **Frontend to Backend API**: from="Frontend Pod (React SPA)", to="Backend API Pod (Node.js)", protocol="HTTP"
- **Backend API to PostgreSQL**: from="Backend API Pod (Node.js)", to="PostgreSQL (StatefulSet)", protocol="PostgreSQL/TLS"
- **Backend API to Redis**: from="Backend API Pod (Node.js)", to="Redis (StatefulSet)", protocol="Redis/TLS"
- **Backend API to Kafka**: from="Backend API Pod (Node.js)", to="Message Broker (Kafka)", protocol="Kafka/SASL"
- **Worker to Kafka**: from="Worker Pod (async jobs)", to="Message Broker (Kafka)", protocol="Kafka/SASL"
- **Worker to PostgreSQL**: from="Worker Pod (async jobs)", to="PostgreSQL (StatefulSet)", protocol="PostgreSQL/TLS"
- **Backend API to Vault**: from="Backend API Pod (Node.js)", to="Vault (Platform)", protocol="HTTPS"
- **Worker to Vault**: from="Worker Pod (async jobs)", to="Vault (Platform)", protocol="HTTPS"
- **Prometheus Scrape**: from="Prometheus + Alertmanager", to="Backend API Pod (Node.js)", protocol="HTTP"
- **Grafana to Prometheus**: from="Grafana", to="Prometheus + Alertmanager", protocol="HTTP"
- **Developer kubectl**: from="Developer", to="kube-apiserver", protocol="HTTPS/mTLS"
- **CI/CD Helm Deploy**: from="CI/CD Pipeline", to="kube-apiserver", protocol="HTTPS/mTLS"
- **CI/CD Image Push**: from="CI/CD Pipeline", to="Container Registry (Harbor)", protocol="HTTPS"
- **Ingress Controller to kube-apiserver**: from="Ingress Controller (Nginx)", to="kube-apiserver", protocol="HTTPS/mTLS"
- **Cert-Manager to kube-apiserver**: from="Cert-Manager", to="kube-apiserver", protocol="HTTPS/mTLS"
- **etcd to kube-apiserver**: from="etcd", to="kube-apiserver", protocol="gRPC/mTLS", bidirectional=True
- **Attacker via exposed API**: from="Attacker", to="Ingress Controller (Nginx)", protocol="HTTPS"
- **Attacker SSRF to metadata**: from="Attacker", to="kube-apiserver", protocol="HTTP"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=solid
- **HTTPS/mTLS**: color=darkgreen, line_style=solid
- **gRPC/mTLS**: color=teal, line_style=solid
- **PostgreSQL/TLS**: color=purple, line_style=solid
- **Redis/TLS**: color=darkorange, line_style=solid
- **Kafka/SASL**: color=steelblue, line_style=dashed
- **SSH**: color=blue, line_style=dashed

## Severity Multipliers
- **kube-apiserver**: 2.0
- **etcd**: 2.0
- **Vault (Platform)**: 1.9
- **Ingress Controller (Nginx)**: 1.7
- **Backend API Pod (Node.js)**: 1.6
- **PostgreSQL (StatefulSet)**: 1.6
- **Container Registry (Harbor)**: 1.5
- **Message Broker (Kafka)**: 1.4

## Custom Mitre Mapping
- **Container Escape via Privileged Pod**: tactics=["Privilege Escalation", "Defense Evasion"], techniques=[{"id": "T1611", "name": "Escape to Host"}]
- **ServiceAccount Token Theft**: tactics=["Credential Access"], techniques=[{"id": "T1528", "name": "Steal Application Access Token"}]
- **RBAC Privilege Escalation**: tactics=["Privilege Escalation"], techniques=[{"id": "T1078", "name": "Valid Accounts"}]
- **Supply Chain — Malicious Image**: tactics=["Initial Access"], techniques=[{"id": "T1195", "name": "Supply Chain Compromise"}, {"id": "T1525", "name": "Implant Internal Image"}]
- **SSRF to Cloud Metadata API**: tactics=["Discovery", "Credential Access"], techniques=[{"id": "T1552", "name": "Unsecured Credentials"}, {"id": "T1190", "name": "Exploit Public-Facing Application"}]
- **Lateral Movement via Service Mesh**: tactics=["Lateral Movement"], techniques=[{"id": "T1210", "name": "Exploitation of Remote Services"}]
- **Secret Exfiltration from etcd**: tactics=["Credential Access", "Collection"], techniques=[{"id": "T1552", "name": "Unsecured Credentials"}]
- **Helm Chart Injection (CI/CD)**: tactics=["Persistence", "Initial Access"], techniques=[{"id": "T1195", "name": "Supply Chain Compromise"}]
