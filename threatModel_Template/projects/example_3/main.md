# Threat Model: EcoShop — E-commerce Platform (Overview)

## Description
EcoShop is a B2C e-commerce platform serving EU and US customers. The architecture follows
a microservices pattern with a public-facing web frontend, a DMZ hosting API gateway and
firewalls, and internal backend services handling authentication, order processing, and
persistent data. The platform is PCI-DSS Level 1 certified and subject to GDPR.

This is the top-level overview model. Each major tier links to a detailed sub-model.
Drill down into a component node to view its internal architecture.

## Context
gdaf_context = context/ecommerce_context.yaml
bom_directory = BOM

## Boundaries
- **Internet**:
  isTrusted=False,
  type=network-on-prem,
  color=red,
  traversal_difficulty=low,
  businessValue="Public internet — untrusted entry point for all customers"
- **DMZ**:
  isTrusted=False,
  type=network-on-prem,
  color=orange,
  traversal_difficulty=low,
  businessValue="Demilitarized zone — terminates public TLS, forwards to backend"
- **Application Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightblue,
  traversal_difficulty=medium,
  businessValue="Internal microservices — protected by DMZ and internal firewall"
- **Data Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lavender,
  traversal_difficulty=high,
  businessValue="Database tier — highest sensitivity, strict access control"

## Actors
- **Customer**:
  boundary=Internet,
  authenticity=credentials,
  isTrusted=False,
  businessValue="End user placing orders — unauthenticated until login"
- **External Attacker**:
  boundary=Internet,
  authenticity=none,
  isTrusted=False,
  businessValue="Adversarial actor targeting public endpoints"
- **Payment Processor**:
  boundary=Internet,
  authenticity=client-certificate,
  isTrusted=False,
  businessValue="PCI-DSS compliant third-party payment gateway (Stripe / Adyen callback)"
- **Platform Admin**:
  boundary="Application Zone",
  authenticity=two-factor,
  isTrusted=True,
  businessValue="Internal platform operator — privileged access to backend APIs"

## Servers
- **WebApp**:
  submodel=./frontend/model.md,
  boundary=Internet,
  type=web-server,
  internet_facing=True,
  confidentiality=low,
  integrity=high,
  availability=critical,
  waf=True,
  businessValue="React SPA + nginx — public entry point"
- **DMZTier**:
  submodel=./dmz/model.md,
  boundary=DMZ,
  type=firewall,
  internet_facing=True,
  confidentiality=medium,
  integrity=critical,
  availability=critical,
  ids=True,
  ips=True,
  businessValue="DMZ — firewalls + API gateway cluster"
- **BackendServices**:
  submodel=./backend/model.md,
  boundary="Application Zone",
  type=application-server,
  confidentiality=high,
  integrity=critical,
  availability=high,
  mfa_enabled=True,
  businessValue="Auth, Order, and Payment microservices"
- **DatabaseCluster**:
  submodel=./backend/database/model.md,
  boundary="Data Zone",
  type=database,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  credentials_stored=True,
  mfa_enabled=True,
  businessValue="PostgreSQL primary + replica — PII and payment tokenization data"

## Data
- **User Request**:
  description="HTTP/S request from browser — may include session cookies and form data",
  classification=PUBLIC,
  encrypted_in_transit=True
- **Encapsulated API Call**:
  description="User request re-packaged by the frontend and forwarded through the DMZ",
  classification=RESTRICTED,
  encrypted_in_transit=True
- **Internal API Call**:
  description="Authenticated call between internal services — carries order and auth payloads",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True

## Dataflows
- **CustomerToWebApp**:
  from=Customer,
  to=WebApp,
  protocol=HTTPS,
  port=443,
  authentication=credentials,
  encryption=TLS,
  data="User Request"
- **WebAppToDMZ**:
  from=WebApp,
  to=DMZTier,
  protocol=HTTPS,
  port=443,
  authentication=credentials,
  encryption=TLS,
  data="Encapsulated API Call"
- **DMZToBackend**:
  from=DMZTier,
  to=BackendServices,
  protocol=HTTP,
  port=8080,
  authentication=credentials,
  encryption=none,
  data="Internal API Call"
- **BackendToDatabase**:
  from=BackendServices,
  to=DatabaseCluster,
  protocol=PostgreSQL,
  port=5432,
  authentication=credentials,
  encryption=TLS,
  data="Internal API Call"
- **PaymentProcessorCallback**:
  from="Payment Processor",
  to=DMZTier,
  protocol=HTTPS,
  port=443,
  authentication=client-certificate,
  encryption=TLS,
  data="Internal API Call"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=dashed
- **gRPC**: color=blue, line_style=solid
- **PostgreSQL**: color=purple, line_style=solid

## Severity Multipliers
- **DatabaseCluster**: 3.0
- **BackendServices**: 2.0
- **DMZTier**: 1.5
- **WebApp**: 1.2
