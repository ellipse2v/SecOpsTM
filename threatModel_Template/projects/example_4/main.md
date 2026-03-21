# Threat Model: PayFlow — Cloud-Native Fintech Payment Platform

## Description
PayFlow is a PCI-DSS Level 1 certified payment processing platform serving EU and US markets.
The architecture uses Kong API Gateway as the single reverse proxy for all internal services:
the gateway terminates TLS, enforces rate limiting, validates mTLS client certificates, and
forwards requests bidirectionally to backend service tiers.

Key architectural property — reverse proxy pattern: **all inbound AND outbound traffic passes
through APIGateway**. Each sub-model diagram therefore shows APIGateway as a single bidirectional
ghost node in a purple "External connections bidirectional" cluster, not duplicated across
green/orange clusters.

This is the top-level overview model. Drill down into any component to view its internal
architecture and sub-component threat analysis.

## Context
gdaf_context = context/fintech_context.yaml
bom_directory = BOM

## Boundaries
- **Internet**:
  isTrusted=False,
  type=network-on-prem,
  color=red,
  traversal_difficulty=low,
  businessValue="Public internet — untrusted PCI-DSS in-scope network"
- **DMZ**:
  isTrusted=False,
  type=network-on-prem,
  color=orange,
  traversal_difficulty=low,
  businessValue="Demilitarized zone — TLS termination, WAF, and API gateway tier"
- **Payment Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightblue,
  traversal_difficulty=medium,
  businessValue="Core payment processing services — PCI-DSS cardholder data environment (CDE)"
- **Vault Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lavender,
  traversal_difficulty=high,
  businessValue="Card data vault — HSM and encrypted card data storage, strictest access control"

## Actors
- **MerchantAPI**:
  boundary=Internet,
  authenticity=client-certificate,
  isTrusted=False,
  businessValue="Merchant integrating PayFlow via REST API — authenticated via mTLS"
- **CardHolder**:
  boundary=Internet,
  authenticity=credentials,
  isTrusted=False,
  businessValue="End user submitting payment credentials via merchant checkout"
- **ExternalAttacker**:
  boundary=Internet,
  authenticity=none,
  isTrusted=False,
  businessValue="Threat actor targeting PCI-DSS card data or payment fraud"
- **ComplianceAuditor**:
  boundary=Internet,
  authenticity=two-factor,
  isTrusted=False,
  businessValue="QSA auditor with read-only access to audit reports"
- **PlatformEngineer**:
  boundary="Payment Zone",
  authenticity=two-factor,
  isTrusted=True,
  businessValue="Internal engineer with privileged access to platform infrastructure"

## Servers
- **WAF**:
  boundary=DMZ,
  type=firewall,
  internet_facing=True,
  confidentiality=low,
  integrity=critical,
  availability=critical,
  ids=True,
  ips=True,
  waf=True,
  businessValue="ModSecurity WAF — OWASP CRS 4.0, PCI-DSS custom rules, geo-blocking"
- **APIGateway**:
  boundary=DMZ,
  type=web-server,
  internet_facing=True,
  confidentiality=medium,
  integrity=critical,
  availability=critical,
  ids=True,
  auth_protocol=client-certificate,
  businessValue="Kong API Gateway — reverse proxy, TLS termination, mTLS, JWT validation, rate limiting"
- **PaymentAPI**:
  submodel=./payment_api/model.md,
  boundary="Payment Zone",
  type=application-server,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  businessValue="Core payment processing microservices — charge, refund, settlement, authorization"
- **CardVault**:
  submodel=./card_vault/model.md,
  boundary="Vault Zone",
  type=database,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  credentials_stored=True,
  mfa_enabled=True,
  encryption=AES-256,
  businessValue="PCI-DSS card data vault — HSM tokenization, encrypted PAN storage"
- **FraudEngine**:
  submodel=./fraud_engine/model.md,
  boundary="Payment Zone",
  type=application-server,
  confidentiality=high,
  integrity=critical,
  availability=high,
  mfa_enabled=True,
  businessValue="Real-time fraud detection — ML scoring, rules engine, velocity checks"

## Data
- **PaymentRequest**:
  description="Merchant API call containing amount, currency, and payment method token",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True
- **CardData**:
  description="PAN, CVV, expiry — PCI-DSS in-scope cardholder data",
  classification=SECRET,
  encrypted_in_transit=True,
  encrypted_at_rest=True
- **FraudSignal**:
  description="Risk score and decision from fraud engine (approve/decline/review)",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True
- **AuditLog**:
  description="Immutable PCI-DSS audit trail — all payment events",
  classification=RESTRICTED,
  encrypted_in_transit=True

## Dataflows
- **MerchantToWAF**:
  from=MerchantAPI,
  to=WAF,
  protocol=HTTPS,
  port=443,
  authentication=client-certificate,
  encryption=TLS,
  data="PaymentRequest"
- **WAFToGateway**:
  from=WAF,
  to=APIGateway,
  protocol=HTTPS,
  port=8443,
  authentication=client-certificate,
  encryption=TLS,
  data="PaymentRequest"
- **GatewayToPayment**:
  from=APIGateway,
  to=PaymentAPI,
  protocol=HTTP,
  port=8080,
  authentication=credentials,
  encryption=none,
  bidirectional=True,
  data="PaymentRequest"
- **GatewayToFraud**:
  from=APIGateway,
  to=FraudEngine,
  protocol=gRPC,
  port=50051,
  authentication=client-certificate,
  encryption=TLS,
  bidirectional=True,
  data="FraudSignal"
- **PaymentToVault**:
  from=PaymentAPI,
  to=CardVault,
  protocol=gRPC,
  port=50052,
  authentication=client-certificate,
  encryption=TLS,
  bidirectional=True,
  data="CardData"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=dashed
- **gRPC**: color=blue, line_style=solid

## Severity Multipliers
- **CardVault**: 3.0
- **PaymentAPI**: 2.5
- **FraudEngine**: 2.0
- **APIGateway**: 1.8
- **WAF**: 1.5
