# Threat Model: PayFlow — Payment API Services

## Description
The payment API tier contains the core payment processing microservices behind the Kong reverse
proxy. An internal load balancer distributes traffic to an Auth service (OAuth 2.0) and a
Charge service (PCI-DSS L1). A Kafka message broker decouples synchronous charges from async
settlement batch processing.

**Ghost node pattern:** APIGateway (parent model) sends requests IN (GatewayToPayment) and
receives responses OUT (PaymentToGateway) — it appears as a SINGLE bidirectional ghost node
in this diagram. CardVault also appears bidirectionally (PaymentToVault / VaultToPayment).

## Context
bom_directory = BOM

## Boundaries
- **Payment Services Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightblue,
  traversal_difficulty=medium,
  businessValue="Core payment microservices — synchronous authorization and capture"
- **Settlement Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightyellow,
  traversal_difficulty=medium,
  businessValue="Async settlement and notification pipeline — decoupled from synchronous path"

## Servers
- **InternalLB**:
  boundary="Payment Services Zone",
  type=web-server,
  machine=virtual,
  confidentiality=low,
  integrity=high,
  availability=critical,
  redundant=True,
  businessValue="Internal HAProxy load balancer — round-robin to AuthService and ChargeService",
  entry_point=True
- **AuthService**:
  boundary="Payment Services Zone",
  type=application-server,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  credentials_stored=True,
  tags=[oauth2, jwt, oidc, pci-dss],
  businessValue="Auth service — validates OAuth2 tokens, enforces scopes for payment operations"
- **ChargeService**:
  boundary="Payment Services Zone",
  type=application-server,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  tags=[pci-dss, authorization, capture, refund, void],
  businessValue="Charge service — PCI-DSS L1 in-scope, handles authorize/capture/refund/void"
- **MessageBroker**:
  boundary="Settlement Zone",
  type=application-server,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=high,
  redundant=True,
  tags=[kafka, event-streaming, pci-dss],
  businessValue="Kafka 3-broker cluster — decouples charge events from settlement and notifications"
- **SettlementService**:
  boundary="Settlement Zone",
  type=application-server,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=medium,
  mfa_enabled=True,
  tags=[batch, settlement, reconciliation, card-network],
  businessValue="Settlement service — daily batch reconciliation and clearing submission to card networks"

## Data
- **AuthToken**:
  description="OAuth 2.0 JWT — scoped to payment operations, 15-minute TTL",
  classification=SECRET,
  encrypted_in_transit=True
- **ChargePayload**:
  description="Authorized payment: amount, currency, token reference — PCI-DSS in-scope",
  classification=SECRET,
  encrypted_in_transit=True
- **SettlementBatch**:
  description="Daily settlement file for card network clearing — ISO 8583",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True,
  encrypted_at_rest=True

## Dataflows
- **LBToAuth**:
  from=InternalLB,
  to=AuthService,
  protocol=HTTP,
  port=8081,
  authentication=credentials,
  encryption=none,
  data="AuthToken"
- **LBToCharge**:
  from=InternalLB,
  to=ChargeService,
  protocol=HTTP,
  port=8082,
  authentication=credentials,
  encryption=none,
  data="ChargePayload"
- **ChargeToMQ**:
  from=ChargeService,
  to=MessageBroker,
  protocol=Kafka,
  port=9092,
  authentication=credentials,
  encryption=TLS,
  data="SettlementBatch"
- **MQToSettlement**:
  from=MessageBroker,
  to=SettlementService,
  protocol=Kafka,
  port=9092,
  authentication=credentials,
  encryption=TLS,
  data="SettlementBatch"

## Protocol Styles
- **HTTP**: color=red, line_style=dashed
- **Kafka**: color=purple, line_style=solid
- **gRPC**: color=blue, line_style=solid

## Severity Multipliers
- **AuthService**: 2.5
- **ChargeService**: 2.5
- **MessageBroker**: 1.8
- **SettlementService**: 2.0
