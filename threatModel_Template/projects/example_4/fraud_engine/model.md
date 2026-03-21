# Threat Model: PayFlow — Fraud Detection Engine

## Description
The fraud detection engine provides real-time payment risk scoring with a latency SLA of
50ms p99. An ML inference engine runs gradient boosting + neural net ensemble models.
A deterministic rules engine enforces velocity checks and geo-blocking. A Redis feature store
provides pre-computed behavioral aggregates. An alert service manages fraud case lifecycle
and analyst review workflows.

**Ghost node pattern:** APIGateway (parent model) sends fraud scoring requests IN
(GatewayToFraud) and receives decisions OUT (FraudToGateway) — it appears as a SINGLE
bidirectional ghost node in this diagram's purple "External connections bidirectional" cluster.

## Context
bom_directory = BOM

## Boundaries
- **Scoring Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightyellow,
  traversal_difficulty=medium,
  businessValue="Real-time ML scoring and rules evaluation — 50ms p99 SLA"
- **Analytics Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightcyan,
  traversal_difficulty=medium,
  businessValue="Feature store and fraud case management — async lifecycle"

## Servers
- **MLEngine**:
  boundary="Scoring Zone",
  type=application-server,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  mfa_enabled=True,
  tags=[ml-inference, xgboost, tensorflow, fraud-scoring, pci-dss],
  businessValue="ML inference — gradient boosting + neural net ensemble, 50ms p99 SLA",
  entry_point=True
- **RulesEngine**:
  boundary="Scoring Zone",
  type=application-server,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  mfa_enabled=True,
  tags=[drools, velocity-checks, geo-blocks, card-testing-detection],
  businessValue="Rules engine — deterministic fraud rules: velocity, geo-blocking, BIN attacks"
- **FeatureStore**:
  boundary="Analytics Zone",
  type=database,
  machine=virtual,
  confidentiality=high,
  integrity=high,
  availability=high,
  redundant=True,
  tags=[redis, behavioral-analytics, velocity-counters, feature-engineering],
  businessValue="Redis Sentinel — 90-day behavioral aggregates and velocity counters per cardholder"
- **AlertService**:
  boundary="Analytics Zone",
  type=application-server,
  machine=virtual,
  confidentiality=high,
  integrity=high,
  availability=medium,
  tags=[case-management, analyst-portal, siem-integration, notifications],
  businessValue="Alert service — fraud case creation, analyst review portal, SIEM webhook"

## Data
- **PaymentSignal**:
  description="Transaction features: amount, merchant, device fingerprint, velocity",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True
- **FraudDecision**:
  description="Risk score 0-100, decision approve/review/decline, triggered rules list",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True
- **BehavioralFeature**:
  description="Pre-computed aggregates: 30d spend, merchant diversity, card testing score",
  classification=RESTRICTED,
  encrypted_in_transit=True

## Dataflows
- **MLToFeatureStore**:
  from=MLEngine,
  to=FeatureStore,
  protocol=Redis,
  port=6379,
  authentication=credentials,
  encryption=TLS,
  data="BehavioralFeature"
- **RulesToFeatureStore**:
  from=RulesEngine,
  to=FeatureStore,
  protocol=Redis,
  port=6379,
  authentication=credentials,
  encryption=TLS,
  data="BehavioralFeature"
- **MLToAlert**:
  from=MLEngine,
  to=AlertService,
  protocol=HTTP,
  port=8083,
  authentication=credentials,
  encryption=TLS,
  data="FraudDecision"
- **RulesToAlert**:
  from=RulesEngine,
  to=AlertService,
  protocol=HTTP,
  port=8083,
  authentication=credentials,
  encryption=TLS,
  data="FraudDecision"

## Protocol Styles
- **Redis**: color=crimson, line_style=solid
- **HTTP**: color=orange, line_style=dashed
- **gRPC**: color=blue, line_style=solid

## Severity Multipliers
- **MLEngine**: 2.0
- **RulesEngine**: 2.0
- **FeatureStore**: 1.8
- **AlertService**: 1.5
