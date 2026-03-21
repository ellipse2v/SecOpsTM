# Threat Model: EcoShop — Backend Services Tier

## Description
The backend services tier hosts the core business microservices: an authentication service,
an order processing service cluster (linked sub-model), and a product database cluster
(linked sub-model). A core switch routes internal gRPC traffic. A database firewall with a
database switch forms a dedicated protected zone isolating the database tier.

All internal service-to-service calls use mutual TLS (mTLS) over gRPC. The Auth Service
validates OAuth 2.0 tokens issued by an external IdP. The Order Service handles order
lifecycle and calls the database via a firewall-protected path.

## Context
bom_directory = BOM

## Boundaries
- **Trusted Application Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lightblue,
  traversal_difficulty=medium,
  businessValue="Internal microservices — gRPC mTLS between services"
- **Protected DB Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lavender,
  traversal_difficulty=high,
  businessValue="Database zone — isolated by dedicated firewall and switch"

## Servers
- **CoreSwitch**:
  boundary="Trusted Application Zone",
  type=switch,
  machine=virtual,
  confidentiality=medium,
  integrity=high,
  availability=critical,
  redundant=True,
  mfa_enabled=False,
  tags=[internal-routing, east-west-traffic],
  businessValue="Internal L3 switch routing gRPC traffic between services",
  entry_point=True
- **AuthService**:
  boundary="Trusted Application Zone",
  type=application-server,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  credentials_stored=True,
  tags=[oauth2, oidc, jwt-issuer, identity],
  businessValue="Auth Service — validates credentials, issues JWT tokens"
- **OrderService**:
  submodel=../order_service/model.md,
  boundary="Trusted Application Zone",
  type=application-server,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=high,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  tags=[order-lifecycle, payment, shipping, pci-dss],
  businessValue="Order Service cluster — PCI-DSS in-scope; handles payment and shipping"
- **DBSwitch**:
  boundary="Protected DB Zone",
  type=switch,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  redundant=False,
  mfa_enabled=False,
  tags=[db-routing, dedicated-vlan],
  businessValue="Dedicated DB VLAN switch — isolates DB traffic"
- **DBFirewall**:
  boundary="Protected DB Zone",
  type=firewall,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  redundant=True,
  ids=True,
  ips=True,
  mfa_enabled=True,
  auth_protocol=credentials,
  tags=[db-firewall, whitelist-only, pgsql-inspection],
  businessValue="DB firewall — whitelist-only rules, deep packet inspection for PostgreSQL"
- **ProductDB**:
  submodel=./database/model.md,
  boundary="Protected DB Zone",
  type=database,
  machine=virtual,
  confidentiality=critical,
  integrity=critical,
  availability=high,
  redundant=True,
  mfa_enabled=True,
  auth_protocol=credentials,
  encryption=AES-256,
  credentials_stored=True,
  tags=[postgresql, pci-dss, encrypted-at-rest],
  businessValue="PostgreSQL cluster — stores product catalog, customer PII, order history"

## Data
- **AuthRequest**:
  description="OAuth 2.0 token introspection or credential validation request",
  classification=SECRET,
  encrypted_in_transit=True
- **OrderProcessingRequest**:
  description="Validated order payload forwarded from API gateway to Order Service",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True
- **DBTransaction**:
  description="PostgreSQL wire protocol transaction — may include PII and financial data",
  classification=SECRET,
  encrypted_in_transit=True,
  encrypted_at_rest=True
- **CustomerPII**:
  description="Customer personal data: name, address, email — GDPR regulated",
  classification=SECRET,
  storage_location=[ProductDB],
  pii=True,
  dpia=True,
  encrypted_at_rest=True

## Dataflows
- **SwitchToAuth**:
  from=CoreSwitch,
  to=AuthService,
  protocol=gRPC,
  port=50051,
  authentication=client-certificate,
  encryption=TLS,
  data="AuthRequest"
- **SwitchToOrders**:
  from=CoreSwitch,
  to=OrderService,
  protocol=gRPC,
  port=50052,
  authentication=client-certificate,
  encryption=TLS,
  data="OrderProcessingRequest"
- **OrdersToDBSwitch**:
  from=OrderService,
  to=DBSwitch,
  protocol=TCP,
  port=5432,
  authentication=credentials,
  encryption=TLS,
  data="DBTransaction"
- **DBSwitchToFirewall**:
  from=DBSwitch,
  to=DBFirewall,
  protocol=TCP,
  port=5432,
  authentication=none,
  encryption=none,
  data="DBTransaction"
- **FirewallToDB**:
  from=DBFirewall,
  to=ProductDB,
  protocol=TCP,
  port=5432,
  authentication=credentials,
  encryption=TLS,
  data="DBTransaction"

## Protocol Styles
- **gRPC**: color=blue, line_style=solid
- **TCP**: color=darkgray, line_style=dotted
- **HTTPS**: color=darkgreen, line_style=solid

## Severity Multipliers
- **AuthService**: 2.5
- **ProductDB**: 2.5
- **OrderService**: 2.0
- **DBFirewall**: 1.8

## Custom Mitre Mapping
- **SQL Injection via unparameterised query**: {"tactics": ["Collection", "Exfiltration"], "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}, {"id": "T1530", "name": "Data from Cloud Storage"}]}
- **OAuth token replay against AuthService**: {"tactics": ["Defense Evasion", "Lateral Movement"], "techniques": [{"id": "T1550.001", "name": "Application Access Token"}]}
