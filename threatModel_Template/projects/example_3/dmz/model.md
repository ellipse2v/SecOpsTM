# Threat Model: EcoShop — DMZ Tier

## Description
The DMZ contains two redundant hardware firewalls (active/passive HA pair) and an API
gateway cluster (see api_gateway sub-model). The firewalls enforce stateful packet
inspection, terminate external connections, and forward clean traffic to the API gateway.
The DMZ is the primary security boundary between the untrusted internet and the internal
application zone.

## Context
bom_directory = BOM

## Boundaries
- **DMZ Perimeter**:
  isTrusted=False,
  type=network-on-prem,
  color=orange,
  traversal_difficulty=low,
  businessValue="Stateful firewall pair — perimeter defense"
- **API Gateway Zone**:
  isTrusted=False,
  type=execution-environment,
  color=lightyellow,
  traversal_difficulty=medium,
  businessValue="API gateway cluster — authentication enforcement point"

## Servers
- **Firewall_1**:
  boundary="DMZ Perimeter",
  type=firewall,
  machine=physical,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  ids=True,
  ips=True,
  redundant=True,
  internet_facing=True,
  mfa_enabled=True,
  auth_protocol=radius,
  tags=[cisco-asa, stateful, ha-active],
  businessValue="Primary firewall — active node in HA pair",
  entry_point=True
- **Firewall_2**:
  boundary="DMZ Perimeter",
  type=firewall,
  machine=physical,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  ids=True,
  ips=True,
  redundant=True,
  internet_facing=True,
  mfa_enabled=True,
  auth_protocol=radius,
  tags=[cisco-asa, stateful, ha-passive],
  businessValue="Secondary firewall — passive node in HA pair (hot standby)",
  entry_point=True
- **ApiGateway**:
  submodel=../api_gateway/model.md,
  boundary="API Gateway Zone",
  type=api-gateway,
  confidentiality=high,
  integrity=critical,
  availability=critical,
  waf=True,
  mfa_enabled=True,
  auth_protocol=oauth,
  businessValue="Kong API gateway — rate limiting, JWT validation, routing"

## Data
- **InboundTraffic**:
  description="Raw HTTPS traffic from the internet before firewall inspection",
  classification=PUBLIC,
  encrypted_in_transit=True
- **FilteredRequest**:
  description="Inspected HTTPS traffic forwarded from firewall to API gateway",
  classification=RESTRICTED,
  encrypted_in_transit=True

## Dataflows
- **Firewall1ToApiGateway**:
  from=Firewall_1,
  to=ApiGateway,
  protocol=HTTPS,
  port=443,
  authentication=none,
  encryption=TLS,
  data="FilteredRequest"
- **Firewall2ToApiGateway**:
  from=Firewall_2,
  to=ApiGateway,
  protocol=HTTPS,
  port=443,
  authentication=none,
  encryption=TLS,
  data="FilteredRequest"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid

## Severity Multipliers
- **Firewall_1**: 2.0
- **Firewall_2**: 2.0
- **ApiGateway**: 1.8
