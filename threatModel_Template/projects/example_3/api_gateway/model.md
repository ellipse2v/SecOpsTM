# Threat Model: EcoShop — API Gateway Cluster

## Description
The API gateway cluster consists of a load balancer distributing requests across two Kong
gateway instances. The gateway enforces JWT authentication, rate limiting (per IP and per
user token), request validation, and routes to backend services. All traffic arriving at
this layer is assumed to have passed firewall inspection. OAuth 2.0 / OIDC is used for
token validation against the Auth Service.

## Context
bom_directory = BOM

## Boundaries
- **Gateway Internal Zone**:
  isTrusted=False,
  type=execution-environment,
  color=lightyellow,
  traversal_difficulty=medium,
  businessValue="Kong gateway instances — enforce auth and rate limiting"

## Servers
- **LoadBalancer**:
  boundary="Gateway Internal Zone",
  type=load-balancer,
  machine=virtual,
  confidentiality=medium,
  integrity=high,
  availability=critical,
  redundant=True,
  mfa_enabled=False,
  auth_protocol=none,
  tags=[nginx, l7, upstream-routing],
  businessValue="L7 load balancer distributing to Kong gateway instances",
  entry_point=True
- **GatewayInstance_1**:
  boundary="Gateway Internal Zone",
  type=api-gateway,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=high,
  redundant=True,
  waf=True,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  tags=[kong, jwt-validation, rate-limiting, active],
  businessValue="Primary Kong instance — JWT validation, rate limiting, routing"
- **GatewayInstance_2**:
  boundary="Gateway Internal Zone",
  type=api-gateway,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=high,
  redundant=True,
  waf=True,
  mfa_enabled=True,
  auth_protocol=oauth,
  encryption=TLS,
  tags=[kong, jwt-validation, rate-limiting, standby],
  businessValue="Secondary Kong instance — active-active for availability"

## Data
- **JWTToken**:
  description="Signed JWT bearer token identifying the authenticated user session",
  classification=RESTRICTED,
  encrypted_in_transit=True,
  encrypted_at_rest=False
- **RoutedRequest**:
  description="Authenticated and rate-limited request forwarded to backend services",
  classification=CONFIDENTIAL,
  encrypted_in_transit=True

## Dataflows
- **LBToInstance1**:
  from=LoadBalancer,
  to=GatewayInstance_1,
  protocol=HTTP,
  port=8000,
  authentication=none,
  encryption=none,
  data="RoutedRequest"
- **LBToInstance2**:
  from=LoadBalancer,
  to=GatewayInstance_2,
  protocol=HTTP,
  port=8000,
  authentication=none,
  encryption=none,
  data="RoutedRequest"

## Protocol Styles
- **HTTP**: color=orange, line_style=dashed
- **HTTPS**: color=darkgreen, line_style=solid

## Severity Multipliers
- **GatewayInstance_1**: 1.8
- **GatewayInstance_2**: 1.8
