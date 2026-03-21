# Threat Model: EcoShop — Frontend Tier

## Description
The frontend tier consists of an nginx web server delivering the React SPA and a HAProxy
load balancer distributing traffic across server instances. This tier terminates public
HTTPS connections and is protected by a Web Application Firewall (WAF). All static assets
are served from nginx; dynamic requests are proxied to the DMZ API gateway.

## Context
bom_directory = BOM

## Boundaries
- **Public Frontend Zone**:
  isTrusted=False,
  type=network-on-prem,
  color=lightsalmon,
  traversal_difficulty=low,
  businessValue="Internet-facing web delivery — high exposure"

## Servers
- **LoadBalancer**:
  boundary="Public Frontend Zone",
  type=load-balancer,
  machine=virtual,
  confidentiality=low,
  integrity=high,
  availability=critical,
  redundant=True,
  internet_facing=True,
  ids=False,
  ips=False,
  mfa_enabled=False,
  tags=[haproxy, layer4, tcp],
  businessValue="HAProxy L4/L7 load balancer — single point of ingress",
  entry_point=True
- **WebServer**:
  boundary="Public Frontend Zone",
  type=web-server,
  machine=virtual,
  confidentiality=low,
  integrity=high,
  availability=critical,
  redundant=True,
  internet_facing=False,
  waf=True,
  ids=True,
  ips=False,
  mfa_enabled=False,
  auth_protocol=none,
  encryption=TLS,
  tags=[nginx, react, spa, static-assets],
  businessValue="nginx — serves React SPA, proxies API calls to DMZ"

## Data
- **StaticAssets**:
  description="HTML, JS bundles, CSS and image files served to the browser",
  classification=PUBLIC,
  encrypted_in_transit=True,
  encrypted_at_rest=False
- **SessionCookie**:
  description="HTTP-only session cookie set after successful authentication",
  classification=RESTRICTED,
  encrypted_in_transit=True,
  encrypted_at_rest=False

## Dataflows
- **LBToWebServer**:
  from=LoadBalancer,
  to=WebServer,
  protocol=HTTP,
  port=80,
  authentication=none,
  encryption=none
- **WebServerLoop**:
  from=WebServer,
  to=LoadBalancer,
  protocol=HTTPS,
  port=443,
  authentication=none,
  encryption=TLS,
  bidirectional=True

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=dashed

## Severity Multipliers
- **WebServer**: 1.5
- **LoadBalancer**: 1.2
