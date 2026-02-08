# Threat Model: On-Prem Enterprise Network

## Description
This model describes a traditional on-premise enterprise network architecture. It includes an external-facing DMZ, a corporate internal network, and a highly restricted zone for sensitive data like financial records. This model highlights threats related to physical infrastructure, legacy protocols, and intra-network segmentation.

## Boundaries
- **Internet**:
  type=network-on-prem,
  isTrusted=False
- **DMZ**:
  type=network-on-prem,
  isTrusted=False, // Considered untrusted from the perspective of the internal network
  color=orange
- **Internal Corporate Network**:
  type=network-on-prem,
  isTrusted=True,
  color=lightgreen
- **Restricted Financial Zone**:
  type=execution-environment,
  isTrusted=True,
  color=lightblue

## Actors
- **Remote Employee**: 
  boundary=Internet, 
  authenticity=two-factor,
  isTrusted=False
- **Internal Employee**:
  boundary="Internal Corporate Network",
  authenticity=credentials,
  isTrusted=True

## Servers
- **Perimeter Firewall**: 
  boundary=DMZ,
  type=firewall,
  machine=physical,
  waf=True,
  ids=True,
  ips=True,
  redundant=True,
  confidentiality=high,
  integrity=high,
  availability=critical,
  tags=[cisco-asa]
- **Web Server**:
  boundary=DMZ,
  machine=virtual,
  confidentiality=low,
  integrity=medium,
  availability=high,
  tags=[apache, centos]
- **Internal Firewall**:
  boundary="Internal Corporate Network",
  type=firewall,
  machine=physical,
  waf=False, // No WAF on internal firewall
  ids=True,
  ips=True,
  redundant=False, // Single point of failure
  tags=[fortinet]
- **Active Directory DC**:
  boundary="Internal Corporate Network",
  type=auth-server,
  machine=physical,
  auth_protocol=ldap,
  mfa_enabled=False, // No MFA for internal AD logins
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  tags=[windows-server]
- **Financial ERP System**:
  boundary="Restricted Financial Zone",
  machine=physical, // Legacy mainframe or bare-metal
  encryption=none, // Data-at-rest is not encrypted
  redundant=False,
  confidentiality=critical,
  integrity=critical,
  availability=critical,
  tags=[sap, mainframe]

## Data
- **Web Request**:
  description="HTTP/S requests from the public internet.",
  classification=PUBLIC
- **Authentication Request**:
  description="An authentication request to Active Directory.",
  classification=SECRET,
  confidentiality=critical,
  integrity=critical,
  availability=high
- **Financial Record**:
  description="A highly sensitive financial record.",
  classification=TOP_SECRET,
  confidentiality=critical,
  integrity=critical,
  availability=critical

## Dataflows
- **PublicToWeb**:
  from="Remote Employee",
  to="Web Server",
  protocol=HTTPS,
  data="Web Request",
  authentication=none,
  authorization=none,
  is_encrypted=True,
  ip_filtered=False
- **WebToInternal**:
  from="Web Server",
  to="Internal Firewall",
  protocol=HTTP, // Unencrypted traffic from DMZ to internal
  data="Web Request",
  is_encrypted=False,
  authentication=none,
  authorization=none
- **RemoteAccessVPN**:
  from="Remote Employee",
  to="Perimeter Firewall",
  protocol=IPSEC,
  authentication=two-factor,
  authorization=enduser-identity-propagation,
  vpn=True,
  is_encrypted=True
- **InternalToAD**:
  from="Internal Employee",
  to="Active Directory DC",
  protocol=TCP,
  data="Authentication Request",
  authentication=credentials,
  authorization=enduser-identity-propagation,
  is_encrypted=False
- **InternalToERP**:
  from="Internal Employee",
  to="Financial ERP System",
  protocol=TCP,
  data="Financial Record",
  authentication=credentials,
  authorization=enduser-identity-propagation,
  is_encrypted=False,
  readonly=False
