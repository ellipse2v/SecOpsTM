# Custom Asset Types and Protocols

## Overview

SecOpsTM DSL provides 31 standard asset types and common protocols. When your model requires types or protocols outside these standards, you must define them in the `config/` directory.

## When to Define Custom Types

### Custom Asset Types

Define `config/asset_types_community.yaml` when:
- Your system uses a component type not in the 31 standard DSL types
- You need domain-specific asset classifications
- Industry-specific components require custom definitions

### Custom Protocols

Define `config/protocols_community.yaml` when:
- Your system uses proprietary communication protocols
- Industry-specific protocols are not in the standard list
- Version-specific protocol variants need distinction

## 31 Standard DSL Types

These types **do NOT** require custom definitions:

```
firewall
domain-controller
auth-server
database
web-server
api-gateway
file-server
mail-server
management-server
workstation
load-balancer
vpn
vpn-gateway
plc
scada
repository
cicd
backup
dns
pki
siem
default
api_server
microservice
secrets_manager
monitoring
message_broker
cache
ingress
service_mesh
container_registry
```

## Common Standard Protocols

These protocols **do NOT** require custom definitions:

```
HTTP
HTTPS
FTP
SSH
TELNET
SMTP
DNS
DHCP
SNMP
LDAP
NTP
RDP
VNC
SMB
NFS
MySQL
PostgreSQL
MongoDB
Redis
MSSQL
Oracle
MQTT
AMQP
Kafka
TCP
UDP
TLS
SSL
IPSec
OpenVPN
WireGuard
IKE
```

## Custom Asset Types Format

### File: `config/asset_types_community.yaml`

```yaml
# Custom Asset Type Definitions

custom_asset_types:
  - name: "{type_name}"
    category: "{category}"
    description: "{Technical description}"
    security_considerations:
      - "{Consideration 1}"
      - "{Consideration 2}"
    recommended_controls:
      - "{Control 1}"
      - "{Control 2}"

  - name: "{another_type}"
    category: "{category}"
    description: "{Description}"
    ...
```

### Example: Drone-Specific Types

```yaml
# asset_types_community.yaml

custom_asset_types:
  - name: "uav_platform"
    category: "embedded-system"
    description: "Unmanned Aerial Vehicle (UAV) flight control platform"
    security_considerations:
      - "Radio link encryption critical"
      - "GPS spoofing protection required"
      - "Flight controller integrity essential"
    recommended_controls:
      - "AES-256 encryption for control channel"
      - "GNSS authentication"
      - "Geofencing enforcement"

  - name: "ground_control_station"
    category: "workstation"
    description: "Ground-based drone control and monitoring station"
    security_considerations:
      - "Physical security important"
      - "Operator authentication required"
      - "Mission data protection needed"
    recommended_controls:
      - "Multi-factor authentication"
      - "Full disk encryption"
      - "Secure communication to cloud"

  - name: "autonomous docking station"
    category: "iot-device"
    description: "Automated drone charging and data upload station"
    security_considerations:
      - "Network isolation recommended"
      - "Physical access control needed"
      - "Firmware update security critical"
    recommended_controls:
      - "VLAN segmentation"
      - "Hardware security module"
      - "Signed firmware updates"

  - name: "flight_data_processor"
    category: "data-processor"
    description: "Real-time flight data processing and analytics engine"
    security_considerations:
      - "Data pipeline integrity"
      - "Stream processing security"
      - "Output validation required"
    recommended_controls:
      - "Input validation"
      - "Stream encryption"
      - "Output sanitization"
```

## Custom Protocol Format

### File: `config/protocols_community.yaml`

```yaml
# Custom Protocol Definitions

custom_protocols:
  - name: "{protocol_name}"
    version: "{version}"
    transport: "{tcp|udp|http|other}"
    encryption: "{none|symmetric|asymmetric|custom}"
    authentication: "{none|credentials|certificate|custom}"
    description: "{Technical description}"
    security_considerations:
      - "{Consideration 1}"
      - "{Consideration 2}"
    threat_model:
      eavesdropping_risk: "{low|medium|high}"
      tampering_risk: "{low|medium|high}"
      spoofing_risk: "{low|medium|high}"

  - name: "{another_protocol}"
    ...
```

### Example: DJI-Specific Protocols

```yaml
# protocols_community.yaml

custom_protocols:
  - name: "ocusync"
    version: "3-enterprise"
    transport: "radio"
    encryption: "aes-256"
    authentication: "certificate"
    description: "DJI O3 Enterprise transmission protocol for drone control and video"
    security_considerations:
      - "Frequency hopping for jamming resistance"
      - "AES-256 encryption for control channel"
      - "Certificate-based authentication"
    threat_model:
      eavesdropping_risk: "medium"
      tampering_risk: "low"
      spoofing_risk: "low"

  - name: "dji-cloud-api"
    version: "2.0"
    transport: "https"
    encryption: "tls-1.3"
    authentication: "oauth2"
    description: "DJI Cloud API for drone-cloud communication"
    security_considerations:
      - "OAuth2 token management critical"
      - "API rate limiting recommended"
      - "Webhook signature verification needed"
    threat_model:
      eavesdropping_risk: "low"
      tampering_risk: "low"
      spoofing_risk: "medium"

  - name: "rtsp-inspection"
    version: "1.0"
    transport: "tcp"
    encryption: "custom-aes"
    authentication: "token"
    description: "Custom RTSP variant for inspection video streaming"
    security_considerations:
      - "Video stream encryption essential"
      - "Token expiration recommended"
      - "Bandwidth limiting for DoS protection"
    threat_model:
      eavesdropping_risk: "high"
      tampering_risk: "medium"
      spoofing_risk: "medium"

  - name: "mauve-link"
    version: "1.5"
    transport: "radio"
    encryption: "aes-128"
    authentication: "pre-shared-key"
    description: "Proprietary mesh network protocol for multi-drone coordination"
    security_considerations:
      - "PSK rotation recommended"
      - "Mesh topology validation needed"
      - "Node authentication critical"
    threat_model:
      eavesdropping_risk: "medium"
      tampering_risk: "high"
      spoofing_risk: "high"
```

## Naming Conventions

### Asset Type Names

**Format:** `snake_case`

**Rules:**
- Use lowercase letters and underscores
- Be descriptive and domain-specific
- Include version if applicable

**Examples:**
- ✅ `uav_platform`
- ✅ `ground_control_station`
- ❌ `UAVPlatform`
- ❌ `uav-platform`

### Protocol Names

**Format:** `kebab-case` with version

**Rules:**
- Use lowercase letters and hyphens
- Include version number
- Be specific about variant

**Examples:**
- ✅ `ocusync-3-enterprise`
- ✅ `dji-cloud-api-2`
- ❌ `OcuSync`
- ❌ `ocusync_3_enterprise`

## Validation Rules

When using custom types/protocols:

1. ✅ All custom types defined in `asset_types_community.yaml`
2. ✅ All custom protocols defined in `protocols_community.yaml`
3. ✅ Names follow naming conventions
4. ✅ Descriptions are technically accurate
5. ✅ Security considerations are relevant
6. ✅ Threat model assessments are reasonable

## Common Mistakes

| ❌ Wrong | ✅ Correct | Reason |
|----------|-----------|--------|
| Using `custom_server` without definition | Define in `asset_types_community.yaml` | All custom types must be documented |
| Protocol named `HTTPS-EXTENDED` | Protocol named `https-extended` | Follow naming conventions |
| Missing security considerations | Include security_considerations | Required for threat modeling |
| Vague descriptions | Technical, specific descriptions | Clarity matters |
| Not defining when needed | Check against 31 standard types | Avoid unnecessary custom types |

## Best Practices

1. **Minimize Custom Types:** Use standard types when possible
2. **Document Thoroughly:** Include security considerations for each custom type
3. **Version Protocols:** Always specify protocol versions
4. **Review Regularly:** Update custom definitions as systems evolve
5. **Team Alignment:** Ensure all team members understand custom types/protocols

## Migration Guide

When migrating from custom to standard types:

1. Identify if custom type has a standard equivalent
2. Update `model.md` references
3. Remove from `config/asset_types_community.yaml`
4. Document migration in notes
5. Validate all references updated

## Related Documents

- [../SKILL.md](../SKILL.md) - SecOpsTM threat modeling skill
- [staging-format.md](staging-format.md) - Information staging format
- [output-structure.md](output-structure.md) - Output structure
- [dsl-syntax.md](dsl-syntax.md) - DSL syntax reference
- [workflow.md](workflow.md) - Information gathering workflow
