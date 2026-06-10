# BOM (Bill of Materials) Format

## Overview

The BOM (Bill of Materials) provides detailed asset information in simple YAML format. Each key asset gets its own YAML file.

## File Naming

**Format:** `{asset_name}.yaml`

**Rules:**
- Lowercase with underscores
- Match the server name from `model.md`
- One asset per file

**Examples:**
- ✅ `api_gateway.yaml`
- ✅ `database_primary.yaml`
- ❌ `API-Gateway.yaml`
- ❌ `apiGateway.yaml`

## Basic Structure

```yaml
# {asset_name}.yaml

# Basic Information
name: "{asset_name}"
type: "{dsl_type}"
description: "{Brief technical description}"

# Deployment
boundary: "{boundary_name}"
machine: "{physical|virtual|container|serverless|embedded|saas}"

# Security Configuration
internet_facing: {true|false}
mfa_enabled: {true|false}
credentials_stored: {true|false}
encryption: "{encryption_method}"

# CIA Triad
confidentiality: "{low|medium|high|critical}"
integrity: "{low|medium|high|critical}"
availability: "{low|medium|high|critical}"

# Authentication
auth_protocol: "{none|ldap|kerberos|saml|oauth|oidc|radius}"

# Protection Measures
waf: {true|false}
ids: {true|false}
ips: {true|false}

# Maintenance
patch_level: "{unknown|current|outdated}"
detection_level: "{none|medium|high}"
redundant: {true|false}

# Classification
classification: "{PUBLIC|INTERNAL|RESTRICTED|SECRET|TOP_SECRET}"

# Business Impact
businessValue: "{Description of business impact if compromised}"

# Tags
tags:
  - "{tag1}"
  - "{tag2}"

# Known Vulnerabilities (if any)
known_cves:
  - "{CVE-YYYY-XXXXX}"

# Additional Notes
notes: |
  {Any additional information}
```

## Field Descriptions

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Asset name (must match model.md) |
| `type` | string | DSL type from 31 standard types |
| `description` | string | 1-2 sentence technical description |
| `boundary` | string | Must reference defined boundary |
| `classification` | enum | PUBLIC, INTERNAL, RESTRICTED, SECRET, or TOP_SECRET |

### Recommended Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `machine` | enum | virtual | Deployment form |
| `internet_facing` | boolean | false | Exposed to internet |
| `mfa_enabled` | boolean | false | Multi-factor authentication |
| `confidentiality` | enum | medium | CIA triad - confidentiality |
| `integrity` | enum | medium | CIA triad - integrity |
| `availability` | enum | medium | CIA triad - availability |
| `patch_level` | enum | unknown | Patch status |
| `detection_level` | enum | none | Monitoring/detection level |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `credentials_stored` | boolean | Stores credentials |
| `encryption` | string | Encryption method |
| `auth_protocol` | enum | Authentication protocol |
| `waf/ids/ips` | boolean | Protection measures |
| `redundant` | boolean | Has redundancy |
| `businessValue` | string | Business impact description |
| `tags` | list | OS/software identifiers |
| `known_cves` | list | Known CVEs |
| `notes` | string | Additional notes |

## Examples

### Example 1: API Gateway

```yaml
# api_gateway.yaml

name: "api_gateway"
type: "api-gateway"
description: "Main API entry point for external clients"
boundary: "dmz"
machine: "container"
internet_facing: true
mfa_enabled: false
credentials_stored: false
encryption: "TLS 1.3"
confidentiality: "high"
integrity: "high"
availability: "critical"
auth_protocol: "oauth"
waf: true
ids: true
ips: true
patch_level: "current"
detection_level: "high"
redundant: true
classification: "RESTRICTED"
businessValue: "Single point of entry for all API traffic. Compromise would allow unauthorized access to backend services."
tags:
  - "nginx"
  - "kubernetes"
  - "v1.24"
notes: |
  Fronted by cloud WAF. Rate limiting enabled.
  Certificate rotation automated every 30 days.
```

### Example 2: Database Server

```yaml
# database_primary.yaml

name: "database_primary"
type: "database"
description: "Primary PostgreSQL database for user data"
boundary: "internal_network"
machine: "virtual"
internet_facing: false
mfa_enabled: true
credentials_stored: true
encryption: "AES-256 at rest, TLS 1.3 in transit"
confidentiality: "critical"
integrity: "critical"
availability: "critical"
auth_protocol: "ldap"
waf: false
ids: true
ips: false
patch_level: "current"
detection_level: "high"
redundant: true
classification: "SECRET"
businessValue: "Contains all user PII and transaction data. Downtime would halt all business operations."
tags:
  - "postgresql"
  - "v14"
  - "ubuntu-22.04"
known_cves: []
notes: |
  Point-in-time recovery enabled.
  Daily backups to separate region.
  Read replica for reporting queries.
```

### Example 3: IoT Device

```yaml
# drone_m300.yaml

name: "drone_m300"
type: "embedded"
description: "DJI Matrice 300 RTK drone platform"
boundary: "drone_rf_link"
machine: "embedded"
internet_facing: false
mfa_enabled: false
credentials_stored: true
encryption: "AES-256"
confidentiality: "high"
integrity: "high"
availability: "high"
auth_protocol: "none"
waf: false
ids: false
ips: false
patch_level: "current"
detection_level: "none"
redundant: false
classification: "RESTRICTED"
businessValue: "Primary data collection platform. Compromise could lead to data theft or physical safety risks."
tags:
  - "dji"
  - "m300-rtk"
  - "pilot-2"
notes: |
  SD card encryption enabled.
  Flight logs stored locally and synced to cloud.
  Physical security controls required during ground operations.
```

## Validation Rules

Before considering BOM complete:

1. ✅ All server names from `model.md` have corresponding BOM files
2. ✅ File names match server names (snake_case)
3. ✅ All required fields present
4. ✅ Boundary references are valid
5. ✅ Type values are from the 31 standard DSL types
6. ✅ Classification values are valid enums
7. ✅ CIA values are valid enums (low/medium/high/critical)

## Common Mistakes

| ❌ Wrong | ✅ Correct | Reason |
|----------|-----------|--------|
| Missing `boundary` field | Include `boundary: "{name}"` | Required field |
| `type: "custom_server"` | `type: "web-server"` | Use standard DSL types |
| `classification: "confidential"` | `classification: "RESTRICTED"` | Use valid enum values |
| File named `API-Gateway.yaml` | File named `api_gateway.yaml` | Follow naming conventions |
| Empty `known_cves: []` with known CVEs | List actual CVEs | Accuracy matters |

## Relationship to Context

BOM files complement the GDAF context:
- **Context**: Attack objectives, threat actors, risk criteria
- **BOM**: Detailed asset security configurations

Both are required for complete threat modeling.

## Related Documents

- [generate_bom.py](../scripts/generate_bom.py) - Auto-generation script
- [dsl-syntax.md](dsl-syntax.md) - DSL syntax
- [output-structure.md](output-structure.md) - Output structure
- [custom-asset-types.md](custom-asset-types.md) - Custom asset types
