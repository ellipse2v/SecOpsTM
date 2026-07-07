# SecOpsTM DSL Syntax Reference

## Table of Contents

- [Overview](#overview)
- [Section: Description](#section-description)
- [Section: Context](#section-context)
- [Section: Boundaries](#section-boundaries)
- [Section: Actors](#section-actors)
- [Section: Servers](#section-servers)
- [Section: Data](#section-data)
- [Section: Dataflows](#section-dataflows)
- [Section: Protocol Styles](#section-protocol-styles)
- [Section: Severity Multipliers](#section-severity-multipliers)
- [Section: Custom Mitre Mapping](#section-custom-mitre-mapping)
- [Custom Type and Protocol Extensions](#custom-type-and-protocol-extensions)
- [Complete DSL Template](#complete-dsl-template)

## Overview

A SecOpsTM system model is a Markdown file parsed in three passes:

1. **Pass 0** — `## Context` (model-level configuration)
2. **First pass** — `## Boundaries`, `## Actors`, `## Servers`, `## Data` (element definitions)
3. **Second pass** — `## Dataflows`, `## Protocol Styles`, `## Severity Multipliers`, `## Custom Mitre Mapping` (relationships and overrides)

**List item format**:
```markdown
- **Element Name**: key=value, key=value, key="quoted value", key=[list, of, values]
```

- Names are **case-sensitive** for display but **case-insensitive** for references (e.g., `boundary=Internet` matches `Internet` or `INTERNET`)
- Multi-line definitions supported: continuation lines indented deeper than `- **Name**:` line
- Comments: `//` to end of line are ignored by parser

---

## Section: Description

**⚠️ CRITICAL**: model.md must use the following title format:

```markdown
# System Model: {System Name}
```

**Format requirements**:
- Must start with `# System Model: ` (English colon `:` + space)
- System name follows after the space
- **Correct**: `# System Model: DJI Power Inspection Drone System`
- **Incorrect**: `# DJI Power Inspection Drone System - System Model`
- The legacy `# Threat Model: {System Name}` form is still read correctly (with a
  deprecation warning) — always write new models with `# System Model:`.

**Impact**: Incorrect title format causes SecOpsTM to fail generating report filenames correctly.

```markdown
## Description
Free text describing the analyzed system.
```

Plain text paragraphs, no key-value parsing. Appears in generated HTML report header and diagram tooltips.

---

## Section: Context

Configure model-level options, parsed before element creation. Each line formatted as `key = value` or `- key = value` or `- key: value`.

### Context Attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `gdaf_context` | string (path) | `None` | GDAF context YAML file path, relative to model file directory |
| `bom_directory` | string (path) | `None` | BOM directory path, relative to model file directory |
| `vex_file` | string (path) | `None` | CycloneDX VEX file path, takes precedence over BOM `known_cves` |
| `vex_directory` | string (path) | `None` | CycloneDX VEX file directory path |
| `gdaf_min_technique_score` | float 0.0–3.0 | `0.8` | Minimum `ScoredTechnique.score` for rendering OR-branch in `.afb` Attack Flow file |

**Context path resolution priority**:
1. Value specified in `## Context`
2. `{model_dir}/context/*.yaml` — auto-discovered when directory exists
3. `config/context.yaml` — SecOpsTM global default

**BOM directory resolution priority**:
1. Value specified in `## Context`
2. `{model_dir}/BOM/` — auto-discovered when directory exists
3. Disabled (no BOM enhancement)

---

## Section: Boundaries

Boundaries represent trust zones, network segments, or logical execution environments, rendered as labeled clusters in diagrams.

### Boundary Attributes

| Attribute              | Type   | Default       | STRIDE Impact          | GDAF Impact              | Description                         |
| ---------------------- | ------ | ------------- | ---------------------- | ------------------------ | ----------------------------------- |
| `isTrusted`            | bool   | `False`       | Trust boundary threats | Entry point detection    | Whether this zone is trusted. Trusted = green solid border; Untrusted = red dashed border |
| `isFilled`             | bool   | `False`       | None                   | None                     | Whether boundary has background fill in diagram |
| `type`                 | string | `""`          | None                   | Context for path scoring | Zone type, see accepted values below |
| `color`                | string | `"lightgray"` | None                   | None                     | Boundary cluster fill color in diagram, CSS color name or hex (`#2e7d32`) |
| `line_style`           | string | `"solid"`     | None                   | None                     | Boundary line style: `solid`, `dashed`, `dotted` |
| `traversal_difficulty` | string | `"low"`       | None                   | `hop_weight` bonus       | Difficulty for attacker to traverse this boundary, see accepted values below |
| `description`          | string | `""`          | None                   | None                     | **Required**. Free-text technical description (1-2 sentences, in English) |
| `businessValue`        | string | `None`        | None                   | None                     | Free-text business value description (in English) |

### Accepted Values for `type`

| Value | Meaning |
|---|---|
| `network-on-prem` | On-premises network segment |
| `network-cloud-provider` | Cloud provider network (AWS VPC, Azure VNet, etc.) |
| `network-cloud-security-group` | Cloud security group or firewall rule boundary |
| `execution-environment` | Logical execution area (data center zone, server room, container namespace) |
| `container-runtime` | Container orchestration boundary (Kubernetes namespace, Docker network) |

### `traversal_difficulty` Values

| Value | `hop_weight` Bonus | Meaning | Example |
|---|---|---|---|
| `low` | +0.3 | Easy to traverse (less control) | Public DMZ, open internal segment |
| `medium` | +0.1 | Moderate control (firewalls, VLAN segmentation) | Standard internal network |
| `high` | +0.0 | Strong control (micro-segmentation, strict firewall rules) | Finance area, OT/SCADA zone |

### Nested Boundaries

Boundaries can be nested, with child boundaries indented deeper than parent:
```markdown
## Boundaries
- **Corporate Network**:
  isTrusted=True, type=network-on-prem, color=lightblue
  - **Finance Zone**:
    isTrusted=True, type=execution-environment, color=lightyellow
```

---

## Section: Actors

Actors represent people, external systems, or roles interacting with the system, displayed as external entities (rectangles without servers) in diagrams.

### Actor Attributes

| Attribute                | Type   | Default  | Description                                            |
| ------------------------ | ------ | -------- | ------------------------------------------------------ |
| `boundary`               | string | `None`   | Boundary name the actor belongs to, must match boundary defined in `## Boundaries` |
| `authenticity`           | string | `"none"` | Authentication method used by actor, see accepted values below |
| `isTrusted`              | bool   | `False`  | Whether to trust this actor. Actors with `isTrusted=False` in untrusted boundaries are GDAF external attacker entry points |
| `providesAuthentication` | bool   | `False`  | Whether this actor provides authentication for other elements |
| `color`                  | string | `None`   | Node fill color in diagram, CSS color name or hex |
| `description`            | string | `""`     | **Required**. Free-text technical description (1-2 sentences, in English) |

### Accepted Values for `authenticity`

| Value | Description |
|---|---|
| `none` | No authentication |
| `credentials` | Username and password |
| `two-factor` | Multi-factor authentication |
| `client-certificate` | Mutual TLS (mTLS) |
| `externalized` | External IdP (SAML, OAuth) |

---

## Section: Servers

Servers represent assets, components, or systems in the system model.

### Server Attributes

| Attribute              | Type   | Default  | STRIDE Impact | GDAF Impact | Description |
|------------------------|--------|----------|---------------|-------------|-------------|
| `boundary`             | string | `None`   | None | None | **Required**. Boundary name, must match `## Boundaries` |
| `type`                 | string | `default` | None | Asset type classification | Asset type, see 31 standard types below |
| `classification`       | string | `UNKNOWN` | Data handling threats | `asset_value` on nodes (0.0–1.0) | Sensitivity classification, see accepted values below |
| `machine`              | string | `virtual` | Deployment-specific threats | None | Deployment form, see accepted values below |
| `internet_facing`      | bool   | `False`  | Internet exposure threats | Entry point detection | Whether exposed to internet |
| `mfa_enabled`          | bool   | `False`  | Credential theft threats | +0.2 on `hop_weight` when `False` | Whether multi-factor authentication enabled |
| `credentials_stored`   | bool   | `False`  | Credential storage threats | None | Whether stores credentials |
| `encryption`           | string | `None`   | Data at rest threats | None | Encryption method for stored data |
| `redundant`            | bool   | `False`  | None | None | Whether has redundancy |
| `auth_protocol`        | string | `None`   | Auth protocol threats | None | Authentication protocol, see accepted values below |
| `waf`                  | bool   | `False`  | Web attack mitigation | None | Whether has Web Application Firewall |
| `ids`                  | bool   | `False`  | Detection capability | None | Whether has Intrusion Detection System |
| `ips`                  | bool   | `False`  | Prevention capability | None | Whether has Intrusion Prevention System |
| `patch_level`          | string | `unknown`| Vulnerability exposure | None | Patch status, see accepted values below |
| `detection_level`      | string | `none`   | Detection capability | None | Monitoring/detection level, see accepted values below |
| `CIA`                  | string | `medium` | None | `asset_value` boost | Combined CIA score, see accepted values below |
| `confidentiality`      | string | `medium` | Confidentiality threats | `asset_value` component | Confidentiality importance |
| `integrity`            | string | `medium` | Integrity threats | `asset_value` component | Integrity importance |
| `availability`         | string | `medium` | Availability threats | `asset_value` component | Availability importance |
| `businessValue`        | string | `None`   | None | None | Free-text business value description (in English) |
| `description`          | string | `""`     | None | None | **Required**. Free-text technical description (1-2 sentences, in English) |
| `color`                | string | `None`   | None | None | Node fill color in diagram |
| `tags`                 | list   | `[]`     | None | None | OS version, software identifiers |
| `submodel`             | string | `None`   | None | None | Subsystem model file path (multi-subsystem scenarios) |

### Accepted Values for `type` (31 Standard Types)

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

### Accepted Values for `machine`

| Value | Description |
|---|---|
| `physical` | Physical hardware |
| `virtual` | Virtual machine |
| `container` | Containerized |
| `serverless` | Serverless function |
| `embedded` | Embedded device |
| `saas` | Software as a Service |

### Accepted Values for `classification`

| Value | GDAF `asset_value` | Description |
|---|---|---|
| `PUBLIC` | 0.0 | Non-sensitive, publicly available |
| `INTERNAL` | 0.2 | Internal use only |
| `RESTRICTED` | 0.4 | Restricted access |
| `SECRET` | 0.7 | Sensitive — requires access control |
| `TOP_SECRET` | 1.0 | Highly sensitive — highest protection |
| `UNKNOWN` | 0.1 | Classification unknown |

### Accepted Values for `auth_protocol`

| Value | Description |
|---|---|
| `none` | No authentication |
| `ldap` | LDAP authentication |
| `kerberos` | Kerberos authentication |
| `saml` | SAML authentication |
| `oauth` | OAuth authentication |
| `oidc` | OpenID Connect |
| `radius` | RADIUS authentication |

### Accepted Values for `patch_level`

| Value | Description |
|---|---|
| `unknown` | Patch status unknown |
| `current` | Regularly patched |
| `outdated` | Known vulnerabilities, not patched |

### Accepted Values for `detection_level`

| Value | Description |
|---|---|
| `none` | No monitoring |
| `medium` | Basic logging |
| `high` | EDR/SIEM monitoring |

### Accepted Values for `CIA` / `confidentiality` / `integrity` / `availability`

| Value | Description |
|---|---|
| `low` | Low importance |
| `medium` | Medium importance |
| `high` | High importance |
| `critical` | Critical importance |

---

## Section: Data

Data objects represent information assets flowing through the system.

### Data Attributes

| Attribute | Type | Default | STRIDE Impact | GDAF Impact | Description |
|---|---|---|---|---|---|
| `classification` | string | `UNKNOWN` | Data handling threats, sensitivity level | `data_value` on edges (0.0–1.0) | Sensitivity classification, case-insensitive, see accepted values below |
| `credentialsLife` | string | `UNKNOWN` | Credential handling threats | None | Credential lifecycle/storage type, see accepted values below |
| `description` | string | `""` | None | None | Free-text description of the data object (in English) |
| `storage_location` | list | `[]` | None | None | List of server names storing this data, must match names in `## Servers` |
| `isPII` | bool | `False` | PII-specific threats | None | Whether contains personally identifiable information |
| `isPassword` | bool | `False` | Password-specific threats | None | Whether is password data |
| `isCryptographicKey` | bool | `False` | Key-specific threats | None | Whether is cryptographic key |
| `isConfidentialityCritical` | bool | `False` | Confidentiality threats | None | Whether confidentiality is critical |
| `isIntegrityCritical` | bool | `False` | Integrity threats | None | Whether integrity is critical |

### Accepted Values for `classification`

| Value | GDAF `data_value` | Description |
|---|---|---|
| `PUBLIC` | 0.0 | Non-sensitive, publicly available data |
| `UNKNOWN` | 0.1 | Classification unknown |
| `RESTRICTED` | 0.4 | Internal use only, not public |
| `SECRET` | 0.7 | Sensitive — requires access control |
| `TOP_SECRET` | 1.0 | Highly sensitive — highest protection |
| `SENSITIVE` | 0.6 | Sensitive data (code extension support) |
| `INTERNAL` | 0.2 | Internal use (code extension support) |

### Accepted Values for `credentialsLife`

| Value | STRIDE Impact | Description |
|---|---|---|
| `NONE` | No credential threats | No credentials |
| `UNKNOWN` | Low signal | Credential lifecycle unknown |
| `SHORT` | Low risk | Short-term tokens or session credentials |
| `LONG` | Medium risk | Long-term credentials (service accounts) |
| `AUTO` | Low risk | Auto-rotated credentials |
| `MANUAL` | Medium risk | Manually managed credentials (rotation risk) |
| `HARDCODED` | High risk | Hardcoded credentials — triggers pytm hardcoded credential threat |

`HARDCODED` and `LONG` credential lifecycles act as credential persistence signals, generating additional credential theft and replay attack STRIDE threats.

---

## Section: Dataflows

Dataflows define communication channels between actors and servers (or between servers), representing directed edges in the system diagram and primary units for STRIDE threat generation.

### Dataflow Attributes

| Attribute | Type | Default | Required | STRIDE Impact | GDAF Impact | Description |
|---|---|---|---|---|---|---|
| `from` | string | — | **Yes** | Determines source element | Source node in the graph | Source element name (actor or server), must match exactly (case-insensitive) |
| `to` | string | — | **Yes** | Determines sink element | Sink node in the graph | Destination element name (actor or server) |
| `protocol` | string | `None` | No | Protocol-specific STRIDE rules | `services` set on both nodes, tactic boosts | Protocol name, any string; common values: HTTPS, HTTP, SSH, RDP, SMB, LDAP, Kerberos, SQL, WinRM, RPC, SMTP, IPSEC, Modbus, DNS, FTP, SAP, TCP, UDP |
| `isEncrypted` | bool | `False` | No | Cleartext data threats | +0.3 on `hop_weight` when `False` | Whether channel is encrypted |
| `isAuthenticated` | bool | `False` | No | Unauthenticated access threats | +0.4 on `hop_weight` when `False` | Whether channel requires authentication |
| `authentication` | string | `"none"` | No | Authentication-specific STRIDE rules | Edge `authentication` attribute | Authentication method on this flow, see accepted values below |
| `authorization` | string | `"none"` | No | Authorization threats | None | Authorization model, see accepted values below |
| `vpn` | bool | `False` | No | VPN-related threat variants | None | Whether this flow traverses VPN tunnel |
| `bidirectional` | bool | `False` | No | None | Reverse edge added to GDAF graph | When `True`, GDAF can traverse this edge in both directions, supporting reverse attack paths |
| `data` | string | `None` | No | Data classification threats | `data_value` on edge (0.0–1.0 from classification) | `## Data` object name transmitted by this flow, must match defined data object |
| `ipFiltered` | bool | `False` | No | IP filtering threat variants | None | Whether this flow is IP filtered |
| `readOnly` | bool | `False` | No | Write-access threats | None | Whether this flow is read-only |
| `usage` | string | `None` | No | None | None | Usage category: `business`, `devops`, `management` |
| `color` | string | `None` | No | None | None | Arrow color in diagram, when set overrides protocol style color, CSS name or hex |

### Accepted Values for `authentication`

| Value | Description |
|---|---|
| `none` | No authentication |
| `credentials` | Username and password |
| `session-id` | Session token (cookie) |
| `token` | API token or bearer token |
| `client-certificate` | Mutual TLS (mTLS) |
| `two-factor` | Multi-factor authentication |
| `externalized` | External IdP (SAML, OAuth) |
| `kerberos` | Kerberos tickets |

### Accepted Values for `authorization`

| Value | Description |
|---|---|
| `none` | No authorization |
| `technical-user` | Fixed service account authorization |
| `enduser-identity-propagation` | User identity propagated to backend (e.g., impersonation, JWT) |

### GDAF Edge Scoring

| Condition | `hop_weight` Bonus |
|---|---|
| `isAuthenticated=False` | +0.4 |
| `isEncrypted=False` | +0.3 |
| `mfa_enabled=False` on sink node | +0.2 |
| CIA score of sink node | +0 to +0.1 |
| Data value from `data` classification | +0 to +0.3 |
| `traversal_difficulty=low` on sink boundary | +0.3 |
| `traversal_difficulty=medium` on sink boundary | +0.1 |

---

## Section: Protocol Styles

Define visualization styles for protocols in diagrams.

### Protocol Style Attributes

| Attribute | Type | Default | Description |
|---|---|---|---|
| `color` | string | Protocol-specific | Line color in diagram |
| `line_style` | string | `solid` | Line style: `solid`, `dashed`, `dotted` |

### Example

```markdown
## Protocol Styles
- **https**: color=darkgreen, line_style=solid
- **http**: color=red, line_style=dashed
- **ssh**: color=blue, line_style=dashed
```

---

## Section: Severity Multipliers

Define risk calculation multipliers for different asset types or threat categories.

### Format

```markdown
## Severity Multipliers
- **AssetType**: 2.0
- **ThreatCategory**: 1.5
```

**Range**: 1.0 - 3.0

### Example

```markdown
## Severity Multipliers
- **CriticalAsset**: 3.0
- **ImportantServer**: 2.0
- **StandardServer**: 1.0
```

---

## Section: Custom Mitre Mapping

Custom MITRE mapping pins specific ATT&CK tactic and technique IDs to environment-relevant named attack patterns.

### Format

```markdown
## Custom Mitre Mapping
- **Pass-the-Hash**: {"tactics": ["Lateral Movement"], "techniques": [{"id": "T1550.002", "name": "Use Alternate Authentication Material: Pass the Hash"}]}
```

Value must be valid Python dict literal (parsed internally with `ast.literal_eval`). Format:
```
{"tactics": [<list of tactic names>], "techniques": [{"id": "<ATT&CK ID>", "name": "<technique name>"}, ...]}
```

Tactic names should match ATT&CK tactic display names (e.g., `"Lateral Movement"`, `"Credential Access"`).
Technique IDs follow ATT&CK format: `T1234` or `T1234.001` (sub-technique).

### Example

```markdown
## Custom Mitre Mapping
- **Drone Hijacking**: {"tactics": ["Execution", "Persistence"], "techniques": [{"id": "T1204", "name": "User Execution"}]}
- **Telemetry Interception**: {"tactics": ["Collection", "Exfiltration"], "techniques": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}]}
```

---

## Custom Type and Protocol Extensions

Use `config/asset_types_community.yaml` and `config/protocols_community.yaml` to extend the DSL, see [custom-asset-types.md](custom-asset-types.md).

---

## Complete DSL Template

**⚠️ CRITICAL FORMAT REQUIREMENT**: SecOpsTM parser requires EXACT DSL syntax. DO NOT use custom Markdown formats like `### Boundary:` or `**Name**:`. Use ONLY the list format shown below.

```markdown
# System Model: {System English Name}

## Description
{High-level system description in English}

## Context
gdaf_context = context/{project-name}_context.yaml
bom_directory = BOM
gdaf_min_technique_score = 0.75
system_description = "One sentence describing the system's purpose and main components."
sector = DevSecOps / Internal Platform
deployment_environment = on-prem
data_sensitivity = HIGH
internet_facing = true
user_base = internal_employees
compliance_requirements = [PCI-DSS, SOC2]
integrations = [Active Directory, SIEM]

## Boundaries
- **Internet**: isTrusted=False, type=network-on-prem, traversal_difficulty=low, description="Untrusted public internet — external attack surface", businessValue="External attack surface — no internal trust"
- **DMZ**: isTrusted=False, type=network-on-prem, traversal_difficulty=low, description="Demilitarized zone — internet-facing services", businessValue="Public-facing services — limited internal access"
- **Internal Network**: isTrusted=True, type=network-on-prem, traversal_difficulty=medium, description="Trusted internal corporate network — core business systems", businessValue="Internal corporate network — trusted employees and systems"

## Actors
- **External Attacker**: boundary=Internet, authenticity=none, isTrusted=False, description="Unauthenticated external threat actor with no prior access", businessValue="Primary threat source — targets customer data"
- **System Administrator**: boundary="Internal Network", authenticity=two-factor, isTrusted=True, description="Privileged internal user with domain admin rights", businessValue="Full system access — can modify configurations"

## Servers
- **API Gateway**:
  boundary=DMZ,
  type=api-gateway,
  classification=RESTRICTED,
  machine=container,
  internet_facing=True,
  mfa_enabled=True,
  credentials_stored=False,
  description="API gateway — all external traffic entry point",
  businessValue="Critical entry point — all customer transactions"
- **Database**:
  boundary="Internal Network",
  type=database,
  classification=SECRET,
  encryption=transparent,
  credentials_stored=True,
  description="PostgreSQL database — stores user data",
  businessValue="Core business data — customer records"

## Data
- **User Credentials**: description="User login credentials", classification=SECRET
- **Financial Records**: description="Financial transaction records", classification=TOP_SECRET

## Dataflows
- **UserToAPI**: from="External Attacker", to="API Gateway", protocol=HTTPS, isEncrypted=True, isAuthenticated=True, authentication=token, data="User Credentials"
- **APIToDB**: from="API Gateway", to=Database, protocol=TCP, isEncrypted=True, isAuthenticated=True, data="Financial Records"

## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=dashed
- **TCP**: color=blue, line_style=solid

## Severity Multipliers
- **API Gateway**: 2.0
- **Database**: 3.0

## Custom Mitre Mapping
- **Technique Name**: {"tactics": ["Initial Access"], "techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application"}]}
```

### DSL Format Rules (MUST FOLLOW)

1. **List format ONLY**: Use `- **Name**: key=value` for Boundaries, Actors, Servers, Data
2. **DO NOT use**: `### Boundary:`, `**Name**:`, or other custom Markdown headers
3. **Multi-line attributes**: Indent continuation lines deeper than `- **Name**:`
4. **References**: `from=`, `to=`, `boundary=` must match defined names (case-insensitive)
5. **String values**: Use double quotes for values with spaces: `description="..."`
6. **Boolean values**: Use `True`/`False` (Python syntax)
7. **Enum values**: Use only valid DSL enum values (e.g., `type=api-gateway`)

---

## Validation Rules

### Hard Constraints (Must Pass)

1. ✅ All `boundary=` references must be defined in `## Boundaries`
2. ✅ All `from=` and `to=` references must be defined in `## Actors` or `## Servers`
3. ✅ All `data=` references must be defined in `## Data`
4. ✅ All `type=` values must be valid enums
5. ✅ All `classification=` values must be valid enums
6. ✅ All `protocol=` values must be defined in `## Protocol Styles` or be standard protocols

### Soft Constraints (Recommended)

1. ✅ All servers have BOM files
2. ✅ All data flows are encrypted when crossing untrusted boundaries
3. ✅ All internet-facing servers have MFA
4. ✅ All credential-storing servers have encryption
5. ✅ All critical assets have high availability

---

## Common Errors

| Error | Fix |
|-------|-----|
| `boundary: undefined_boundary` | Define boundary in `## Boundaries` |
| `type: custom_type` | Use standard type or define in config/ |
| `classification: confidential` | Use `RESTRICTED` or other valid enum |
| `from: undefined_server` | Define server in `## Servers` |
| Missing required fields | Add all required fields |

---

### DSL Format Rules (MUST FOLLOW)

1. **List format ONLY**: Use `- **Name**: key=value` for Boundaries, Actors, Servers, Data
2. **DO NOT use**: `### Boundary:`, `**Name**:`, or other custom Markdown headers
3. **Multi-line attributes**: Indent continuation lines deeper than `- **Name**:`
4. **References**: `from=`, `to=`, `boundary=` must match defined names (case-insensitive)
5. **String values**: Use double quotes for values with spaces: `description="..."`
6. **Boolean values**: Use `True`/`False` (Python syntax)
7. **Enum values**: Use only valid DSL enum values (e.g., `type=api-gateway`)
