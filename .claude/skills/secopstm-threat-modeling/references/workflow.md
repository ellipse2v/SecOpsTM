# SecOpsTM Workflow Reference

## Table of Contents

- [Step 1: Information Gathering](#step-1-information-gathering)
- [Step 2: Information Staging](#step-2-information-staging)
- [Step 3: Complexity Assessment and Modeling Strategy](#step-3-complexity-assessment-and-modeling-strategy)
- [Step 4: Define Custom Asset and Protocol Types](#step-4-define-custom-asset-and-protocol-types)
- [Step 5: Present Modeling Strategy and Wait for User Confirmation](#step-5-present-modeling-strategy-and-wait-for-user-confirmation)
- [Step 6: Generate Model File](#step-6-generate-model-file)
- [Step 7: Generate Context and BOM](#step-7-generate-context-and-bom)
- [Step 8: Generate Custom Extension Configuration](#step-8-generate-custom-extension-configuration)
- [Step 9: Reference Integrity Self-Check](#step-9-reference-integrity-self-check)
- [Multi-Subsystem Decomposition Strategies](#multi-subsystem-decomposition-strategies)
- [Output File Checklist](#output-file-checklist)

## Complete Workflow

### Step 1: Information Gathering

Collect system information using the following checklist to ensure all DSL fields can be populated.

**Information Acquisition Priority:**
1. **Public Channels** (Highest): Web search, official documentation, technical whitepapers, product manuals, API documentation
2. **Agent Inference** (Medium): Industry knowledge, architecture patterns, security best practices
3. **User Confirmation** (Low): Internal configurations, security policies, vulnerability information

#### 1.1 System Basic Information

**Required Fields:**
- `System Name`: Official product name or project codename
- `System Description`: Product documentation or website introduction
- `Industry Domain`: Inferred from product positioning (e.g., Industrial IoT, SaaS, Finance)
- `Compliance Requirements`: Industry regulations (Equal Protection 2.0, ISO 27001, GDPR, etc.)

#### 1.2 Network Topology and Trust Boundaries (Boundaries)

**Required Fields:**
- `name`: Network zone/security domain name
- `type`: `network-on-prem`, `network-cloud-provider`, `execution-environment`, `container-runtime`
- `isTrusted`: External=untrusted, Internal=trusted
- `traversal_difficulty`: External=low, Internal=medium, Core=high
- `description`: 1-2 sentence technical description
- `businessValue`: Boundary business impact description

**Optional Fields:**
- `color`: Inferred from trust level
- Boundary nesting relationships: Architecture diagram hierarchy

#### 1.3 Actors

**Required Fields:**
- `name`: User roles, external systems, potential attackers
- `boundary`:所属 boundary name
- `authenticity`: `none`, `credentials`, `two-factor`, `client-certificate`, `externalized`
- `isTrusted`: External=untrusted, Internal=trusted
- `description`: 1-2 sentence technical description
- `businessValue`: Actor business impact description

**Optional Fields:**
- `color`: Inferred from role
- `providesAuthentication`: Whether it provides authentication for other elements

#### 1.4 Asset Inventory (Servers)

**Required Fields:**
- `name`: Component name/function
- `boundary`:所属 boundary name
- `type`: Infer DSL type from function (31 standard types, see dsl-syntax.md)
- `description`: 1-2 sentence technical description
- `classification`: Core assets=RESTRICTED/SECRET, Public=PUBLIC
- `internet_facing`: Public service=true

**Recommended Fields:**
- `machine`: Deployment form (`physical`, `virtual`, `container`, `serverless`, `embedded`, `saas`)
- `CIA`: Confidentiality/Integrity/Availability (`low`, `medium`, `high`, `critical`)
- `mfa_enabled`: Modern systems default=true
- `credentials_stored`: Auth/database servers=true
- `encryption`: Stored data encryption method
- `redundant`: Core assets=true
- `auth_protocol`: `none`, `ldap`, `kerberos`, `saml`, `oauth`, `oidc`, `radius`
- `waf`/`ids`/`ips`: Firewall/gateway type default=true
- `businessValue`: Core asset business impact
- `color`: Inferred from asset type
- `patch_level`: Default unknown; many known vulnerabilities=outdated, Regular updates=current
- `detection_level`: Default unknown; EDR/SIEM=high, Basic logging=medium, No monitoring=none
- `tags`: OS version, software identifiers
- `submodel`: Auto-set for multi-subsystem scenarios

#### 1.5 Data Assets (Data)

**Required Fields:**
- `name`: Data object name
- `classification`: `PUBLIC`, `INTERNAL`, `RESTRICTED`, `SECRET`, `TOP_SECRET`

**Optional Fields:**
- `description`: Inferred from name
- `credentialsLife`: `NONE`, `SHORT`, `LONG`, `AUTO`, `MANUAL`, `HARDCODED`
- `isPII`/`isPassword`/`isCryptographicKey`: Special data type markers

#### 1.6 Data Flows (Dataflows)

**Required Fields:**
- `from`: Source element name (actor or server)
- `to`: Destination element name (actor or server)

**Recommended Fields:**
- `protocol`: Protocol name (HTTP, HTTPS, SSH, TCP, UDP, Modbus, etc.)
- `isEncrypted`: HTTPS/TLS=true, HTTP/plaintext=false
- `isAuthenticated`: Internal services=true, Public interfaces=false
- `authentication`: `none`, `credentials`, `session-id`, `token`, `two-factor`, `externalized`, `kerberos`
- `authorization`: `none`, `technical-user`, `enduser-identity-propagation`
- `data`: Name of data being transferred (reference ## Data)

**Optional Fields:**
- `vpn`: Remote access=true
- `bidirectional`: Bidirectional communication=true
- `ipFiltered`: Internal services=true
- `readOnly`: Monitoring/logging=true
- `usage`: `business`, `devops`, `management`
- `color`: Inferred from protocol

#### 1.7 Security Controls and Mitigations

**Fields:** Existing security controls, network isolation (VLAN, micro-segmentation, zero trust), monitoring and detection (logging, SIEM, EDR)

#### 1.8 GDAF Context

**Fields:**
- `gdaf_context`: Default `context/{name}_context.yaml`
- `bom_directory`: Default `BOM`
- `vex_file`/`vex_directory`: User-provided (internal vulnerability intelligence)
- `gdaf_min_technique_score`: Default 0.75-0.8

#### 1.9 Protocol Styles

**Fields:** Protocol styles (infer color and line style by protocol type)

#### 1.10 Severity Multipliers

**Fields:** Severity multipliers (core assets=2.0-3.0, general=1.0)

#### 1.11 Custom Mitre Mapping

**Fields:** Custom MITRE mapping (infer ATT&CK techniques based on domain knowledge)

#### 1.12 BOM Information (Asset Inventory Supplement)

**Fields:**
- OS version, software version, running services
- `patch_level`: Default unknown
- `known_cves`: User-provided (internal vulnerability scans)
- `detection_level`: Default unknown

**Search Suggestions:** System architecture, technical whitepapers, network topology, security design, deployment architecture, API documentation, data dictionary, compliance requirements

---

### Step 2: Information Staging

Structure and write collected information to `{project-name}/.tm-raw/` directory, supporting multiple collections, incremental additions, and source tracking.

**Directory Structure:**
```
{project-name}/.tm-raw/
├── _search-log.md       # Search log (keywords, URLs, timestamps, credibility)
├── architecture.md      # System architecture
├── assets.md            # Asset inventory
├── actors.md            # Actors
├── boundaries.md        # Boundary information
├── data.md              # Data assets
├── dataflows.md         # Data flow information
├── security.md          # Security controls
├── context.md           # GDAF context
├── protocol-styles.md   # Protocol styles
├── severity.md          # Severity multipliers
├── mitre-mapping.md     # Custom MITRE mapping
└── compliance.md        # Compliance requirements
```

**Writing Rules:**
1. Append to `_search-log.md` after each search to avoid duplicate searches
2. Tag each piece of information with source (URL/search query/timestamp/credibility)
3. Mark conflicts with `Conflict:` prefix
4. Mark insufficient information with `To be supplemented:` prefix

**Credibility Levels:** High (official documentation), Medium (technical blogs/third-party analysis), Low (forums/news releases)

**Complete Format Specification:** See [staging-format.md](staging-format.md)

---

### Step 3: Complexity Assessment and Modeling Strategy Selection

Based on information collected in Step 1, assess system complexity and decide whether to use single-model or multi-subsystem model:

#### Single-Model Use Case (Default Recommended)

Use single-model when **ALL** of the following conditions are met:

- Server/component count ≤ 15
- Data flow count ≤ 30
- Boundary count ≤ 5
- Relatively flat architecture, no obvious layering
- All components maintained by same team/project

**Typical Examples:**
- Small web application (frontend + backend + database)
- Single cloud service (e.g., SaaS platform)
- Simple IoT system (device + cloud platform + App)

#### Multi-Subsystem Model Use Case

Use multi-subsystem model when **ANY** of the following conditions are met:

- Server/component count > 15
- Data flow count > 30
- System has clear **layered architecture** (e.g., edge layer + platform layer + application layer)
- System contains **independently deployed subsystems**
- Different subsystems maintained by **different teams**
- Clear **boundaries and interfaces** between subsystems

**Typical Examples:**
- Drone system (aircraft + ground station + cloud platform + docking station)
- Smart factory (OT network + IT network + cloud MES)
- Healthcare HIS system (outpatient + inpatient + laboratory + imaging)

---

### Step 4: Define Custom Asset and Protocol Types

Scan staging files for asset types and protocols to determine if custom configuration is needed.

**Decision Rules:**
| Check Item | Condition | Result |
|------------|-----------|--------|
| `Server.type` | Not in 31 standard DSL types | Need `config/asset_types_community.yaml` |
| `Dataflow.protocol` | Not in common standard protocols | Need `config/protocols_community.yaml` |

**31 Standard DSL Types:** `firewall`, `domain-controller`, `auth-server`, `database`, `web-server`, `api-gateway`, `file-server`, `mail-server`, `management-server`, `workstation`, `load-balancer`, `vpn`, `vpn-gateway`, `plc`, `scada`, `repository`, `cicd`, `backup`, `dns`, `pki`, `siem`, `default`, `api_server`, `microservice`, `secrets_manager`, `monitoring`, `message_broker`, `cache`, `ingress`, `service_mesh`, `container_registry`

**Common Standard Protocols:** HTTP, HTTPS, FTP, SSH, TELNET, SMTP, DNS, DHCP, SNMP, LDAP, NTP, RDP, VNC, SMB, NFS, MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle, MQTT, AMQP, Kafka, TCP, UDP, TLS, SSL, IPSec, OpenVPN, WireGuard, IKE

**Naming Conventions:** See [references/naming-conventions.md](references/naming-conventions.md)
- Asset types: snake_case (e.g., `uav_platform`)
- Protocols: kebab-case, include version (e.g., `ocusync-3-enterprise`)

---

### Step 5: Present Modeling Strategy and Wait for User Confirmation

After information gathering and complexity assessment, **present the modeling strategy for user confirmation first**:

```markdown
【Modeling Strategy Recommendation】
- System Name: {system_name}
- System Complexity: {high/medium/low} ({N} servers, {M} data flows, {K} boundaries)
- Recommended Model: **Single-Model** or **Multi-Subsystem Model**

{If multi-subsystem:}
- Decomposition Strategy: By physical deployment/business domain/trust domain
- Subsystem Division:
  - {subsystem1}/ - {description} ({N} servers)
  - {subsystem2}/ - {description} ({M} servers)
  - ...
- Rationale: {Why this decomposition}

Please confirm if the modeling strategy is appropriate:
1. Confirm - Generate system model with this strategy
2. Adjust - User provides modification suggestions (e.g., merge some subsystems/change to single-model)
```

**After user confirmation**, then generate the specific system model files.
---

### Step 6: Generate Model File

**Single-Model Scenario**: Directly generate `model.md` containing all components and data flows.

**Multi-Subsystem Scenario**:

1. **Generate main.md (Top-level Architecture)**: Cross-subsystem boundaries, data flows, subsystem entry points (`submodel=` reference), global Context
2. **Generate each subsystem model.md**: Subsystem internal components, data flows, subsystem-level BOM
3. **Generate BOM and Context**: Global Context (required), subsystem Context (only when independent attack objectives exist), subsystem BOM (required)

---

### Step 7: Generate Context and BOM

**Context**: Global Context (`context/{project-name}_context.yaml`) required, subsystem Context only created when independent attack objectives exist. Includes `attack_objectives`, `threat_actors`, `risk_criteria`.

**BOM**: One YAML file per key asset (simple YAML format). Single-model: `{system-name}/BOM/`; Multi-subsystem: `{subsystem}/BOM/`.

---

### Step 8: Generate Custom Extension Configuration (If Needed)

When the model uses non-standard asset types or protocols:

```
{project-name}/
└── config/
    ├── asset_types_community.yaml  # Custom asset types
    └── protocols_community.yaml    # Custom protocols
```

---

### Step 9: Reference Integrity Self-Check

**Single-Model Scenario Checks**:
- Boundary references: All `boundary=` referenced names defined in `## Boundaries`
- Actor references: All `from=` and `to=` referenced names defined in `## Actors` or `## Servers`
- Data references: All `data=` referenced names defined in `## Data`
- Server references: All `target_asset_names` match names defined in `## Servers`
- BOM filenames: lowercase + underscore (e.g., `api_gateway.yaml`)
- DSL enum values: All hard constraint fields use valid enum values
- Filename: Single-model scenario uses `model.md`

**Multi-Subsystem Scenario Additional Checks**:
- submodel paths: All `submodel=` paths point to existing files
- Entry point marking: Subsystem entry servers should set `internet_facing=True` (if applicable)
- Cross-subsystem data flows: `from=` and `to=` can be servers from different subsystems
- Ghost Node consistency: Parent model servers mentioned in sub-models must be defined in parent model
- Context references: Sub-models either reference global Context or define their own Context
- BOM coverage: Every server has definition in some BOM file

---

## Multi-Subsystem Decomposition Strategies

### Strategy 1: By Physical Deployment (Recommended)

```
{project-name}/
├── main.md
├── context/{project-name}_context.yaml
├── drone_subsystem/
│   ├── model.md
│   └── BOM/
├── ground_subsystem/
│   ├── model.md
│   └── BOM/
├── cloud_subsystem/
│   ├── model.md
│   └── BOM/
└── dock_subsystem/
    ├── model.md
    └── BOM/
```

### Strategy 2: By Business Domain

```
{project-name}/
├── main.md
├── frontend/
│   ├── model.md
│   └── BOM/
├── backend/
│   ├── model.md
│   └── BOM/
└── data/
    ├── model.md
    └── BOM/
```

### Strategy 3: By Trust Domain

```
{project-name}/
├── main.md
├── internet_facing/
│   ├── model.md
│   └── BOM/
├── dmz/
│   ├── model.md
│   └── BOM/
└── internal/
    ├── model.md
    └── BOM/
```

---

## Output File Checklist

### Single-Model Scenario

```
{system-name}/
├── model.md
├── context/
│   └── {system-name}_context.yaml
├── BOM/
│   ├── {asset1}.yaml
│   └── {asset2}.yaml
└── config/                    # If needed
    ├── asset_types_community.yaml
    └── protocols_community.yaml
```

### Multi-Subsystem Scenario

```
{project-name}/
├── main.md
├── context/
│   └── {project-name}_context.yaml
├── BOM/                       # Optional
├── config/                    # If needed
│   ├── asset_types_community.yaml
│   └── protocols_community.yaml
├── {subsystem1}/
│   ├── model.md
│   └── BOM/
│       └── {asset}.yaml
├── {subsystem2}/
│   ├── model.md
│   └── BOM/
│       └── {asset}.yaml
└── ...
```
