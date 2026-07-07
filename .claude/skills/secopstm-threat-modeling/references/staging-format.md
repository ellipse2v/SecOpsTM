# Information Staging Format

## Overview

Before generating the system model, collect and structure information in the `{project-name}/.tm-raw/` directory. This enables incremental collection, source tracking, and conflict resolution.

## Directory Structure

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

## File Formats

### _search-log.md

Record every search with metadata:

```markdown
## Search Log

### 2026-06-08 10:30
**Query:** "DJI M300 RTK communication protocol security"
**Sources:**
- [DJI Data Security Page](https://enterprise.dji.com/cn/data-security) - High credibility (official)
- [Tech Blog Analysis](https://example.com/dji-security) - Medium credibility (third-party)

**Findings:**
- Data encrypted with AES-256
- HTTPS/WSS for cloud communication
- SD card encryption supported

**Conflicts:** None
**Gaps:** Need more info on specific port numbers
```

### architecture.md

```markdown
## System Architecture

### Overview
{High-level description}

### Components
- **Component Name**: {Function}
- **Deployment**: {Physical/Virtual/Cloud}
- **Dependencies**: {External systems}

### Network Topology
{Diagram or description}
```

### assets.md

```markdown
## Asset Inventory

### Servers/Components

| Name | Type | Boundary | Description | Classification |
|------|------|----------|-------------|----------------|
| api_gateway | api-gateway | dmz | Main API entry point | RESTRICTED |
| database | database | internal | Primary database | SECRET |

### Notes
- {Additional observations}
- {Source references}
```

### actors.md

```markdown
## Actors

### External
- **External Attacker**: boundary=internet, authenticity=none, isTrusted=false
- **End User**: boundary=internet, authenticity=credentials, isTrusted=false

### Internal
- **System Administrator**: boundary=internal_network, authenticity=two-factor, isTrusted=true
- **Service Account**: boundary=internal_network, authenticity=client-certificate, isTrusted=true
```

### boundaries.md

```markdown
## Trust Boundaries

- **internet**: type=network-on-prem, isTrusted=false, traversal_difficulty=low, color=red
- **dmz**: type=network-on-prem, isTrusted=false, traversal_difficulty=medium, color=orange
- **internal_network**: type=network-on-prem, isTrusted=true, traversal_difficulty=high, color=green
```

### data.md

```markdown
## Data Assets

| Name | Classification | Description | Credentials Life |
|------|----------------|-------------|------------------|
| user_credentials | SECRET | User authentication data | AUTO |
| flight_logs | RESTRICTED | Drone flight records | MANUAL |
| telemetry_data | INTERNAL | Real-time telemetry | NONE |
```

### dataflows.md

```markdown
## Data Flows

| From | To | Protocol | Encrypted | Authenticated | Data |
|------|-----|----------|-----------|---------------|------|
| drone | ground_station | ocusync-3 | true | true | telemetry_data |
| ground_station | cloud | https | true | true | flight_logs |
```

### security.md

```markdown
## Security Controls

### Network Isolation
- VLAN segmentation
- Micro-segmentation
- Zero trust architecture

### Monitoring
- Centralized logging
- SIEM integration
- EDR on all endpoints

### Access Control
- MFA for all admin access
- RBAC for applications
- Network-level ACLs
```

### context.md

```markdown
## GDAF Context

- **gdaf_context**: context/{name}_context.yaml
- **bom_directory**: BOM
- **gdaf_min_technique_score**: 0.75
- **vex_file**: {Optional - internal vulnerability intelligence}
```

### protocol-styles.md

```markdown
## Protocol Styles

| Protocol | Color | Line Style |
|----------|-------|------------|
| https | darkgreen | solid |
| http | red | dashed |
| ssh | blue | dashed |
| ocusync-3 | purple | solid |
```

### severity.md

```markdown
## Severity Multipliers

| Asset Type | Multiplier | Reason |
|------------|------------|--------|
| Critical Asset | 3.0 | Core business function |
| Important Server | 2.0 | Significant impact if compromised |
| Standard Server | 1.0 | Normal impact |
```

### mitre-mapping.md

```markdown
## Custom MITRE ATT&CK Mapping

### Industry-Specific Techniques

- **Drone Hijacking**: {"tactics": ["Execution", "Persistence"], "techniques": [{"id": "T1204", "name": "User Execution"}]}
- **Telemetry Interception**: {"tactics": ["Collection", "Exfiltration"], "techniques": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}]}
```

### compliance.md

```markdown
## Compliance Requirements

- **Industry**: Industrial IoT, Aviation
- **Regulations**: 
  - Equal Protection 2.0 (等保 2.0)
  - ISO 27001
  - GDPR (if EU data involved)
- **Certifications**: {Required certifications}
```

## Writing Rules

1. **Append to `_search-log.md`** after each search to avoid duplicate work
2. **Tag sources** (URL/search query/timestamp/credibility) for every piece of information
3. **Mark conflicts** with `Conflict:` prefix
4. **Mark gaps** with `To be supplemented:` prefix
5. **Credibility levels**:
   - **High**: Official documentation
   - **Medium**: Technical blogs/third-party analysis
   - **Low**: Forums/news releases

## Credibility Rating

| Level | Source Type | Example |
|-------|-------------|---------|
| High | Official docs, whitepapers | DJI official website |
| Medium | Tech blogs, vendor analysis | Security researcher blog |
| Low | Forums, news | Reddit, news articles |

## Next Steps

After completing information staging:

1. Review all files for completeness
2. Resolve conflicts
3. Fill identified gaps
4. Proceed to complexity assessment (Step 3 in workflow)

## Related Documents

- [../SKILL.md](../SKILL.md) - SecOpsTM threat modeling skill
- [dsl-syntax.md](dsl-syntax.md) - DSL syntax reference
- [output-structure.md](output-structure.md) - Output structure
- [workflow.md](workflow.md) - Information gathering workflow
- [modeling-strategy.md](modeling-strategy.md) - Modeling strategy guide
