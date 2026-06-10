# GDAF Context Format

## Overview

The GDAF (Generic Threat Modeling and Attack Framework) context file defines the attack context for threat modeling. It includes attack objectives, threat actors, and risk criteria.

## File Location

**Single-Model:** `{system-name}/context/{system-name}_context.yaml`

**Multi-Subsystem:** `{project-name}/context/{project-name}_context.yaml`

## Basic Structure

```yaml
# {system-name}_context.yaml

# GDAF Configuration
gdaf_context: "context/{name}_context.yaml"
bom_directory: "BOM"
gdaf_min_technique_score: 0.75

# Attack Objectives
attack_objectives:
  - name: "{Objective Name}"
    description: "{Brief description}"
    priority: "{high|medium|low}"
    categories:
      - "{category1}"
      - "{category2}"

# Threat Actors
threat_actors:
  - name: "{Actor Name}"
    type: "{external|internal|partner|supplier}"
    sophistication: "{low|medium|high|expert}"
    motivation: "{financial|ideological|reputation|state-sponsored|opportunistic}"
    resources: "{limited|moderate|substantial|extensive}"
    description: "{Brief description}"

# Risk Criteria
risk_criteria:
  asset_importance:
    "{asset_type}": "{1.0-3.0}"
  
  threat_likelihood:
    "{threat_type}": "{1.0-3.0}"
  
  vulnerability_severity:
    "{vulnerability_type}": "{1.0-3.0}"

# Optional: VEX (Vulnerability Exchange)
vex_file: "{optional_vex_file}"
vex_directory: "{optional_vex_directory}"
```

## Attack Objectives

### Standard Categories

| Category | Description | Example |
|----------|-------------|---------|
| `data-breach` | Unauthorized access to data | Steal customer PII |
| `service-disruption` | Disrupt service availability | DDoS attack |
| `data-tampering` | Modify data integrity | Change flight logs |
| `identity-theft` | Steal identities/credentials | Credential harvesting |
| `reputation-damage` | Damage organizational reputation | Deface website |
| `financial-loss` | Direct financial impact | Ransomware |
| `physical-safety` | Threaten physical safety | Drone hijacking |
| `intellectual-property` | Steal IP/trade secrets | Code theft |

### Example Objectives

```yaml
attack_objectives:
  - name: "Data Exfiltration"
    description: "Attacker steals sensitive data including user PII and flight records"
    priority: "high"
    categories:
      - "data-breach"
      - "intellectual-property"

  - name: "Service Disruption"
    description: "Attacker disrupts drone operations through DoS or hijacking"
    priority: "high"
    categories:
      - "service-disruption"
      - "physical-safety"

  - name: "Command Injection"
    description: "Attacker gains unauthorized control of drone systems"
    priority: "critical"
    categories:
      - "data-tampering"
      - "physical-safety"
```

## Threat Actors

### Actor Types

| Type | Description | Example |
|------|-------------|---------|
| `external` | Outside the organization | Hacktivists, criminals |
| `internal` | Employees/contractors | Disgruntled employee |
| `partner` | Business partners | Third-party vendor |
| `supplier` | Supply chain | Hardware supplier |

### Sophistication Levels

| Level | Description | Capabilities |
|-------|-------------|--------------|
| `low` | Script kiddies | Pre-built tools |
| `medium` | Skilled attackers | Custom scripts |
| `high` | Advanced persistent threats | Zero-days, custom malware |
| `expert` | Nation-state level | Full-spectrum capabilities |

### Motivation Types

| Type | Description | Typical Targets |
|------|-------------|-----------------|
| `financial` | Monetary gain | Payment systems, data |
| `ideological` | Political/social agenda | Government, NGOs |
| `reputation` | Personal/company reputation | Competitors |
| `state-sponsored` | National interests | Critical infrastructure |
| `opportunistic` | Easy targets | Any vulnerable system |

### Example Threat Actors

```yaml
threat_actors:
  - name: "Organized Crime Group"
    type: "external"
    sophistication: "high"
    motivation: "financial"
    resources: "substantial"
    description: "Well-funded criminal organization targeting customer data for sale on dark web"

  - name: "Competitor"
    type: "external"
    sophistication: "medium"
    motivation: "reputation"
    resources: "moderate"
    description: "Competing drone manufacturer seeking to steal proprietary technology"

  - name: "Disgruntled Employee"
    type: "internal"
    sophistication: "medium"
    motivation: "revenge"
    resources: "limited"
    description: "Former employee with knowledge of internal systems"

  - name: "Nation-State Actor"
    type: "external"
    sophistication: "expert"
    motivation: "state-sponsored"
    resources: "extensive"
    description: "Foreign intelligence service targeting critical infrastructure data"
```

## Risk Criteria

### Asset Importance Multipliers

Define how important different asset types are:

```yaml
risk_criteria:
  asset_importance:
    "database": 3.0
    "api-gateway": 2.5
    "web-server": 2.0
    "workstation": 1.5
    "default": 1.0
```

### Threat Likelihood Multipliers

Define likelihood of different threat types:

```yaml
risk_criteria:
  threat_likelihood:
    "credential-theft": 2.5
    "ddos": 2.0
    "insider-threat": 1.5
    "zero-day": 1.0
    "default": 1.0
```

### Vulnerability Severity Multipliers

Define severity of different vulnerability types:

```yaml
risk_criteria:
  vulnerability_severity:
    "remote-code-execution": 3.0
    "authentication-bypass": 2.5
    "information-disclosure": 2.0
    "dos": 1.5
    "default": 1.0
```

## VEX (Vulnerability Exchange)

Optional fields for integrating vulnerability intelligence:

```yaml
# Reference to VEX data
vex_file: "vex/internal_vulnerabilities.yaml"
vex_directory: "vex/"

# VEX file format (example)
# known_vulnerabilities:
#   - cve: "CVE-2024-1234"
#     asset: "api_gateway"
#     status: "mitigated"
#     justification: "WAF rules in place block this attack vector"
```

## Validation Rules

1. ✅ File location matches structure (single vs multi-subsystem)
2. ✅ All attack objectives have required fields
3. ✅ All threat actors have required fields
4. ✅ Risk criteria use valid multipliers (1.0-3.0)
5. ✅ Categories use standard GDAF categories
6. ✅ File references (VEX) exist if specified

## Relationship to Model

The context file works with `model.md`:
- **Context**: Who attacks, what they want, how to score risk
- **Model**: What's being attacked, how data flows, security controls

Both are required for complete threat modeling.

## Example Complete File

```yaml
# dji_power_inspection_context.yaml

gdaf_context: "context/dji_power_inspection_context.yaml"
bom_directory: "BOM"
gdaf_min_technique_score: 0.75

attack_objectives:
  - name: "Drone Hijacking"
    description: "Attacker takes unauthorized control of drone for malicious purposes"
    priority: "critical"
    categories:
      - "physical-safety"
      - "service-disruption"

  - name: "Flight Data Theft"
    description: "Attacker steals proprietary flight data and inspection results"
    priority: "high"
    categories:
      - "intellectual-property"
      - "data-breach"

  - name: "Command Channel Interception"
    description: "Attacker intercepts or injects commands to drone systems"
    priority: "high"
    categories:
      - "data-tampering"
      - "physical-safety"

threat_actors:
  - name: "Competitor"
    type: "external"
    sophistication: "medium"
    motivation: "financial"
    resources: "moderate"
    description: "Competing drone manufacturer seeking to steal proprietary inspection data"

  - name: "Hacktivist Group"
    type: "external"
    sophistication: "medium"
    motivation: "ideological"
    resources: "limited"
    description: "Privacy advocacy group targeting drone surveillance capabilities"

  - name: "Organized Crime"
    type: "external"
    sophistication: "high"
    motivation: "financial"
    resources: "substantial"
    description: "Criminal group seeking to ransom drone operations or steal customer data"

risk_criteria:
  asset_importance:
    "drone": 3.0
    "ground-station": 2.5
    "cloud-platform": 2.5
    "database": 3.0
    "default": 1.5
  
  threat_likelihood:
    "radio-interference": 2.5
    "credential-theft": 2.0
    "insider-threat": 1.5
    "default": 1.0
  
  vulnerability_severity:
    "authentication-bypass": 3.0
    "command-injection": 3.0
    "encryption-bypass": 2.5
    "default": 1.5
```

## Related Documents

- [generate_context.py](../scripts/generate_context.py) - Auto-generation script
- [dsl-syntax.md](dsl-syntax.md) - DSL syntax
- [output-structure.md](output-structure.md) - Output structure
- [custom-asset-types.md](custom-asset-types.md) - Custom asset types
