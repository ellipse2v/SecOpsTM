---
name: secopstm-threat-modeling
description: Perform comprehensive threat modeling for target systems using SecOpsTM Markdown DSL. Trigger when users request threat modeling, threat model generation, or security analysis in SecOpsTM format. Supports both single-model and multi-subsystem project structures.
---

# SecOpsTM Threat Modeling

## Quick Start

1. **Gather System Information** → 2. **Stage Information** → 3. **Assess Complexity** → 4. **Define Custom Assets/Protocols (if needed)** → 5. **Present Modeling Strategy** (user confirmation) → 6. **Generate Model** → 7. **Generate Context/BOM** → 8. **Generate Custom Configuration** → 9. **Review Configuration** → 10. **Validate Model**

**Related Documentation**:
- [references/workflow.md](references/workflow.md) — Information collection checklist (12 DSL fields)
- [references/dsl-syntax.md](references/dsl-syntax.md) — DSL syntax details
- [references/staging-format.md](references/staging-format.md) — Information staging format
- [references/naming-conventions.md](references/naming-conventions.md) — Naming conventions
- [references/custom-asset-types.md](references/custom-asset-types.md) — Custom types/protocols
- [references/modeling-strategy.md](references/modeling-strategy.md) — Single/multi-subsystem strategy
- [references/context-format.md](references/context-format.md) — Context YAML format
- [references/bom-format.md](references/bom-format.md) — BOM YAML format

## Output Structure

### Single-Model Structure (Default, ≤15 Servers)

```
{system-name}/
├── model.md                    # Threat model
├── context/
│   └── {system-name}_context.yaml
├── BOM/
│   └── {asset_name}.yaml
└── config/                     # Optional (generated when custom types/protocols exist)
    ├── asset_types_community.yaml   # Generated when custom asset types exist
    └── protocols_community.yaml     # Generated when non-standard protocols exist
```

### Multi-Subsystem Structure (>15 Servers)

```
{project-name}/
├── main.md                     # Top-level architecture
├── context/
│   └── {project-name}_context.yaml   # Global Context (required)
├── {subsystem1}/
│   ├── model.md
│   └── BOM/
├── config/                     # Optional (generated when custom types/protocols exist)
│   ├── asset_types_community.yaml
│   └── protocols_community.yaml
└── ...
```

**Note**: Subsystems by default **do NOT create** context/ directories, they reference the global Context directly (`gdaf_context = ../context/{project-name}_context.yaml`). Only create subsystem-specific Context when the subsystem has independent attack objectives.

## Modeling Workflow

### Step 1: Information Gathering

Follow the information collection checklist in [references/workflow.md](references/workflow.md) to gather system information, ensuring all DSL fields can be fully populated.

**Search Recommendations**: System architecture, technical whitepapers, network topology, security design, asset inventory, data classification, compliance requirements

**Language**: Information gathering phase can use Chinese for notes.

### Step 2: Information Staging

Structurally write collected information to `{project-name}/.tm-raw/` directory, supporting multiple collection rounds, incremental appending, and source traceability.

**Directory Structure**:
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

**Write Rules**:
- Append to `_search-log.md` after each search to avoid duplicate searches
- Tag each information item with source (URL/search term/time/credibility)
- Mark conflicting information as `Conflict: `
- Mark insufficient information as `To be supplemented: `

**Language**: Staging files can use Chinese for notes.

**Format Specifications**: See [references/staging-format.md](references/staging-format.md)

### Step 3: Complexity Assessment

| Metric | Single-Model | Multi-Subsystem |
|------|--------|----------|
| Server count | ≤15 | >15 |
| Data flows | ≤30 | >30 |
| Boundaries | ≤5 | >5 |

### Step 4: Define Custom Asset and Protocol Types (If Needed)

**Decision Rules** (scan `.tm-raw/assets.md` and `.tm-raw/dataflows.md`):
- `Server.type` not in 31 standard DSL types → requires `config/asset_types_community.yaml`
- `Dataflow.protocol` not in common standard protocols → requires `config/protocols_community.yaml`

**31 Standard Types**: firewall, domain-controller, auth-server, database, web-server, api-gateway, file-server, mail-server, management-server, workstation, load-balancer, vpn, vpn-gateway, plc, scada, repository, cicd, backup, dns, pki, siem, default, api_server, microservice, secrets_manager, monitoring, message_broker, cache, ingress, service_mesh, container_registry

**Common Protocols**: HTTP, HTTPS, SSH, TCP, UDP, TLS, FTP, SMTP, DNS, MySQL, PostgreSQL, MongoDB, Redis, MQTT, AMQP, Kafka, RDP, VNC, SMB, NFS (SecOpsTM built-in support, no definition needed)

**Naming Conventions**: Asset types = snake_case (e.g., `uav_platform`), Protocols = kebab-case with version (e.g., `ocusync-3-enterprise`)

### Step 5: Present Modeling Strategy and Confirm

Output modeling strategy for user confirmation: system name, complexity (high/medium/low), custom types/protocols list, recommended model (single-model/multi-subsystem), subsystem breakdown (if applicable). Generate models only after user confirmation.

**System Name Standardization**:
- Use **lowercase + hyphen** format (e.g., `dji-power-inspection`)
- Replace spaces and underscores with hyphens
- Remove special characters
- Examples:
  - "DJI Power Inspection" → `dji-power-inspection`
  - "My_System" → `my-system`
  - "Drone 350" → `drone-350`

**Filename Consistency**:
- model.md title: `# Threat Model: DJI Power Inspection`
- Context file: `context/dji-power-inspection_context.yaml`
- Ensure consistent use of hyphens/underscores

### Step 6: Generate Model File

**Read staging files as needed**:
- Read `.tm-raw/boundaries.md` → generate `## Boundaries`
- Read `.tm-raw/actors.md` → generate `## Actors`
- Read `.tm-raw/assets.md` → generate `## Servers`
- Read `.tm-raw/data.md` → generate `## Data`
- Read `.tm-raw/dataflows.md` → generate `## Dataflows`
- Read `.tm-raw/compliance.md` → supplement Context and descriptions

**Language Requirements**: **All output files must be in English** (model.md, Context YAML, BOM YAML, config YAML). Staging files and information gathering phase can use Chinese.

**DSL Enum Values**: See [references/dsl-syntax.md](references/dsl-syntax.md), must strictly comply.

**⚠️ description Field**: Boundaries/Actors/Servers all **require** filling (1-2 sentence technical descriptions), otherwise validator errors. Data is optional.

**⚠️ businessValue Field**: Boundaries/Actors/Servers all support, recommend filling for core assets.

**⚠️ Custom Type Rules**:
- Must generate `config/asset_types_community.yaml` when using custom types
- Custom type names cannot conflict with standard DSL enum values
- Fallback strategy: revert to `default` when config is undefined

### Step 7: Generate Context and BOM

**⚠️ Critical: Must Use Scripts to Generate YAML Files**

**Script Locations**: Scripts in the skill directory's `scripts/` subdirectory
- Skill directory: `{skill-root}/` (e.g., `E:/myvault/mydocuments/projects/02qaxctc/skills/tm/`)
- Script paths: `{skill-root}/scripts/generate_context.py`, `{skill-root}/scripts/generate_bom.py`

**Using Scripts**:
```bash
# Enter skill directory
cd {skill-root}

# Generate Context YAML
python scripts/generate_context.py --model model.md --output context/

# Generate BOM YAML
python scripts/generate_bom.py --model model.md --output BOM/
```

**Scripts Automatically Generate**:
- Context YAML: includes `attack_objectives`, `threat_actors`, `risk_criteria` (GDAF required fields)
- BOM YAML: one simple YAML file per Server (not nested structure)

**YAML Format Requirements**: Pure YAML format, comments with `#`, key-value pairs with `key: value`, **all field values in English**.

**User Supplement**: After script generation, supplement `os_version`, `software_version`, `patch_level`, `known_cves` and other specific information.

**⚠️ Do NOT Write Manually**: DO NOT manually write BOM or Context YAML files. Always use the scripts.

### Step 8: Generate Custom Configuration Files (Agent Manually Writes)

**⚠️ Must Read**: Before creating config files, **must read** [references/custom-asset-types.md](references/custom-asset-types.md) to understand complete format requirements and examples.

If custom types or protocols are detected, Agent manually creates `config/` directory.

**Create `config/asset_types_community.yaml` Format Template**:
```yaml
asset_types:
  {type_name}:
    description: "{1 sentence English description}"
    category: {iot|mobile_device|saas|cloud|industrial}
    platforms: [{platform1}, {platform2}]
    tactics: [{tactic1}, {tactic2}]
    key_techniques: [{technique1}, {technique2}]
    fuzzy_matches: [{alias1}, {alias2}]
```

**Create `config/protocols_community.yaml` Format Template**:
```yaml
protocols:
  {protocol-name}:
    description: "{1 sentence English description}"
    category: {wireless|cloud|industrial|physical|internet|streaming}
    encryption: {AES-256|TLS|none|code-signing}
    tactic_boost: [{tactic1}, {tactic2}]
```

**⚠️ Required Rules**:
- Use `asset_types:` and `protocols:` root keys (dictionary format, not list format)
- **Only custom protocols need definition** (standard protocols like HTTPS, TCP, USB, RTMP, etc. do NOT need definition)
- Each asset type must have 6 required fields: description, category, platforms, tactics, key_techniques, fuzzy_matches
- Each protocol must have 4 required fields: description, category, encryption, tactic_boost
- See [references/custom-asset-types.md](references/custom-asset-types.md)

### Step 9: Review Custom Extension Configuration

User reviews `config/asset_types_community.yaml` and `config/protocols_community.yaml` generated in Step 8, supplementing asset-specific information (models, CVEs, MITRE techniques).

### Step 10: Validate Model

**Use Validation Script**:

```bash
python scripts/validate_model.py --model-dir .
```

**Validation Checks**:
- DSL enum values: all hard-constraint fields use valid enum values
- DSL format: use `- **Name**: key=value` list format (NOT `### Boundary:` or `**Name**:`)
- Boundary references: all `boundary=` references are defined in `## Boundaries`
- Actor/Dataflow references: all `from=`, `to=`, `data=` references exist
- BOM correspondence: each Server has corresponding YAML file in BOM directory
- config/ directory: custom types/protocols are defined
- YAML syntax: use pure YAML format (simple structure, not nested)
- submodel paths: in multi-subsystem scenarios, paths point to existing files
- **Language check**: output files (model.md, YAML) all in English

**Final Self-Check List**:
- [ ] Script validation passed
- [ ] DSL format correct (use list format, not custom Markdown)
- [ ] Output structure complete (model.md, context/, BOM/, config/)
- [ ] Output files in English (model.md, YAML field values)
- [ ] BOM/Context generated with scripts (not manually written)
- [ ] Custom asset types defined (dictionary format, not list format)
- [ ] Custom protocols defined (dictionary format, not list format, **only custom protocols**)
- [ ] Reference integrity 100% passed
- [ ] GDAF fallback strategy acceptable

---

## Pre-Validation Checklist

Before running `validate_model.py`, Agent must check:

### model.md Checks
- [ ] `gdaf_context` path in `## Context` matches generated YAML filename (hyphen-separated)
- [ ] All `Server.type` values defined in `config/asset_types_community.yaml`
- [ ] All **custom protocols** in `Dataflow.protocol` defined in `config/protocols_community.yaml`
- [ ] Custom Mitre Mapping uses correct format or removed

### config/asset_types_community.yaml Checks
- [ ] Has `asset_types:` root key (not list format)
- [ ] Each type has 6 required fields: description, category, platforms, tactics, key_techniques, fuzzy_matches
- [ ] Uses dictionary format (not list format)

### config/protocols_community.yaml Checks
- [ ] Has `protocols:` root key (not list format)
- [ ] Each protocol has 4 required fields: description, category, encryption, tactic_boost
- [ ] **Only includes custom protocols** (standard protocols like HTTPS, TCP, USB, RTMP, etc. do NOT need definition)

### Validation
- [ ] Run `python scripts/validate_model.py --model-dir .`
- [ ] Ensure result: 0 failures

**Common Error Fixes**:
- ❌ "Invalid Python dict literal" → Remove or simplify Custom Mitre Mapping section
- ❌ "Custom type not defined" → Check `asset_types:` root key and 6 required fields
- ❌ "Custom protocol not defined" → Only custom protocols need definition, standard protocols do NOT
- ❌ "Path does not exist" → Ensure Context filename matches model.md reference (hyphen-separated)

---

## Boundaries and Limitations

**Agent Should NOT**:
- Use Chinese in output files → Output files (model.md, YAML) must all be in English
- Use custom Markdown formats → Must use DSL list format (`- **Name**: key=value`)
- Manually write BOM/Context YAML → Must use scripts to generate
- Use list format for config/*.yaml → Must use dictionary format
- Guess sensitive security configurations (passwords, API keys, vulnerability details) → Mark "To be provided by user"
- Access private documents requiring authentication → Use only public information
- Generate model files before user confirms modeling strategy
- Create subsystem nesting beyond 2 levels

**Language Notes**:
- Skill documentation, information gathering, staging files: can use Chinese
- Output files (model.md, Context YAML, BOM YAML, config YAML): must all be in English

**Format Warnings**:
- ❌ Wrong: `### Boundary: Name` + `**Description**:` → ✅ Correct: `- **Name**: key=value`
- ❌ Wrong: BOM YAML nested structure (`asset: name: "..."`) → ✅ Correct: BOM YAML simple structure (`asset: "..."`)
- ❌ Wrong: config YAML list (`- name: "type"`) → ✅ Correct: config YAML dictionary (`type_name: description: "..."`)
- ❌ Wrong: Defining standard protocols in config (HTTPS, TCP, USB) → ✅ Correct: Only define custom protocols

---

Full DSL template, syntax, and examples see [references/dsl-syntax.md](references/dsl-syntax.md).
