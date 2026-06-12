# Claude Code Skill — AI-Assisted Threat Model Generation

SecOpsTM ships a **Claude Code skill** that guides an AI agent through the full threat modeling
workflow: information gathering, DSL file generation, BOM/context YAML generation, and validation.
The skill is installed automatically when you clone the repository — Claude Code detects it from
`.claude/skills/secopstm-threat-modeling/`.

---

## Prerequisites

| Requirement | Details |
|---|---|
| [Claude Code](https://claude.ai/code) | CLI or IDE extension — any recent version |
| SecOpsTM installed | `pip install -e .` from repo root, or `pip install SecOpsTM` |
| Graphviz | Required for diagram generation after the model is built |

The skill does not require a running SecOpsTM server or any AI API key — it generates the DSL
files locally and validates them using the `secopstm validate` CLI command.

---

## How to Trigger the Skill

Open Claude Code in the SecOpsTM repository directory (or any working directory where you
want to create the model), then describe the system you want to model:

```
Generate a threat model for our Kubernetes-based SaaS invoicing platform.
It has a React frontend, a Node.js API gateway, three microservices, and
a PostgreSQL database. The platform is PCI DSS scoped.
```

Claude Code automatically invokes the `secopstm-threat-modeling` skill. You do not need to
name the skill explicitly.

---

## Workflow

The skill follows a ten-step process. Steps 1–4 run autonomously; **step 5 always pauses for
your confirmation** before any file is written.

```
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│ 1. Gather    │──▶│ 2. Stage     │──▶│ 3. Assess    │──▶│ 4. Custom    │──▶│ 5. CONFIRM   │
│    info      │   │    info      │   │    complexity│   │    types?    │   │    strategy  │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                                                     │ your go-ahead
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────▼───────┐
│ 10. Validate │◀──│ 9. Review    │◀──│ 8. Config    │◀──│ 7. BOM +     │◀──│ 6. Generate  │
│              │   │    config    │   │    yaml      │   │    context   │   │    model.md  │
└──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
```

### Step 1 — Information Gathering

Claude asks about your system: actors, servers, trust boundaries, data flows, protocols,
compliance requirements, and threat actor profiles. It may run web searches for publicly
documented architectures (open-source products, cloud services, published whitepapers).

For private systems, answer Claude's questions directly in the chat.

### Step 2 — Staging

Claude writes the raw collected information into a `.tm-raw/` scratch directory. This provides
source traceability and lets you correct facts before any DSL is generated.

```
{system-name}/.tm-raw/
├── _search-log.md     # search keywords, URLs, credibility
├── architecture.md
├── assets.md
├── actors.md
├── boundaries.md
├── dataflows.md
├── security.md
└── ...
```

You can inspect and edit these files before confirming in step 5. Claude will re-read them
during generation.

### Step 3 — Complexity Assessment

| Threshold | Structure chosen |
|---|---|
| ≤ 15 servers, ≤ 30 dataflows, ≤ 5 boundaries | **Single-model** |
| > 15 servers or > 30 dataflows or > 5 boundaries | **Multi-subsystem** |

See [modeling-strategy.md](../​.claude/skills/secopstm-threat-modeling/references/modeling-strategy.md)
for the breakdown logic.

### Step 4 — Custom Types Detection

Claude checks whether any servers or dataflows require types or protocols beyond the 31 standard
DSL values. If so, it plans the `config/` extension files.

**31 built-in server types:** `firewall`, `database`, `web-server`, `api-gateway`, `load-balancer`,
`vpn`, `plc`, `scada`, `cicd`, `siem`, `microservice`, `secrets_manager`, `message_broker`,
`cache`, `container_registry` … (full list in `threat_analysis/core/dsl_constants.py`)

**Common built-in protocols** (no definition needed): `HTTPS`, `SSH`, `TLS`, `MQTT`, `AMQP`,
`Kafka`, `RDP`, `SMB`, `DNS`, `Redis`, `PostgreSQL`, `MySQL`, `MongoDB`

### Step 5 — Strategy Confirmation *(you act here)*

Claude presents its plan and waits:

```
System name:    my-saas-platform
Complexity:     medium
Model type:     single-model
Custom types:   payment_processor (category: saas)
Custom protocols: ISO-8583 (category: internet, encryption: TLS)

Confirm to generate?
```

Reply **yes** (or with corrections) to proceed. This is the only mandatory interaction
after the initial description.

### Step 6 — model.md Generation

Claude writes the threat model DSL file. All output is in English regardless of the language
used during information gathering.

Key rules enforced automatically:
- `## Boundaries`, `## Actors`, `## Servers`, `## Data`, `## Dataflows` sections present
- Every server has a `description=` (required by the validator)
- All `boundary=`, `from=`, `to=`, `data=` references resolve to defined names
- Enum values match `DSL_ENUMS` from `threat_analysis/core/dsl_constants.py`

### Step 7 — BOM and Context Generation

Claude runs the bundled scripts to generate YAML files:

```bash
python .claude/skills/secopstm-threat-modeling/scripts/generate_context.py \
  --model model.md --output context/

python .claude/skills/secopstm-threat-modeling/scripts/generate_bom.py \
  --model model.md --output BOM/
```

The **context YAML** contains GDAF fields: `attack_objectives`, `threat_actors`, `risk_criteria`.
Each **BOM YAML** covers one server with `os_version`, `software_version`, `patch_level`,
`known_cves` placeholders for you to fill in later.

### Step 8 — Custom Config Generation

If custom types or protocols were detected in step 4, Claude creates:

```
config/
├── asset_types_community.yaml   # custom server types (dict format, 6 required fields each)
└── protocols_community.yaml     # custom protocols (dict format, 4 required fields each)
```

### Step 9 — Config Review *(you act here, optional)*

Inspect the generated `config/` files and supplement asset-specific details: known CVEs,
MITRE technique overrides, platform specifics. Claude presents a summary of what was generated
and what is left as placeholder.

### Step 10 — Validation

Claude runs:

```bash
secopstm validate --model-dir .
# or via the bundled script:
python .claude/skills/secopstm-threat-modeling/scripts/validate_model.py --model-dir .
```

The validator checks:
- DSL enum values (against `DSL_ENUMS`)
- Reference integrity (all `boundary=`, `from=`, `to=`, `data=` names resolve)
- BOM file presence (one YAML per server)
- Custom types defined if used
- YAML syntax validity
- Submodel paths exist (multi-subsystem only)
- Output files in English

Target: **0 failures**. Claude fixes any failures and re-runs before reporting completion.

---

## Output Structure

### Single-Model

```
{system-name}/
├── .tm-raw/                              # scratch files (not committed)
├── model.md                              # threat model DSL
├── context/
│   └── {system-name}_context.yaml       # GDAF objectives, actors, risk criteria
├── BOM/
│   └── {asset_name}.yaml                # one file per server
└── config/                              # only if custom types/protocols exist
    ├── asset_types_community.yaml
    └── protocols_community.yaml
```

### Multi-Subsystem

```
{project-name}/
├── .tm-raw/
├── main.md
├── context/
│   └── {project-name}_context.yaml      # global context (required)
├── {subsystem1}/
│   ├── model.md
│   └── BOM/
├── {subsystem2}/
│   ├── model.md
│   └── BOM/
└── config/                              # shared custom types
```

---

## Running the Generated Model

Once validation passes, run SecOpsTM normally:

```bash
# CLI — offline STRIDE + MITRE report
secopstm --model-file {system-name}/model.md

# CLI — with AI enrichment and GDAF attack flows
secopstm --model-file {system-name}/model.md --gdaf

# Web editor — load and iterate
secopstm --server
# then open http://localhost:5000 and load the model file
```

---

## Example: UAV Drone System

The repository includes a complete reference model generated with this skill:

```
threatModel_Template/UAV_Drone_System/
├── model.md                              # 15 servers, 8 boundaries, DJI Power Inspection
├── context/dji-power-inspection_context.yaml
├── BOM/                                  # 10 BOM files
└── config/
    ├── asset_types_community.yaml        # uav_aircraft, ground_controller,
    │                                     # gimbal_payload, cloud_fleet_management
    └── protocols_community.yaml          # OcuSync 3, DJI O3 Enterprise, …
```

Validate it to see a passing run:

```bash
secopstm validate --model-dir threatModel_Template/UAV_Drone_System
# → 0 failures
```

---

## Skill Reference Docs

The skill bundles detailed reference documentation consulted internally by Claude during
generation. You can read them directly if you want to understand the constraints:

| File | Content |
|---|---|
| `references/dsl-syntax.md` | Complete DSL field reference with all enum values |
| `references/workflow.md` | Information collection checklist (12 DSL fields) |
| `references/modeling-strategy.md` | Single vs multi-subsystem decision rules |
| `references/custom-asset-types.md` | `config/` YAML format and examples |
| `references/bom-format.md` | BOM YAML field reference |
| `references/context-format.md` | Context YAML and GDAF field reference |
| `references/staging-format.md` | `.tm-raw/` file format specifications |
| `references/naming-conventions.md` | File/directory naming rules |
| `references/output-structure.md` | Expected output tree per model type |

The same DSL reference is published at [`docs/dsl-syntax.md`](dsl-syntax.md) for standalone reading.
