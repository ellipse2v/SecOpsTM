# Output Structure

## Overview

This document describes the output structure for SecOpsTM threat modeling.

## Single-Model Structure (Default, ≤15 Servers)

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

### File Descriptions

| File | Required | Description |
|------|----------|-------------|
| `model.md` | ✅ | Main threat model file in SecOpsTM DSL format |
| `context/{system-name}_context.yaml` | ✅ | GDAF attack context (objectives, threat actors, risk criteria) |
| `BOM/{asset_name}.yaml` | ✅ | Bill of Materials - one file per key asset |
| `config/asset_types_community.yaml` | ❌ | Custom asset type definitions (if needed) |
| `config/protocols_community.yaml` | ❌ | Custom protocol definitions (if needed) |

## Multi-Subsystem Structure (>15 Servers)

```
{project-name}/
├── main.md                     # Top-level architecture
├── context/
│   └── {project-name}_context.yaml   # Global Context (required)
├── BOM/                       # Optional (global BOM if needed)
├── config/                    # Optional (custom types/protocols)
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

### File Descriptions

| File | Required | Description |
|------|----------|-------------|
| `main.md` | ✅ | Top-level architecture showing subsystem boundaries and data flows |
| `context/{project-name}_context.yaml` | ✅ | Global GDAF context for the entire project |
| `{subsystem}/model.md` | ✅ | Subsystem-specific threat model |
| `{subsystem}/BOM/{asset}.yaml` | ✅ | Subsystem-specific BOM files |
| `config/*` | ❌ | Custom asset types and protocols (shared across subsystems) |

## Key Differences: Single vs Multi-Subsystem

| Aspect | Single-Model | Multi-Subsystem |
|--------|--------------|-----------------|
| Main file | `model.md` | `main.md` + multiple `model.md` |
| Context | One per system | Global + optional per-subsystem |
| BOM | Flat structure | Hierarchical (per-subsystem) |
| Complexity | ≤15 servers | >15 servers |
| Use case | Simple systems | Complex, layered architectures |

## Naming Rules

- **System names:** Use snake_case (e.g., `dji_power_inspection`)
- **File names:** Lowercase with underscores
- **Asset names:** Descriptive and unique within scope
- **BOM files:** One asset per file, named after the asset

## Validation Checklist

Before considering output complete:

- [ ] All required files exist
- [ ] File naming follows conventions
- [ ] All references are valid (boundaries, actors, servers, data)
- [ ] DSL syntax is correct
- [ ] BOM files correspond to all key assets
- [ ] Context file includes attack objectives and threat actors
- [ ] Custom types/protocols are documented in config/ (if used)

## Examples

### Single-Model Example

```
dji-power-inspection/
├── model.md
├── context/
│   └── dji_power_inspection_context.yaml
├── BOM/
│   ├── drone_m300.yaml
│   ├── ground_station.yaml
│   └── cloud_platform.yaml
└── config/
    └── protocols_community.yaml
```

### Multi-Subsystem Example

```
smart-factory/
├── main.md
├── context/
│   └── smart_factory_context.yaml
├── ot_network/
│   ├── model.md
│   └── BOM/
│       ├── plc_1.yaml
│       └── scada_server.yaml
├── it_network/
│   ├── model.md
│   └── BOM/
│       ├── file_server.yaml
│       └── database.yaml
└── cloud/
    ├── model.md
    └── BOM/
        └── mes_platform.yaml
```

## Related Documents

- [../SKILL.md](../SKILL.md) - SecOpsTM threat modeling skill
- [staging-format.md](staging-format.md) - Information staging format
- [dsl-syntax.md](dsl-syntax.md) - DSL syntax reference
- [workflow.md](workflow.md) - Information gathering workflow
- [modeling-strategy.md](modeling-strategy.md) - Modeling strategy guide
