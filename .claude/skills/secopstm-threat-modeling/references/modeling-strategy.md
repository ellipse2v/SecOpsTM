# Modeling Strategy: Single vs Multi-Subsystem

## Overview

This document describes how to choose between single-model and multi-subsystem threat modeling strategies based on system complexity.

## Complexity Assessment

### Metrics to Measure

| Metric | Threshold | Measurement |
|--------|-----------|-------------|
| Servers/Components | ≤15 vs >15 | Count all distinct servers in model |
| Data Flows | ≤30 vs >30 | Count all dataflow connections |
| Boundaries | ≤5 vs >5 | Count trust boundaries |
| Architecture | Flat vs Layered | Assess structural complexity |
| Maintenance | Single team vs Multiple | Check ownership structure |

## Single-Model Strategy (Default)

### When to Use

Use single-model when **ALL** of the following are true:

- ✅ Servers/components ≤ 15
- ✅ Data flows ≤ 30
- ✅ Boundaries ≤ 5
- ✅ Relatively flat architecture
- ✅ Single team/project ownership

### Typical Examples

| System Type | Description | Component Count |
|-------------|-------------|-----------------|
| Small Web App | Frontend + Backend + Database | 3-5 servers |
| Single SaaS | One cloud service | 5-10 servers |
| Simple IoT | Device + Cloud + App | 5-8 servers |
| Microservice App | Few services, same domain | 10-15 servers |

### Output Structure

```
{system-name}/
├── model.md                    # Single system model
├── context/
│   └── {system-name}_context.yaml
├── BOM/
│   ├── {asset1}.yaml
│   ├── {asset2}.yaml
│   └── ...
└── config/                     # Optional
    ├── asset_types_community.yaml
    └── protocols_community.yaml
```

### Advantages

- ✅ Simple to create and maintain
- ✅ Easy to understand relationships
- ✅ Faster modeling process
- ✅ Lower cognitive load
- ✅ Good for documentation and presentations

### Disadvantages

- ❌ Can become unwieldy for complex systems
- ❌ Hard to manage large data flow diagrams
- ❌ Difficult to assign ownership
- ❌ May obscure architectural layers

## Multi-Subsystem Strategy

### When to Use

Use multi-subsystem when **ANY** of the following are true:

- ❌ Servers/components > 15
- ❌ Data flows > 30
- ❌ Clear layered architecture (edge + platform + application)
- ❌ Independently deployed subsystems
- ❌ Different teams own different parts
- ❌ Clear boundaries and interfaces between subsystems

### Typical Examples

| System Type | Subsystems | Component Count |
|-------------|------------|-----------------|
| Drone System | Aircraft + Ground + Cloud + Dock | 20-30 servers |
| Smart Factory | OT Network + IT Network + Cloud MES | 25-40 servers |
| Healthcare HIS | Outpatient + Inpatient + Lab + Imaging | 30-50 servers |
| E-commerce | Frontend + Backend + Payment + Logistics | 20-35 servers |

### Output Structure

```
{project-name}/
├── main.md                     # Top-level architecture
├── context/
│   └── {project-name}_context.yaml   # Global context
├── config/                     # Optional (shared)
│   ├── asset_types_community.yaml
│   └── protocols_community.yaml
├── {subsystem1}/
│   ├── model.md
│   └── BOM/
├── {subsystem2}/
│   ├── model.md
│   └── BOM/
├── {subsystem3}/
│   ├── model.md
│   └── BOM/
└── ...
```

### Advantages

- ✅ Manageable model size per subsystem
- ✅ Clear ownership and responsibility
- ✅ Easier to update individual subsystems
- ✅ Matches organizational structure
- ✅ Better for distributed teams

### Disadvantages

- ❌ More complex overall structure
- ❌ Cross-subsystem flows need careful modeling
- ❌ Global context must be maintained
- ❌ Higher coordination overhead

## Subsystem Decomposition Strategies

### Strategy 1: Physical Deployment (Recommended)

Decompose based on physical/network deployment locations.

**Example: Drone System**

```
drone-system/
├── main.md
├── context/drone_system_context.yaml
├── drone_subsystem/          # Aircraft itself
│   ├── model.md
│   └── BOM/
├── ground_subsystem/         # Ground control station
│   ├── model.md
│   └── BOM/
├── cloud_subsystem/          # Cloud platform
│   ├── model.md
│   └── BOM/
└── dock_subsystem/           # Autonomous docking station
    ├── model.md
    └── BOM/
```

**When to Use:**
- Clear physical separation
- Different network zones
- Independent deployment units

### Strategy 2: Business Domain

Decompose based on business functions or domains.

**Example: E-commerce Platform**

```
ecommerce-platform/
├── main.md
├── context/
├── frontend/                 # User-facing applications
│   ├── model.md
│   └── BOM/
├── backend/                  # Business logic services
│   ├── model.md
│   └── BOM/
├── payment/                  # Payment processing
│   ├── model.md
│   └── BOM/
└── logistics/                # Shipping and tracking
    ├── model.md
    └── BOM/
```

**When to Use:**
- Clear business domain boundaries
- Different teams own different domains
- Domain-specific security requirements

### Strategy 3: Trust Domain

Decompose based on trust levels and security boundaries.

**Example: Enterprise System**

```
enterprise-system/
├── main.md
├── context/
├── internet_facing/          # Public-facing components
│   ├── model.md
│   └── BOM/
├── dmz/                      # Demilitarized zone
│   ├── model.md
│   └── BOM/
└── internal/                 # Internal network
    ├── model.md
    └── BOM/
```

**When to Use:**
- Strong trust boundaries
- Compliance requirements
- Defense-in-depth strategy

## Cross-Subsystem Data Flows

### Modeling in main.md

Cross-subsystem flows are defined in the top-level `main.md`:

```markdown
## Dataflows

### Cross-Subsystem Flows

- **DroneToCloud**: 
  - from: `drone_subsystem/drone_m300`
  - to: `cloud_subsystem/cloud_platform`
  - protocol: `dji-cloud-api-2`
  - isEncrypted: true
  - data: `flight_logs`

- **GroundToDrone**:
  - from: `ground_subsystem/ground_station`
  - to: `drone_subsystem/drone_m300`
  - protocol: `ocusync-3-enterprise`
  - isEncrypted: true
  - data: `control_commands`
```

### Subsystem Entry Points

Mark subsystem entry points in each `model.md`:

```markdown
## Servers

- **drone_m300**: 
  - boundary: `drone_rf_link`
  - type: `uav_platform`
  - internet_facing: false  # Entry point for drone subsystem
  - ...
```

## Ghost Nodes

When a subsystem references a server from another subsystem:

1. Define the server in `main.md` as a "ghost node"
2. Reference it in the subsystem model
3. Ensure consistency across models

```markdown
# In main.md

## Servers

- **cloud_platform**: 
  - boundary: `cloud_network`
  - type: `microservice`
  - submodel: cloud_subsystem/model.md
  ...

# In drone_subsystem/model.md

## Dataflows

- **DroneToCloud**:
  - from: `drone_m300`
  - to: `cloud_platform`  # Ghost node reference
  - ...
```

## Validation Checklist

### Single-Model

- [ ] All servers ≤ 15
- [ ] All data flows ≤ 30
- [ ] All boundaries ≤ 5
- [ ] Architecture is relatively flat
- [ ] Single ownership team

### Multi-Subsystem

- [ ] Each subsystem model is manageable (<15 servers)
- [ ] Global context defined in main.md
- [ ] Cross-subsystem flows documented in main.md
- [ ] Subsystem entry points marked
- [ ] Ghost nodes consistent across models
- [ ] BOM files for all assets
- [ ] Custom types/protocols in config/

## Decision Flowchart

```
Start
  │
  ▼
Count servers/components
  │
  ├─ ≤15 ──┐
  │         ▼
  ├─ >15 ──► Use Multi-Subsystem
  │         (check other factors too)
  │
  ▼
Count data flows
  │
  ├─ ≤30 ──┐
  │         ▼
  ├─ >30 ──► Use Multi-Subsystem
  │
  ▼
Assess architecture
  │
  ├─ Flat ──┐
  │          ▼
  ├─ Layered ► Use Multi-Subsystem
  │
  ▼
Check ownership
  │
  ├─ Single team ──► Use Single-Model
  │
  └─ Multiple teams ► Use Multi-Subsystem
```

## Migration Between Strategies

### Single → Multi-Subsystem

When a single model grows too complex:

1. Identify natural subsystem boundaries
2. Create new directory structure
3. Extract subsystem models from main model
4. Create `main.md` with cross-subsystem flows
5. Update context and BOM files
6. Validate all references

### Multi-Subsystem → Single-Model

When subsystems merge or simplify:

1. Consolidate all `model.md` into one
2. Merge BOM files
3. Update context file
4. Remove subsystem directories
5. Validate consolidated model

## Best Practices

1. **Start Simple:** Begin with single-model, refactor when needed
2. **Natural Boundaries:** Choose decomposition that matches system architecture
3. **Team Alignment:** Match subsystem boundaries to team structure
4. **Documentation:** Document why you chose your strategy
5. **Review Periodically:** Reassess as system evolves

## Related Documents

- [../SKILL.md](../SKILL.md) - SecOpsTM threat modeling skill
- [staging-format.md](staging-format.md) - Information staging format
- [output-structure.md](output-structure.md) - Output structure
- [dsl-syntax.md](dsl-syntax.md) - DSL syntax reference
- [workflow.md](workflow.md) - Information gathering workflow
