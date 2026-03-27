# Goal-Driven Attack Flow Engine (GDAF)

## Overview

The **Goal-Driven Attack Flow Engine** (GDAF) is a top-down attack scenario generator that works from attacker objectives down to individual attack hops. It is the complement — not the replacement — of the existing bottom-up `AttackChainAnalyzer`.

| Approach | Starting point | Direction | Output |
|---|---|---|---|
| `AttackChainAnalyzer` | Individual threats (per component) | Bottom-up: threats → chains | Multi-step paths derived from existing threat findings |
| `GDAFEngine` | Attacker objectives + threat actor profiles | Top-down: goals → graph traversal → technique assignment | Attack scenarios with MITRE techniques per hop, ranked by risk score |

GDAF answers a different question: **"If an attacker with these capabilities wanted to achieve this objective, what path would they take through this architecture?"**

All processing is fully offline — no network calls. GDAF reads `enterprise-attack.json` from `threat_analysis/external_data/` and the system model from the parsed `ThreatModel`.

---

## How It Works

### Step 1 — Load context YAML

GDAF reads a YAML file that defines `attack_objectives`, `threat_actors`, and `risk_criteria`. See [Context YAML Schema](#context-yaml-schema) below.

### Step 2 — Build a directed graph

`GDAFEngine._build_graph()` creates a node for every actor and server defined in the threat model. Dataflows become directed edges carrying metadata (protocol, encryption, authentication). In project mode, the graph is unified across the main model and all sub-models.

### Step 3 — Identify entry points

For each threat actor, entry points are selected based on the actor's `entry_preference`:
- `internet-facing` — actors in untrusted boundaries, or fallback to untrusted servers (VPN gateways, edge routers)
- `insider` — trusted actors with outbound edges
- `supply-chain` — treated as internet-facing (same selection logic)

### Step 4 — BFS path traversal

`GDAFEngine._bfs_paths()` performs breadth-first search from each entry point to each target asset that matches the objective's `target_asset_names` or `target_types`. The search is bounded by `max_hops` (default 7) and collects up to 20 raw paths per (entry, target) pair before pruning.

### Step 5 — Assign MITRE techniques per hop

For every node along a discovered path, `AssetTechniqueMapper.get_techniques()` returns the top-k ranked MITRE ATT&CK techniques. The mapper considers:
- Platform match (asset type → MITRE platform)
- Tactic relevance for the asset type
- Hop position (entry / intermediate / target)
- Actor's known TTPs (boosted score)
- Vulnerability signals on the dataflow or asset (no authentication, no encryption, no MFA, legacy tags)

### Step 6 — Score and classify scenarios

Each hop gets a `hop_score` based on the average technique score multiplied by a vulnerability weight. The path score is the average of all hop scores plus a target asset CIA bonus (0–0.5). Paths are classified as:

| Risk level | Path score threshold |
|---|---|
| CRITICAL | ≥ 4.0 |
| HIGH | ≥ 2.8 |
| MEDIUM | ≥ 1.8 |
| LOW | < 1.8 |

### Step 7 — Output

The top `max_paths_per_objective` scenarios per (actor, target) pair are emitted. `AttackFlowBuilder` serializes each scenario to an Attack Flow `.afb` file, and a `gdaf_summary.json` collects all scenarios. Scenarios are also rendered directly in the HTML threat report — see [GDAF in the HTML Report](#gdaf-in-the-html-report).

---

## GDAF in the HTML Report

When GDAF scenarios are generated, they appear in the HTML threat report as a collapsible **"Goal-Driven Attack Scenarios (GDAF)"** `<details>` accordion, inserted between the *Attack Chain Analysis* section and the *Severity Calculation Explained* section. The accordion is closed by default to keep the report readable; click the header to expand it.

The section is only shown when at least one GDAF scenario has been produced (i.e., a valid context YAML with `attack_objectives` and `threat_actors` was found and produced results). If no scenarios were generated, the section is omitted entirely.

### Summary table

Each scenario occupies one row:

| Column | Content |
|---|---|
| **Risk** | Coloured badge: CRITICAL / HIGH / MEDIUM / LOW |
| **Objective** | `objective_name` from the context YAML |
| **Actor** | `actor_name` + sophistication level in parentheses |
| **Attack Path** | Abbreviated hop chain: `Entry Node → Pivot → … → Target` |
| **Score** | Numeric `path_score` (two decimal places) |
| **Hops** | Total number of hops in the path |
| **Detection** | `detection_coverage` percentage (from BOM `detection_level` averages) |

### Hop details (row expansion)

Clicking a row expands an inline detail panel showing one entry per hop:

- **Node** — asset name
- **Type** — normalized asset type (e.g., `web-server`, `domain-controller`)
- **Protocol** — protocol of the incoming dataflow (if applicable)
- **Flags** — `cleartext` if the dataflow is unencrypted, `no-auth` if unauthenticated
- **Techniques** — MITRE ATT&CK technique IDs and names assigned to this hop, with links to `attack.mitre.org`

---

## Context YAML Schema

### Linking a context file to a model

The recommended way is to declare `gdaf_context` in the model's `## Context` DSL section:

```markdown
## Context
gdaf_context = context/enterprise_onprem_context.yaml
```

Resolution order:
1. `gdaf_context` key from the model's `## Context` section (path relative to the working directory)
2. `config/context.yaml` (project-wide fallback)

If neither exists, GDAF is silently skipped for that model.

> **Web editor**: When using the **"📂 Load Project"** button in Simple Mode, any `context/` directory found inside the selected project folder is detected automatically. Its YAML files are uploaded to the server on "Generate All", and a **Context ✓** badge appears next to the button. The `gdaf_context` key in `## Context` still takes precedence if present.

### Top-level keys

```yaml
attack_objectives: []    # list of AttackObjective dicts
threat_actors: []        # list of ThreatActor dicts
risk_criteria: {}        # engine tuning parameters
```

### `attack_objectives`

```yaml
attack_objectives:
  - id: OBJ-DOMAIN-COMPROMISE            # unique string ID, used in threat_actor.objectives
    name: "Compromise Active Directory Domain"
    description: "Gain domain admin rights by exploiting trust relationships."
    target_asset_names:                  # exact match against server/actor names in the model
      - "Primary Domain Controller"
    target_types:                        # normalized type match (see Asset Types table)
      - "domain-controller"
    mitre_final_tactic: "credential-access"   # tactic expected at the final hop
    business_impact: "Full domain compromise, all systems accessible"
```

All fields except `id` are optional, but at least one of `target_asset_names` or `target_types` must be non-empty for the objective to match nodes in the graph.

### `threat_actors`

```yaml
threat_actors:
  - id: TA-FIN-CRIMINAL                  # unique string ID
    name: "Financial Cybercriminal"
    sophistication: medium               # low | medium | high | nation-state
    entry_preference: internet-facing    # internet-facing | insider | supply-chain
    objectives:                          # list of attack_objective IDs this actor pursues
      - OBJ-FINANCIAL-EXFIL
      - OBJ-DOMAIN-COMPROMISE
    known_ttps:                          # MITRE technique IDs that get a score boost
      - "T1566.001"
      - "T1059.001"
    capable_tactics:                     # whitelist of tactics this actor can use
      - "initial-access"                 # omit to allow all tactics
      - "execution"
      - "credential-access"
      - "lateral-movement"
      - "exfiltration"
```

**`entry_preference` values:**
- `internet-facing` — selects actors in untrusted boundaries (or untrusted servers as fallback)
- `insider` — selects trusted actors with outgoing dataflows
- `supply-chain` — same selection as `internet-facing`

**`sophistication` values:** `low`, `medium`, `high`, `nation-state`. Currently used as informational metadata in output; does not alter graph traversal but is preserved in each `AttackScenario` for reporting.

### `risk_criteria`

```yaml
risk_criteria:
  acceptable_risk_score: 5.0    # path_score >= this → unacceptable_risk=true
  max_hops: 8                   # maximum path length in hops (default 7)
  max_paths_per_objective: 3    # top N paths kept per (actor, target) pair (default 3)
  # Minimum ScoredTechnique score to render a technique as an OR branch in .afb files.
  # Techniques below this threshold are still used for hop scoring but not displayed.
  # Typical values: 0.5 (broad), 0.8 (default, balanced), 1.2 (key techniques only)
  gdaf_min_technique_score: 0.8
```

`gdaf_min_technique_score` can also be overridden per-model in the `## Context` DSL section:

```markdown
## Context
gdaf_context=./config/my_context.yaml
gdaf_min_technique_score=1.0
```

When set in the DSL, the value is passed directly to the scenario and takes precedence over the context YAML value.

---

## Scoring Algorithm

### Technique scoring (`AssetTechniqueMapper`)

For each technique in `enterprise-attack.json`, a score is computed from additive bonuses:

| Signal | Bonus |
|---|---|
| Platform match (asset type → MITRE platform) | +0.5 |
| Primary tactic for asset type (top 3) | +0.4 |
| Hop position tactic match | +0.3 |
| Key technique for asset type | +0.6 |
| Actor known TTP match | +0.5 |
| No authentication on dataflow/asset (initial-access or lateral-movement) | +0.3 |
| No encryption (credential-access tactics) | +0.2 |
| No MFA (credential-access or initial-access) | +0.2 |
| Legacy tag on asset (initial-access or execution) | +0.2 |

Techniques with a total score below 0.4 are excluded. The top `top_k` (default 3 per hop) are returned.

### Hop scoring

```
hop_weight = 1.0
    + 0.4  if dataflow has no authentication
    + 0.3  if dataflow has no encryption
    + 0.2  if asset has no MFA
    + cia_score × 0.1   (CIA score = normalized 0–1 from confidentiality/integrity/availability)

avg_technique_score = mean(top technique scores for this hop)
hop_score = avg_technique_score × hop_weight
```

### Path scoring

```
path_score = mean(hop_scores across all hops)
           + target_cia_score × 0.5    (CIA bonus from the final target asset)
```

### CIA score formula

```
c = {critical: 3, high: 2, medium: 1, low: 0}[confidentiality]
i = {critical: 3, high: 2, medium: 1, low: 0}[integrity]
a = {critical: 3, high: 2, medium: 1, low: 0}[availability]
cia_score = min((c×3 + i×2 + a) / 18.0, 1.0)   # maximum = 1.0
```

---

## Asset Types

The following `type` values are recognized in `ASSET_TYPE_TO_PLATFORMS`. When a server's `type=` in the DSL does not exactly match, `_normalize_type()` applies fuzzy matching (e.g., `"web_server"` → `"web-server"`, `"domain_controller"` → `"domain-controller"`).

| Asset type | MITRE platforms | Primary tactics |
|---|---|---|
| `firewall` | Network Devices | initial-access, defense-evasion, lateral-movement |
| `domain-controller` | Windows | credential-access, privilege-escalation, persistence, lateral-movement |
| `auth-server` | Windows, Linux | credential-access, privilege-escalation, initial-access |
| `database` | Windows, Linux | credential-access, collection, exfiltration |
| `web-server` | Windows, Linux | initial-access, execution, persistence |
| `api-gateway` | Windows, Linux | initial-access, execution |
| `file-server` | Windows, Linux | collection, lateral-movement, exfiltration |
| `mail-server` | Windows, Linux, Office Suite | initial-access, collection |
| `management-server` | Windows, Linux | lateral-movement, privilege-escalation, execution |
| `workstation` | Windows | execution, persistence, privilege-escalation, credential-access |
| `load-balancer` | Network Devices, Linux | initial-access, defense-evasion |
| `vpn` / `vpn-gateway` | Network Devices | initial-access, credential-access |
| `plc` | Linux | impact, execution |
| `scada` | Windows, Linux | initial-access, execution, impact |
| `repository` | Linux | collection, exfiltration |
| `cicd` | Linux | execution, persistence, lateral-movement |
| `backup` | Linux, Windows | collection, exfiltration, impact |
| `dns` | Windows, Linux | defense-evasion, lateral-movement, command-and-control |
| `pki` | Windows | credential-access, privilege-escalation |
| `siem` | Linux | defense-evasion, collection |
| `default` (fallback) | Windows, Linux | initial-access, execution, lateral-movement |

**Normalization rules (applied by `_normalize_type()`):**
- Contains "domain" or "dc" → `domain-controller`
- Contains "database", "db", or "sql" → `database`
- Contains "web" and "server" → `web-server`
- Contains "mail" → `mail-server`
- Contains "vpn" → `vpn-gateway`
- Contains "firewall" or "fw" → `firewall`
- Contains "scada" or "hmi" → `scada`
- Contains "workstation", "laptop", or "desktop" → `workstation`
- Contains "pki", equals "ca", or contains "certificate" → `pki`
- Contains "auth" → `auth-server`
- Contains "cicd", "ci_cd", "pipeline", or "jenkins" → `cicd`
- Contains "repository" or "git" → `repository`
- Contains "backup" → `backup`
- Contains "siem" or "log" → `siem`
- Contains "jump", "bastion", or "paw" → `management-server`
- Contains "dns" → `dns`

---

## Output Files

GDAF outputs are written to `output/gdaf/` by default.

### `gdaf_summary.json`

A JSON array of all `AttackScenario` objects:

```json
[
  {
    "scenario_id": "GDAF-A1B2C3D4",
    "objective_id": "OBJ-DOMAIN-COMPROMISE",
    "objective_name": "Compromise Active Directory Domain",
    "objective_description": "...",
    "objective_business_impact": "Full domain compromise",
    "objective_mitre_final_tactic": "credential-access",
    "actor_id": "TA-FIN-CRIMINAL",
    "actor_name": "Financial Cybercriminal",
    "actor_sophistication": "medium",
    "entry_point": "External Attacker",
    "target_asset": "Primary Domain Controller",
    "path_score": 3.72,
    "risk_level": "HIGH",
    "unacceptable_risk": false,
    "detection_coverage": 0.0,
    "hops": [
      {
        "asset_name": "Web Application",
        "asset_type": "web-server",
        "hop_position": "entry",
        "dataflow_name": "HTTPS Request",
        "protocol": "HTTPS",
        "is_encrypted": true,
        "is_authenticated": false,
        "hop_score": 2.45,
        "techniques": [
          {
            "id": "T1190",
            "name": "Exploit Public-Facing Application",
            "tactics": ["initial-access"],
            "score": 1.8,
            "rationale": "platform match, primary tactic, key technique",
            "url": "https://attack.mitre.org/techniques/T1190"
          }
        ]
      }
    ]
  }
]
```

### `.afb` files

One Attack Flow `.afb` file per scenario, written to `output/gdaf/<objective_id>/<actor_id>_<scenario_id>.afb`. These files are valid Attack Flow JSON that can be opened in the [Attack Flow Builder](https://center-for-threat-informed-defense.github.io/attack-flow/ui/) web application.

---

## Integration with Project Mode (Sub-model Bridging)

In project mode (multiple markdown files), `GDAFEngine` accepts an `extra_models` parameter. The attack graph is unified across all models: actors and servers from each sub-model are added as nodes (first definition wins on name conflict), and their dataflows become edges.

When a server in any model has a `_submodel_tm` reference (set by `_recursively_generate_reports()` for servers with `submodel=` in the DSL), GDAF adds **bridging edges**:

1. **Entry bridge** — `parent_server` → `sub_root_servers`: represents internal access after the parent component is compromised. Root servers are those that are not the sink of any sub-model dataflow.
2. **Exit bridge** — `sub_leaf_servers` → `original_targets`: sub-model leaf servers inherit the parent's outgoing edges, so attack paths can exit through the component's internal structure.

This enables GDAF to trace an attack path that starts in the external network, enters a monolithic server node, "drills into" its internal sub-model architecture, and exits toward the final target.

---

## Example Context File

The following example is suitable for a standard on-premises enterprise network with Active Directory and financial systems.

```yaml
# threatModel_Template/On-Prem_Enterprise_Network/context/enterprise_onprem_context.yaml
# GDAF context for an on-premises enterprise with domain infrastructure

attack_objectives:
  - id: OBJ-DOMAIN-COMPROMISE
    name: "Compromise Active Directory Domain"
    description: "Obtain domain administrator privileges via credential theft or Kerberoasting."
    target_asset_names:
      - "Primary Domain Controller"
      - "Domain Controller"
    target_types:
      - "domain-controller"
    mitre_final_tactic: "credential-access"
    business_impact: "Full domain compromise — all systems, identities, and data accessible"

  - id: OBJ-FINANCIAL-EXFIL
    name: "Financial Data Exfiltration"
    description: "Exfiltrate financial records from the ERP or accounting database."
    target_asset_names:
      - "Financial Database"
      - "ERP Database"
    target_types:
      - "database"
    mitre_final_tactic: "exfiltration"
    business_impact: "Regulatory fines, customer data breach, financial fraud"

  - id: OBJ-RANSOMWARE
    name: "Ransomware Deployment"
    description: "Deploy ransomware to maximize operational disruption."
    target_types:
      - "file-server"
      - "backup"
      - "domain-controller"
    mitre_final_tactic: "impact"
    business_impact: "Full operational shutdown, potential regulatory notification"

threat_actors:
  - id: TA-FIN-CRIMINAL
    name: "Financial Cybercriminal"
    sophistication: medium
    entry_preference: internet-facing
    objectives:
      - OBJ-FINANCIAL-EXFIL
      - OBJ-RANSOMWARE
      - OBJ-DOMAIN-COMPROMISE
    known_ttps:
      - "T1566.001"   # Spearphishing Attachment
      - "T1059.001"   # PowerShell
      - "T1486"       # Data Encrypted for Impact
    capable_tactics:
      - "initial-access"
      - "execution"
      - "persistence"
      - "privilege-escalation"
      - "credential-access"
      - "lateral-movement"
      - "collection"
      - "exfiltration"
      - "impact"

  - id: TA-NATION-STATE
    name: "Nation-State APT"
    sophistication: nation-state
    entry_preference: supply-chain
    objectives:
      - OBJ-DOMAIN-COMPROMISE
      - OBJ-FINANCIAL-EXFIL
    known_ttps:
      - "T1195.002"   # Compromise Software Supply Chain
      - "T1021.001"   # Remote Desktop Protocol
      - "T1558.003"   # Kerberoasting
      - "T1003.001"   # LSASS Memory
    capable_tactics:
      - "initial-access"
      - "execution"
      - "persistence"
      - "privilege-escalation"
      - "defense-evasion"
      - "credential-access"
      - "lateral-movement"
      - "collection"
      - "exfiltration"
      - "command-and-control"

  - id: TA-INSIDER
    name: "Malicious Insider"
    sophistication: low
    entry_preference: insider
    objectives:
      - OBJ-FINANCIAL-EXFIL
    known_ttps:
      - "T1078"   # Valid Accounts
      - "T1048"   # Exfiltration Over Alternative Protocol
    capable_tactics:
      - "initial-access"
      - "collection"
      - "exfiltration"

risk_criteria:
  acceptable_risk_score: 5.0
  max_hops: 8
  max_paths_per_objective: 3
```

---

## Asset Enrichment Sources

GDAF combines multiple enrichment signals when building the attack graph and scoring techniques. The following sources are merged at graph-build time, before any BFS traversal.

### BOM files (Bill of Materials)

Per-asset YAML files placed in a `BOM/` directory alongside the model file (or at the path declared by `bom_directory` in `## Context`). Each file is named after the asset using lowercase with underscores replacing spaces (e.g., `primary_domain_controller.yaml`).

**Supported keys:**

| Key | Type | Effect on scoring |
|---|---|---|
| `os_version` | str | Informational; used for notes |
| `patch_level` | str (`current` / `outdated` / `critical`) | Informational |
| `known_cves` | list of CVE IDs | CVE-CAPEC matching for STRIDE severity boost. When `analysis.state` is present (CycloneDX VEX), only `affected`/`exploitable`/`in_triage` CVEs score; `fixed`/`resolved` act as a mitigation signal. |
| `running_services` | list of protocol names | Added to node `services` set → tactic boosts applied |
| `detection_level` | str (`none` / `low` / `medium` / `high`) | Mapped to `detection_coverage` (0.0–0.8), averaged across hops |
| `credentials_stored` | bool | If true, adds +0.4 to credential-access techniques |
| `software_version` | str | Informational |
| `notes` | str | Informational |

**CVE source priority (single chain, first match wins):**

1. Standalone VEX file/directory (`vex_file` / `vex_directory` in `## Context`, or auto-discovered `VEX/` / `vex.json`)
2. BOM CycloneDX file with `vulnerabilities[].analysis.state` — VEX states parsed automatically
3. BOM `known_cves` without state — all CVEs treated as active (legacy YAML or stateless CycloneDX)
4. `cve_definitions.yml` at project root

**BOM resolution order:**

1. `bom_directory` key in the model's `## Context` DSL section (resolved as a path)
2. `BOM/` subdirectory alongside the model file (auto-discovered)
3. None — BOM enrichment is silently skipped

**VEX resolution order** (for standalone VEX files):

1. `vex_file` key in `## Context` — single VEX document
2. `vex_directory` key in `## Context` — directory of VEX files
3. `VEX/` subdirectory alongside the model file (auto-discovered)
4. `vex.json` file alongside the model file (auto-discovered)
5. None — VEX enrichment skipped; BOM `known_cves` used as fallback

**Example `## Context` declaration:**

```markdown
## Context
- gdaf_context = context/enterprise_onprem_context.yaml
- bom_directory = BOM
```

BOM data overrides DSL values where both are present (e.g., `credentials_stored` in BOM takes precedence over the server DSL attribute).

> **Web editor**: When using the **"📂 Load Project"** button in Simple Mode, the browser automatically detects any `BOM/` directory inside the selected project folder and uploads its YAML files to the server before generation. A **BOM ✓** badge appears next to the button confirming the directory was found. No `bom_directory` entry in `## Context` is required in this workflow.

### `internet_facing` on servers

```markdown
## Servers
- **Edge Router**:
  boundary=DMZ,
  type=firewall,
  internet_facing=True,
  ...
```

When `internet_facing=True`, the server is added as an entry point for `internet-facing` and `supply-chain` threat actors, in addition to untrusted boundary actors. This ensures that internet-exposed servers in trusted boundaries (e.g., a VPN gateway in a partially trusted zone) are still considered as attacker entry points.

### `credentials_stored` on servers

```markdown
## Servers
- **Primary Domain Controller**:
  credentials_stored=True,
  ...
```

When `credentials_stored=True` (DSL or BOM), any MITRE technique whose tactic includes `credential-access` receives a +0.4 score bonus for that node. This reflects the elevated attacker interest in nodes that hold authentication material (AD NTDS.dit, SAM database, credential vaults, HSMs).

### `traversal_difficulty` on boundaries

Boundaries can declare how difficult they are for an attacker to traverse, independently of whether they are trusted.

```markdown
## Boundaries
- **OT SCADA Zone**:
  type=execution-environment,
  isTrusted=True,
  traversal_difficulty=high
```

| Value | hop_weight bonus | Meaning | Examples |
|---|---|---|---|
| `low` | +0.3 | No network filtering, open segment | Internet, flat internal LAN |
| `medium` | +0.1 | Basic firewall rules, logged | Corporate LAN, DMZ |
| `high` | +0.0 | Strict firewall + access control, audited | OT/SCADA zone, payment HSM, classified segment |

The `traversal_difficulty` of the sink node's boundary is applied to each hop's `hop_weight`. Easier segments (low) increase the hop score because they are more easily exploitable; harder segments (high) do not add weight.

### Protocols from dataflows (`services` collection)

GDAF automatically collects all protocols that appear on dataflows connected to each node (both as source and as sink). These are accumulated in the node's `services` set and used to boost relevant techniques:

- **Tactic boost** — if the protocol maps to one or more MITRE tactics (e.g., `smb` → `lateral-movement`, `credential-access`), any technique in those tactics gets +0.35
- **Key-technique boost** — specific high-value techniques associated with the protocol (e.g., `rdp` → `T1021.001`, `T1078`) get +0.5

The `PROTOCOL_TO_TACTIC_BOOST` and `PROTOCOL_KEY_TECHNIQUES` maps in `asset_technique_mapper.py` define these relationships. Protocols from the BOM `running_services` field are merged into the same `services` set.

### `bidirectional` dataflows

Dataflows can be marked bidirectional:

```markdown
## Dataflows
- **AdminConsole**:
  from="Jump Server",
  to="Primary Domain Controller",
  protocol=WinRM,
  bidirectional=True,
  ...
```

When `bidirectional=True`, GDAF generates a reverse edge automatically (`Primary Domain Controller` → `Jump Server`). This allows BFS to discover paths that use the return channel of a bidirectional protocol — important for protocols like RPC, WinRM, and LDAP where responses carry data or commands.

### Data classification and `data_value` scoring

When a dataflow carries `Data` objects, GDAF computes a `data_value` (0.0–1.0) from the highest classification present on that flow:

| Classification | data_value |
|---|---|
| `TOP_SECRET` | 1.0 |
| `SECRET` | 0.7 |
| `RESTRICTED` | 0.4 |
| `PUBLIC` | 0.0 |
| (unknown) | 0.1 |

The `data_value` adds `data_value × 0.3` to the hop's `hop_weight`. A dataflow carrying `TOP_SECRET` data therefore adds +0.3 to every hop along that edge, reflecting the higher attacker motivation to traverse that path.

---

## Key Files

| File | Role |
|---|---|
| `threat_analysis/core/gdaf_engine.py` | `GDAFEngine` — main engine: context loading, graph construction, BFS, scenario assembly |
| `threat_analysis/core/asset_technique_mapper.py` | `AssetTechniqueMapper`, `ScoredTechnique` — maps asset type + attributes to ranked MITRE techniques |
| `threat_analysis/generation/attack_flow_builder.py` | `AttackFlowBuilder` — serializes `AttackScenario` objects to `.afb` Attack Flow files |
| `config/context.yaml` | Default context file (edit to define your objectives and actors) |
| `threatModel_Template/On-Prem_Enterprise_Network/context/enterprise_onprem_context.yaml` | Example context for on-premises enterprise networks |
| `threat_analysis/external_data/enterprise-attack.json` | MITRE ATT&CK Enterprise dataset (loaded once, class-level cache) |
