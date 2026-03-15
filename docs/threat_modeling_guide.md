# How to Create a Threat Model with SecOpsTM DSL

This guide walks you through building a complete, production-quality threat model for a real
system. By the end, you will have a working SecOpsTM model file (`.md`) that produces STRIDE
threat reports, MITRE ATT&CK mappings, GDAF attack paths, and navigable HTML diagrams.

**Before you start:** Read `docs/defining_threat_models.md` for a complete reference of every
DSL keyword and accepted value. Use the present guide as a practical walkthrough; use the
reference for precise attribute details.

**Companion files:**
- `docs/data_collection_guide.md` — questionnaire to fill in with your team before modeling
- `docs/project_onboarding_questionnaire.md` — short form to send to a project team
- `threatModel_Template/projects/example_3/` — fully worked e-commerce example

---

## Overview: What SecOpsTM Produces

From a Markdown DSL file, SecOpsTM generates:

| Output | Description |
|---|---|
| HTML threat report | STRIDE threats with MITRE ATT&CK mappings, attack chains, severity heat map |
| JSON export | Versioned, schema-validated threat inventory (for SIEM / CI integration) |
| SVG/HTML diagram | Architecture diagram with trust boundary colors and severity heat map |
| STIX 2.1 bundle | Machine-readable threat intelligence |
| ATT&CK Navigator layer | Heatmap of relevant ATT&CK techniques |
| Attack Flow `.afb` | GDAF-generated attack paths for adversary simulation |

---

## Step 0: Understand the DSL Structure

A SecOpsTM model file is a Markdown file with specific section headers. The parser reads these
sections in order:

```
Pass 0   →  ## Context        (model settings: GDAF context file, BOM directory)
Pass 1   →  ## Boundaries     (trust zones, network segments)
             ## Actors         (users, external systems)
             ## Servers        (components: services, databases, firewalls, etc.)
             ## Data           (data assets with classification)
Pass 2   →  ## Dataflows      (connections between actors and servers)
             ## Protocol Styles (visual styling for diagram edges)
             ## Severity Multipliers (weight adjustments per component)
             ## Custom Mitre Mapping (explicit ATT&CK technique assignments)
```

Every element is a Markdown list item:
```markdown
- **Element Name**: key=value, key="quoted string", key=True, key=[list, of, values]
```

Multi-line definitions are supported — indent continuation lines:
```markdown
- **My Server**:
  boundary="Internal Zone",
  type=web-server,
  confidentiality=high,
  integrity=critical
```

---

## Step 1: Give Your Model a Title and Description

Start the file with:

```markdown
# Threat Model: My Application Name

## Description
Brief description of the system under analysis. Include:
- What the system does (business function)
- Who uses it (user types, number of users)
- How it is deployed (cloud, on-prem, hybrid)
- Relevant compliance requirements (PCI-DSS, GDPR, HIPAA, SOX, etc.)
- Any notable integrations with third-party systems
```

**Why this matters:** The description appears in the HTML report header and helps reviewers
understand the system context. It also improves AI-generated threats if AI enrichment is enabled.

---

## Step 2: Configure the Context Section

Add a `## Context` section to enable GDAF attack path analysis and BOM asset enrichment:

```markdown
## Context
gdaf_context = context/my_context.yaml
bom_directory = BOM
gdaf_min_technique_score = 0.75
```

| Key | Required | Description |
|---|---|---|
| `gdaf_context` | Recommended | Path to the GDAF context YAML (attack objectives, threat actors). Relative to this model file. |
| `bom_directory` | Recommended | Path to the directory containing asset BOM files. Relative to this model file. |
| `gdaf_min_technique_score` | Optional | Filter threshold for ATT&CK techniques in Attack Flow output (default: 0.8). |

**If you skip Context:** The analysis still runs — you get STRIDE threats and MITRE mappings.
You lose GDAF attack path analysis and BOM-based CVE scoring.

---

## Step 3: Define Trust Boundaries

Boundaries are the security zones in your architecture. Think of them as the bubbles you draw
on a whiteboard when mapping out network segments.

```markdown
## Boundaries
- **Internet**:
  isTrusted=False,
  type=network-on-prem,
  color=red,
  traversal_difficulty=low,
  businessValue="Public internet — all external users and attackers enter here"
- **Internal Network**:
  isTrusted=True,
  type=execution-environment,
  color=lightblue,
  traversal_difficulty=medium,
  businessValue="Internal application services — protected by firewall"
- **Database Zone**:
  isTrusted=True,
  type=execution-environment,
  color=lavender,
  traversal_difficulty=high,
  businessValue="Highly restricted — only whitelisted DB firewall connections allowed"
```

**Key decisions per boundary:**

1. **`isTrusted`** — Is this zone under your organization's control and enforcing your security
   policy? Public internet = `False`. Internal data center = `True`.
   - Effect: Untrusted boundaries render in red/dashed in diagrams; trusted in green/solid.
   - Effect: GDAF uses untrusted and `internet_facing=True` servers as attacker entry points.

2. **`traversal_difficulty`** — How hard is it for an attacker to move from this boundary to
   the next? Use `low` for open segments, `high` for microsegmented or heavily firewalled zones.

3. **`type`** — Network segment or execution environment? See the DSL reference for all values.

**Common mistake:** Putting everything in one boundary. Split at trust transitions: internet vs
DMZ, DMZ vs internal, internal vs database, cloud vs on-prem.

---

## Step 4: Define Actors

Actors are the humans and external systems that interact with your architecture.

```markdown
## Actors
- **Customer**:
  boundary=Internet,
  authenticity=credentials,
  isTrusted=False
- **Admin**:
  boundary="Internal Network",
  authenticity=two-factor,
  isTrusted=True
- **External API**:
  boundary=Internet,
  authenticity=client-certificate,
  isTrusted=False
- **Attacker**:
  boundary=Internet,
  authenticity=none,
  isTrusted=False
```

**Key decisions per actor:**

1. **`authenticity`** — How does this actor prove their identity?

   | Value | Meaning | Example |
   |---|---|---|
   | `none` | No authentication | Anonymous internet user, attacker |
   | `credentials` | Username + password | Typical end user login |
   | `two-factor` | Password + TOTP/hardware token | Admin, privileged user |
   | `client-certificate` | Mutual TLS certificate | Machine-to-machine, payment gateway |
   | `externalized` | Delegated to external IdP | SSO via SAML/OIDC |

2. **`isTrusted`** — Even if an actor authenticates, do you trust them? An authenticated
   customer is still `isTrusted=False` — they can only access their own data.

**Include an attacker actor.** Always add an `External Attacker` with `authenticity=none,
isTrusted=False` in the Internet boundary. This enables realistic GDAF entry-point paths.

---

## Step 5: Define Servers (Components)

Servers represent any component that processes, stores, or routes data: APIs, databases,
firewalls, load balancers, message queues, CI/CD systems, etc.

```markdown
## Servers
- **WebAPI**:
  boundary="Internal Network",
  type=web-server,
  machine=virtual,
  confidentiality=high,
  integrity=critical,
  availability=high,
  redundant=True,
  internet_facing=False,
  mfa_enabled=True,
  auth_protocol=oauth,
  waf=True,
  ids=True,
  encryption=TLS,
  tags=[nodejs, rest, json],
  businessValue="Core API serving 100k daily users"
```

**The most impactful security attributes:**

| Attribute | Values | Impact on Analysis |
|---|---|---|
| `confidentiality` | low / medium / high / critical | Higher = higher base threat score |
| `integrity` | low / medium / high / critical | Higher = higher base threat score |
| `availability` | low / medium / high / critical | Higher = higher DoS threat score |
| `internet_facing` | True / False | `True` → GDAF entry point (even in trusted boundary) |
| `mfa_enabled` | True / False | `False` → GDAF +0.2 score on credential-access path |
| `credentials_stored` | True / False | `True` → GDAF +0.4 on credential-access techniques |
| `waf` | True / False | WAF presence affects web threat likelihood |
| `ids` / `ips` | True / False | Detection/prevention capabilities |
| `redundant` | True / False | `False` → higher DoS impact |

**Linking to a sub-model (drill-down):**
```markdown
- **AuthService**:
  submodel=./auth/model.md,
  boundary="Internal Network",
  type=application-server,
  ...
```
This creates a clickable node in the HTML diagram that opens the child model's detailed view.

**Common mistakes:**
- Omitting `confidentiality` / `integrity` / `availability` — these drive the threat severity score.
- Forgetting `internet_facing=True` on load balancers and web servers — GDAF won't identify them as entry points.
- Setting `mfa_enabled=True` on services that actually have no MFA — check reality.

---

## Step 6: Define Data Assets

Data objects represent what flows through and is stored in your system.

```markdown
## Data
- **CustomerRecord**:
  description="Customer name, email, address, order history",
  classification=SECRET,
  storage_location=[UserDB, BackupDB],
  pii=True,
  dpia=True,
  encrypted_at_rest=True,
  encrypted_in_transit=True
- **PaymentToken**:
  description="Tokenized payment reference — no raw PAN",
  classification=SECRET,
  storage_location=[PaymentDB],
  pii=False,
  encrypted_at_rest=True
- **APIKey**:
  description="Third-party API key for logistics provider",
  classification=SECRET,
  credentialsLife=MANUAL,
  storage_location=[ConfigService]
```

**Classification levels** (ascending sensitivity):
`PUBLIC` → `RESTRICTED` → `CONFIDENTIAL` → `SECRET` → `TOP_SECRET`

**Key decisions:**
- `pii=True` + `dpia=True` — marks GDPR-regulated data; increases regulatory impact scoring.
- `credentialsLife` — rotation period in days; triggers specific credential management threats.
- `storage_location` — list of server names where this data is stored (used for CVE/risk correlation).

---

## Step 7: Define Dataflows

Dataflows are the connections between actors and servers. They represent data in motion.

```markdown
## Dataflows
- **UserLogin**:
  from=Customer,
  to=WebAPI,
  protocol=HTTPS,
  port=443,
  authentication=credentials,
  encryption=TLS,
  data="CustomerRecord"
- **APIToDatabase**:
  from=WebAPI,
  to=UserDB,
  protocol=TCP,
  port=5432,
  authentication=credentials,
  encryption=TLS,
  data="CustomerRecord",
  bidirectional=True
- **LegacyInternalAPI**:
  from=LegacyService,
  to=WebAPI,
  protocol=HTTP,
  port=80,
  authentication=none,
  encryption=none
```

**Security-critical attributes:**

| Attribute | Values | Impact |
|---|---|---|
| `authentication` | none / credentials / certificate / multi-factor | `none` → spoofing/tampering threats, higher GDAF score |
| `encryption` | none / TLS / IPSec / mTLS | `none` → information disclosure threats, cleartext flag |
| `protocol` | HTTP, HTTPS, SSH, gRPC, AMQP, TCP, ... | Drives protocol-specific threat rules |
| `bidirectional` | True / False | `True` → GDAF generates reverse edge for bidirectional attack paths |

**Unauthenticated + unencrypted flows get the highest threat scores.** If you have an internal
`HTTP` flow with `authentication=none`, expect CRITICAL severity threats. If that's intentional
(e.g. a load balancer to a backend on a private VLAN), add a comment and consider `## Severity Multipliers` to adjust.

---

## Step 8: Add Protocol Styles

Define how protocols appear in diagrams (colors and line styles):

```markdown
## Protocol Styles
- **HTTPS**: color=darkgreen, line_style=solid
- **HTTP**: color=red, line_style=dashed
- **gRPC**: color=blue, line_style=solid
- **TCP**: color=darkgray, line_style=dotted
- **AMQP**: color=orange, line_style=dashed
- **SSH**: color=purple, line_style=solid
```

Accepted `line_style` values: `solid`, `dashed`, `dotted`

**Convention:** Red = unencrypted/unsafe (HTTP, Telnet). Green = encrypted (HTTPS, mTLS). Blue = internal secure. Orange = message queue. This creates an immediately readable security posture in the diagram.

---

## Step 9: Tune Severity with Multipliers

Override the default severity scoring for specific components:

```markdown
## Severity Multipliers
- **PaymentService**: 3.0
- **CustomerDB**: 2.5
- **Firewall**: 2.0
- **LoggingService**: 0.5
```

Values `> 1.0` increase threat severity for that component. Values `< 1.0` reduce it.

**When to use:**
- Critical business assets (payment, identity) → multiply up (2.0–3.0)
- Low-value internal components where threats are acceptable → multiply down (0.5–0.8)
- Internet-facing entry points → multiply up (1.5–2.0) to surface them at the top of reports

---

## Step 10: Create a GDAF Context File

The GDAF context file defines **what an attacker is trying to achieve** and **who they are**.
Place it at `context/my_context.yaml` relative to your model file.

Minimum viable context file:

```yaml
system_description: "Brief description of the system"
sector: "healthcare"  # retail, finance, manufacturing, government, healthcare, ...
internet_facing: true
compliance_requirements:
  - "HIPAA"
  - "SOC 2 Type II"

attack_objectives:
  - id: "OBJ-DATA-BREACH"
    name: "Patient Data Exfiltration"
    description: "Steal patient health records for ransomware leverage or sale"
    target_asset_names:
      - "PatientDB"
    target_types: ["database"]
    attacker_intent: "Ransomware demand or underground market sale"
    business_impact: "HIPAA fine, breach notification to 500k+ patients"
    mitre_final_tactic: "exfiltration"
    min_severity_score: 6.0

threat_actors:
  - id: "TA-RANSOMWARE"
    name: "Ransomware Operator"
    sophistication: "medium"
    objectives: ["OBJ-DATA-BREACH"]
    entry_preference: "internet-facing"
    description: "Ransomware-as-a-Service operator using phishing and RDP brute-force"
    known_ttps:
      - "T1566.001"  # Spearphishing Attachment
      - "T1110.001"  # Password Guessing (RDP)
    capable_tactics:
      - "initial-access"
      - "execution"
      - "persistence"
      - "credential-access"
      - "lateral-movement"
      - "exfiltration"
      - "impact"

risk_criteria:
  acceptable_risk_score: 5.0
  max_hops: 6
  max_paths_per_objective: 3
  gdaf_min_technique_score: 0.75
```

See `threatModel_Template/projects/example_3/context/ecommerce_context.yaml` and
`threatModel_Template/On-Prem_Enterprise_Network/context/enterprise_onprem_context.yaml`
for complete real-world examples.

---

## Step 11: Create BOM Files

A BOM (Bill of Materials) file enriches a server node with real asset data: OS version,
software version, patch level, known CVEs, and detection capabilities.

Create one YAML file per server in your `BOM/` directory. The filename must match the server
name (lowercased, spaces/dashes replaced by underscores):

- Server `Payment Service` → `BOM/payment_service.yaml`
- Server `WebServer` → `BOM/webserver.yaml`

Minimum BOM file:

```yaml
asset: "Payment Service"
os_version: "Ubuntu 22.04 LTS"
software_version: "Python 3.11 / FastAPI 0.103"
patch_level: current   # current | outdated | critical
known_cves:
  - CVE-2023-12345
running_services:
  - fastapi-uvicorn
  - node-exporter
detection_level: high  # low | medium | high
credentials_stored: false
notes: "Security-relevant observation — patch status, missing controls, known risks"
```

**What BOM data does:**
- `known_cves` — matched against CAPEC patterns to boost threat severity (VOC scoring +0.5)
- `detection_level` — contributes to GDAF `detection_coverage` scoring per path
- `credentials_stored` — boosts credential-access technique scores in GDAF (+0.4)
- `patch_level: outdated` — flags the asset for prioritized review

See `threatModel_Template/projects/example_3/*/BOM/` for 19 real examples.

---

## Step 12: Run the Analysis

### Single model file:
```bash
secopstm --model-file path/to/your_model.md
```

### Multi-model project (recommended for complex systems):
```bash
secopstm --project path/to/your_project/ --server
```
Then open the browser UI and use "Generate All" for cross-linked navigable reports.

### Full analysis with all outputs:
```bash
secopstm --model-file model.md --navigator --attack-flow
```

### CI/CD integration (JSON to stdout):
```bash
secopstm --model-file model.md --stdout | jq '.threats[] | select(.severity == "CRITICAL")'
```

**Outputs** (in `output/`):
- `stride_mitre_report.html` — main threat report
- `tm_diagram.html` — interactive diagram with severity heat map toggle
- `mitre_analysis.json` — versioned JSON for CI/SIEM
- `stix_report_*.json` — STIX 2.1 bundle

---

## Step 13: Interpret the Report

The HTML report contains:

1. **Executive Summary** — threat count by severity, top 5 threats, risk matrix
2. **Threat Table** — all threats with STRIDE category, target, MITRE techniques, CVE links,
   severity score, and risk badges (`CVE`, `CWE`, `NET`, `D3F`)
3. **Attack Chain Analysis** — multi-step paths through your architecture (from
   `AttackChainAnalyzer` — bottom-up from discovered threats)
4. **GDAF Attack Flows** — top-down adversary paths toward your defined objectives (if context
   file provided)
5. **Severity filters** — filter the threat table by CRITICAL / HIGH / MEDIUM / LOW

**Reading the severity heat map on the diagram:**
Click "Toggle Severity Heat Map" on the HTML diagram to color-code each component by its
highest threat severity. Red = CRITICAL, orange = HIGH, yellow = MEDIUM, green = LOW.

---

## Common Mistakes and How to Avoid Them

| Mistake | Effect | Fix |
|---|---|---|
| No `## Context` section | No GDAF paths, no BOM enrichment | Add `gdaf_context` and `bom_directory` |
| All boundaries `isTrusted=True` | No entry points detected; fewer threats | Mark internet/DMZ boundaries as `isTrusted=False` |
| No `authentication=none` flows | Fewer spoofing/tampering threats | Be honest — mark unauthenticated internal flows |
| Omitting `confidentiality` / `integrity` | Low/default threat scores | Set these on every server |
| `internet_facing=False` on public servers | GDAF misses entry points | Set `internet_facing=True` on all public servers |
| No `External Attacker` actor | GDAF has no external entry path | Add `authenticity=none, isTrusted=False` actor in Internet boundary |
| BOM file not found | No CVE enrichment | Normalize filename: lowercase + underscores (no spaces) |
| Sub-model path wrong | Drill-down link broken | Use paths relative to the model file (e.g., `./backend/model.md`) |

---

## Project Structure for Multi-Model Systems

For complex systems, split into a project with one model file per subsystem:

```
my_project/
├── main.md                    # Top-level overview — links to sub-models
├── context/
│   └── system_context.yaml   # GDAF objectives and threat actors
├── BOM/                       # Optional: BOMs for components in main.md
├── frontend/
│   ├── model.md               # Frontend tier detail
│   └── BOM/                   # BOMs for frontend servers
├── backend/
│   ├── model.md               # Backend tier detail
│   ├── BOM/
│   └── database/
│       ├── model.md           # Database cluster detail
│       └── BOM/
└── ...
```

Run with: `secopstm --project my_project/ --server`

The main model's servers reference sub-models via `submodel=./frontend/model.md`. The drill-down
creates clickable links in the HTML diagram. Each sub-model can have its own `BOM/` directory
and its own `## Context` section pointing to the same or a different context YAML.

See `threatModel_Template/projects/example_3/` for a complete working example of this structure.
