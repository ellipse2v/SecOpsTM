# SecOpsTM — From Conception to Run

This page walks through the **complete workflow** for threat modeling with SecOpsTM, from the first
whiteboard conversation with the system owner to automated reports in CI/CD.

---

## Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  1. CONCEIVE    │───▶│   2. MODEL      │───▶│  3. ENRICH      │───▶│    4. RUN       │
│  Understand     │    │  Write the DSL  │    │  BOM / VEX /    │    │  Generate /     │
│  the system     │    │  Markdown file  │    │  AI context     │    │  Review / CI    │
└─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
       30 min                1–3 hours             30 min                  seconds
  (information              (first model)         (optional)           (every run)
   gathering)
```

Phases 1 and 2 are mandatory. Phase 3 is optional but significantly improves AI-generated threats.
Phase 4 can be automated.

---

## Phase 1 — Conceive: Understand the System

Before writing a single line of DSL, gather the information that will determine the quality of your
threat model. The goal is to answer five questions:

| Question | Why it matters |
|---|---|
| What does the system do? | Becomes the `## Description` section — the AI uses this as system context |
| What are the trust boundaries? | Defines your `## Boundaries` — drives STRIDE crossing rules |
| Who interacts with the system? | Defines your `## Actors` — external vs internal, trusted vs untrusted |
| What components make up the system? | Defines your `## Servers` — one entry per deployable unit |
| What data flows between components? | Defines your `## Dataflows` — required by STRIDE rules |

**Resources for this phase:**

- `docs/data_collection_guide.md` — full questionnaire to run with the system owner
- `docs/project_onboarding_questionnaire.md` — short form to send to a developer team in advance
- Use a whiteboard or architecture diagram to identify boundaries before opening any file

**Typical output of Phase 1:**

```
System: B2B SaaS invoicing platform, multi-tenant, PCI DSS scope
Boundary 1: Internet (untrusted, traversal = low)
Boundary 2: DMZ (partially trusted, traversal = medium)
Boundary 3: Internal (trusted, traversal = high)
Actors: Browser (public), Admin Console (internal)
Servers: WebApp, API Gateway, Auth Service, DB Cluster, File Store
Dataflows: Browser→WebApp (HTTPS), WebApp→API (HTTPS/JWT), API→DB (TLS/mutual-auth)
```

---

## Phase 2 — Model: Write the DSL File

Create a `.md` file (e.g. `model.md`). Start with the mandatory structure, then add optional
enrichment attributes.

### Step 1 — Skeleton (mandatory)

Every model needs at least one actor, one server, and one dataflow:

```markdown
## Description

B2B SaaS invoicing platform. Multi-tenant. PCI DSS scope.

## Boundaries

- Internet
  - isTrusted: false
- Internal
  - isTrusted: true

## Actors

- Browser
  - boundary: Internet
  - is_public: true

## Servers

- WebApp
  - boundary: Internal
  - type: webserver

## Dataflows

- BrowserToWebApp
  - from: Browser
  - to: WebApp
  - protocol: HTTPS
  - is_encrypted: true
  - is_authenticated: false
```

This alone will produce STRIDE threats via pytm rules. Run it now to get a first report — you can
always enrich later.

### Step 2 — Improve STRIDE coverage (optional, no AI needed)

Add attributes that activate more pytm rules:

```markdown
## Servers

- WebApp
  - boundary: Internal
  - type: webserver
  - confidentiality: high     # activates higher-severity scoring
  - integrity: high
  - availability: medium
  - redundant: false          # activates DoS likelihood
  - encryption: none          # activates data-at-rest threat

## Dataflows

- BrowserToWebApp
  - from: Browser
  - to: WebApp
  - protocol: HTTPS
  - is_encrypted: true
  - is_authenticated: false   # activates Spoofing threats
  - authorization: none       # activates Elevation of Privilege threats
```

### Step 3 — Improve AI threat quality (optional, requires AI config)

Add description and context to each component — this is the single highest-impact change for AI:

```markdown
## Servers

- WebApp
  - boundary: Internal
  - type: webserver
  - description: "Nginx reverse proxy + Python Flask app. Renders invoice PDFs, calls internal API
    for billing. Runs in Docker. Receives unauthenticated public traffic on port 443."
  - tags: [nginx, python, flask, docker]
  - machine: CONTAINER
  - internet_facing: true
  - mfa_enabled: false        # AI will generate credential-theft paths
  - waf: false                # AI will focus on injection threats
```

> **Rule of thumb:** A `description=` on each server is the fastest way to improve AI threat
> quality. Without it, the AI prompt says "No description provided" and generates generic threats.

For a complete list of attributes and their effect on AI output, see
[Enriching AI Threats](enriching_ai_threats.md).

### Step 4 — Large systems: use sub-models

If the system has more than ~15 components, split it into sub-models. In the parent model, mark
a server as a sub-model:

```markdown
## Servers

- AuthService
  - boundary: Internal
  - type: webserver
  - submodel: ./auth/model.md   # drills into a separate model
```

The parent diagram links to the child. The child diagram shows ghost nodes for external connections.
GDAF attack paths traverse into the sub-model automatically.

---

## Phase 3 — Enrich (optional)

Enrichment adds real-world operational data that improves threat scoring, GDAF attack path
accuracy, and AI threat specificity. All enrichment is optional — the model runs without it.

### 3a — AI context (`config/context.yaml` or per-model `context/`)

The fastest way to improve all AI threats at once. Edit `config/context.yaml`:

```yaml
system_description: "B2B SaaS invoicing platform. Multi-tenant. PCI DSS scope."
sector: "Financial technology"
deployment_environment: "AWS EKS"
data_sensitivity: "Financial"
compliance_requirements:
  - "PCI DSS"
  - "SOC 2"
```

This block is injected into every component prompt. Without it, the LLM has no business context.

For per-model overrides, create `{model_dir}/context/my_context.yaml` and reference it in
`## Context`:

```markdown
## Context

gdaf_context = context/my_context.yaml
```

### 3b — BOM files (Bill of Materials)

BOM files carry the operational inventory for each asset: OS version, patch level, known CVEs,
detection capability. Create one YAML file per asset in a `BOM/` directory next to the model:

```
model.md
BOM/
  WebApp.yaml
  AuthService.yaml
  DBCluster.yaml
```

Minimal BOM file (`BOM/WebApp.yaml`):

```yaml
asset: WebApp
os: "Ubuntu 22.04"
patch_level: current
known_cves:
  - CVE-2023-44487   # HTTP/2 rapid reset
detection_level: medium
```

**Effect on threat scoring:**

| BOM field | Effect |
|---|---|
| `known_cves` | CVE-CAPEC match → +0.5 to STRIDE base score |
| `detection_level: high` | `detection_coverage = 0.8` at this node in GDAF |
| `credentials_stored: true` | +0.4 on credential-access technique scores in GDAF |

**Auto-discovery:** `BOMLoader` looks for `BOM/` next to the model file automatically. No DSL
configuration required.

### 3c — VEX files (precise CVE exploitability)

If your scanner exports CycloneDX JSON with `analysis.state` (Grype, Trivy, Qualys, Tenable),
place the files in a `BOM/` directory. SecOpsTM reads the states automatically:

| State | Interpretation |
|---|---|
| `affected`, `exploitable` | Active CVE → +0.5 score boost |
| `fixed`, `resolved` | Remediated → −0.5 (D3FEND signal) |
| `not_affected`, `false_positive` | Ignored — not counted |

For a standalone VEX file, reference it in `## Context`:

```markdown
## Context

vex_file = vex/my_system.vex.json
```

**CVE source priority** (only one active per component):

```
VEX file/directory  >  BOM CycloneDX with analysis.state  >  BOM known_cves  >  cve_definitions.yml
```

### 3d — AI provider (`config/ai_config.yaml`)

To use AI threat generation, add an API key and enable a provider:

```yaml
ai_providers:
  - name: gemini
    enabled: true
    model: "gemini/gemini-2.0-flash"
    api_key_env: GEMINI_API_KEY
```

Then set the environment variable:

```bash
export GEMINI_API_KEY=your-key-here
```

SecOpsTM works fully offline without an API key — AI features are additive and degrade gracefully.

---

## Phase 4 — Run: Generate Reports

### CLI — single model

```bash
# Full analysis (HTML + JSON + SVG + STIX + Navigator)
secopstm --model-file model.md

# JSON to stdout for CI/SIEM
secopstm --model-file model.md --stdout

# With GDAF attack paths (requires context YAML with objectives)
secopstm --model-file model.md --attack-flow
```

Outputs land in `output/`:

| File | Content |
|---|---|
| `stride_mitre_report.html` | Full threat report: executive summary, STRIDE table, attack chains, severity heat map |
| `mitre_analysis.json` | Schema-validated JSON (IDs `T-0001`, `schema_version: "1.0"`) — for SIEM / CI |
| `tm_diagram.svg` | Architecture diagram with trust boundary colors |
| `tm_diagram.html` | Interactive diagram with severity heat map toggle |
| `attack_navigator_layer_*.json` | MITRE ATT&CK Navigator layer (import at attack.mitre.org) |
| `stix_report_*.json` | STIX 2.1 bundle |
| `remediation_checklist.csv` | Mitigation action list per threat-technique pair |
| `*.afb` | Attack Flow files (if `--attack-flow`) |

### CLI — project (multiple models)

```bash
# Analyze an entire project directory (main model + all sub-models)
secopstm --project path/to/project/

# With SSE progress output
secopstm --project path/to/project/ --server
```

A global project report aggregates threats across all models. Cross-model RAG threats surface
risks that span component boundaries.

### Web UI

```bash
secopstm --server
# then open http://127.0.0.1:5000/
```

The web UI provides:

- **Monaco editor** — edit DSL with live diagram preview
- **Graphical editor** — drag-and-drop canvas (experimental)
- **Generate All** — runs full analysis with progress bar and SSE streaming
- **Export** — download any output format from the browser

### Interpreting results

**HTML report reading order:**

1. **Executive summary** (top) — total threats by severity, top 5 critical, STRIDE distribution
2. **Risk matrix** — 5×5 likelihood × impact grid — which quadrant has most threats
3. **Threat table** — filter by severity (CRITICAL/HIGH/MEDIUM/LOW) or STRIDE category
4. **Attack Chain Analysis** — multi-step scenarios chaining individual threats across dataflows
5. **GDAF Attack Paths** (if generated) — adversary simulation from objective to target

**Severity scores** are computed from:
- Base STRIDE score per category
- CIA modifiers from server attributes
- CVE match (+0.5), high-risk CWE (+0.3), network exposure (+0.7), D3FEND mitigation (−0.5)
- Custom severity multipliers (per-component, defined in `## Severity Multipliers`)

**VOC badges** in the threat table indicate which risk signals fired:
- `CVE` — a CVE matched this threat's CAPEC
- `CWE⚠` — a high-risk CWE class detected
- `NET` — component is network-exposed without full auth/encryption
- `D3F` — D3FEND mitigations exist (reduces score)
- `⛔D3F` — CVE is fixed (BOM/VEX state = `fixed`)

---

## Phase 5 — Iterate and Automate

### Comparing two model versions (diff)

```bash
# Diff two JSON exports — shows new, resolved, and severity-changed threats
secopstm --diff output/v1/mitre_analysis.json output/v2/mitre_analysis.json
```

Output:
```
[+] T-0014  HIGH  SQL Injection on DBCluster  (new)
[-] T-0007  MEDIUM  Missing TLS on InternalAPI  (resolved)
[~] T-0003  LOW → HIGH  Spoofing on AuthService  (severity increased)
```

### CI/CD integration

```yaml
# .github/workflows/threat-model.yml
- name: Run threat model
  run: secopstm --model-file model.md --output-format json --output-file report.json

- name: Check for new CRITICAL threats
  run: |
    CRITICAL=$(jq '[.threats[] | select(.severity == "CRITICAL")] | length' report.json)
    if [ "$CRITICAL" -gt 0 ]; then
      echo "::error::$CRITICAL CRITICAL threats found"
      exit 1
    fi

- name: Diff against baseline
  run: secopstm --diff baseline.json report.json
```

### Suggested iteration cadence

| Trigger | Action |
|---|---|
| New component added | Add server + dataflows to DSL → re-run |
| Architecture change | Update dataflows, boundaries → diff against last run |
| Scanner produces new CVEs | Update BOM/ directory → re-run |
| AI threats seem generic | Add `description=` to servers → re-run |
| New compliance requirement | Update `config/context.yaml` compliance_requirements → re-run |

---

## Quick Reference

```
# Minimal — works offline, no AI
secopstm --model-file model.md

# With AI threats (needs API key in env)
export GEMINI_API_KEY=...
secopstm --model-file model.md

# With GDAF attack paths
secopstm --model-file model.md --attack-flow

# Full project
secopstm --project ./my-system/

# JSON for SIEM
secopstm --model-file model.md --stdout | jq '.threats[] | select(.severity == "CRITICAL")'

# Diff
secopstm --diff before.json after.json

# Web editor
secopstm --server
```

---

## Related Documentation

- [Defining Threat Models](defining_threat_models.md) — complete DSL reference (all attributes, all sections)
- [Enriching AI Threats](enriching_ai_threats.md) — which attributes improve AI output and how
- [Data Collection Guide](data_collection_guide.md) — questionnaire for Phase 1 information gathering
- [Examples](examples.md) — ready-to-use model templates
- [GDAF](gdaf.md) — attack path engine details and context YAML format
- [Usage](usage.md) — all CLI flags and server mode details
