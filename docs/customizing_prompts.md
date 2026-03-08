# Customizing LLM Prompts

All LLM prompts used by SecOpsTM are defined in a single file: **`config/prompts.yaml`**.

You can tune them for your specific domain, sector, or compliance context **without touching Python code**.
Changes take effect on the next analysis run — no restart or rebuild needed.

---

## How It Works

```
config/prompts.yaml
       │
       ▼
threat_analysis/ai_engine/prompt_loader.py   (lazy-loaded, cached)
       │
       ├── stride_prompts.py        → LiteLLMProvider.generate_threats()
       ├── attack_flow_prompts.py   → LiteLLMProvider.generate_attack_flow()
       └── rag_service.py           → RAGThreatGenerator (LangChain chain)
```

**Variable syntax in templates:**

| Syntax | Replaced by | Example |
|---|---|---|
| `<<varname>>` | The tool at runtime | `<<comp_name>>` → `"WebServer"` |
| `{varname}` | LangChain at invoke time (RAG only) | `{system_description}` |
| `{uuid4}` | Passed to the LLM as a literal placeholder | LLM generates a UUID there |

---

## Sections

### 1. `dsl_generation.system`

**Used when:** a user types a natural-language description in the web editor
("Generate a threat model for a banking API with OAuth") and the tool
converts it into the SecOpsTM Markdown DSL.

**Variables:** none — this is a pure system prompt.

**When to customize:**
- You use a non-standard DSL extension (e.g. custom `## Severity Multipliers` entries)
- You want the generator to always apply your organisation's naming conventions
- You want to enforce specific classification levels for your sector

**Example — enforce naming conventions and PCI-DSS defaults:**

```yaml
dsl_generation:
  system: |
    You are an expert cybersecurity architect for a payment-processing organisation.
    Generate threat models in the SecOpsTM Markdown DSL.

    Naming conventions:
    - Boundaries: use zone names (e.g. "DMZ", "CardholderDataEnvironment", "Management")
    - Servers: prefix with role (e.g. "app-", "db-", "gw-")
    - Dataflows: include protocol version (e.g. "TLS1.3", "mTLS")

    Always apply these defaults:
    - Any server processing card data → classification=confidential, is_public=false
    - Any internet-facing component → isTrusted=false on its boundary
    - Payment flows → is_authenticated=true, is_encrypted=true

    ## DSL Structure
    ... (keep the rest of the original rules)
```

---

### 2. `stride_analysis.system`

**Used when:** the component-level LLM generates STRIDE threats for each
Actor, Server, and Dataflow in the model.

**Variables:** none — this is a pure system prompt.

**When to customize:**
- You operate in a specific sector (healthcare, finance, ICS/OT, SaaS)
- You need to add or remove compliance frameworks
- You want the LLM to adopt a particular threat actor profile

**Example — healthcare / HIPAA context:**

```yaml
stride_analysis:
  system: |
    You are an elite threat modeler specializing in healthcare information systems.
    You have deep expertise in:
    - HIPAA Security Rule (§164.312 technical safeguards)
    - HL7 FHIR API security
    - Medical device security (FDA guidance, IEC 62443)
    - MITRE ATT&CK for Enterprise v14+
    - OWASP Top 10 and API Security Top 10
    - MITRE D3FEND defensive techniques

    When analyzing threats always consider:
    - PHI (Protected Health Information) exposure risk
    - Audit log integrity (HIPAA requires 6-year retention)
    - Break-glass access patterns and their abuse potential
    - Medical device integration points as attack surface

    Your threats must be specific, actionable, and reference real CVEs or breaches
    (e.g. Change Healthcare 2024, Scripps Health 2021) where relevant.
```

**Example — ICS / OT context:**

```yaml
stride_analysis:
  system: |
    You are an expert in Industrial Control System (ICS) and OT security.
    You apply STRIDE to SCADA, DCS, PLC, and HMI components.

    Frameworks you master:
    - MITRE ATT&CK for ICS (v2)
    - IEC 62443 (Security Levels SL1–SL4)
    - NIST SP 800-82 Rev3
    - Purdue Model network segmentation

    Key differences from IT threat modeling:
    - Availability is the PRIMARY concern — model DoS threats as CRITICAL
    - Safety impacts (physical harm, environmental damage) must be explicitly assessed
    - Air-gap violations and USB/removable media are high-probability vectors
    - Legacy protocols (Modbus, DNP3, Profibus) lack authentication by design

    Always assess: safety impact, environmental impact, regulatory (NIS2 Directive).
```

---

### 3. `stride_analysis.component_template`

**Used when:** building the user-side prompt for each component analysis.
This is where component details and system context are injected.

**Available variables:**

| Variable | Value |
|---|---|
| `<<comp_name>>` | Component name (e.g. `"AuthService"`) |
| `<<comp_type>>` | `"Server"`, `"Actor"`, or `"Dataflow"` |
| `<<description>>` | Component description from the model |
| `<<trust_boundary>>` | Boundary name the component belongs to |
| `<<authentication>>` | Auth method if declared |
| `<<protocol>>` | Protocol (HTTPS, SQL, SSH…) |
| `<<internet_facing>>` | `"Yes"` or `"No"` |
| `<<deployment>>` | Deployment environment |
| `<<system_desc>>` | System-level description |
| `<<data_sensitivity>>` | From context.yaml |
| `<<compliance>>` | Comma-separated compliance list |
| `<<user_base>>` | Audience description |
| `<<integrations>>` | External integrations |

**When to customize:**
- You need the LLM to output more or fewer threats per component
- You want to add domain-specific output fields
- You want to change the table/output format to match your reporting tool

**Example — fewer threats, add CVSS estimate:**

```yaml
stride_analysis:
  component_template: |
    # STRIDE Analysis — <<comp_name>>

    ## Component
    Type: <<comp_type>> | Name: <<comp_name>> | Protocol: <<protocol>>
    Internet-facing: <<internet_facing>> | Boundary: <<trust_boundary>>
    Description: <<description>>

    ## Context
    <<system_desc>>
    Data sensitivity: <<data_sensitivity>> | Compliance: <<compliance>>

    ## Task
    Identify exactly 3 critical threats for this component.
    For each threat output:
    - category, title, description, attack_scenario (3 steps min)
    - business_impact (severity, financial, regulatory)
    - likelihood, mitre_techniques, cwe_ids, d3fend_techniques
    - cvss_estimate: a CVSS v3.1 base score estimate (float 0.0–10.0)
    - confidence (0.0–1.0)

    Return valid JSON: {"threats": [...]}
```

---

### 4. `attack_flow.system`

**Used when:** generating STIX 2.1 Attack Flow objects for key threats.

**Variables:** none — pure system prompt.

**When to customize:**
- You want flows scoped to a specific kill chain (e.g. only Initial Access → Lateral Movement)
- You need to enforce a maximum number of actions for readability
- You want to add specific detection data sources relevant to your SIEM

**Example — limit to 4 actions, add Splunk/Sentinel data sources:**

```yaml
attack_flow:
  system: |
    You are an expert in cyber attack chain analysis (MITRE ATT&CK v14+).
    You produce Attack Flow diagrams in STIX 2.1 format.

    Rules:
    - Generate exactly 4 main actions (no more, no less)
    - All ATT&CK technique IDs must be real and current. Verify before using.
    - For every detection point, specify the exact data source:
        * Splunk: index name + search term
        * Microsoft Sentinel: KQL query skeleton
        * Sysmon: Event ID
    - Model the most REALISTIC path, not the most damaging theoretical one
    - Every action must reference a detection node
```

---

### 5. `attack_flow.component_template`

**Used when:** building the user-side Attack Flow prompt for a specific threat.

**Available variables:**

| Variable | Value |
|---|---|
| `<<threat_category>>` | STRIDE category (e.g. `"Tampering"`) |
| `<<threat_category_lower>>` | Lowercase, hyphenated (for STIX ID) |
| `<<threat_title>>` | Threat title |
| `<<threat_description>>` | Threat description |
| `<<attack_scenario>>` | Base scenario from threat generation |
| `<<mitre_techniques>>` | Comma-separated technique IDs |
| `<<component_type>>` | `"Server"`, `"Actor"`, etc. |
| `<<component_name>>` | Component name |
| `<<component_description>>` | Component description |
| `<<system_context>>` | System-level description |

**When to customize:** rarely — the template is structural. Edit only if
you need additional STIX fields in the output.

---

### 6. `rag.system`

**Used when:** the RAG pipeline generates **system-level** threats by querying
the ChromaDB vector store (CAPEC, CVE, ATT&CK, D3FEND knowledge base) and
passing retrieved context to the LLM.

**Variables:** none — pure system prompt.

**When to customize:**
- You want to emphasise specific risk categories (e.g. "focus on ransomware paths")
- You want the RAG to include supply chain or third-party risks
- You want to scope output to specific architectural patterns in your organisation

**Example — financial sector, ransomware focus:**

```yaml
rag:
  system: |
    You are a senior threat modeler for a financial services organisation.
    You operate at SYSTEM level — your role is to identify threats that emerge
    from component INTERACTIONS, not single-component vulnerabilities.

    Priority threat categories for this sector:
    1. Ransomware kill chains (Initial Access → Encryption → Extortion)
    2. Business Email Compromise leading to fraudulent wire transfers
    3. Supply chain compromise via third-party SaaS integrations
    4. Regulatory non-compliance cascades (DORA, PCI-DSS breach notification)

    Focus on:
    - Cross-component attack paths (pivot chains)
    - Trust boundary violations between internal zones
    - Data classification mismatches (SWIFT data in low-trust channels)

    Do NOT repeat single-component threats — those are covered separately.
```

---

### 7. `rag.human_template`

**Used when:** the LangChain chain formats the user message for RAG generation.

**Variables (substituted by LangChain):**

| Variable | Value |
|---|---|
| `{system_description}` | From `config/user_context.example.json` |
| `{user_threat_intelligence}` | Threat intel from user context |
| `{threat_model_markdown}` | Full Markdown model passed at runtime |
| `{context}` | Retrieved chunks from ChromaDB vector store |

**When to customize:**
- You want to add a structured output field (e.g. `affected_zone` for OT)
- You want to change the number of system-level threats generated (default 3–6)
- You want the output to include CVSS estimates or remediation priorities

**Example — add remediation priority field:**

```yaml
rag:
  human_template: |
    ## System Description
    {system_description}

    ## Threat Intelligence
    {user_threat_intelligence}

    ## Architecture (Threat Model)
    {threat_model_markdown}

    ## Retrieved Security Knowledge
    {context}

    ---
    Generate 4 to 8 SYSTEM-LEVEL threats. For each threat include:
    - name, description, affected_components, category, likelihood, impact, source ("LLM")
    - remediation_priority: Critical / High / Medium (considering likelihood × impact × cost-to-fix)

    Return a JSON array.
```

---

## Reloading Prompts Without Restart

Prompts are cached in memory after the first load. To force a reload
(e.g. after editing `prompts.yaml`) without restarting the server:

```python
from threat_analysis.ai_engine.prompt_loader import reload
reload()
```

Or restart the Flask server — it reloads on startup automatically.

---

## Validating Your Edits

```bash
python -c "
from threat_analysis.ai_engine.prompt_loader import get
print(get('stride_analysis', 'system')[:200])
print('---')
from threat_analysis.ai_engine.prompts.stride_prompts import build_component_prompt
p = build_component_prompt(
    {'name': 'TestServer', 'type': 'Server', 'description': 'Test'},
    {'system_description': 'My system'}
)
assert '<<' not in p, 'Unreplaced placeholder found!'
print('OK — no unreplaced placeholders')
print(f'Template length: {len(p)} chars')
"
```

---

## Sector Quick-Reference

| Sector | Key additions to `stride_analysis.system` |
|---|---|
| **Healthcare** | HIPAA §164.312, HL7 FHIR, PHI exposure, medical device FDA guidance |
| **Finance / PCI** | PCI-DSS v4, DORA, SWIFT CSP, Business Email Compromise, ransomware |
| **ICS / OT** | ATT&CK for ICS v2, IEC 62443, Purdue Model, availability first |
| **Cloud-native** | CSPM misconfiguration, container escape, IMDS abuse, IAM privilege escalation |
| **SaaS / Multi-tenant** | Tenant isolation bypass, API rate-limit abuse, OAuth token leakage |
| **Government** | NIST SP 800-53 r5, FedRAMP, insider threat, supply chain (SSDF) |
