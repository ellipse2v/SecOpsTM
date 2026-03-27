# Enriching AI Threat Generation

This document explains which DSL attributes, BOM fields, and context files affect the quality of
AI-generated threats, and precisely how each one improves the output.

---

## Mental model

SecOpsTM runs two threat engines in parallel:

| Engine | Source | What it needs |
|---|---|---|
| **pytm STRIDE** | Rule-based, deterministic | Structural attributes only (`from`/`to`, `is_encrypted`, `isTrusted`, …) |
| **AI (per-component LLM)** | LLM call per server/actor/boundary | The richer the component description, the better |
| **RAG (cross-model LLM)** | Vector search + LLM call | The system `## Description` + all component details |

pytm threats come from topology rules. AI threats come from LLM prompts. The prompts are
constructed from DSL attributes — so the more you fill in, the more targeted the AI output.

---

## Part 1 — DSL Attributes

### Mandatory (pytm will not produce threats without these)

| Attribute | Where | Why mandatory |
|---|---|---|
| At least one `## Actors` or `## Servers` entry | Actors / Servers | pytm needs elements to target |
| At least one `## Dataflows` entry | Dataflows | pytm needs data movement to apply STRIDE rules |
| `from: <name>` | Dataflows | Source element reference — must match a defined actor or server |
| `to: <name>` | Dataflows | Sink element reference — must match a defined actor or server |

Everything else is optional. The system degrades gracefully when attributes are absent.

---

### Optional — improve pytm STRIDE coverage

These attributes activate additional pytm rule conditions. They affect the rule-based engine only
and do not require an AI provider.

| Attribute | Section | Effect on STRIDE threats |
|---|---|---|
| `isTrusted: false` | Boundaries | Enables boundary-crossing threats (Spoofing, Elevation of Privilege) |
| `is_encrypted: false` | Dataflows | Activates Tampering and Information Disclosure threats |
| `is_authenticated: false` | Dataflows | Activates Spoofing threats |
| `authentication: none` | Dataflows | Finer-grained auth threats (e.g. missing OAuth) |
| `authorization: none` | Dataflows | Finer-grained authz threats |
| `protocol: HTTP` | Dataflows | Protocol-specific threats (cleartext HTTP vs HTTPS) |
| `ip_filtered: false` | Dataflows | Missing firewall filter threats |
| `readonly: false` | Dataflows | Write-access threats |
| `vpn: false` | Dataflows | Missing VPN tunnel threats |
| `classification` | Data | Sensitivity-based threats (RESTRICTED, TOP SECRET raise severity) |
| `credentialsLife` | Data | Credential expiry threats |
| `confidentiality` / `integrity` / `availability` | Servers | CIA-based severity scoring |
| `machine` | Servers | DoS variant rules (PHYSICAL, VIRTUAL, CONTAINER) |
| `redundant: false` | Servers | DoS likelihood increase (single point of failure) |
| `encryption: none` | Servers | Data-at-rest threats |
| `is_public: true` (actor) | Actors | External attacker threats — Spoofing, DoS |

---

### Optional — improve AI threat quality

These attributes are directly injected into the LLM prompt for each component. The more of these
you fill in, the more specific and actionable the AI-generated threats will be.

#### High impact — always worth filling in

| Attribute | Section | What it adds to the AI prompt | AI threat improvement |
|---|---|---|---|
| `description: "..."` | Servers, Actors | Verbatim description block in the prompt | Most impactful — gives the AI semantic context. Without it, the prompt says "No description provided" and threats are generic. |
| `type: database` / `type: webserver` | Servers | Component type field in the prompt | Tells the AI what attack surface to focus on (SQL injection for databases, XSS for webservers, etc.) |
| `boundary: <zone>` | Servers, Actors | Trust zone name + TRUSTED/UNTRUSTED label | The AI receives "component lives in zone X (UNTRUSTED)" — enables lateral movement and trust-crossing scenarios |
| `isTrusted: true/false` | Boundaries | TRUSTED/UNTRUSTED injected for every component in this boundary | Shapes whether AI generates insider vs. external attacker threats |

#### Medium impact — fill when relevant

| Attribute | Section | What it adds to the AI prompt | AI threat improvement |
|---|---|---|---|
| `confidentiality` / `integrity` / `availability` | Servers | `CIA Triad: Confidentiality: high \| Integrity: medium \| Availability: high` | AI prioritises threats matching the declared sensitivity profile |
| `businessValue: "..."` | Servers, Actors, Boundaries | Business value context in the prompt | AI reasons about business impact — more realistic risk narrative |
| `machine: PHYSICAL/VIRTUAL/CONTAINER/SERVERLESS` | Servers | Machine type field | AI generates platform-appropriate threats (container escape, cold boot, etc.) |
| `tags: [nginx, python3, redis]` | Servers | Technology tags field | AI generates CVE-class threats matching the declared stack |
| `authenticity: certificate` | Actors | Authentication mechanism | AI generates more specific spoofing threats (e.g. certificate forgery) |
| `authentication: OAuth2` | Dataflows | Auth type in flow description | AI generates OAuth-specific threats (token hijack, PKCE bypass) |
| `authorization: RBAC` | Dataflows | Authz type in flow description | AI generates privilege escalation paths targeting role boundaries |
| `protocol: LDAP` | Dataflows | Protocol label in flow description | AI generates protocol-specific threats (LDAP injection, LDAP null bind) |

#### Lower impact — still useful

| Attribute | Section | What it adds to the AI prompt | AI threat improvement |
|---|---|---|---|
| `waf: true/false` | Servers | WAF: Yes/No in security controls block | AI de-prioritises or adjusts web injection threats when WAF is present |
| `ids: true/false` | Servers | IDS: Yes/No in security controls block | AI factors in detection capability |
| `ips: true/false` | Servers | IPS: Yes/No in security controls block | AI notes whether exploit attempts would be blocked |
| `mfa_enabled: false` | Servers | MFA: No in security controls block | AI generates credential-theft and account-takeover paths |
| `auth_protocol: Kerberos` | Servers | Auth protocol in security controls block | AI generates protocol-specific auth attacks |
| `encryption: full` | Servers | Encryption at rest status | AI considers data exfiltration difficulty |
| `redundant: true` | Servers | Redundant: Yes | AI considers HA bypass scenarios |
| `internet_facing: true` | Servers | "Yes (directly internet-facing)" in prompt | AI focuses on external attacker entry points |
| `is_public: true` | Actors | Same as above for actors | Shapes attacker position in AI scenario |

#### Dataflow details (injected into inbound/outbound flow lists)

Every dataflow connected to a component is listed in the prompt as a one-line summary:
```
[HTTPS] BrowserA → WebApp (encrypted, auth=OAuth2, authz=RBAC)
```

Each of these fields adds detail:
- `protocol` — protocol label
- `is_encrypted` — "encrypted" or "CLEARTEXT"
- `is_authenticated` — "authenticated" or "unauthenticated"
- `authentication` — specific auth mechanism
- `authorization` — specific authz mechanism
- `vpn` — "VPN" flag
- `ip_filtered` — "IP-filtered" flag
- `data` — referenced Data object name (pulled from `## Data`)

---

## Part 2 — Context Files

### `config/context.yaml` (or per-model `context/*.yaml`)

This file injects **system-level** context into every component prompt and the RAG query.
It is the fastest way to improve all AI threats at once.

| Key | Type | AI prompt section | Effect |
|---|---|---|---|
| `system_description` | string | `## System Context` block | Included in every component prompt. Without it, the AI has no system-level context. |
| `sector` | string | `## Adversarial Context — Sector` | AI generates sector-appropriate threats (healthcare → HIPAA violations, finance → fraud) |
| `threat_actor_profiles` | string | `## Adversarial Context — Known Threat Actors` | AI generates threats matching declared adversary capabilities (nation-state vs script kiddie) |
| `business_goals_to_protect` | string | `## Adversarial Context — Business Goals` | AI prioritises threats to the declared crown jewels |
| `deployment_environment` | string | `Deployment: Kubernetes` | AI generates platform-appropriate threats (K8s RBAC escape, cloud metadata abuse) |
| `data_sensitivity` | string | `Data Sensitivity: PHI` | AI raises severity for sensitive data paths |
| `compliance_requirements` | list | `Compliance: HIPAA, GDPR` | AI flags threats that would cause compliance violations |
| `user_base` | string | `User base: 100,000 patients` | AI reasons about breach scale and business impact |
| `integrations` | list | `Integrations: EHR system, Payment gateway` | AI generates supply-chain and third-party threats |

**Example — minimal high-value context:**

```yaml
system_description: "B2B SaaS invoicing platform. Multi-tenant. PCI DSS scope."
sector: "Financial technology"
deployment_environment: "AWS EKS"
data_sensitivity: "Financial"
compliance_requirements:
  - "PCI DSS"
  - "SOC 2"
```

**Effect:** Every component prompt will include this context. The LLM will generate threats
like "tenant isolation bypass", "AWS metadata SSRF", "PCI zone boundary violations" — which
a blank context would never produce.

---

### GDAF context YAML (`gdaf_context = context/my_context.yaml`)

Used by the GDAF attack path engine, not by the per-component LLM prompts. However, it shapes
which attack scenarios are generated and exported in Attack Flow files.

Key sections:

```yaml
attack_objectives:
  - name: "Data Exfiltration"
    target: "Customer Database"
    value: 10

threat_actors:
  - name: "External Adversary"
    capabilities: [phishing, exploit_public_facing]
    motivation: financial
```

Without this file, GDAF runs with an auto-generated minimal context (servers with highest CIA
scores become implicit targets). With it, you control exactly which scenarios are explored.

---

## Part 3 — BOM Files

BOM files are per-asset operational inventory. They do not feed AI prompts directly, but they
affect **STRIDE severity scoring** (VOC signals) and **GDAF attack path scoring**.

### What BOM adds to STRIDE scoring

| BOM field | CVE source used | Effect on severity |
|---|---|---|
| `known_cves` (no state) | All listed CVEs | CVE-CAPEC match → +0.5 to base score |
| `active_cves` (auto from `analysis.state`) | Only exploitable CVEs | Same boost, but false positives filtered |
| `fixed_cves` (auto from `analysis.state`) | Remediated CVEs | Mitigation signal → −0.5 (same as D3FEND) |
| VEX standalone file | All affected CVEs | Same as `active_cves` — highest priority source |

### What BOM adds to GDAF scoring

| BOM field | Effect on GDAF |
|---|---|
| `detection_level: high` | `detection_coverage = 0.8` at this node — reduces scenario attractiveness |
| `credentials_stored: true` | +0.4 on credential-access technique scores at this node |
| `running_services: [SSH, RDP]` | Adds to node `services` set → activates protocol-specific technique boosts |
| `patch_level: outdated` | Informational only (no direct scoring, but visible in reports) |

### CVE source priority

Only **one** CVE source is active at a time, in this order:

```
VEX file/directory (vex_file / vex_directory in ## Context, or VEX/ auto-discovery)
    ↓ if absent
BOM CycloneDX with analysis.state  (active_cves / fixed_cves auto-derived)
    ↓ if absent
BOM known_cves without state       (all CVEs treated as active)
    ↓ if absent
cve_definitions.yml at project root (global fallback)
```

> **Practical note:** If your scanner (Qualys, Grype, Trivy, Tenable) exports CycloneDX JSON that
> includes `vulnerabilities[].analysis.state`, place those files in `BOM/` — SecOpsTM will read
> the states automatically. No separate VEX file is required.

---

## Quick checklist — getting the most from AI threats

```
[ ] ## Description section filled in (becomes system_description in prompts)
[ ] description= on every server and actor that matters
[ ] type= on every server (database, webserver, ldap, loadbalancer, …)
[ ] boundary= on every actor and server
[ ] isTrusted= on every boundary
[ ] confidentiality/integrity/availability on sensitive servers
[ ] is_encrypted and is_authenticated on every dataflow
[ ] authentication= and authorization= on sensitive flows
[ ] config/context.yaml: system_description, sector, deployment_environment, data_sensitivity
[ ] BOM files: known_cves (or CycloneDX with analysis.state), detection_level, credentials_stored
[ ] GDAF context: attack_objectives + threat_actors (for Attack Flow export)
```

---

## Related documentation

- [DSL Reference](defining_threat_models.md) — full attribute syntax
- [GDAF Documentation](gdaf.md) — attack path engine details
- [Customizing AI Prompts](customizing_prompts.md) — editing system prompts
- [Threat Modeling Guide](threat_modeling_guide.md) — step-by-step walkthrough
