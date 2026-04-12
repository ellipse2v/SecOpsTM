# User Context — Threat Intelligence Injection

`config/user_context.example.json` is an **optional** file that lets you inject
organization-specific threat intelligence into the AI enrichment pipeline.
Copy and rename it to `config/user_context.json` (or any path you pass via
`--ai-context-file`) to activate it.

## Schema

```json
{
  "system_description": "<string>",
  "threat_intelligence": ["<string>", ...]
}
```

| Field | Type | Purpose |
|---|---|---|
| `system_description` | `string` | Natural-language description of the system being modeled. Injected into every LLM prompt as additional context so the model understands the business domain, deployment environment, and sensitivity of the data. |
| `threat_intelligence` | `string[]` | List of threat intelligence bullet points relevant to your organization or sector. Each entry is appended verbatim to the STRIDE prompt so the LLM can correlate known active threats with the architecture under review. |

## Example

```json
{
  "system_description": "High-availability cloud-native e-commerce platform on AWS/Kubernetes, handling payment data.",
  "threat_intelligence": [
    "Increased credential-stuffing attacks targeting cloud management consoles (2025 Q1).",
    "CVE-2024-1234 actively exploited against PostgreSQL 14.x — patch applied.",
    "Insider threat risk elevated: 3rd-party contractors have read access to S3 buckets."
  ]
}
```

## How it is used

1. `AIService._enrich_with_ai_threats()` reads this file (if present) and prepends
   its content to the component-level STRIDE prompt.
2. `RAGThreatGenerator` includes `system_description` in the RAG query so retrieved
   CAPEC/CVE knowledge is ranked by relevance to your specific deployment.
3. The file is **never required** — if absent, the AI enrichment runs with the
   architecture model alone.

## Alternative: per-model DSL `## Context` section

Since v1.1, the preferred way to provide system description and compliance
requirements is directly in the DSL file under `## Context`:

```markdown
## Context
project_description = Cloud-native e-commerce platform on AWS
compliance_requirements = PCI-DSS, SOC 2
```

`user_context.json` remains useful for sharing threat intelligence that applies
across multiple models (e.g., a SOC feed that you want every model to consume)
without duplicating it in every DSL file.

## Security note

This file may contain sensitive threat intelligence. Do **not** commit it to
public repositories. Add it to `.gitignore` if your repo is public:

```
config/user_context.json
```
