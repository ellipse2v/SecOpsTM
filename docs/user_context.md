# User Context — Threat Intelligence Injection

`config/user_context.example.json` is an **optional** file that lets you inject
organization-specific threat intelligence into the RAG pass of the AI enrichment pipeline.

⚠️ The filename is currently read **literally** — `RAGThreatGenerator` is always constructed
with no path override (`ai_service.py`), so renaming this file (e.g. to `user_context.json`)
or passing a different path has **no effect**; the app keeps reading
`config/user_context.example.json` regardless. There is also no `--ai-context-file` CLI flag
(removed along with the deprecated `config/context.yaml`, see `architecture.md` tech debt #11).
**Edit `config/user_context.example.json` in place** to activate this feature.

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

1. `RAGThreatGenerator._load_user_context()` reads this file (if present) and includes
   `system_description` + `threat_intelligence` in the RAG retrieval query, so retrieved
   CAPEC/CVE knowledge is ranked by relevance to your specific deployment.
2. This only affects the **RAG cross-model pass** (`rag.enabled: true` in
   `config/ai_config.yaml`) — it is **not** injected into the per-component STRIDE prompts
   (`AIService._enrich_with_ai_threats()` does not read this file at all).
3. The file is **never required** — if absent or empty, RAG runs with the architecture
   model alone.

## Alternative: per-model DSL `## Context` section

Since v1.1, the preferred way to provide system description and compliance
requirements is directly in the DSL file under `## Context`:

```markdown
## Context
project_description = Cloud-native e-commerce platform on AWS
compliance_requirements = PCI-DSS, SOC 2
```

`user_context.example.json` remains useful for sharing threat intelligence that applies
across every model's RAG pass (e.g., a SOC feed) without duplicating it in every DSL file —
but note it is a single global file, not per-model like `## Context`.

## Security note

This file may contain sensitive threat intelligence. Do **not** commit real content to
public repositories — either keep the repo private, or add it to `.gitignore` and document
locally that operators must populate it:

```
config/user_context.example.json
```
