# AI roles

When AI is enabled, SecOpsTM runs several distinct LLM passes, each with its own system
prompt and purpose (all defined in `threat_analysis/config/prompts.yaml`, editable without touching Python
code). All roles share the one provider configured in `config/ai_config.yaml` — there's no
per-role provider selection — and every pass degrades gracefully offline: if no provider is
reachable, the tool falls back to the pytm rule engine silently.

| Role | Purpose | Where it shows up |
|---|---|---|
| **DSL Generation** | Turns a natural-language system description into a valid SecOpsTM Markdown model | "Generate from prompt" in the web editor |
| **STRIDE Component Analysis** | Generates STRIDE threats per actor/server/boundary, strictly scoped to the component's declared technology tags (no invented stacks) | Per-component AI enrichment, `(AI)`-sourced threats in the report |
| **RAG System-Level Analysis** | Cross-component/cross-boundary threats retrieved from a local ChromaDB knowledge base (CVE, CAPEC, ATT&CK, D3FEND) | System-level pass, `(LLM)`-sourced threats — skipped on small models below `rag.min_components` |
| **SOC Analyst** | Detection-engineering pass: Sigma/Splunk SPL/KQL rule suggestions and IOCs per threat | HTML report "SOC Analysis" section |
| **CISO Triage** | Board-level risk briefing summarizing the highest-priority threats | HTML report "CISO Briefing" section |
| **Red Team** | Attempts to advance a GDAF attack scenario, citing only facts from the grounding block (CVE, misconfig, exposed ports) | Red/Blue adversarial debate on top GDAF scenarios |
| **Blue Team** | Challenges the Red team's attempt with SIEM/EDR/IDS controls and calls out detection gaps | Red/Blue adversarial debate |
| **Attack Path Narrator** | Short grounded narrative + business impact for each automatically discovered attack path (already-fixed hops/techniques — explains them, never adds new ones). Instructed to never emit an ID (T-number, CVE, CAPEC, D3-); any response that does is discarded, not trusted | "Automatically Discovered Attack Paths" section |

Prompts are customized in [customizing_prompts.md](customizing_prompts.md); provider setup and
the hybrid engines are described in [features.md § AI-Enhanced Threat Analysis](features.md#ai-enhanced-threat-analysis).
The Red/Blue debate is evaluated in [evaluation.md](evaluation.md).
