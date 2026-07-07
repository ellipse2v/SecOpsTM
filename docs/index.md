# SecOpsTM Documentation

**SecOpsTM** is a STRIDE threat modeling framework with MITRE ATT&CK mapping, AI-enhanced
threat generation, and interactive diagram export.

It follows a **Threat Modeling as Code (TMasC)** approach: you describe your system in a
human-readable, version-controlled Markdown file (the system model), and SecOpsTM generates
the threat model from it — a workflow that fits naturally into CI/CD pipelines and
cross-functional review.

## Why Automated Threat Modeling?

- **Proactive risk identification** — shift left by catching design flaws early in the SDLC
- **Scalable security** — automate threat analysis across distributed systems and microservices
- **Actionable intelligence** — translate abstract threats into MITRE ATT&CK-mapped techniques
- **DevSecOps enablement** — version-controlled, machine-readable models shared across Dev, Sec, and Ops
- **Continuous assurance** — integrate threat analysis directly into CI/CD pipelines

## Core Capabilities

- **STRIDE threat identification** — automatic coverage across all six STRIDE categories for every component and dataflow
- **Rich enrichment** — each threat mapped to MITRE ATT&CK tactics/techniques, CAPEC attack patterns, and D3FEND countermeasures
- **AI-enhanced generation** — LLM + RAG pipeline surfaces threats beyond rule-based analysis
- **Context-aware severity** — scoring adjusts for encryption, authentication, network exposure, CVE signals, and D3FEND mitigations
- **Hierarchical modeling** — decompose large systems into linked sub-models with drill-down diagrams
- **Exports** — HTML reports, STIX 2.1, ATT&CK Navigator layers, SVG diagrams, ZIP bundles
- **IaC integration** — generate system models directly from Ansible and Terraform configurations

## Documentation

- [Getting Started](getting_started.md) — Installation, first run, web editor
- [**Claude Code Skill**](claude-code-skill.md) — AI-assisted system model generation: describe your system, Claude writes the DSL
- [**Workflow: Conception to Run**](workflow.md) — End-to-end guide: conception, modeling, enrichment, CI/CD
- [Usage](usage.md) — CLI flags, project mode, export formats
- [Features](features.md) — Feature list: AI engines, diagrams, exports
- [Defining Your System Model](defining_threat_models.md) — Markdown DSL reference
- [Enriching AI Threats](enriching_ai_threats.md) — DSL attributes, BOM, and context files that improve AI-generated threats
- [Data Collection Guide](data_collection_guide.md) — What information to gather before threat modeling
- [Examples](examples.md) — Ready-to-use model templates
- [Extensibility](extensibility.md) — Custom threats, IaC plugins, mappings
- [Customizing LLM Prompts](customizing_prompts.md) — `config/prompts.yaml` reference
- [Technical Documentation](technical_documentation/index.md) — Architecture deep-dive
- [Roadmap](Roadmap.md)

> **Note:** The graphical editor feature is currently under active development and may not be fully stable.
