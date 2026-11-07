<p align="center">
  <img src="https://raw.githubusercontent.com/ellipse2v/SecOpsTM/main/docs/images/logo.svg" alt="SecOpsTM logo" width="110">
</p>

<h1 align="center">SecOpsTM</h1>

<p align="center">
  <b>Threat modeling as code.</b> One Markdown file in, a STRIDE + MITRE ATT&amp;CK threat report out.<br>
  Interactive diagrams, CAPEC / D3FEND / CVE mapping, attack paths, SARIF and STIX, ready for CI.
</p>

<p align="center">
  <a href="https://ellipse2v.github.io/SecOpsTM/"><b>Live demo</b></a> ·
  <a href="https://github.com/ellipse2v/SecOpsTM#quick-start--installation">Quick start</a> ·
  <a href="https://github.com/ellipse2v/SecOpsTM/blob/main/docs/index.md">Docs</a> ·
  <a href="https://owasp.org/www-project-secopstm/">OWASP project page</a>
</p>

<p align="center">
  <a href="https://owasp.org/www-project-secopstm/"><img src="https://img.shields.io/badge/OWASP-project-000000?logo=owasp&logoColor=white" alt="OWASP project"></a>
  <a href="https://pypi.org/project/SecOpsTM/"><img src="https://img.shields.io/pypi/v/SecOpsTM?label=PyPI&color=3775A9" alt="PyPI version"></a>
  <a href="https://hub.docker.com/r/ellipse2v/secopstm"><img src="https://img.shields.io/docker/pulls/ellipse2v/secopstm?label=Docker%20pulls&color=2496ED" alt="Docker pulls"></a>
  <a href="https://github.com/ellipse2v/SecOpsTM/actions/workflows/coverage_check.yml"><img src="https://github.com/ellipse2v/SecOpsTM/actions/workflows/coverage_check.yml/badge.svg" alt="Tests"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.11+-blue.svg" alt="Python 3.11+"></a>
  <a href="https://github.com/ellipse2v/SecOpsTM/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
</p>

<p align="center">
  <a href="https://ellipse2v.github.io/SecOpsTM/">
    <img src="https://raw.githubusercontent.com/ellipse2v/SecOpsTM/main/docs/images/threat-layer-demo.gif" alt="Interactive threat diagram: threat badges per element, threat panel, STRIDE filter, heat map and zoom" width="900">
  </a>
  <br>
  <sub>The generated HTML diagram: click a badge to list its threats, isolate a STRIDE category, show the heat map. <a href="https://ellipse2v.github.io/SecOpsTM/">Try it live.</a></sub>
</p>

```bash
pip install SecOpsTM
secopstm demo                          # analyses a bundled example and opens its diagram
secopstm --model-file threat_model.md  # then your own model
```

<table>
  <tr>
    <td width="50%"><img src="https://raw.githubusercontent.com/ellipse2v/SecOpsTM/main/docs/images/threat-panel.png" alt="Threat panel opened on a dataflow"></td>
    <td width="50%"><img src="https://raw.githubusercontent.com/ellipse2v/SecOpsTM/main/docs/images/stride-filter.png" alt="Threat layer filtered on Spoofing in a large enterprise network"></td>
  </tr>
  <tr>
    <td align="center"><sub>Every component and dataflow carries its threats, scored and mapped to ATT&amp;CK.</sub></td>
    <td align="center"><sub>Scales to real networks: isolate one STRIDE category across 40+ elements.</sub></td>
  </tr>
</table>

## Overview
SecOpsTM is an [OWASP project](https://owasp.org/www-project-secopstm/): a Python-based, end-to-end STRIDE threat modeling and analysis framework with MITRE ATT&CK mapping. It enables you to:

-   **Model your system architecture** in Markdown (`threatModel_Template/threat_model.md`), including boundaries, actors, servers, data, and dataflows.
-   **Automatically identify STRIDE threats** for each component and dataflow.
-   **Map threats to MITRE ATT&CK techniques** for actionable, real-world context.
-   **Calculate severity** using customizable base scores, target multipliers, protocol adjustments, and VOC risk signals (CVE, CWE, network exposure, D3FEND mitigations).
-   **Generate detailed reports** (HTML, JSON) and **visual diagrams** (DOT, SVG, HTML) with threat highlights.
-   **⛓️ Attack Chain Analysis**: Automatically identifies multi-step attack paths that chain threats across dataflows; shown in a dedicated section of the HTML report.
-   **Trust Boundary Visualization**: Trusted zones rendered green solid, untrusted zones red dashed — baked into the DOT/SVG output, with an interactive severity heat map overlay and a threat layer (per-element threat badges, filterable by severity from the legend) in HTML diagrams.
-   **Generate MITRE ATT&CK Navigator layers** for visualizing identified techniques.
-   **Generate optimized Attack Flow diagrams** for key objectives (Tampering, Spoofing, Information Disclosure, Repudiation).
-   **Red/Blue adversarial debate** over the top GDAF attack paths (opt-in). A reproducible harness measures its effect on prioritisation — see [`docs/evaluation.md`](docs/evaluation.md) (first result: the debate moves the ranking meaningfully but not reproducibly; read its reasoning, not its score).
-   **Extend and customize** all mappings, calculations, and reporting logic.
-   **Run as a web-based editor** for live, interactive threat modeling.
-   **AI-Enhanced Threat Analysis (Hybrid Mode)**: Threats from three independent engines — pytm rule engine, component-level LLM, and a cross-model RAG pipeline (ChromaDB + HuggingFace) — are automatically deduplicated and unified before reporting. Boundary objects are also analysed as AI targets. Supports Ollama (offline), Gemini, OpenAI, Mistral, Groq, xAI, and any LiteLLM-compatible provider. Configured in `config/ai_config.yaml`.
-   **Pure CLI & CI integration**: A `secopstm` command ships after `pip install -e .`. Use `--output-format json --stdout` to pipe structured output to dashboards or SIEM without starting a server.
-   **Versioned JSON output**: Every JSON export is stamped `schema_version: "1.0"` and validated against `threat_analysis/schemas/v1/threat_model_report.schema.json`.

> **Based on [PyTM](https://github.com/OWASP/pytm) >= 1.4.0:** This framework leverages PyTM's modeling primitives and extends them with advanced reporting, MITRE mapping, and diagram generation.

---

## 🤖 AI Roles

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

---

## ✨ New Interactive Features

The web interface now supports the following.

### Interactive Diagrams
The generated diagrams (both in the live editor and in exported HTML reports) are not static images. They are fully interactive SVGs that allow you to:
-   **Click to Highlight**: Click on any element (node or connection) to highlight it and its direct relationships. The rest of the diagram fades out, allowing you to focus on the selected components.
-   **Toggle Selection**: Click the same element again or the diagram background to clear the selection.
-   **Sub-model Navigation**: In generated project reports, elements that represent sub-models have a distinct hover effect and are clickable, allowing for easy navigation between different parts of a complex architecture.

### Interactive Legend
-   **Filter Connections**: The diagram legend is now interactive. Click on a protocol (e.g., HTTPS, TCP) to instantly show or hide all dataflows using that protocol, making it easy to analyze specific parts of your data flow.

### Project Generation
-   The **"Generate All"** feature handles projects with nested sub-models.
-   If you have a project with multiple system model files, it detects when a referenced sub-model is not currently open in the editor and prompts you to select your project's root directory, so all files are found before generating reports and diagrams.

### Simple Server Mode
-   The integrated web server can be started with a path to a project directory (`--project path/to/your/project`). It automatically finds all `*.md` system model files within that project and opens them in tabs, ready for editing.

---

## 📚 Full Documentation

For detailed information on features, usage, and advanced customization, please refer to our full documentation in the [docs](docs/index.md) directory.

---

## Quick Start / Installation

### Option A — Docker (no Python setup required)

```bash
docker run -p 127.0.0.1:5000:5000 \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest
```

Open <http://localhost:5000>. Reports land in `$(pwd)/output/<timestamp>/`.

> **Security note:** the server has no authentication on any route (it's a
> single-user tool). `-p 127.0.0.1:5000:5000` keeps it reachable only from
> this machine. Only bind it to all interfaces (`-p 5000:5000`) on a network
> you fully trust.

#### With AI enrichment (LLM + RAG)

**Default provider: NVIDIA NIM** (Nemotron 3.5 Lightning) — free API key at https://build.nvidia.com/models

```bash
# Step 1 — Download RAG vector store (one-time, ~200 MB)
docker run --rm -v secopstm-rag:/app/rag ellipse2v/secopstm:latest --init-rag

# Step 2 — Run
docker run -p 127.0.0.1:5000:5000 \
  -e NVIDIA_NIM_API_KEY=your_key \
  -v secopstm-rag:/app/rag \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest
```

Other supported providers: `GEMINI_API_KEY`, `OPENAI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `XAI_API_KEY`. Ollama works fully offline (no key needed).

---

### Option B — PyPI

```bash
pip install SecOpsTM
secopstm demo     # check the install: analyses a bundled example and opens its diagram
```

Install Graphviz for diagram generation:
- Windows: <https://graphviz.org/download/>
- macOS: `brew install graphviz`
- Linux: `sudo apt-get install graphviz`

---

### Option C — From source

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ellipse2v/SecOpsTM.git
    cd SecOpsTM
    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -e .
    ```
    After this step the `secopstm` command is available in your environment.

3.  **Install Graphviz** (see Option B above).

After installation, restart your terminal or IDE.

### Basic CLI usage

```bash
# Try it: analyse a bundled example (rule engine only, no API key) and open its diagram
secopstm demo                # or: secopstm demo on-prem   (40+ elements)

# Full analysis — HTML + JSON + SVG in output/
secopstm --model-file threatModel_Template/threat_model.md

# Rule engine only, even if config/ai_config.yaml enables an LLM provider
secopstm --model-file model.md --no-ai

# JSON only, printed to stdout — ideal for CI pipelines
secopstm --model-file model.md --stdout

# JSON to a specific file
secopstm --model-file model.md --output-format json --output-file report.json

# Launch the web editor
secopstm --server
```

### In CI: the GitHub Action

Threat-model every pull request: the action analyses your model, posts a summary comment on the PR, uploads the reports as an artifact and fails the job when threats at or above `gate` are found.

```yaml
# .github/workflows/threat-model.yml
name: Threat model
on: pull_request
permissions:
  contents: read
  pull-requests: write      # PR comment
jobs:
  secopstm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ellipse2v/SecOpsTM@main
        with:
          model-file: threat_model.md
          gate: HIGH                       # CRITICAL | HIGH | MEDIUM | LOW | none
          # baseline: threat_baseline.json # only NEW threats fail the gate
          # sarif: 'true'                  # Security > Code scanning (needs security-events: write)
```

Other inputs: `terraform-path` / `ansible-path` (analyse IaC instead of a model), `navigator`, `attack-flow`, `accepted-risks`, `ai-config-file`. Outputs: `output-dir`, `report-json`, `report-html`, `total-threats`, `critical-threats`... See [`action.yml`](action.yml) for the full list. Without `ai-config-file` the action uses the rule engine only: no API key, nothing leaves the runner.

---

## Server Configuration (Optional)

When running `secopstm --server`, you can configure the following optional environment variables:

| Environment variable | Notes |
|---|---|
| `SECOPSTM_REQUIRE_AUTH` | Optional. When set to `true`, requires bearer token authentication (via `SECOPSTM_API_TOKEN`) for all routes. Off by default — single-user deployments remain frictionless. |
| `SECOPSTM_API_TOKEN` | Required if `SECOPSTM_REQUIRE_AUTH=true`. Bearer token for authentication (env var or `?token=` query param). Example: `SECOPSTM_REQUIRE_AUTH=true SECOPSTM_API_TOKEN=my_secret secopstm --server` |
| `SECOPSTM_WORKSPACES_DIR` | Optional. Directory containing one subdirectory per project. When set, a workspace picker appears in the `/simple` editor. See docs/usage.md § Multi-User Workspaces. |

---

## Roadmap
[roadmap link](docs/Roadmap.md)
---

## License

Apache License 2.0. See [LICENSE](LICENSE).
---

## Author

ellipse2v

