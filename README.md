# STRIDE Threat Analysis Framework with MITRE ATT&CK Integration

## Overview

This project is a Python-based, end-to-end STRIDE threat modeling and analysis framework with MITRE ATT&CK mapping. It enables you to:

-   **Model your system architecture** in Markdown (`threatModel_Template/threat_model.md`), including boundaries, actors, servers, data, and dataflows.
-   **Automatically identify STRIDE threats** for each component and dataflow.
-   **Map threats to MITRE ATT&CK techniques** for actionable, real-world context.
-   **Calculate severity** using customizable base scores, target multipliers, protocol adjustments, and VOC risk signals (CVE, CWE, network exposure, D3FEND mitigations).
-   **Generate detailed reports** (HTML, JSON) and **visual diagrams** (DOT, SVG, HTML) with threat highlights.
-   **⛓️ Attack Chain Analysis**: Automatically identifies multi-step attack paths that chain threats across dataflows; shown in a dedicated section of the HTML report.
-   **Trust Boundary Visualization**: Trusted zones rendered green solid, untrusted zones red dashed — baked into the DOT/SVG output, with an interactive severity heat map overlay in HTML diagrams.
-   **Generate MITRE ATT&CK Navigator layers** for visualizing identified techniques.
-   **Generate optimized Attack Flow diagrams** for key objectives (Tampering, Spoofing, Information Disclosure, Repudiation).
-   **Extend and customize** all mappings, calculations, and reporting logic.
-   **Run as a web-based editor** for live, interactive threat modeling.
-   **AI-Enhanced Threat Analysis (Hybrid Mode)**: Threats from three independent engines — pytm rule engine, component-level LLM, and a cross-model RAG pipeline (ChromaDB + HuggingFace) — are automatically deduplicated and unified before reporting. Boundary objects are also analysed as AI targets. Supports Ollama (offline), Gemini, OpenAI, Mistral, and any LiteLLM-compatible provider. Configured in `config/ai_config.yaml`.
-   **Pure CLI & CI integration**: A `secopstm` command ships after `pip install -e .`. Use `--output-format json --stdout` to pipe structured output to dashboards or SIEM without starting a server.
-   **Versioned JSON output**: Every JSON export is stamped `schema_version: "1.0"` and validated against `threat_analysis/schemas/v1/threat_model_report.schema.json`.

> **Based on [PyTM](https://github.com/OWASP/pytm):** This framework leverages PyTM's modeling primitives and extends them with advanced reporting, MITRE mapping, and diagram generation.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/cybersec-mapping/graphs/commit-activity)

---

## ✨ New Interactive Features

The framework's web interface has been significantly updated to provide a more powerful and seamless threat modeling experience.

### Interactive Diagrams
The generated diagrams (both in the live editor and in exported HTML reports) are not static images. They are fully interactive SVGs that allow you to:
-   **Click to Highlight**: Click on any element (node or connection) to highlight it and its direct relationships. The rest of the diagram fades out, allowing you to focus on the selected components.
-   **Toggle Selection**: Click the same element again or the diagram background to clear the selection.
-   **Sub-model Navigation**: In generated project reports, elements that represent sub-models have a distinct hover effect and are clickable, allowing for easy navigation between different parts of a complex architecture.

### Interactive Legend
-   **Filter Connections**: The diagram legend is now interactive. Click on a protocol (e.g., HTTPS, TCP) to instantly show or hide all dataflows using that protocol, making it easy to analyze specific parts of your data flow.

### Robust Project Generation
-   The **"Generate All"** feature is designed to handle complex projects with nested sub-models.
-   If you have a project with multiple threat model files, it intelligently detects if any referenced sub-models are not currently open in the editor and prompts you to select your project's root directory. This ensures that all necessary files are found and included for a complete and accurate generation of all reports and diagrams.

### Simple Server Mode
-   The integrated web server can be started with a path to a project directory (`--project path/to/your/project`). It will automatically find all `*.md` threat model files within that project and open them in tabs, ready for editing.
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/ellipse2v/cybersec-mapping/graphs/commit-activity)

---

## 📚 Full Documentation

For detailed information on features, usage, and advanced customization, please refer to our full documentation in the [docs](docs/index.md) directory.

---

## Quick Start / Installation

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

3.  **Install Graphviz (for diagram generation):**
    -   Windows: [https://graphviz.org/download/](https://graphviz.org/download/)
    -   macOS: `brew install graphviz`
    -   Linux: `sudo apt-get install graphviz`

After installation, restart your terminal or IDE.

### Basic CLI usage

```bash
# Full analysis — HTML + JSON + SVG in output/
secopstm --model-file threatModel_Template/threat_model.md

# JSON only, printed to stdout — ideal for CI pipelines
secopstm --model-file model.md --stdout

# JSON to a specific file
secopstm --model-file model.md --output-format json --output-file report.json

# Launch the web editor
secopstm --server
```

---

## Roadmap
[roadmap link](docs/Roadmap.md)
---

## License

Apache License 2.0. See [LICENSE](LICENSE).
---

## Author

ellipse2v

