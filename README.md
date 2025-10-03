# STRIDE Threat Analysis Framework with MITRE ATT&CK Integration

## Overview

This project is a Python-based, end-to-end STRIDE threat modeling and analysis framework with MITRE ATT&CK mapping. It enables you to:

- **Model your system architecture** in Markdown (`threatModel_Template/threat_model.md`), including boundaries, actors, servers, data, and dataflows.
- **Automatically identify STRIDE threats** for each component and dataflow.
- **Map threats to MITRE ATT&CK techniques** for actionable, real-world context.
- **Calculate severity** using customizable base scores, target multipliers, and protocol adjustments.
- **Generate detailed reports** (HTML, JSON) and **visual diagrams** (DOT, SVG, HTML) with threat highlights.
- **Generate MITRE ATT&CK Navigator layers** for visualizing identified techniques.
- **Generate optimized Attack Flow diagrams** for key objectives (Tampering, Spoofing, Information Disclosure, Repudiation).
- **Extend and customize** all mappings, calculations, and reporting logic.

> **Based on [PyTM](https://github.com/OWASP/pytm):** This framework leverages PyTM's modeling primitives and extends them with advanced reporting, MITRE mapping, and diagram generation.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/cybersec-mapping/graphs/commit-activity)

---

## Features

- **Markdown-based Threat Modeling**: Use a simple DSL to describe your architecture and flows.
- **Automated STRIDE Analysis**: Detects threats for each element and flow.
- **MITRE ATT&CK Mapping**: Each threat is mapped to relevant MITRE tactics and techniques.
- **Severity Calculation**: Customizable scoring (base, target, protocol).
- **Comprehensive Reporting**:
  - HTML report with integrated threat statistics, detailed threat information, STRIDE/MITRE mapping, and D3FEND mitigations.
  - JSON export for integration or further analysis.
- **Visual Diagrams**:
  - DOT, SVG, and HTML diagrams with threat highlights.
- **Navigable Project Reports**:
  - Generate a unified, navigable HTML report for complex projects with multiple nested threat models.
  - Diagrams are interactive, with hover effects (zoom, shadow) on clickable elements.
  - Fully self-contained and works offline, with all necessary assets (like `svg-pan-zoom.js`) included locally.
- **Real-time Markdown Editing**: Edit your threat model in Markdown with live diagram preview.
- **Extensible**: All mappings and calculations are modular and easy to override.
- **PyTM Compatibility**: Supports PyTM's model structure and can be extended with PyTM's features.

---

## Quick Start / Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ellipse2v/SecOpsTM.git
        cd SecOpsTM    ```

2.  **Install Python dependencies:**
    ```bash
    pip install -e .
    ```
    This command installs all project dependencies and sets up the project in "editable" mode, which is recommended for development.
    For a standard installation (e.g., for deployment), you can use:
    ```bash
    pip install .
    ```
    **Note on Installation Modes:**
    - `pip install -e .`: Installs the project in "editable" mode. This is recommended for development as any changes you make to the source code in your project directory are immediately reflected without needing to reinstall.
    - `pip install .`: Performs a standard installation, copying the project files into your Python environment. Use this for deployment or when using the package as a dependency.

3.  **Install Graphviz (for diagram generation):**
    -   Windows: [https://graphviz.org/download/](https://graphviz.org/download/)
    -   macOS: `brew install graphviz`
    -   Linux: `sudo apt-get install graphviz`

After installation, restart your terminal or IDE.

---

## Usage

This framework supports two modes of operation: Command Line Interface (CLI) for automated analysis and a Web-based Graphical User Interface (GUI) for interactive editing and visualization.

### Threat Model as Code Philosophy

This framework is designed to be used in a "Threat Model as Code" workflow. This means that the threat model is defined in a simple, version-controllable format (Markdown), and the analysis is performed by running a script. This approach has several advantages:

-   **Version Control**: Threat models can be stored in a Git repository, allowing you to track changes over time.
-   **Automation**: The threat modeling process can be integrated into your CI/CD pipeline, allowing you to automatically update your threat model whenever your architecture changes.
-   **Collaboration**: Developers can collaborate on the threat model using the same tools they use for code.

### 1. Command Line Interface (CLI) Mode

Use the CLI mode for automated threat analysis, report generation, and diagram creation. This is ideal for integration into CI/CD pipelines or batch processing.

1.  **Edit `threatModel_Template/threat_model.md`** to describe your architecture.
2.  **Run the analysis:**
    ```bash
    python -m threat_analysis --model-file threatModel_Template/threat_model.md --navigator
    ```
    (You can omit `--model-file threatModel_Template/threat_model.md` if your model file is named `threatModel_Template/threat_model.md` and is in the root directory.)
3.  **Generate Attack Flow diagrams:** Add the `--attack-flow` flag to any analysis command to generate optimized Attack Flow `.afb` files for key objectives.
    ```bash
    python -m threat_analysis --model-file path/to/your_model.md --attack-flow
    ```
    This will generate one `.afb` file for each of the main objectives (Tampering, Spoofing, Information Disclosure, Repudiation) found in your model, selecting the highest-scoring path for each.
4.  **View the results** in the generated `output/` folder:
    -   HTML report
    -   JSON export
    -   DOT/SVG/HTML diagrams
    -   MITRE ATT&CK Navigator layer (JSON)
    -   Optimized Attack Flow `.afb` files

### 2. Project Mode: Hierarchical Threat Models

The framework excels at handling complex projects with multiple, nested threat models. By structuring your models in directories (e.g., `projects/my_app/main.md`, `projects/my_app/backend/model.md`), you can generate a unified, navigable report.

1.  **Organize your project** in the `threatModel_Template/projects/` directory (see examples).
2.  **Run the analysis on the project folder:**
    ```bash
    python -m threat_analysis --project threatModel_Template/projects/example_2
    ```
3.  **Explore the output:** A fully interactive, cross-linked HTML report will be generated in the `output/` directory. Diagrams for sub-models are placed in corresponding sub-directories, with all links and asset paths adjusted automatically.

### 3. Infrastructure as Code (IaC) Integration (Ansible Example)

This framework can automatically generate a complete threat model directly from IaC configurations. It automatically includes a set of default protocol styles from `threatModel_Template/base_protocol_styles.md` to ensure consistent visualization.

Here's how to use the Ansible plugin with a sample playbook:

1.  **Ensure you have the test playbook:** The sample Ansible playbook is located at `tests/ansible_playbooks/simple_web_server/simple_web_server.yml`.
2.  **Run the analysis with the Ansible plugin:**
    ```bash
    python -m threat_analysis --ansible-path tests/ansible_playbooks/simple_web_server/simple_web_server.yml
    ```
    This command will generate a complete threat model based on the Ansible playbook. The generated Markdown model will be saved in the `output/` directory with a filename derived from your Ansible playbook (e.g., `simple_web_server.md`).

    If you wish to specify a different output file for the generated model, you can use the `--model-file` option:
    ```bash
    python -m threat_analysis --ansible-path tests/ansible_playbooks/simple_web_server/simple_web_server.yml --model-file my_generated_model.md
    ```
3.  **View the results** in the generated `output/` folder, which will now include elements from your Ansible configuration.

### 4. CVE-Based Threat Generation (Optional)

This framework can generate threats based on a list of Common Vulnerabilities and Exposures (CVEs) that you provide for specific components in your threat model.

#### Prerequisites

To use this feature, you must first clone the `CVE2CAPEC` repository from GitHub next to the `SecOpsTM` project directory.

```bash
# In the same directory where you cloned SecOpsTM
git clone https://github.com/Galeax/CVE2CAPEC.git
```

This will create a directory structure like this:
```
/your/development/folder/
├── SecOpsTM/
└── CVE2CAPEC/
```

The tool will then use the `CVE2CAPEC` database to map your specified CVEs to CAPEC attack patterns, which are then used to identify relevant MITRE ATT&CK techniques.

#### Usage

1.  **Create `cve_definitions.yml`**: In the root of the `SecOpsTM` project, create a file named `cve_definitions.yml`.

2.  **Define CVEs for your equipment**: In this file, list the equipment (servers or actors from your threat model) and the CVEs associated with them.

    **Example `cve_definitions.yml`:**
    ```yaml
    # The equipment name must match the name of a server or actor in your threat_model.md file.

    WebServer:
      - CVE-2021-44228 # Log4Shell
      - CVE-2023-1234

    DatabaseServer:
      - CVE-2022-5678
    ```

3.  **Run the analysis**: Run the analysis as usual. The tool will automatically detect the `cve_definitions.yml` file, generate threats based on the CVEs, and include them in the report.

    ```bash
    python -m threat_analysis --model-file path/to/your_model.md
    ```
The new CVE-based threats will appear in the generated report, linked to the corresponding equipment.

### 2. Web-based Graphical User Interface (GUI) Mode (Optional)

Launch the interactive web editor to visualize your threat model in real-time, edit Markdown content, and export various formats directly from your browser.

1.  **Launch the GUI:**
    ```bash
    python -m threat_analysis --gui
    ```
    The console will display the address (e.g., `http://127.0.0.1:5001`) where you can access the GUI in your web browser.

> **Note:** When using `--gui`, the `--model-file` option can be used to load an initial threat model as a template into the editor. If not provided, the GUI will start with an an empty editor.

---

## Threat Model DSL & Examples (`threatModel_Template/threat_model.md`)

This framework leverages PyTM's modeling primitives. For a comprehensive reference of all available attributes and their usage, please refer to the [PyTM Documentation](https://owasp.github.io/PyTM/Threat-Model-as-Code/). Note that this framework may extend PyTM with additional attributes or behaviors.

```markdown
# Threat Model: Advanced DMZ Architecture

## Description
A network with a DMZ, external/internal firewalls, and a command zone. The goal is to identify STRIDE threats and map them to MITRE ATT&CK.

## Boundaries
- **Internet**: color=lightcoral
- **DMZ**: color=khaki
- **Intranet**: color=lightgreen
- **Command Zone**: color=lightsteelblue

## Actors
- **External Client 1**: boundary=Internet
- **Operator**: boundary=Command Zone

## Servers
- **External Firewall**: boundary=DMZ
- **Internal Firewall**: boundary=Intranet
- **Central Server**: boundary=Intranet

## Data
- **Web Traffic**: classification=public, lifetime=transient

## Dataflows
- **External Client to External Firewall**: from="External Client 1", to="External Firewall", protocol="HTTPS", data="Web Traffic", is_encrypted=True

## Severity Multipliers
- **Central Server**: 1.5
- **External Firewall**: 2.0

## Custom Mitre Mapping
- **Protocol Tampering**: tactics=["Impact", "Defense Evasion"], techniques=[{"id": "T1565", "name": "Data Manipulation"}]
```

### Common Attributes

Several elements in the threat model DSL support common attributes to enhance their representation and behavior:

-   **`color`**: Specifies the color of the element in the generated diagrams.
    -   **Applies to**: Boundaries, Actors, Dataflows, Protocol Styles.
    -   **Values**: Can be a standard HTML color name (e.g., `red`, `blue`, `lightgray`), or a hexadecimal color code (e.g., `#FF0000`).

-   **`line_style`**: Defines the style of lines for dataflows or protocols in diagrams.
    -   **Applies to**: Protocol Styles.
    -   **Values**: `solid`, `dashed`, `dotted`.

-   **`is_trusted`**: Indicates whether a Boundary is considered trusted. This can influence threat analysis.
    -   **Applies to**: Boundaries.
    -   **Values**: `True` or `False`.

-   **`is_encrypted`**: Specifies whether a Dataflow is encrypted. This is crucial for information disclosure threat analysis.
    -   **Applies to**: Dataflows.
    -   **Values**: `True` or `False`.

### Protocol Styles and Legends

To ensure that protocols are correctly styled in diagrams and appear in the legend, you must define them in the `## Protocol Styles` section of your threat model. The system **intentionally does not** assign default colors to new protocols. This gives you full control over the final visualization.

**How it works:**

1.  **Use a protocol** in a `Dataflow`, e.g., `protocol="NEW_PROTO"`.
2.  **Define its style** under `## Protocol Styles` to make it appear in the legend:
    ```markdown
    ## Protocol Styles
    - **HTTPS**: color=darkgreen, line_style=solid
    - **HTTP**: color=red, line_style=solid
    - **NEW_PROTO**: color=cyan, line_style=dotted
    ```

If you skip step 2, the protocol will be drawn in the diagram with a default style, but it will **not** be included in the legend.

### Bidirectional Dataflow Visualization

This makes bidirectional communications visually clear and reduces clutter in your architecture diagrams.

**Example:**

If your model contains:
```markdown
## Dataflows
- A to B: from="A", to="B", protocol="HTTPS"
- B to A: from="B", to="A", protocol="HTTPS"
```

The diagram will show:
```
A <--> B
```
(with a single arrow using `dir="both"` in DOT/Graphviz)

This feature is enabled by default and works for all protocols.

---

## Example Output

After running the analysis, you will find a timestamped folder in `output/` (e.g., `output/example`) containing:

- `stride_mitre_report.html`:  
  ![HTML Report Screenshot](output/example/stride_mitre_report__example.png.jpg)
- `mitre_analysis.json`:  
  ```json
  {
    "analysis_date": "2025-06-29T15:31:56.517773",
    "threats_detected": 183,
    "threat_types": [
      "Threat",
      "Tampering",
      "Information Disclosure",
      "Elevation of Privilege",
      "Spoofing",
      "Denial of Service",
      "Repudiation"
    ],
    "mitre_mapping": {
      "Spoofing": {
        "tactics": [
          "Initial Access",
          "Defense Evasion",
          "Credential Access"
        ],
        "techniques": [
          {
            "id": "T1566",
            "name": "Phishing",
            "description": "Identity spoofing via phishing"
          }
        ]
      },
      "Tampering": {
        "tactics": [
          "Defense Evasion",
          "Impact",
          "Initial Access",
          "Execution"
        ],
        "techniques": [
          {
            "id": "T1565",
            "name": "Data Manipulation",
            "description": "Unauthorized data modification"
          }
        ]
      }
    },
    "detailed_threats": [
      {
        "type": "Threat",
        "description": "Vulnerability in the management interface of External Firewall",
        "target": "External Firewall",
        "severity": {"score": 8.5, "level": "HIGH"},
        "mitre_techniques": [{"id": "T1068", "name": "Exploitation for Privilege Escalation"}],
        "stride_category": "Elevation of Privilege"
      },
      {
        "type": "Threat",
        "description": "Lateral movement from Central Server to other systems in the network",
        "target": "Central Server",
        "severity": {"score": 8.5, "level": "HIGH"},
        "mitre_techniques": [{"id": "T1021", "name": "Remote Services"}],
        "stride_category": "Elevation of Privilege"
      },
      {
        "type": "Threat",
        "description": "Insecure security configuration or hardening on App Server 1",
        "target": "App Server 1",
        "severity": {"score": 6.0, "level": "MEDIUM"},
        "mitre_techniques": [{"id": "T1562", "name": "Impair Defenses"}],
        "stride_category": "Information Disclosure"
      },
      {
        "type": "Threat",
        "description": "Data exfiltration or leakage from Application Database",
        "target": "Application Database",
        "severity": {"score": 8.5, "level": "HIGH"},
        "mitre_techniques": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}],
        "stride_category": "Information Disclosure"
      }
    ]
  }
  ```
- `tm_diagram__example.dot`:  
  (Graphviz DOT format for architecture)
- `tm_diagram__example.svg`:  
  ![SVG Diagram Example](./output/example/tm_diagram__example.svg)

- **Project Structure Example**:
  ![Project Example](output/example/project_example.gif)

- **MITRE ATT&CK Navigator Integration**:
  ![Navigator Example](output/example/navigator_example.jpg)

> **Note:** All screenshots and example files are located in the `output/example/` directory for easy preview and documentation.

### Using Pre-defined Templates

To accelerate the creation of new threat models, the framework includes a set of pre-defined templates for common architectures. You can load these templates directly from the web interface.

![Loading a template](output/example/gui_example.gif)

---

## Extensibility & Customization

### Model Capabilities

-   **STRIDE Threat Detection**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
-   **MITRE ATT&CK Mapping**: Each STRIDE threat is mapped to one or more MITRE ATT&CK techniques and tactics.
-   **Severity Calculation**:
    -   Base scores per STRIDE category.
    -   Target multipliers per STRIDE category.
    -   Protocol-based adjustments (e.g., HTTP vs HTTPS).
-   **Diagram Generation**:
    -   DOT, SVG, and HTML diagrams with threat highlights and legends.
-   **Report Generation**:
    -   HTML report with summary, statistics, threat details, and recommendations.
    -   JSON export for integration or further analysis.
-   **Extensibility**:
    -   Add new STRIDE categories or custom threat patterns.
    -   Extend MITRE mappings.
    -   Customize severity logic.
    -   Integrate with PyTM models and features.

### PyTM-Based Extensions & Evolutions

You can leverage and extend all PyTM features, including:

-   **Custom Threat Patterns**: Define new threat types and detection logic.
-   **Advanced Dataflow Modeling**: Use PyTM's dataflow and element types.
-   **Integration with PyTM Plugins**: Use or develop plugins for reporting, risk scoring, or compliance.
-   **Automated Testing**: Integrate with PyTM's test harness for CI/CD.
-   **Custom Reports**: Extend the reporting module to output in any format (PDF, Excel, etc.).
-   **Visualization**: Use PyTM's or your own visualization tools for advanced diagrams.

---

## Data Sources

### STRIDE to CAPEC Mapping

The `threat_analysis/external_data/stride_to_capec.json` file, which provides mappings from STRIDE threats to CAPEC patterns, is generated by the `tooling/download_stride_mappings.py` script. This script parses the content from the markdown files available at [Osterling's CAPEC-STRIDE Mapping page](https://ostering.com/capec-stride-mapping/index.html).

---

## Limitations


-   The default architecture is DMZ-oriented; adapt the model for your environment as needed.

---

## Roadmap
[roadmap link](https://github.com/ellipse2v/SecOpsTM/wiki/roadmap)
---

## License

Apache License 2.0. See [LICENSE](LICENSE).

---

## Author

ellipse2v