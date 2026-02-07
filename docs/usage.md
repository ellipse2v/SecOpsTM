# Usage

This framework supports two modes of operation: Command Line Interface (CLI) for automated analysis and a Web-based Graphical User Interface (GUI) for interactive editing and visualization.

## Threat Model as Code Philosophy

This framework is designed to be used in a "Threat Model as Code" workflow. This means that the threat model is defined in a simple, version-controllable format (Markdown), and the analysis is performed by running a script. This approach has several advantages:

-   **Version Control**: Threat models can be stored in a Git repository, allowing you to track changes over time.
-   **Automation**: The threat modeling process can be integrated into your CI/CD pipeline, allowing you to automatically update your threat model whenever your architecture changes.
-   **Collaboration**: Developers can collaborate on the threat model using the same tools they use for code.

## 1. Command Line Interface (CLI) Mode

Use the CLI mode for automated threat analysis, report generation, and diagram creation. This is ideal for integration into CI/CD pipelines or batch processing.

1.  **Learn how to define your threat model in Markdown** by reading the [Defining Your Threat Model](defining_threat_models.md) guide.
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

### Specifying Custom File Paths

You can use the following command-line arguments to specify custom paths for the `implemented_mitigations.txt` and `cve_definitions.yml` files:

-   `--implemented-mitigations-file`: Path to the implemented mitigations file. If not provided, the tool will look for a file named 'implemented_mitigations.txt' in the same directory as the model or project.
-   `--cve-definitions-file`: Path to the CVE definitions file. If not provided, the tool will look for a file named 'cve_definitions.yml' in the same directory as the model or project.

Example:
```bash
python -m threat_analysis --model-file path/to/your_model.md --implemented-mitigations-file path/to/your/mitigations.txt --cve-definitions-file path/to/your/cves.yml
```

Here's a more comprehensive example using test files:
```bash
python -m threat_analysis --model-file threatModel_Template/threat_model.md \
      --navigator \
      --attack-flow \
      --implemented-mitigations-file tests/implemented_mitigations.txt \
      --cve-definitions-file tests/cve_definitions.yml
```

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

1.  **Create `cve_definitions.yml`**: By default, the tool looks for `cve_definitions.yml` in the directory of the model or project. You can override this path using the `--cve-definitions-file` command-line argument.

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

## 2. Web-based UserInterface (Server Mode)

For a more interactive experience, the framework provides a web-based UI that runs on a local server. This unified interface gives you access to two distinct modes from a central menu.

1.  **Launch the server:**
    ```bash
    python -m threat_analysis --server
    ```
    The console will display the address (e.g., `http://127.0.0.1:5000`) to open in your web browser.

2.  **Choose a Mode from the Menu:**
    -   **Simple Mode**: An interface to load a Markdown file and see the generated diagram and analysis in real-time. It now supports multi-file project editing through a tabbed interface. Ideal for quick visualization and reporting on existing models.
    -   **Graphical Editor**: A full-featured, interactive canvas to build, modify, and analyze threat models from scratch directly in the browser. It includes a toolbar for adding elements, a properties panel for editing, and the ability to generate all artifacts without touching Markdown directly.

### Working with Projects and Sub-models (Simple Mode)

The Simple Mode has been enhanced with a tabbed interface to support editing a main threat model and its sub-models simultaneously, providing a larger editing area for each file.

1.  **Define Your Sub-models**: In your main threat model, define a `server` element and use the `submodel` attribute to link to an external markdown file.
    ```markdown
    ## Servers
    - **Backend Services**: submodel=backend/model.md, boundary="Internal"
    ```

2.  **Add a Sub-model Tab**: Click the **"➕ Add Sub-model"** button in the header. You will be prompted to enter the path for the sub-model. This path **must exactly match** the path you specified in the `submodel` attribute (e.g., `backend/model.md`).

3.  **Edit in Tabs**: A new tab will appear for your sub-model, providing a full-sized editor. You can switch between your `main.md` and any sub-model files by clicking on their respective tabs.

4.  **Generate the Project**: Once you have all your tabs open and edited, click **"Generate All"**. The system will collect the content from all open tabs, reconstruct the project structure in the background, and generate a unified, navigable set of reports and diagrams.

> **Note:** When using `--server`, the `--model-file` option can be used to load an initial threat model for the **Simple Mode**. The Graphical Editor starts with a new, empty model.
