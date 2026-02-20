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

The framework excels at handling complex projects with multiple, nested threat models. While you can run project-based analysis from the CLI, the recommended workflow is to use the **Web-based User Interface (Server Mode)**, which provides a more interactive and intuitive experience.

1.  **Organize your project** in a directory, with a `main.md` at the root and sub-models in sub-directories (e.g., `my_project/main.md`, `my_project/backend/model.md`).
2.  **Launch the server with your project path:**
    ```bash
    python -m threat_analysis --server --project path/to/your_project
    ```
3.  **Use the "Generate All" button** in the web UI. A fully interactive, cross-linked HTML report will be generated in the `output/` directory.

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
    -   To start with an empty model:
        ```bash
        python -m threat_analysis --server
        ```
    -   To load a single file:
        ```bash
        python -m threat_analysis --server --model-file path/to/your_model.md
        ```
    -   **To load an entire project:**
        ```bash
        python -m threat_analysis --server --project path/to/your_project
        ```
    The console will display the address (e.g., `http://127.0.0.1:5000`) to open in your web browser.

2.  **Choose a Mode from the Menu:**
    -   **Simple Mode**: An interface designed for editing and visualizing threat models described in Markdown. It features a tabbed editor, a live interactive diagram, and full reporting capabilities. When a project is loaded, all model files are automatically opened in separate tabs.
    -   **Graphical Editor**: A full-featured, interactive canvas to build, modify, and analyze threat models from scratch directly in the browser. It includes a toolbar for adding elements, a properties panel for editing, and the ability to generate all artifacts without touching Markdown directly.

### Working with Projects and Sub-models (Simple Mode)

The Simple Mode is optimized for working with complex, multi-file projects.

1.  **Launch the Server with Your Project**: For the best experience, start the server with the `--project` flag pointing to your project's root directory. This will automatically open all `main.md` and `model.md` files in tabs.

2.  **Define Your Sub-models**: In your `main.md` (or any other model file), define a `server` element and use the `submodel` attribute to link to another markdown file using a relative path.
    ```markdown
    ## Servers
    - **Backend Services**: submodel=backend/model.md, boundary="Internal"
    ```

3.  **Generate the Full Project**: Click the **"Generate All"** button. The system is designed to be robust:
    -   It gathers the content from all open tabs.
    -   It intelligently detects if any model references a sub-model that is not currently open.
    -   If a missing sub-model is found, it will prompt you to select your project's root directory. It then scans this directory to find the missing files and includes them in the generation process.
    -   This ensures that a complete, unified, and navigable set of reports and diagrams is always generated.

