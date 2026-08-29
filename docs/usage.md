# Usage

This framework supports two modes of operation: Command Line Interface (CLI) for automated analysis and a Web-based Graphical User Interface (GUI) for interactive editing and visualization.

## Threat Modeling as Code Philosophy

This framework is designed to be used in a "Threat Modeling as Code" workflow. This means that the system model is defined in a simple, version-controllable format (Markdown), and the threat analysis is performed by running a script. This approach has several advantages:

-   **Version Control**: System models can be stored in a Git repository, allowing you to track changes over time.
-   **Automation**: The threat modeling process can be integrated into your CI/CD pipeline, allowing you to automatically update your threat model whenever your architecture changes.
-   **Collaboration**: Developers can collaborate on the system model using the same tools they use for code.

## 0. Data layers and installation

SecOpsTM relies on three data layers fetched separately:

| Layer | Content | Size | Command |
|---|---|---|---|
| **Security knowledge base** | MITRE ATT&CK, CAPEC, D3FEND, CIS, NIST, CVE mappings | ~140 MB | `secopstm download-data` |
| **RAG vector store** | Pre-built embeddings for AI threat generation | ~1.8 GB | `secopstm --init-rag` |
| **Fresh CVE data** | Up-to-date CVE→CAPEC database (dev/contributors only) | ~94 MB | clone [Galeax/CVE2CAPEC](https://github.com/Galeax/CVE2CAPEC) |

The **security knowledge base** is required for full STRIDE + MITRE analysis.
The **RAG vector store** is optional and enables AI-powered threat enrichment.
The CVE data bundled in the knowledge base covers 1999–2025 — clone CVE2CAPEC only if you need the absolute latest entries.

### Via Docker

#### Quick start

```bash
# Offline — no API key needed
docker run -p 5000:5000 -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest

# With LLM inference — default provider is NVIDIA NIM (free tier available)
# See https://build.nvidia.com/meta/llama-3_3-70b-instruct for a free API key
docker run -p 5000:5000 \
  -e NVIDIA_NIM_API_KEY=your_key \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest

# Switch provider or model without rebuilding — mount your own ai_config.yaml
docker run -p 5000:5000 \
  -e GEMINI_API_KEY=your_key \
  -v $(pwd)/ai_config.yaml:/app/config/ai_config.yaml:ro \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest

# With LLM + RAG
docker run -p 5000:5000 \
  -e NVIDIA_NIM_API_KEY=your_key \
  -v secopstm-rag:/app/rag \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest
```

Open `http://localhost:5000`. Generated reports land in `$(pwd)/output/<timestamp>/`.

#### One-time RAG vector store download

```bash
docker run --rm \
  -v secopstm-rag:/app/rag \
  ellipse2v/secopstm:latest \
  --init-rag
```

The named volume `secopstm-rag` persists across container restarts and image rebuilds.

#### Docker reference

**API key environment variables**

| Provider | Environment variable | Free tier |
|---|---|---|
| NVIDIA NIM *(default)* | `NVIDIA_NIM_API_KEY` | ✅ [build.nvidia.com](https://build.nvidia.com/meta/llama-3_3-70b-instruct) |
| Google Gemini | `GEMINI_API_KEY` | ✅ |
| OpenAI | `OPENAI_API_KEY` | ❌ |
| Mistral | `MISTRAL_API_KEY` | ✅ |
| Groq | `GROQ_API_KEY` | ✅ [console.groq.com](https://console.groq.com) |
| xAI | `XAI_API_KEY` | ❌ [console.x.ai](https://console.x.ai) |
| Ollama (local) | — no key needed — | ✅ |

**Volumes and mounts**

| What | Mount | Notes |
|---|---|---|
| Output reports | `-v $(pwd)/output:/app/output` | Files land in `output/<timestamp>/` on the host |
| AI config | `-v $(pwd)/ai_config.yaml:/app/config/ai_config.yaml:ro` | Switch provider/model without rebuilding |
| Prompts | `-v $(pwd)/prompts.yaml:/app/threat_analysis/config/prompts.yaml:ro` | Override LLM prompts |
| System model files | `-v $(pwd)/models:/models` | Pass `--model-file /models/model.md` |
| CVE definitions | `-v $(pwd)/cve_definitions.yml:/app/cve_definitions.yml:ro` | Per-asset CVE list |
| RAG vector store | `-v secopstm-rag:/app/rag` | Named volume, required for RAG |

**Changing the port**

Use `-p host_port:5000` — Flask always listens on 5000 inside the container:
```bash
docker run -p 8080:5000 ...   # accessible on http://localhost:8080
```

#### CLI pipeline (no server)

```bash
docker run --rm \
  -v $(pwd)/models:/models \
  -v $(pwd)/output:/app/output \
  ellipse2v/secopstm:latest \
  --model-file /models/threat_model.md --output-format json --stdout
```

### Via pip

```bash
pip install SecOpsTM

# Install Graphviz (required for diagram generation)
#   Windows: https://graphviz.org/download/
#   macOS:   brew install graphviz
#   Linux:   sudo apt-get install graphviz

# Step 1 — Security knowledge base (~140 MB, required for MITRE/CVE mapping)
secopstm download-data

# Step 2 — RAG vector store (~1.8 GB, optional — enables AI threat enrichment)
secopstm --init-rag

# Step 3 — Start
secopstm --server
```

Both `download-data` and `--init-rag` are one-time steps that download from
[GitHub Releases](https://github.com/ellipse2v/SecOpsTM/releases) and work
fully offline afterwards. Re-run with `--force` to update.

### Via source (development)

```bash
git clone https://github.com/ellipse2v/SecOpsTM.git
cd SecOpsTM
pip install -e .                  # external_data/ is already in the repo
pip install -r requirements.txt   # full AI/ML deps for tooling scripts
```

To get the **latest CVE entries** (beyond the 1999–2025 snapshot in the repo):

```bash
# Clone the CVE2CAPEC database next to the SecOpsTM directory
git clone https://github.com/Galeax/CVE2CAPEC.git ../CVE2CAPEC
python tooling/copy_cve_data.py
```

---

## 1. Command Line Interface (CLI) Mode

Use the `secopstm` command for automated threat analysis:

```bash
# Full analysis — HTML + JSON + SVG in output/
secopstm --model-file threatModel_Template/threat_model.md

# JSON only, printed to stdout — ideal for CI pipelines and SIEM ingestion
secopstm --model-file model.md --stdout

# JSON to a specific file
secopstm --model-file model.md --output-format json --output-file report.json

# STIX 2.1 bundle only
secopstm --model-file model.md --output-format stix

# Launch the web editor
secopstm --server
```

You can also still use `python -m threat_analysis` with all the same flags — they are 100% equivalent.

1.  **Learn how to define your system model in Markdown** by reading the [Defining Your System Model](defining_threat_models.md) guide.
2.  **Generate Attack Flow diagrams:** Add the `--attack-flow` flag to generate `.afb` files for key STRIDE objectives (Tampering, Spoofing, Information Disclosure, Repudiation).
    ```bash
    secopstm --model-file path/to/your_model.md --attack-flow
    ```
3.  **View the results** in the generated `output/` folder:
    -   `stride_mitre_report.html` — HTML report with attack chains, severity heat map data, executive summary
    -   `mitre_analysis.json` — versioned JSON export (`schema_version: "1.0"`, threats with stable IDs `T-NNNN`)
    -   `tm_diagram.svg` / `tm_diagram.html` — SVG diagram (trust colors) + interactive HTML with severity heat map toggle
    -   `attack_navigator_layer_*.json` — MITRE ATT&CK Navigator layer
    -   `stix_report_*.json` — STIX 2.1 bundle
    -   `remediation_checklist.csv` — actionable mitigations per threat-technique pair
    -   Optimized Attack Flow `.afb` files (if `--attack-flow`)

### Specifying Custom File Paths

You can use the following command-line arguments to specify custom paths for the `implemented_mitigations.txt` and `cve_definitions.yml` files:

-   `--implemented-mitigations-file`: Path to the implemented mitigations file. If not provided, the tool will look for a file named 'implemented_mitigations.txt' in the same directory as the model or project.
-   `--cve-definitions-file`: Path to the CVE definitions file. If not provided, the tool will look for a file named 'cve_definitions.yml' in the same directory as the model or project.

Example:
```bash
python -m threat_analysis --model-file path/to/your_model.md --implemented-mitigations-file path/to/your/mitigations.txt --cve-definitions-file path/to/your/cves.yml
```

Here's another example using test files:
```bash
python -m threat_analysis --model-file threatModel_Template/threat_model.md \
      --navigator \
      --attack-flow \
      --implemented-mitigations-file tests/implemented_mitigations.txt \
      --cve-definitions-file tests/cve_definitions.yml
```

### 2. Project Mode: Hierarchical System Models

The framework handles projects with multiple, nested system models. You can run project-based analysis from the CLI, but the recommended workflow is the **Web-based User Interface (Server Mode)**, which is more interactive.

1.  **Organize your project** in a directory, with a `main.md` at the root and sub-models in sub-directories (e.g., `my_project/main.md`, `my_project/backend/model.md`).
2.  **Launch the server with your project path:**
    ```bash
    python -m threat_analysis --server --project path/to/your_project
    ```
3.  **Use the "Generate All" button** in the web UI. A fully interactive, cross-linked HTML report will be generated in the `output/` directory.

### 3. Infrastructure as Code (IaC) Integration (Ansible Example)

This framework can generate a complete system model directly from IaC configurations. It automatically includes a set of default protocol styles from `threatModel_Template/base_protocol_styles.md` to ensure consistent visualization.

Here's how to use the Ansible plugin with a sample playbook:

1.  **Ensure you have the test playbook:** The sample Ansible playbook is located at `tests/ansible_playbooks/simple_web_server/simple_web_server.yml`.
2.  **Run the analysis with the Ansible plugin:**
    ```bash
    python -m threat_analysis --ansible-path tests/ansible_playbooks/simple_web_server/simple_web_server.yml
    ```
    This command will generate a complete system model based on the Ansible playbook. The generated Markdown model will be saved in the `output/` directory with a filename derived from your Ansible playbook (e.g., `simple_web_server.md`).

    If you wish to specify a different output file for the generated model, you can use the `--model-file` option:
    ```bash
    python -m threat_analysis --ansible-path tests/ansible_playbooks/simple_web_server/simple_web_server.yml --model-file my_generated_model.md
    ```
3.  **View the results** in the generated `output/` folder, which will now include elements from your Ansible configuration.

### 3b. Infrastructure as Code (IaC) Integration (Docker Compose Example)

The Docker Compose plugin maps `services:` to Servers (type inferred from the image — e.g.
`postgres` → `database`, `redis` → `cache`, `nginx` → `web-server`), `networks:` to Boundaries,
and both `depends_on:` and services sharing a custom network to Dataflows. A published `ports:`
entry sets `internet_facing=true`; credential-looking `environment:` keys or any use of
`secrets:`/`configs:` set `credentials_stored=true`.

1.  **Point it at your compose file** (a direct path, or a directory containing
    `docker-compose.yml`/`docker-compose.yaml`/`compose.yml`/`compose.yaml`):
    ```bash
    python -m threat_analysis --docker-compose-path path/to/docker-compose.yml
    ```
2.  **BOM files are generated automatically** — one per service under `output/<run>/BOM/`,
    using the image name:tag as `software_version`. Populate `known_cves`/`patch_level` from
    your vulnerability scanner to feed CVE-based scoring (see section 4).
3.  **View the results** in the generated `output/` folder, same as the Ansible/Terraform flows.

### 3c. Multi-User Workspaces (Optional)

By default SecOpsTM is single-user: one model/project per server invocation. For a small team
sharing one server instance, set `SECOPSTM_WORKSPACES_DIR` to a directory containing one
subdirectory per project (each with its own `main.md`/`model.md`, optionally `BOM/` and
`context/`):

```bash
export SECOPSTM_WORKSPACES_DIR=/path/to/workspaces_root
python -m threat_analysis --server
```

A "Workspace" dropdown appears in the `/simple` editor toolbar, listing every valid subdirectory.
Switching workspaces is per-browser-session (via a session cookie) — two people with two browser
tabs open against the same server can each be looking at a different workspace without
interfering with each other. There's no per-user access control: everyone reaching the server
(with the same bearer token, if `SECOPSTM_REQUIRE_AUTH` is set) can pick any listed workspace —
this is meant as a convenience for a trusted team, not a security boundary.

Leaving `SECOPSTM_WORKSPACES_DIR` unset (the default) keeps single-user behavior identical to
every previous version — no dropdown, no change.

### 4. CVE-Based Threat Generation (Optional)

This framework can generate threats based on a list of Common Vulnerabilities and Exposures (CVEs) that you provide for specific components in your system model.

#### CVE data source

The security knowledge base (downloaded with `secopstm download-data`) includes CVE→CAPEC mappings covering **1999–2025**. This is sufficient for most use cases.

If you need the **absolute latest CVE entries** (contributors and dev installs only), clone the upstream database next to the SecOpsTM directory:

```bash
git clone https://github.com/Galeax/CVE2CAPEC.git ../CVE2CAPEC
python tooling/copy_cve_data.py
```

The tool maps your specified CVEs to CAPEC attack patterns, which are then used to identify relevant MITRE ATT&CK techniques.

#### Usage

1.  **Create `cve_definitions.yml`**: By default, the tool looks for `cve_definitions.yml` in the directory of the model or project. You can override this path using the `--cve-definitions-file` command-line argument.

2.  **Define CVEs for your equipment**: In this file, list the equipment (servers or actors from your system model) and the CVEs associated with them.

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
    -   **Simple Mode**: An interface for editing and visualizing system models described in Markdown. It features a tabbed editor, a live interactive diagram, and full reporting. When a project is loaded, all model files open automatically in separate tabs.
    -   **Graphical Editor**: An interactive canvas to build, modify, and analyze system models from scratch directly in the browser. It includes a toolbar for adding elements, a properties panel for editing, and the ability to generate all artifacts without touching Markdown directly.

### Working with Projects and Sub-models (Simple Mode)

The Simple Mode is optimized for working with complex, multi-file projects.

1.  **Launch the Server with Your Project**: For the best experience, start the server with the `--project` flag pointing to your project's root directory. This will automatically open all `main.md` and `model.md` files in tabs.

2.  **Define Your Sub-models**: In your `main.md` (or any other model file), define a `server` element and use the `submodel` attribute to link to another markdown file using a relative path.
    ```markdown
    ## Servers
    - **Backend Services**: submodel=backend/model.md, boundary="Internal"
    ```

3.  **Generate the Full Project**: Click the **"Generate All"** button:
    -   It gathers the content from all open tabs.
    -   It detects if any model references a sub-model that is not currently open.
    -   If a missing sub-model is found, it prompts you to select your project's root directory, then scans this directory to find the missing files and includes them in the generation process.
    -   The result is a complete, unified, navigable set of reports and diagrams.

#### Loading a Project with the Directory Picker

Instead of launching the server with `--project`, you can load a project directly from the browser using the **"📂 Load Project"** button in Simple Mode:

1. Click **"📂 Load Project"** — a directory picker opens.
2. Select the root directory of your project.
3. The button automatically:
   - Opens all `.md` files found in the directory into editor tabs.
   - Scans for `BOM/` and `context/` subdirectories.
4. If a `BOM/` directory is detected, a **BOM ✓** badge appears next to the button.
5. If a `context/` directory is detected, a **Context ✓** badge appears.
6. When you click **"Generate All"**, the BOM and context files are sent to the server automatically — no manual path configuration required.

This workflow is especially useful when cloning a project template and wanting to start immediately without restarting the server.

---

## 3. Comparing Reports (Diff)

SecOpsTM can compare two versioned JSON exports to track how the threat landscape changes between runs — after architecture changes, after applying mitigations, or between CI pipeline runs.

### Web interface (`/diff`)

1. Launch the server and open `http://127.0.0.1:5000/diff` in your browser.
2. Paste or upload two JSON report files (the older one on the left, the newer one on the right).
3. The page displays a summary with counts per category:
   - `[+]` New threats introduced
   - `[-]` Threats resolved or removed
   - `[~]` Threats whose severity changed

### CLI

```bash
secopstm --diff old_report.json new_report.json
```

Output is printed to stdout, one line per difference, suitable for CI pipelines:

```
[+] T-0042 HIGH   SQL Injection on DatabaseServer (Tampering)
[-] T-0017 MEDIUM Unencrypted traffic on API Gateway (Information Disclosure)
[~] T-0005 LOW → HIGH Privilege escalation on WebServer (Elevation of Privilege)
```

Both the web and CLI interfaces expect files generated by `--output-format json` (schema version 1.0).

---

## 4. GitHub Action (CI/CD)

SecOpsTM ships as an official GitHub Action for threat-modeling-as-code workflows:

```yaml
# .github/workflows/threat-model.yml
name: Threat Model Analysis
on: [push, pull_request]

jobs:
  threat-model:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./  # or: uses: your-org/secopstm@v1
        with:
          model-file: threatModel_Template/threat_model.md
          output-format: json
          fail-on: HIGH          # fail the job if any HIGH or CRITICAL threat is found
```

Available inputs: `model-file`, `output-format` (`all`/`html`/`json`/`stix`), `output-file`, `fail-on` (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`), `accepted-risks`, `baseline`, `gate`, `ai-enabled`.

The Action installs SecOpsTM, runs the analysis, uploads artifacts, and can block merges when the threat severity threshold is exceeded. No server required.

See `.github/workflows/threat-model.yml` and `action.yml` in the repository root for the full example workflow.

---

## 5. Exporting JSON via the REST API

The `/api/export_json` endpoint returns the full schema-validated JSON report from a single HTTP request, without writing files or generating a ZIP bundle. This is the recommended integration point for CI/CD pipelines, SIEM connectors, and dashboard tools.

```bash
curl -X POST http://localhost:5000/api/export_json \
  -H "Content-Type: application/json" \
  -d '{"markdown_content": "## Actors\n- **External User**: boundary=\"Internet\"\n## Servers\n..."}' \
  --output report.json
```

The response is a JSON object with `schema_version: "1.0"` and all threats carrying stable IDs (`T-NNNN`). Pipe directly to `jq` to extract counts or specific fields:

```bash
# Count CRITICAL threats — fail the CI build if any are present
CRITICAL=$(curl -s -X POST http://localhost:5000/api/export_json \
  -H "Content-Type: application/json" \
  -d @payload.json | jq '[.threats[] | select(.severity=="CRITICAL")] | length')

if [ "$CRITICAL" -gt 0 ]; then
  echo "Build blocked: $CRITICAL CRITICAL threat(s) found."
  exit 1
fi
```

