# Developer Guide

## Running Tests

To run the tests for this project, navigate to the root directory of the project in your terminal and execute the following command:

```bash
python3 -m pytest
```

This command will discover and run all tests in the `tests/` directory.

### Running Specific Test Files

To run tests in a specific file, you can provide the path to the file:

```bash
python3 -m pytest tests/test_diagram_generator.py
```

### Generating Code Coverage Report

To generate a code coverage report, which shows how much of your code is exercised by the tests, use the following command:

```bash
PYTHONPATH=. pytest --cov=.
```

This will display a summary of the coverage in your terminal.

---

## External Data

### NIST Data

The application uses NIST 800-53 R5 mappings. This data is not included in the repository and must be downloaded separately.

To download the NIST data, run the following command from the root of the project:

```bash
python3 tooling/download_nist_data.py
```

This will download the necessary file to `threat_analysis/external_data/`.

---

## Future Development: Infrastructure as Code (IaC) Integration

This section outlines the planned integration of Infrastructure as Code (IaC) tools, starting with Ansible, into the STRIDE Threat Analysis Framework. The goal is to enhance the "Threat Modeling as Code" philosophy by enabling automated system model generation and threat analysis directly from IaC configurations.

### Vision

The core idea is to bridge the gap between infrastructure definitions (e.g., Ansible playbooks, Terraform configurations) and the system model. By parsing IaC files, we can automatically infer system components, data flows, and configurations, and then use this information to:

1.  **Dynamically Generate/Update System Models**: Automatically create or update `threatModel_Template/threat_model.md` based on the deployed infrastructure.
2.  **Automate Threat Detection**: Identify potential STRIDE threats and map them to MITRE ATT&CK techniques based on the IaC configuration (e.g., open ports, insecure configurations).
3.  **Detect New Threats**: Compare threat analysis reports before and after IaC changes to highlight newly introduced threats or changes in the attack surface.

This initiative directly supports the "Threat Modeling as Code" workflow detailed in the main [README.md](README.md), pushing automation further into the threat modeling lifecycle.

### High-Level Mechanics

The integration will involve the following steps:

1.  **IaC Parser Development**: Create dedicated modules to read and interpret IaC configuration files (e.g., Ansible playbooks, Terraform `.tf` files). These parsers will extract relevant infrastructure details (e.g., servers, network configurations, deployed services).
2.  **Mapping to System Model DSL**: The extracted IaC data will be translated into the components of our Markdown-based System Model DSL (Boundaries, Actors, Servers, Data, Dataflows).
3.  **Dynamic `threatModel_Template/threat_model.md` Generation**: The translated data will be used to generate or update the `threatModel_Template/threat_model.md` file programmatically.
4.  **Automated Analysis & Reporting**: The existing threat analysis framework (`threat_analysis/__main__.py`) will then process the generated `threatModel_Template/threat_model.md` to perform STRIDE analysis, MITRE mapping, and report generation.
5.  **Change Detection (Future)**: Mechanisms will be explored to compare analysis results over time, identifying new or mitigated threats resulting from IaC changes.

### Phase 1: Ansible Integration

We will begin by integrating with Ansible. This phase will focus on:

1.  **Ansible Playbook/Inventory Parser**: A module will be developed to parse Ansible playbooks and inventory files to identify hosts, roles, tasks, and network configurations.
2.  **Mapping Logic**: Define clear rules for how Ansible constructs (e.g., hosts, tasks that open ports, roles that install services) map to system model elements.
3.  **CLI Integration**: A new command-line option (e.g., `--from-ansible <path_to_ansible_project>`) will be added to `threat_analysis/__main__.py` to trigger the Ansible-based system model generation.

#### Test Playbook

To facilitate development and testing, a sample Ansible playbook will be stored within the project. This playbook will define a simple infrastructure that can be used to validate the parsing and system model generation logic.

**Location**: `tests/ansible_playbooks/simple_web_server.yml` (or similar)

This playbook will include:
-   Definition of a web server.
-   Opening of common ports (e.g., 80, 443).
-   Installation of a web server software (e.g., Nginx, Apache).

This structured approach will allow us to incrementally build and test the IaC integration, starting with a well-defined scope.