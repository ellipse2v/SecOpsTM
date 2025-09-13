# Project Roadmap

This document outlines the development roadmap for the SecOpsTM framework, tracking both completed features and future ambitions.

---

## ✅ Implemented Features

This section highlights the core capabilities that are already integrated into the framework.

-   **Hierarchical & Interactive Threat Models**: Decompose a large system into multiple, linked sub-models with navigable HTML diagrams.
-   **Advanced Threat Model Validation**: A dedicated validation module (`model_validator.py`) checks for consistency, unique names, and valid references within the model before analysis.
-   **Automated and Enriched Mitigation Suggestions**: The framework proposes context-aware mitigations based on recognized frameworks (OWASP ASVS, NIST, CIS Controls) for each identified MITRE ATT&CK technique.
-   **Ansible IaC Integration**: Automatically generate a threat model directly from Ansible playbooks and inventories, using embedded metadata for a rich, accurate representation.
-   **Pre-defined Architecture Templates**: A library of pre-built threat models for common architectural patterns is available in the `threatModel_Template/` directory to accelerate initial setup.
-   **Web-Based GUI**: An interactive web interface for real-time editing of threat models with a live-updating diagram preview.
-   **MITRE ATT&CK Navigator Export**: Generate JSON layer files for visualization and analysis in the MITRE ATT&CK Navigator.
-   **STIX 2.1 Reporting**: Export threat intelligence data in the standardized STIX 2.1 format for interoperability with other security tools.

---

## 🚀 Future Enhancements

This section outlines the strategic vision and planned features for future releases.

-   **Integration with Vulnerability Databases (CVE)**: Link identified MITRE ATT&CK techniques to known CVEs or common vulnerabilities (e.g., OWASP Top 10) to provide even deeper context.
-   **Attack Path Enumeration and Simulation**: Implement algorithms to automatically identify and visualize potential attack paths through the threat model.
-   **Integration with Security Orchestration, Automation, and Response (SOAR) Platforms**: Develop connectors to push threat intelligence and mitigation recommendations directly into SOAR platforms.
-   **Machine Learning-Enhanced Threat Identification**: Train a machine learning model to predict potential threats that may not be covered by existing rules.
-   **Expanded IaC Tool Support (Terraform, CloudFormation)**: Create new plugins for other popular IaC tools.
-   **Enhanced User Interface (UI) and User Experience (UX)**: Redesign the web GUI to be more intuitive, with features like drag-and-drop model creation and a visual rule editor.
-   **Compliance Mapping (NIST, PCI-DSS, etc.)**: Map identified threats and suggested mitigations to specific controls in major compliance frameworks.
-   **Threat Intelligence Feed Integration**: Integrate with external threat intelligence feeds (e.g., from MISP, Anomali) to automatically update the threat model with the latest real-world attack techniques.
-   **Collaborative Real-Time Editing**: Enhance the web GUI to support real-time, multi-user collaborative editing of threat models.
-   **Risk Quantification and Financial Impact Analysis**: Integrate with risk quantification models (e.g., FAIR) to estimate the potential financial impact of identified threats.
-   **Automated Attack Path Analysis**: Generate potential attack paths by chaining together identified MITRE ATT&CK techniques across all nodes in the threat model. This will involve enriching the CAPEC to ATT&CK mappings to build a comprehensive attack graph.
-   **Advanced Severity Multiplier Calculation**: Implement a more granular and qualitative method for calculating the severity multiplier of each asset. This will be based on a rating of four key security criteria:
    *   **Confidentiality**: The impact of unauthorized disclosure of data.
    *   **Integrity**: The impact of unauthorized modification of data.
    *   **Availability**: The impact of the asset being unavailable.
    *   **Traceability**: The importance of being able to trace actions back to a specific user.

    Each criterion will be rated on a scale (e.g., 1-5, from low to high), and the final severity multiplier for the asset will be calculated as the average of these four ratings. This will provide a more nuanced and defensible risk score for each identified threat.
-   **Offline LLM (Large Language Model) Enhancement for Threat Analysis**: Go beyond rule-based analysis by integrating a specialized language model that runs locally to ensure data privacy.
    *   **Principle**: The goal is to use an LLM's contextual reasoning capabilities to identify complex, non-obvious threats and to generate more realistic attack scenarios than a deterministic rule engine allows.
    *   **Training Phase (Fine-Tuning)**:
        1.  **Model Selection**: Choose a high-performing, open-source model (such as Llama, Mistral, or a derivative) that can be run offline.
        2.  **Dataset Creation**: Build a high-quality dataset for fine-tuning, including:
            -   The complete knowledge bases of **MITRE ATT&CK, CAPEC, and D3FEND**.
            -   Thousands of public **threat intelligence reports** (from CISA, Mandiant, etc.) and **CVE** descriptions.
            -   All existing **threat models (`.md` files)** from the project, so the LLM can learn the DSL and architectural patterns.
            -   Pairs of "input threat model" -> "output list of threats and attack paths" generated by the current tool for supervised learning.
        3.  **Training**: Fine-tune the base model on this dataset to specialize it in the "thinking" of a security expert.
    *   **Usage Phase (Inference)**:
        1.  **Hybrid Approach**: The current rule engine remains the baseline for fast, deterministic analysis. The LLM acts as a second pass.
        2.  **Contextual Prompting**: After the initial analysis, the tool sends a detailed prompt to the local LLM, containing:
            -   The complete architecture description (the `.md` model).
            -   The list of threats already identified by the rule engine.
        3.  **Augmented Generation**: The prompt asks the LLM to perform several tasks:
            -   "Based on recent threat reports, are there any emerging threats applicable to this architecture that are not covered by the rules?"
            -   "Combine the identified threats to create the 3 most plausible attack paths, explaining the attacker's logic at each step."
            -   "Suggest specific and non-trivial countermeasures for this context."
        4.  **Reporting**: The LLM's results are integrated into the final report, clearly labeled as "AI-Suggested" to distinguish them from the deterministic results, allowing the user to validate the relevance of the suggestions.
