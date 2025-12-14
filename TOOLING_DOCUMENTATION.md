# Tooling Scripts Documentation

This document provides an explanation for each of the Python scripts located in the `tooling/` directory. These scripts are used for data acquisition, data processing, and quality assurance for the threat modeling framework.

---

### `build_stride_capec_mapping.py`

*   **Purpose**: Builds the `stride_to_capec.json` file, which maps STRIDE threat categories to specific CAPEC (Common Attack Pattern Enumeration and Classification) entries.
*   **Process**:
    1.  Scrapes data from Markdown files on `ostering.com`.
    2.  Applies manual corrections from a hardcoded `CORRECTIONS` dictionary.
    3.  Enriches the data with supplemental mappings from a `SUPPLEMENTAL_MAPPINGS` dictionary.
    4.  Writes the final data to `threat_analysis/external_data/stride_to_capec.json`.
*   **Usage**: A data maintenance tool to be run when the source data changes or when manual corrections need to be updated.

---

### `capec_mitre_parser.py`

*   **Purpose**: A web scraper to parse and extract detailed information from the official CAPEC and MITRE ATT&CK websites.
*   **Functionality**:
    *   `parse_capec_entry(capec_id)`: Fetches a specific CAPEC page and extracts details like title, description, severity, mitigations, etc.
    *   `parse_mitre_attack_technique(technique_id)`: Fetches a specific MITRE ATT&CK technique page and extracts details like tactics, platforms, mitigations, etc.
    *   Saves the aggregated results into a `capec_mitre_results.json` file.
*   **Usage**: An ad-hoc tool for deep-diving into specific attack patterns or techniques for research purposes.

---

### `capec_to_mitre_builder.py`

*   **Purpose**: Creates the `capec_to_mitre_structured_mapping.json` file, which bridges CAPEC attack patterns and MITRE ATT&CK techniques.
*   **Process**:
    1.  Downloads a ZIP file with CAPEC data in CSV format from the MITRE website.
    2.  Parses the CSV to extract CAPEC ID, name, and linked ATT&CK techniques.
    3.  Uses a web scraping fallback to fetch ATT&CK techniques from the CAPEC HTML page if they are missing in the CSV.
    4.  Adds a few hardcoded manual mappings.
    5.  Saves the structured JSON to `threat_analysis/external_data/capec_to_mitre_structured_mapping.json`.
*   **Usage**: A crucial data-building script that should be run periodically to keep the CAPEC to ATT&CK mapping up-to-date.

---

### `cis_controls_parser.py`

*   **Purpose**: Parses the official CIS Controls to MITRE ATT&CK mapping from an Excel file and converts it to a structured JSON file.
*   **Process**:
    1.  Reads the `CIS_Controls_v8_to_Enterprise_ATTCK_v82_Master_Mapping__5262021.xlsx` file.
    2.  Extracts the CIS Safeguard ID, title, and the corresponding MITRE ATT&CK Technique ID.
    3.  Generates a documentation URL for each CIS control.
    4.  Saves the data as `cis_to_mitre_mapping.json` in `threat_analysis/external_data/`.
*   **Usage**: Generates a key data file for suggesting CIS Control mitigations. Run if the source Excel file is updated.

---

### `copy_cve_data.py`

*   **Purpose**: A utility to copy the CVE-to-CAPEC mapping database from an external repository into the project's `external_data` directory.
*   **Process**:
    1.  Assumes the `CVE2CAPEC` repository is cloned next to the project directory.
    2.  Copies the `database` directory from `CVE2CAPEC` to `threat_analysis/external_data/cve2capec`.
*   **Usage**: Must be run by a developer after cloning the `CVE2CAPEC` repository to enable the optional CVE-based threat generation feature.

---

### `download_attack_data.py`

*   **Purpose**: Downloads data from MITRE.
*   **Functionality**: The active code is configured to download a CSV file from `capec.mitre.org` and save it as `CAPEC_VIEW_ATT&CK_Related_Patterns.csv`.
*   **Usage**: A data acquisition script. (Note: There is a discrepancy between the script's comments, which mention `enterprise-attack.json`, and its active code).

---

### `download_nist_data.py`

*   **Purpose**: Downloads the official NIST 800-53 R5 to MITRE ATT&CK mapping file.
*   **Process**:
    1.  Downloads the `nist800-53-r5-mappings.xlsx` file from the "Center for Threat-Informed Defense" GitHub repository.
    2.  Saves the file to `threat_analysis/external_data/`.
*   **Usage**: Acquires the necessary data file for providing NIST 800-53 control suggestions.

---

### `generate_attack_flow.py`

*   **Purpose**: A library of helper functions to programmatically generate `.afb` files compatible with the `attack-flow` application.
*   **Functionality**: Provides functions like `create_action_object`, `create_asset_object`, and `create_connection_objects` to build the components of an attack flow diagram.
*   **Usage**: This script is a toolkit used by other parts of the application (like the `AttackFlowGenerator` class) to construct attack flow diagrams. It does not perform any analysis itself.

---

### `validate_capec_json.py`

*   **Purpose**: Validates the local `stride_to_capec.json` file against the official MITRE CAPEC website to ensure descriptions are correct.
*   **Process**:
    1.  Loads the local JSON file.
    2.  For each entry, it scrapes the official CAPEC definition page on `capec.mitre.org`.
    3.  It compares the local description with the official online description.
    4.  It prints a summary report of any mismatches found.
*   **Usage**: A quality assurance tool to be run after `build_stride_capec_mapping.py` to check for data drift or scraping errors.
