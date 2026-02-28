# Copyright 2025 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Mitigation Suggestions Module

This module provides mitigation suggestions from two sources:
1.  Official MITRE ATT&CK mitigations (Courses of Action) parsed from STIX data.
2.  A curated list of framework-specific mitigations (OWASP, NIST, CIS).
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any
from collections import defaultdict
from threat_analysis.core.data_loader import load_cis_to_mitre_mapping, load_nist_mappings

# Define the path to the STIX data file
STIX_DATA_FILE = Path(__file__).parent / 'external_data' / 'enterprise-attack.json'

class MitigationStixMapper:
    def __init__(self):
        self._attack_to_mitigations_map = None

    @property
    def attack_to_mitigations_map(self):
        if self._attack_to_mitigations_map is None:
            self._attack_to_mitigations_map = self._load_stix_mitigations()
        return self._attack_to_mitigations_map

    def _load_stix_mitigations(self):
        mitigations_map = {}
        try:
            with open(STIX_DATA_FILE, 'r', encoding='utf-8') as f:
                stix_data = json.load(f)

            # Extract mitigations and their relationships to techniques
            objects = stix_data.get('objects', [])
            
            # First pass: collect all mitigations
            mitigations = {}
            for obj in objects:
                if obj.get('type') == 'course-of-action':
                    external_id = next((ref['external_id'] for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), None)
                    if external_id:
                        mitigations[obj['id']] = {
                            'id': external_id,
                            'name': obj.get('name'),
                            'description': obj.get('description'),
                            'url': next((ref['url'] for ref in obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), None)
                        }
            
            # Second pass: map techniques to mitigations
            for obj in objects:
                if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'mitigates':
                    source_ref = obj.get('source_ref') # This is the mitigation (course-of-action)
                    target_ref = obj.get('target_ref') # This is the technique (attack-pattern)

                    if source_ref in mitigations:
                        # Find the ATT&CK ID for the target_ref (technique)
                        technique_obj = next((o for o in objects if o['id'] == target_ref and o.get('type') == 'attack-pattern'), None)
                        if technique_obj:
                            technique_external_id = next((ref['external_id'] for ref in technique_obj.get('external_references', []) if ref.get('source_name') == 'mitre-attack'), None)
                            if technique_external_id:
                                if technique_external_id not in mitigations_map:
                                    mitigations_map[technique_external_id] = []
                                mitigations_map[technique_external_id].append(mitigations[source_ref])

        except FileNotFoundError:
            logging.error(f"Error: STIX data file not found at {STIX_DATA_FILE}.")
        except Exception as e:
            logging.error(f"Error processing STIX data for mitigations: {e}")
        
        logging.info(f"Loaded {len(mitigations_map)} ATT&CK techniques with STIX mitigations.")
        return mitigations_map

logging.info("DEBUG: mitigation_suggestions.py loaded")

# --- Framework-Specific Mitigations (Hardcoded) ---

FRAMEWORK_MITIGATION_MAP = {
    # T1190: Exploit Public-Facing Application (e.g., SQL Injection)
    "T1190": [
        {
            "name": "OWASP ASVS V5.3.3: Parameterized Queries",
            "description": "Use parameterized queries (also known as prepared statements) to prevent SQL injection vulnerabilities.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md#v53-output-encoding-and-injection-prevention-requirements"
        },
        {
            "name": "OWASP ASVS V5.3.4: Input Validation",
            "description": "Validate that all user input is well-formed and matches the expected data type and format.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md#v51-input-validation-requirements"
        }
    ],
    # T1059: Command and Scripting Interpreter (e.g., Command Injection)
    "T1059": [
        {
            "name": "OWASP ASVS V5.3.1: OS Command Injection Prevention",
            "description": "Avoid calling OS commands directly. If unavoidable, use structured APIs and ensure all user input is sanitized.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        }
    ],
    # T1083: File and Directory Discovery
    "T1083": [
        {
            "name": "OWASP ASVS V14.1.2: Disable Directory Listing",
            "description": "Verify that directory listing is disabled on web servers to prevent attackers from discovering sensitive files.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x21-V14-Configuration.md#v141-general-configuration-requirements"
        }
    ],
    # T1059.007: JavaScript (e.g., XSS)
    "T1059.007": [
        {
            "name": "OWASP ASVS V5.2.1: Content Security Policy (CSP)",
            "description": "Implement a strong, restrictive Content Security Policy (CSP) to mitigate the risk and impact of XSS attacks.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md#v52-sanitization-and-sandboxing-requirements"
        },
        {
            "name": "OWASP ASVS V5.2.2: Contextual Output Encoding",
            "description": "Apply contextual output encoding to all user-supplied data when it is rendered in HTML, JavaScript, CSS, or other contexts.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x13-V5-Validation-Sanitization-Encoding.md#v53-output-encoding-and-injection-prevention-requirements"
        }
    ],
    # T1557: Adversary-in-the-Middle (e.g., weak TLS)
    "T1557": [
        {
            "name": "OWASP ASVS V9.1: Strong TLS Configuration",
            "description": "Use strong, validated TLS protocols (TLS 1.2, TLS 1.3) and ciphers for all network communications.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x17-V9-Communications.md#v91-communication-security-requirements"
        }
    ],
    # T1078: Valid Accounts (e.g., weak passwords)
    "T1078": [
        {
            "name": "OWASP ASVS V2.1.1: Password Strength Requirements",
            "description": "Enforce strong password policies, including length, complexity, and resistance to common passwords.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        }
    ],
    # T1110: Brute Force
    "T1110": [
        {
            "name": "OWASP ASVS V2.2.1: Account Lockout Mechanism",
            "description": "Implement account lockout mechanisms after a configured number of failed login attempts to slow down brute-force attacks.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x11-V2-Authentication.md#v22-authenticator-lifecycle-requirements"
        },
        {
            "name": "OWASP ASVS V2.2.2: Automated Threat Detection",
            "description": "Use CAPTCHA or other automated threat detection mechanisms to prevent credential stuffing and brute-force attacks.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x11-V2-Authentication.md#v22-authenticator-lifecycle-requirements"
        }
    ],
    # T1068: Exploitation for Privilege Escalation
    "T1068": [
        {
            "name": "OWASP ASVS V1.4.1: Access Control Design",
            "description": "Ensure a robust and well-designed access control mechanism is in place to prevent vertical and horizontal privilege escalation.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x10-V1-Architecture.md#v14-access-control-requirements"
        }
    ],
    # T1499: Endpoint Denial of Service
    "T1499": [
        {
            "name": "OWASP ASVS V13.2.1: Resource Limiting",
            "description": "Implement rate limiting and resource controls on application endpoints to prevent resource exhaustion from a single user or source.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x20-V13-Malicious-Code.md#v132-denial-of-service-requirements"
        }
    ],
    # T1070: Indicator Removal on Host
    "T1070": [
        {
            "name": "OWASP ASVS V7.1: Logging and Auditing",
            "description": "Ensure that all security-relevant events are logged in a way that is sufficient to trace suspicious or malicious activity.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        }
    ],
    # T1040: Network Sniffing
    "T1040": [
        {
            "name": "OWASP ASVS V9.1: Communication Security",
            "description": "Ensure all communication channels use strong, validated TLS with secure ciphers and configurations.",
            "framework": "OWASP ASVS",
            "url": "https://owasp.org/www-project-application-security-verification-standard/"
        }
    ],
    # T1566: Phishing
    "T1566": [
        {
            "name": "OWASP ASVS V2: Strong Authentication",
            "description": "Implement strong authentication (MFA, credential stuffing resistance) to mitigate the impact of phished credentials, as required by the ASVS V2 controls.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x11-V2-Authentication.md#v2-authentication-verification-requirements"
        }
    ],
    # T1562: Impair Defenses
    "T1562": [
        {
            "name": "OWASP ASVS V7.1: Immutable and Protected Logs",
            "description": "Ensure the application generates audit logs for security-relevant events and that these logs are protected from tampering, which directly counters attempts to impair defenses.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x15-V7-Error-Logging.md#v71-logging-and-auditing-requirements"
        }
    ],
    # T1592: Gather Victim Host Information
    "T1592": [
        {
            "name": "OWASP ASVS V1.1.1: Secure Software Development Lifecycle",
            "description": "Verify that a secure software development lifecycle is in place, which includes security requirements, design, implementation, testing, and maintenance.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x10-V1-Architecture.md#v11-secure-software-development-lifecycle-requirements"
        },
        {
            "name": "OWASP ASVS V7.4.1: Sensitive Information in Error Messages",
            "description": "Verify that error messages or stack traces do not reveal sensitive information, such as internal paths, configuration details, or excessive personal data.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x15-V7-Error-Logging.md#v74-sensitive-information-requirements"
        }
    ],
    # T1595: Active Scanning
    "T1595": [
        {
            "name": "OWASP ASVS V14.2.1: Automated Vulnerability Scanning",
            "description": "Verify that automated vulnerability scanning tools are used to identify vulnerabilities in the application and its dependencies.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x21-V14-Configuration.md#v142-dependency-and-third-party-component-requirements"
        }
    ],
    # T1548: Abuse Elevation Control Mechanism
    "T1548": [
        {
            "name": "OWASP ASVS V1.4.1: Access Control Design",
            "description": "Ensure a robust and well-designed access control mechanism is in place to prevent vertical and horizontal privilege escalation.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x10-V1-Architecture.md#v14-access-control-requirements"
        }
    ],
    # T1055: Process Injection
    "T1055": [
        {
            "name": "OWASP ASVS V1.14.1: Process Injection Prevention",
            "description": "Verify that the application is not vulnerable to process injection attacks.",
            "framework": "OWASP ASVS",
            "url": "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x10-V1-Architecture.md#v114-process-and-threading-requirements"
        }
    ]
}

def _create_mitre_to_cis_map() -> Dict[str, List[Dict[str, str]]]:
    """
    Loads the CIS->MITRE mapping and inverts it to create a MITRE->CIS mapping.
    """
    cis_to_mitre = load_cis_to_mitre_mapping()
    mitre_to_cis = defaultdict(list)
    for cis_id, data in cis_to_mitre.items():
        cis_name = data.get("name", "")
        cis_url = data.get("url", "https://www.cisecurity.org/controls/cis-controls-v8") # Use new URL
        for technique_id in data.get("techniques", []):
            # Avoid duplicates
            if not any(d['id'] == cis_id for d in mitre_to_cis[technique_id]):
                mitre_to_cis[technique_id].append({
                    "id": cis_id,
                    "name": f"CIS {cis_id}: {cis_name}",
                    "url": cis_url,
                    "framework": "CIS"
                })
    logging.info(f"Successfully created MITRE to CIS reverse map for {len(mitre_to_cis)} techniques.")
    return mitre_to_cis

# Lazy load framework-specific mitigation maps
_MITRE_TO_CIS_MAP = None
_NIST_MITIGATION_MAP = None

def get_mitre_to_cis_map() -> Dict[str, List[Dict[str, str]]]:
    global _MITRE_TO_CIS_MAP
    if _MITRE_TO_CIS_MAP is None:
        _MITRE_TO_CIS_MAP = _create_mitre_to_cis_map()
    return _MITRE_TO_CIS_MAP

def get_nist_mitigation_map() -> Dict[str, List[Dict[str, str]]]:
    global _NIST_MITIGATION_MAP
    if _NIST_MITIGATION_MAP is None:
        _NIST_MITIGATION_MAP = load_nist_mappings()
    return _NIST_MITIGATION_MAP

def get_framework_mitigation_suggestions(technique_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Retrieves a list of framework-specific mitigation suggestions for the given
    MITRE ATT&CK technique IDs.
    """
    suggestions = []
    mitre_to_cis = get_mitre_to_cis_map()
    nist_mitigation = get_nist_mitigation_map()
    
    for tech_id in technique_ids:
        if tech_id in FRAMEWORK_MITIGATION_MAP:
            suggestions.extend(FRAMEWORK_MITIGATION_MAP[tech_id])
        if tech_id in mitre_to_cis:
            suggestions.extend(mitre_to_cis[tech_id])
        if tech_id in nist_mitigation:
            suggestions.extend(nist_mitigation[tech_id])
    return suggestions
