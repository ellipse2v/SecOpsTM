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
Threat severity calculation module
"""
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
import re
import logging

# CWE IDs (numeric strings as stored in JSONL) that indicate high exploitability.
# These classes are commonly weaponised (injection flaws, memory corruption,
# hardcoded credentials, deserialization, SSRF, path traversal…).
_HIGH_RISK_CWES: frozenset = frozenset({
    "22",   # Path Traversal
    "78",   # OS Command Injection
    "89",   # SQL Injection
    "94",   # Code Injection
    "119",  # Buffer Errors
    "120",  # Classic Buffer Overflow
    "125",  # Out-of-bounds Read
    "134",  # Format String
    "190",  # Integer Overflow / Wrap-around
    "434",  # Unrestricted Upload of Dangerous File
    "502",  # Deserialization of Untrusted Data
    "611",  # XML External Entity (XXE)
    "798",  # Use of Hardcoded Credentials
    "918",  # Server-Side Request Forgery (SSRF)
})


@dataclass
class RiskContext:
    """
    Contextual risk factors that complement the base STRIDE score.

    All fields default to the neutral/unknown position so callers only set
    what they actually know — unset factors contribute 0 to the score.

    Scoring deltas (applied in ``SeverityCalculator.calculate_score``):
        has_cve_match          +0.5   confirmed exploitability evidence
        cwe_high_risk          +0.3   easily weaponisable vulnerability class
        network_exposed        +0.7   reachable without authentication or encryption
        has_d3fend_mitigations −0.5   active defensive controls reduce residual risk
    """
    has_cve_match: bool = False
    """A known CVE mapping exists for this target and threat category."""

    cwe_ids: List[str] = field(default_factory=list)
    """Numeric CWE ID strings from the CVE JSONL for the matched CVEs."""

    network_exposed: bool = False
    """Target is reachable by an unauthenticated/unencrypted path."""

    has_d3fend_mitigations: bool = False
    """At least one D3FEND defensive technique counters this threat."""

    @property
    def cwe_high_risk(self) -> bool:
        """True when at least one CWE ID belongs to the high-risk set."""
        return bool(set(self.cwe_ids) & _HIGH_RISK_CWES)


class SeverityCalculator:
    """Class for calculating threat severity"""
    
    def __init__(self, markdown_file_path: str = "threatModel_Template/threat_model.md"):
        self.base_scores = {
            "ElevationOfPrivilege": 9.0,
            "Tampering": 8.0,
            "InformationDisclosure": 7.5,
            "Spoofing": 7.0,
            "DenialOfService": 6.0,
            "Repudiation": 5.0
        }
        
        self.target_multipliers = self._load_severity_multipliers_from_markdown(markdown_file_path)
        
        self.protocol_adjustments = {
            "SSH": 0.5,
            "HTTPS": -0.3,
            "HTTP": 0.2
        }
        
        self.severity_levels = {
            "CRITICAL": (9.0, 10.0, "critical"),
            "HIGH": (7.5, 8.9, "high"),
            "MEDIUM": (6.0, 7.4, "medium"),
            "LOW": (4.0, 5.9, "low"),
            "INFORMATIONAL": (1.0, 3.9, "info")
        }
        
        self.classification_multipliers = {
            "PUBLIC": 1.0,
            "RESTRICTED": 1.2,
            "SECRET": 1.5,
            "TOP_SECRET": 2.0
        }

    def _load_severity_multipliers_from_markdown(self, markdown_file_path: str) -> Dict[str, float]:
        """
        Loads severity multipliers from the '## Severity Multipliers' section of a Markdown file.
        Expected format:
        ## Severity Multipliers
        - **Server Name 1**: 1.5
        - **Server Name 2**: 2.0
        """
        multipliers = {}
        try:
            with open(markdown_file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            multipliers_section_match = re.search(r'## Severity Multipliers\n(.*?)(\n## |$)', content, re.DOTALL)
            if multipliers_section_match:
                multipliers_content = multipliers_section_match.group(1).strip()
                
                for line in multipliers_content.split('\n'):
                    line = line.strip()
                    match = re.match(r'- \*\*(.*?)\*\*: (\d+\.\d+)', line)
                    if match:
                        name = match.group(1).strip()
                        value = float(match.group(2))
                        multipliers[name] = value
        except FileNotFoundError:
            logging.warning(f"Warning: Severity multipliers file not found at {markdown_file_path}")
        except Exception as e:
            logging.error(f"Error loading severity multipliers from markdown: {e}")
        return multipliers
    
    def calculate_score(
        self,
        threat_type: str,
        target_name: str,
        protocol: Optional[str] = None,
        classification: Optional[str] = None,
        impact: Optional[int] = None,
        likelihood: Optional[int] = None,
        risk_context: Optional["RiskContext"] = None,
    ) -> float:
        """Calculates the severity score for a threat.

        The score is built in three stages:
        1. Base STRIDE score + impact/likelihood + target/protocol adjustments
        2. Data classification multiplier
        3. VOC context adjustments (RiskContext) — additive deltas before final clamp

        All stages are optional; missing context falls back to the pre-existing
        static scoring so existing call sites continue to work unchanged.
        """
        # --- Stage 1: base score ---
        score = self.base_scores.get(threat_type, 5.0)

        if impact is not None and likelihood is not None:
            score += (impact * likelihood) / 5.0

        for target_key, multiplier in self.target_multipliers.items():
            if target_key in target_name:
                score += multiplier
                break

        if protocol:
            score += self.protocol_adjustments.get(protocol.upper(), 0.0)

        # --- Stage 2: data classification multiplier ---
        if classification:
            score *= self.classification_multipliers.get(classification.upper(), 1.0)

        # --- Stage 3: VOC context factors ---
        if risk_context is not None:
            # Known CVE match — confirmed exploitability evidence
            if risk_context.has_cve_match:
                score += 0.5

            # High-risk CWE class — easily weaponisable vulnerability
            if risk_context.cwe_high_risk:
                score += 0.3

            # Network-exposed — attacker can reach the target without auth/encryption
            if risk_context.network_exposed:
                score += 0.7

            # Active D3FEND controls — reduce residual exploitability
            if risk_context.has_d3fend_mitigations:
                score -= 0.5

        return min(10.0, max(1.0, score))
    
    def get_severity_level(self, score: float) -> Tuple[str, str]:
        """Converts the numeric score to a severity level"""
        for level_name, (min_score, max_score, css_class) in self.severity_levels.items():
            if min_score <= score <= max_score:
                return level_name, css_class
        return "INFORMATIONAL", "info"
    
    def get_severity_info(
        self,
        threat_type: str,
        target_name: str,
        protocol: Optional[str] = None,
        classification: Optional[str] = None,
        impact: Optional[int] = None,
        likelihood: Optional[int] = None,
        risk_context: Optional["RiskContext"] = None,
    ) -> Dict[str, object]:
        """Returns complete severity information."""
        score = self.calculate_score(
            threat_type, target_name, protocol, classification,
            impact, likelihood, risk_context
        )
        level, css_class = self.get_severity_level(score)
        
        return {
            "score": score,
            "level": level,
            "css_class": css_class,
            "formatted_score": f"{score:.1f}/10"
        }
    
    def update_target_multipliers(self, new_multipliers: Dict[str, float]):
        """Updates target multipliers"""
        self.target_multipliers.update(new_multipliers)

    def get_calculation_explanation(self) -> str:
        """
        Returns a detailed explanation of how severity scores are calculated.
        """
        explanation = (
            "Threat severity is calculated on a scale of 1.0 to 10.0 using the following factors:\n\n"
            "1.  **Base Score**: Each STRIDE threat category has a predefined base score "
            "(ElevationOfPrivilege: 9.0, Tampering: 8.0, InformationDisclosure: 7.5, "
            "Spoofing: 7.0, DenialOfService: 6.0, Repudiation: 5.0).\n"
            "2.  **Impact and Likelihood**: If provided (scale 1–5), their product is normalised and added.\n"
            "3.  **Target Multipliers**: Per-element multipliers from the '## Severity Multipliers' section of the model.\n"
            "4.  **Protocol Adjustments**: SSH +0.5, HTTP +0.2, HTTPS −0.3.\n"
            "5.  **Data Classification**: PUBLIC ×1.0 → TOP_SECRET ×2.0 multiplier.\n"
            "6.  **VOC Context (when available)**:\n"
            "    - Known CVE match for this target: +0.5\n"
            "    - High-risk CWE class (injection, buffer overflow, hardcoded creds…): +0.3\n"
            "    - Network-exposed without authentication or encryption: +0.7\n"
            "    - Active D3FEND defensive controls in place: −0.5\n\n"
            "The final score is clamped to [1.0, 10.0] and mapped to "
            "INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL."
        )
        return explanation