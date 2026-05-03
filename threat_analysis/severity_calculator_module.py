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
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re
import logging

try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SCORING_CONFIG_PATH = _PROJECT_ROOT / "config" / "scoring_config.yaml"

_scoring_config: Optional[Dict] = None


def _load_scoring_config() -> Dict:
    global _scoring_config
    if _scoring_config is not None:
        return _scoring_config
    if _yaml is None:
        _scoring_config = {}
        return _scoring_config
    try:
        with open(_SCORING_CONFIG_PATH, "r", encoding="utf-8") as f:
            _scoring_config = _yaml.safe_load(f) or {}
    except Exception as exc:
        logging.warning("Cannot load scoring_config.yaml: %s — using built-in defaults", exc)
        _scoring_config = {}
    return _scoring_config


def _get_high_risk_cwes() -> frozenset:
    """Return the set of high-risk CWE IDs from scoring_config.yaml (or built-in defaults)."""
    defaults = [
        "22", "78", "89", "94", "119", "120", "125", "134",
        "190", "434", "502", "611", "798", "918",
    ]
    cwes = _load_scoring_config().get("high_risk_cwes", defaults)
    return frozenset(str(c) for c in cwes)


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
        """True when at least one CWE ID belongs to the high-risk set (from scoring_config.yaml)."""
        return bool(set(self.cwe_ids) & _get_high_risk_cwes())


class SeverityCalculator:
    """Class for calculating threat severity"""
    
    def __init__(self, markdown_file_path: str = "threatModel_Template/threat_model.md"):
        cfg = _load_scoring_config()
        stride_cfg = cfg.get("stride", {})

        self.base_scores = stride_cfg.get("base_scores", {
            "ElevationOfPrivilege": 9.0,
            "Tampering": 8.0,
            "InformationDisclosure": 7.5,
            "Spoofing": 7.0,
            "DenialOfService": 6.0,
            "Repudiation": 5.0,
        })

        self.target_multipliers = self._load_severity_multipliers_from_markdown(markdown_file_path)

        self.protocol_adjustments = stride_cfg.get("protocol_adjustments", {
            "SSH": 0.5,
            "HTTPS": -0.3,
            "HTTP": 0.2,
        })

        raw_thresholds = stride_cfg.get("severity_thresholds", {
            "CRITICAL":      [9.0, 10.0],
            "HIGH":          [7.5,  8.9],
            "MEDIUM":        [6.0,  7.4],
            "LOW":           [4.0,  5.9],
            "INFORMATIONAL": [1.0,  3.9],
        })
        css_map = {
            "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
            "LOW": "low", "INFORMATIONAL": "info",
        }
        self.severity_levels = {
            label: (float(bounds[0]), float(bounds[1]), css_map.get(label, "info"))
            for label, bounds in raw_thresholds.items()
        }

        self.classification_multipliers = stride_cfg.get("classification_multipliers", {
            "PUBLIC": 1.0,
            "RESTRICTED": 1.2,
            "SECRET": 1.5,
            "TOP_SECRET": 2.0,
        })

        self._voc_deltas = stride_cfg.get("voc_deltas", {
            "cve_match": 0.5,
            "cwe_high_risk": 0.3,
            "network_exposed": 0.7,
            "d3fend_mitigations": -0.5,
        })

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
            if risk_context.has_cve_match:
                score += self._voc_deltas.get("cve_match", 0.5)
            if risk_context.cwe_high_risk:
                score += self._voc_deltas.get("cwe_high_risk", 0.3)
            if risk_context.network_exposed:
                score += self._voc_deltas.get("network_exposed", 0.7)
            if risk_context.has_d3fend_mitigations:
                score += self._voc_deltas.get("d3fend_mitigations", -0.5)

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
        """Returns a detailed explanation of how severity scores are calculated."""
        bs = self.base_scores
        voc = self._voc_deltas
        base_lines = ", ".join(
            f"{k}: {v}" for k, v in sorted(bs.items(), key=lambda x: -x[1])
        )
        return (
            "Threat severity is calculated on a scale of 1.0 to 10.0 using the following factors:\n\n"
            f"1.  **Base Score**: Each STRIDE threat category has a predefined base score "
            f"({base_lines}).\n"
            "2.  **Impact and Likelihood**: If provided (scale 1–5), their product is normalised and added.\n"
            "3.  **Target Multipliers**: Per-element multipliers from the '## Severity Multipliers' section of the model.\n"
            f"4.  **Protocol Adjustments**: "
            + ", ".join(f"{p} {'+' if v >= 0 else ''}{v}" for p, v in self.protocol_adjustments.items())
            + ".\n"
            "5.  **Data Classification**: "
            + ", ".join(f"{k} ×{v}" for k, v in sorted(self.classification_multipliers.items(), key=lambda x: x[1]))
            + " multiplier.\n"
            "6.  **VOC Context (when available)**:\n"
            f"    - Known CVE match for this target: {'+' if voc.get('cve_match', 0.5) >= 0 else ''}{voc.get('cve_match', 0.5)}\n"
            f"    - High-risk CWE class (injection, buffer overflow, hardcoded creds…): {'+' if voc.get('cwe_high_risk', 0.3) >= 0 else ''}{voc.get('cwe_high_risk', 0.3)}\n"
            f"    - Network-exposed without authentication or encryption: {'+' if voc.get('network_exposed', 0.7) >= 0 else ''}{voc.get('network_exposed', 0.7)}\n"
            f"    - Active D3FEND defensive controls in place: {voc.get('d3fend_mitigations', -0.5)}\n\n"
            "The final score is clamped to [1.0, 10.0] and mapped to "
            "INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL."
        )