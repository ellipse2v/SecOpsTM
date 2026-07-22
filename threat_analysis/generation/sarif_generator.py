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
SARIF 2.1.0 export — maps the consolidated threat list (T-NNNN ids, severity,
component location) directly onto GitHub's Security > Code scanning alerts tab.
No UI to build: GitHub renders SARIF natively once uploaded via
github/codeql-action/upload-sarif.
"""

import json
from typing import Any, Dict, List, Optional

try:
    from threat_analysis import __version__ as _SECOPSTM_VERSION
except Exception:
    _SECOPSTM_VERSION = "unknown"

# SARIF `level` — GitHub renders error/warning/note with different icons and
# lets users filter by severity; "note" is the closest fit for LOW (SARIF has
# no dedicated low-severity level).
_SEVERITY_TO_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


class SarifGenerator:
    """Generates a SARIF 2.1.0 log from the fully-scored, MITRE-mapped threat
    list (the same list used for the HTML/JSON reports)."""

    def __init__(
        self,
        threat_model_name: str,
        all_detailed_threats: List[Dict[str, Any]],
        model_file_path: Optional[str] = None,
    ):
        self.threat_model_name = threat_model_name
        self.all_detailed_threats = all_detailed_threats
        # GitHub's code scanning UI anchors each result to a repo-relative file;
        # SecOpsTM findings are architectural, not line-level, so the model file
        # itself (the thing that produced the finding) is the natural anchor.
        self.artifact_uri = self._to_repo_relative_uri(model_file_path) if model_file_path else "threat_model.md"

    @staticmethod
    def _to_repo_relative_uri(path: str) -> str:
        # SARIF wants forward-slash relative URIs; a bare filename is used as a
        # last resort if the given path is absolute with no obvious repo root.
        normalized = path.replace("\\", "/")
        return normalized.lstrip("/")

    def _rule_id(self, threat: Dict[str, Any]) -> str:
        return threat.get("id") or f"SECOPSTM-{abs(hash(threat.get('description', ''))) % 100000:05d}"

    def _build_rule(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        stride = threat.get("stride_category", "Unknown")
        techniques = threat.get("mitre_techniques", []) or []
        help_uri = techniques[0].get("url") if techniques and techniques[0].get("url") else "https://github.com/ellipse2v/SecOpsTM"
        tags = ["security", f"stride/{stride}"]
        tags.extend(f"attack/{t['id']}" for t in techniques if t.get("id"))

        severity = threat.get("severity") or {}
        level = threat.get("severity", {}).get("level", "LOW")
        score = severity.get("score")

        rule: Dict[str, Any] = {
            "id": self._rule_id(threat),
            "name": stride.replace(" ", ""),
            "shortDescription": {"text": f"[{level}] {stride} — {threat.get('target', 'Unknown')}"},
            "fullDescription": {"text": threat.get("description", "")},
            "helpUri": help_uri,
            "defaultConfiguration": {"level": _SEVERITY_TO_SARIF_LEVEL.get(level, "warning")},
            "properties": {"tags": tags},
        }
        if isinstance(score, (int, float)):
            rule["properties"]["security-severity"] = f"{score:.1f}"
        return rule

    def _build_result(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        level = (threat.get("severity") or {}).get("level", "LOW")
        target = threat.get("target", "Unknown")
        cve_ids = threat.get("cve") or []
        message = threat.get("description", "")
        if cve_ids:
            message += f"\n\nRelated CVE(s): {', '.join(cve_ids)}"

        return {
            "ruleId": self._rule_id(threat),
            "level": _SEVERITY_TO_SARIF_LEVEL.get(level, "warning"),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": self.artifact_uri},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"name": target, "kind": "module"}],
                }
            ],
            "properties": {
                "stride_category": threat.get("stride_category", ""),
                "source": threat.get("source", ""),
                "target": target,
            },
        }

    def generate_sarif_log(self) -> Dict[str, Any]:
        """Generates the full SARIF 2.1.0 log object. One rule per threat id
        (T-NNNN), deduplicated, plus one result per threat occurrence."""
        rules: Dict[str, Dict[str, Any]] = {}
        results: List[Dict[str, Any]] = []

        for threat in self.all_detailed_threats:
            rule = self._build_rule(threat)
            rules.setdefault(rule["id"], rule)
            results.append(self._build_result(threat))

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecOpsTM",
                            "informationUri": "https://github.com/ellipse2v/SecOpsTM",
                            "version": _SECOPSTM_VERSION,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def save_sarif_to_file(self, output_path: str) -> None:
        """Generates and saves the SARIF log to a file."""
        sarif_log = self.generate_sarif_log()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sarif_log, f, indent=2)
