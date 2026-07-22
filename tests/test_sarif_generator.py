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

import json
from pathlib import Path

import pytest

from threat_analysis.generation.sarif_generator import SarifGenerator


@pytest.fixture
def sample_threats():
    return [
        {
            "id": "T-0001",
            "description": "SQL injection via unsanitized input",
            "target": "WebApp",
            "stride_category": "Tampering",
            "source": "pytm",
            "severity": {"score": 9.5, "level": "CRITICAL", "formatted_score": "9.5/10"},
            "mitre_techniques": [{"id": "T1190", "name": "Exploit Public-Facing Application",
                                  "url": "https://attack.mitre.org/techniques/T1190"}],
            "cve": ["CVE-2023-12345"],
        },
        {
            "id": "T-0002",
            "description": "Credential theft via phishing",
            "target": "AuthService",
            "stride_category": "Spoofing",
            "source": "AI",
            "severity": {"score": 4.0, "level": "LOW", "formatted_score": "4.0/10"},
            "mitre_techniques": [],
            "cve": [],
        },
    ]


class TestSarifGenerator:
    def test_generates_valid_sarif_structure(self, sample_threats):
        gen = SarifGenerator("Test Model", sample_threats, model_file_path="threat_model.md")
        sarif = gen.generate_sarif_log()

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "SecOpsTM"
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2

    def test_severity_maps_to_sarif_level(self, sample_threats):
        gen = SarifGenerator("Test Model", sample_threats)
        sarif = gen.generate_sarif_log()
        results_by_rule = {r["ruleId"]: r for r in sarif["runs"][0]["results"]}

        assert results_by_rule["T-0001"]["level"] == "error"    # CRITICAL
        assert results_by_rule["T-0002"]["level"] == "note"     # LOW

    def test_rule_includes_security_severity_and_attack_tag(self, sample_threats):
        gen = SarifGenerator("Test Model", sample_threats)
        sarif = gen.generate_sarif_log()
        rules_by_id = {r["id"]: r for r in sarif["runs"][0]["tool"]["driver"]["rules"]}

        rule = rules_by_id["T-0001"]
        assert rule["properties"]["security-severity"] == "9.5"
        assert "attack/T1190" in rule["properties"]["tags"]
        assert rule["helpUri"] == "https://attack.mitre.org/techniques/T1190"

    def test_result_location_uses_model_file_path(self, sample_threats):
        gen = SarifGenerator("Test Model", sample_threats, model_file_path="threatModel_Template/threat_model.md")
        sarif = gen.generate_sarif_log()
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "threatModel_Template/threat_model.md"

    def test_defaults_to_threat_model_md_when_no_path_given(self, sample_threats):
        gen = SarifGenerator("Test Model", sample_threats)
        sarif = gen.generate_sarif_log()
        loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "threat_model.md"

    def test_result_message_includes_cve(self, sample_threats):
        gen = SarifGenerator("Test Model", sample_threats)
        sarif = gen.generate_sarif_log()
        result = sarif["runs"][0]["results"][0]
        assert "CVE-2023-12345" in result["message"]["text"]

    def test_no_duplicate_rules_for_same_id(self, sample_threats):
        # Two threats with the same id (e.g. re-run on the same T-NNNN) must
        # produce exactly one rule entry, not a duplicate.
        threats = sample_threats + [dict(sample_threats[0])]
        gen = SarifGenerator("Test Model", threats)
        sarif = gen.generate_sarif_log()
        rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
        assert len(rule_ids) == len(set(rule_ids))

    def test_save_sarif_to_file(self, tmp_path, sample_threats):
        gen = SarifGenerator("Test Model", sample_threats)
        output_path = tmp_path / "report.sarif.json"
        gen.save_sarif_to_file(str(output_path))

        assert output_path.exists()
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["version"] == "2.1.0"

    def test_empty_threat_list(self):
        gen = SarifGenerator("Empty Model", [])
        sarif = gen.generate_sarif_log()
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []
