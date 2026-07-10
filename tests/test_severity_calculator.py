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

import pytest
from unittest.mock import patch

import threat_analysis.severity_calculator_module as mod
from threat_analysis.severity_calculator_module import (
    SeverityCalculator,
    RiskContext,
    _load_scoring_config,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CUSTOM_CONFIG = {
    "stride": {
        "base_scores": {"Spoofing": 4.0, "Tampering": 4.5},
        "severity_thresholds": {
            "CRITICAL": [9.0, 10.0],
            "HIGH": [7.0, 8.9],
            "MEDIUM": [5.0, 6.9],
            "LOW": [3.0, 4.9],
            "INFORMATIONAL": [1.0, 2.9],
        },
        "protocol_adjustments": {"SSH": 1.0, "HTTPS": -0.5},
        "classification_multipliers": {"PUBLIC": 1.0, "SECRET": 2.0},
        "voc_deltas": {
            "cve_match": 1.0,
            "cwe_high_risk": 0.5,
            "network_exposed": 1.5,
            "d3fend_mitigations": -1.0,
        },
    },
    "high_risk_cwes": ["89", "78"],
}


@pytest.fixture(autouse=True)
def reset_scoring_config_cache():
    """Reset module-level cache before each test."""
    mod._scoring_config = None
    yield
    mod._scoring_config = None


# ---------------------------------------------------------------------------
# Loader tests
# ---------------------------------------------------------------------------

class TestLoadScoringConfig:
    def test_returns_dict(self):
        cfg = _load_scoring_config()
        assert isinstance(cfg, dict)

    def test_cached_on_second_call(self):
        first = _load_scoring_config()
        second = _load_scoring_config()
        assert first is second

    def test_returns_empty_dict_when_yaml_missing(self):
        mod._scoring_config = None
        with patch("threat_analysis.severity_calculator_module._SCORING_CONFIG_PATH",
                   "/nonexistent/path/scoring_config.yaml"):
            cfg = _load_scoring_config()
        assert cfg == {}

    def test_cache_reset_clears_module_variable(self):
        _load_scoring_config()
        assert mod._scoring_config is not None
        mod._scoring_config = None
        assert mod._scoring_config is None


# ---------------------------------------------------------------------------
# SeverityCalculator — YAML-driven construction
# ---------------------------------------------------------------------------

class TestSeverityCalculatorFromYaml:
    def test_custom_base_score_used(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        assert calc.base_scores["Spoofing"] == 4.0

    def test_custom_protocol_adjustment_used(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        assert calc.protocol_adjustments["SSH"] == 1.0

    def test_custom_classification_multiplier_used(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        assert calc.classification_multipliers["SECRET"] == 2.0

    def test_fallback_base_scores_when_yaml_empty(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value={}):
            calc = SeverityCalculator()
        assert calc.base_scores["ElevationOfPrivilege"] == 9.0


# ---------------------------------------------------------------------------
# HIGH_RISK_CWES from YAML
# ---------------------------------------------------------------------------

class TestHighRiskCwes:
    def test_default_cwes_include_sql_injection(self):
        from threat_analysis.severity_calculator_module import _get_high_risk_cwes
        cwes = _get_high_risk_cwes()
        assert "89" in cwes

    def test_custom_cwes_loaded_from_yaml(self):
        from threat_analysis.severity_calculator_module import _get_high_risk_cwes
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value={"high_risk_cwes": ["1234"]}):
            cwes = _get_high_risk_cwes()
        assert "1234" in cwes
        assert "89" not in cwes

    def test_risk_context_cwe_high_risk_uses_configurable_set(self):
        from threat_analysis.severity_calculator_module import _get_high_risk_cwes
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value={"high_risk_cwes": ["9999"]}):
            ctx = RiskContext(cwe_ids=["9999"])
            assert ctx.cwe_high_risk is True


# ---------------------------------------------------------------------------
# VOC deltas from YAML
# ---------------------------------------------------------------------------

class TestVocDeltas:
    def test_custom_cve_delta_applied(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        base = calc.base_scores.get("Spoofing", 7.0)
        ctx = RiskContext(has_cve_match=True)
        score = calc.calculate_score("Spoofing", "server", risk_context=ctx)
        # cve_match delta = 1.0 from CUSTOM_CONFIG
        assert score > base

    def test_custom_network_exposed_delta_applied(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        ctx = RiskContext(network_exposed=True)
        score_with = calc.calculate_score("Spoofing", "server", risk_context=ctx)
        score_without = calc.calculate_score("Spoofing", "server", risk_context=RiskContext())
        assert score_with > score_without

    def test_d3fend_delta_reduces_score(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        ctx_with = RiskContext(has_d3fend_mitigations=True)
        ctx_without = RiskContext(has_d3fend_mitigations=False)
        score_with = calc.calculate_score("Spoofing", "server", risk_context=ctx_with)
        score_without = calc.calculate_score("Spoofing", "server", risk_context=ctx_without)
        assert score_with < score_without


# ---------------------------------------------------------------------------
# Severity label from configurable thresholds
# ---------------------------------------------------------------------------

class TestSeverityLevelsFromYaml:
    def test_custom_threshold_changes_label(self):
        custom = {
            "stride": {
                "severity_thresholds": {
                    "CRITICAL": [5.0, 10.0],
                    "HIGH": [3.0, 4.9],
                    "MEDIUM": [2.0, 2.9],
                    "LOW": [1.0, 1.9],
                    "INFORMATIONAL": [0.0, 0.9],
                }
            }
        }
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=custom):
            calc = SeverityCalculator()
        label, _ = calc.get_severity_level(5.0)
        assert label == "CRITICAL"


# ---------------------------------------------------------------------------
# get_calculation_explanation — reflects YAML values
# ---------------------------------------------------------------------------

class TestCalculationExplanation:
    def test_explanation_reflects_custom_base_score(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        explanation = calc.get_calculation_explanation()
        # Custom Spoofing score is 4.0 — must appear in the explanation
        assert "4.0" in explanation

    def test_explanation_reflects_custom_voc_delta(self):
        with patch("threat_analysis.severity_calculator_module._load_scoring_config",
                   return_value=CUSTOM_CONFIG):
            calc = SeverityCalculator()
        explanation = calc.get_calculation_explanation()
        # Custom cve_match delta is 1.0
        assert "1.0" in explanation


# ---------------------------------------------------------------------------
# update_target_multipliers — must REPLACE, not merge
# ---------------------------------------------------------------------------

class TestUpdateTargetMultipliers:
    def test_replaces_previous_multipliers(self):
        """A long-lived SeverityCalculator (server singleton) reused across different
        models must not leak a previous model's multipliers into a later one — a merge
        (.update()) would; a replace won't.
        """
        calc = SeverityCalculator()
        calc.target_multipliers = {"OldServer": 2.0}
        calc.update_target_multipliers({"NewServer": 1.5})
        assert calc.target_multipliers == {"NewServer": 1.5}
        assert "OldServer" not in calc.target_multipliers

    def test_empty_dict_clears_previous_multipliers(self):
        """A model with no '## Severity Multipliers' section of its own must clear
        whatever a previous model (or the constructor default) left behind.
        """
        calc = SeverityCalculator()
        calc.target_multipliers = {"StaleServer": 3.0}
        calc.update_target_multipliers({})
        assert calc.target_multipliers == {}


# ---------------------------------------------------------------------------
# SeverityCalculator(markdown_content=...) — in-memory content takes precedence
# ---------------------------------------------------------------------------

class TestSeverityCalculatorMarkdownContent:
    def test_markdown_content_used_over_file(self, tmp_path):
        content = "## Severity Multipliers\n- **RealServer**: 2.5\n"
        # Point markdown_file_path at a file that would give DIFFERENT multipliers,
        # to prove markdown_content wins.
        bogus_file = tmp_path / "bogus.md"
        bogus_file.write_text("## Severity Multipliers\n- **WrongServer**: 9.0\n")
        calc = SeverityCalculator(markdown_file_path=str(bogus_file), markdown_content=content)
        assert calc.target_multipliers == {"RealServer": 2.5}

    def test_markdown_content_none_falls_back_to_file(self, tmp_path):
        f = tmp_path / "model.md"
        f.write_text("## Severity Multipliers\n- **FileServer**: 1.8\n")
        calc = SeverityCalculator(markdown_file_path=str(f))
        assert calc.target_multipliers == {"FileServer": 1.8}

    def test_markdown_content_with_no_multipliers_section_is_empty(self):
        calc = SeverityCalculator(markdown_content="# System Model: X\n\n## Boundaries\n")
        assert calc.target_multipliers == {}
