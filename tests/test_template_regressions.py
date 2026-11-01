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

"""Regression tests for the bundled threat model templates.

Covers failures reported by the scheduled template run:
  - IoT: boundary 'Physical Environment' defined but unused → model rejected.
  - Zero_Trust: server type 'policy_engine' (and two others) not standard →
    `secopstm validate` failed 3/16 checks.
"""

from pathlib import Path

import pytest

from threat_analysis.core.model_parser import ModelParser
from threat_analysis.core.model_validator import ModelValidator
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.validate import ThreatModelValidator

TEMPLATE_ROOT = Path(__file__).resolve().parents[1] / "threatModel_Template"
TEMPLATES = sorted(d.name for d in TEMPLATE_ROOT.iterdir() if (d / "model.md").exists())


def _load(template: str) -> ThreatModel:
    tm = ThreatModel(template, "template regression test")
    ModelParser(tm, tm.mitre_mapper).parse_markdown(
        (TEMPLATE_ROOT / template / "model.md").read_text(encoding="utf-8")
    )
    return tm


def _cli_failures(template: str, capsys) -> list:
    validator = ThreatModelValidator(str(TEMPLATE_ROOT / template))
    validator.run()
    capsys.readouterr()  # silence the validator's console output
    return [r.message for r in validator.results if not r.passed]


@pytest.mark.parametrize("template", TEMPLATES)
def test_template_passes_model_validation(template):
    """Every bundled template must load and pass the analysis-time ModelValidator,
    otherwise create_threat_model() returns None and the report run aborts."""
    assert ModelValidator(_load(template)).validate() == []


@pytest.mark.parametrize("template", TEMPLATES)
def test_template_has_no_unused_boundaries(template, capsys):
    failures = [m for m in _cli_failures(template, capsys) if "defined but not used" in m]
    assert failures == []


def test_iot_physical_environment_boundary_is_used():
    tm = _load("IoT")
    validator = ModelValidator(tm)
    validator._validate_unused_boundaries()
    assert validator.errors == []
    assert "physical environment" in tm.boundaries


def test_zero_trust_validate_passes(capsys):
    assert _cli_failures("Zero_Trust", capsys) == []


def test_zero_trust_policy_engine_uses_standard_type(capsys):
    failures = _cli_failures("Zero_Trust", capsys)
    assert not any("policy_engine" in m for m in failures)
