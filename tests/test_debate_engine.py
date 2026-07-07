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

"""Tests for threat_analysis/core/debate_engine.py"""

import asyncio
from unittest.mock import MagicMock, AsyncMock

from threat_analysis.core.debate_engine import RedBlueDebateEngine
from threat_analysis.core.gdaf_engine import AttackScenario, AttackHop
from threat_analysis.core.asset_technique_mapper import ScoredTechnique


def make_scenario(path_score=4.5, detection_coverage=0.2, risk_level="CRITICAL"):
    hop = AttackHop(
        asset_name="WebServer",
        asset_type="web_server",
        techniques=[ScoredTechnique(
            id="T1190", name="Exploit Public-Facing Application",
            tactics=["initial-access"], score=1.5, rationale="",
        )],
        dataflow_name="UserToWeb",
        protocol="https",
        is_encrypted=True,
        is_authenticated=False,
        hop_score=1.8,
        hop_position="entry",
    )
    return AttackScenario(
        scenario_id="GDAF-TEST01",
        objective_id="obj1",
        objective_name="Exfiltrate customer data",
        objective_description="",
        objective_business_impact="High",
        objective_mitre_final_tactic="exfiltration",
        actor_id="actor1",
        actor_name="Organized Crime",
        actor_sophistication="high",
        entry_point="ExternalUser",
        target_asset="WebServer",
        hops=[hop],
        path_score=path_score,
        risk_level=risk_level,
        detection_coverage=detection_coverage,
        unacceptable_risk=True,
    )


class FakeProvider:
    """Returns queued canned responses in call order."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    async def generate_debate_turn(self, prompt, system_prompt):
        self.calls.append((prompt, system_prompt))
        if not self._responses:
            return {}
        return self._responses.pop(0)


RED_TURN_HIGH = {
    "viability_score": 0.8,
    "techniques_attempted": ["T1190"],
    "failed_alternatives": [],
    "rationale": "Exploiting unauthenticated HTTPS endpoint",
    "evidence": [
        {"claim": "endpoint has no auth", "evidence_type": "misconfig",
         "evidence_ref": "hop 1 is_authenticated=false", "confidence": "high"},
    ],
}
BLUE_TURN_BLOCK_ALL = {
    "viability_score": 0.1,
    "techniques_blocked": ["T1190"],
    "detection_gaps": [
        {"step": "WebServer entry", "control_family": "EDR", "covered": True,
         "detail": "EDR rule X blocks T1190 payloads", "confidence": "high"},
    ],
    "rationale": "Blocked by EDR rule",
    "evidence": [],
}
BLUE_TURN_GAP = {
    "viability_score": 0.6,
    "techniques_blocked": [],
    "detection_gaps": [
        {"step": "WebServer entry", "control_family": "SIEM", "covered": False,
         "detail": "No rule for this payload", "confidence": "medium"},
    ],
    "rationale": "No coverage",
    "evidence": [],
}
RED_TURN_ALT = {
    "viability_score": 0.3,
    "techniques_attempted": ["T1210"],
    "failed_alternatives": [],
    "rationale": "Switching to a different lateral movement technique",
    "evidence": [],
}


def test_selects_only_scenarios_above_viability_threshold():
    low = make_scenario(path_score=0.5, detection_coverage=0.9, risk_level="LOW")
    high = make_scenario(path_score=4.5, detection_coverage=0.0, risk_level="CRITICAL")
    engine = RedBlueDebateEngine(FakeProvider([]), config={"min_viability_threshold": 0.5})
    selected = engine._select_scenarios([low, high])
    assert selected == [high]


def test_top_n_caps_selection():
    scenarios = [make_scenario(path_score=4.0 + i, detection_coverage=0.0) for i in range(10)]
    engine = RedBlueDebateEngine(FakeProvider([]), config={"top_n": 3, "min_viability_threshold": 0.0})
    selected = engine._select_scenarios(scenarios)
    assert len(selected) == 3
    assert selected[0].path_score == max(s.path_score for s in scenarios)


def test_convergence_stops_before_max_rounds():
    scenario = make_scenario()
    provider = FakeProvider([RED_TURN_HIGH, BLUE_TURN_BLOCK_ALL])
    engine = RedBlueDebateEngine(provider, config={"max_rounds": 3, "viability_delta_threshold": 0.5})
    result = asyncio.run(engine._debate_scenario(scenario))
    assert result is not None
    assert result.converged is True
    assert len(result.rounds) == 2


def test_max_rounds_respected_when_not_converging():
    scenario = make_scenario()
    # Viability must genuinely keep moving round to round — identical canned turns would
    # converge on repetition (delta hits an exact 0.0 fixed point), which is not what this
    # test is exercising. Alternating RED_TURN_HIGH/RED_TURN_ALT keeps the delta above
    # threshold every round.
    provider = FakeProvider([
        RED_TURN_HIGH, BLUE_TURN_GAP,
        RED_TURN_ALT, BLUE_TURN_GAP,
        RED_TURN_HIGH, BLUE_TURN_GAP,
    ])
    engine = RedBlueDebateEngine(provider, config={"max_rounds": 3, "viability_delta_threshold": 0.001})
    result = asyncio.run(engine._debate_scenario(scenario))
    assert result is not None
    assert len(result.rounds) == 6
    assert result.converged is False


def test_malformed_turn_json_skipped_gracefully():
    scenario = make_scenario()
    provider = FakeProvider([{"unexpected": "shape"}])
    engine = RedBlueDebateEngine(provider, config={"max_rounds": 3})
    result = asyncio.run(engine._debate_scenario(scenario))
    assert result is None


def test_debate_factor_bounded_and_risk_level_recomputed():
    scenario = make_scenario(path_score=4.5, risk_level="CRITICAL")
    provider = FakeProvider([RED_TURN_HIGH, BLUE_TURN_BLOCK_ALL])
    # BLUE_TURN_BLOCK_ALL only blocks 1 technique, so the round viability (0.8 - 0.15*1 = 0.65)
    # stays above the engine's default min_viability_threshold (0.5) — residual_path_viable would
    # be True and the >1.0 cap would never engage. Raising the threshold to 0.7 for this test
    # makes 0.65 register as "not viable," which is what "Blue blocked everything -> capped at
    # 1.0" is meant to exercise.
    engine = RedBlueDebateEngine(
        provider,
        config={"max_rounds": 1, "debate_factor_min": 0.5, "debate_factor_max": 1.5,
                "viability_delta_threshold": 0.5, "min_viability_threshold": 0.7},
    )
    results = asyncio.run(engine.run([scenario]))
    assert len(results) == 1
    assert scenario.path_score_pre_debate == 4.5
    assert 0.5 <= scenario.debate_factor <= 1.5
    assert scenario.path_score <= 4.5  # Blue blocked everything -> factor capped at 1.0
    assert scenario.risk_level in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_evidence_without_ref_marked_unverified():
    scenario = make_scenario()
    turn_with_bad_evidence = dict(RED_TURN_HIGH)
    turn_with_bad_evidence["evidence"] = [
        {"claim": "unsupported claim", "evidence_type": "none", "evidence_ref": "", "confidence": "low"},
    ]
    provider = FakeProvider([turn_with_bad_evidence, BLUE_TURN_BLOCK_ALL])
    engine = RedBlueDebateEngine(provider, config={"max_rounds": 1})
    result = asyncio.run(engine._debate_scenario(scenario))
    assert result is not None
    red_turn = result.rounds[0]
    assert red_turn.evidence[0].verified is False


def test_grounding_includes_hop_facts_and_bom_cves(tmp_path):
    bom_dir = tmp_path / "BOM"
    bom_dir.mkdir()
    (bom_dir / "webserver.yaml").write_text("known_cves:\n  - CVE-2024-1234\n", encoding="utf-8")
    scenario = make_scenario()
    engine = RedBlueDebateEngine(FakeProvider([]), bom_directory=str(bom_dir))
    grounding = engine._build_grounding(scenario)
    assert "unauthenticated" in grounding
    assert "https" in grounding
    assert "CVE-2024-1234" in grounding


from threat_analysis.generation.report_generator import ReportGenerator


def test_run_debate_disabled_by_default():
    rg = ReportGenerator(MagicMock(), MagicMock())
    rg.ai_provider = MagicMock()
    rg._debate_config = {}
    threat_model = MagicMock()
    threat_model.gdaf_scenarios = [make_scenario()]
    result = asyncio.run(rg._run_debate(threat_model))
    assert result == []


def test_run_debate_no_provider():
    rg = ReportGenerator(MagicMock(), MagicMock())
    rg.ai_provider = None
    rg._debate_config = {"enabled": True}
    threat_model = MagicMock()
    threat_model.gdaf_scenarios = [make_scenario()]
    result = asyncio.run(rg._run_debate(threat_model))
    assert result == []


def test_run_debate_no_scenarios():
    rg = ReportGenerator(MagicMock(), MagicMock())
    rg.ai_provider = MagicMock()
    rg._debate_config = {"enabled": True}
    threat_model = MagicMock()
    threat_model.gdaf_scenarios = []
    result = asyncio.run(rg._run_debate(threat_model))
    assert result == []


def test_run_debate_runs_engine_when_enabled_and_online():
    rg = ReportGenerator(MagicMock(), MagicMock())
    mock_client = MagicMock()
    mock_client.ai_online = True
    rg.ai_provider = MagicMock()
    rg.ai_provider._get_client = AsyncMock(return_value=mock_client)
    rg.ai_provider.generate_debate_turn = AsyncMock(side_effect=[RED_TURN_HIGH, BLUE_TURN_BLOCK_ALL])
    rg._debate_config = {"enabled": True, "max_rounds": 1, "viability_delta_threshold": 0.5}
    threat_model = MagicMock()
    threat_model.gdaf_scenarios = [make_scenario()]
    threat_model.context_config = {}
    threat_model._model_file_path = None
    result = asyncio.run(rg._run_debate(threat_model))
    assert len(result) == 1
    assert result[0].scenario_id == "GDAF-TEST01"


import re
import jinja2
from pathlib import Path

_TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "threat_analysis" / "templates" / "report_template.html"


def _extract_debate_section() -> str:
    text = _TEMPLATE_PATH.read_text(encoding="utf-8")
    match = re.search(
        r"<!-- DEBATE_SECTION_START -->(.*?)<!-- DEBATE_SECTION_END -->",
        text, re.DOTALL,
    )
    assert match, "DEBATE_SECTION markers not found in report_template.html"
    return match.group(1)


def test_debate_section_hidden_when_no_results():
    tmpl = jinja2.Template(_extract_debate_section())
    html = tmpl.render(debate_results=[])
    assert "Red/Blue Adversarial Debate" not in html


def test_debate_section_shows_persuasion_order():
    tmpl = jinja2.Template(_extract_debate_section())
    debate_results = [{
        "objective_name": "Exfiltrate data",
        "entry_point": "ExternalUser",
        "target_asset": "WebServer",
        "residual_path_viable": True,
        "final_viability": 0.6,
        "blocked_paths": ["T1078"],
        "residual_detection_gaps": [
            {"step": "hop1", "control_family": "SIEM", "covered": False,
             "detail": "no rule", "confidence": "medium"},
        ],
        "red_failed_attempts": ["Tried T1110 — blocked"],
        "round_count": 2,
        "converged": True,
        "convergence_delta": 0.05,
        "debate_factor": 1.2,
        "rounds": [],
    }]
    html = tmpl.render(debate_results=debate_results)
    assert "Red/Blue Adversarial Debate" in html
    idx_blocked = html.index("Paths Blue successfully blocked")
    idx_gaps = html.index("Detection gaps on the residual path")
    idx_failed = html.index("Red's failed alternative attempts")
    idx_footnote = html.index("round(s)")
    assert idx_blocked < idx_gaps < idx_failed < idx_footnote
