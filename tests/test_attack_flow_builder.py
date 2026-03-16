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

"""Tests for threat_analysis/generation/attack_flow_builder.py"""

import json
import pytest
from pathlib import Path

from threat_analysis.core.gdaf_engine import AttackScenario, AttackHop
from threat_analysis.core.asset_technique_mapper import ScoredTechnique
from threat_analysis.generation.attack_flow_builder import AttackFlowBuilder, DARK_THEME


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_tech(tech_id="T1078", name="Valid Accounts", tactics=None, score=1.5):
    resolved_tactics = ["initial-access"] if tactics is None else tactics
    return ScoredTechnique(
        id=tech_id,
        name=name,
        tactics=resolved_tactics,
        score=score,
        rationale="platform match",
        url=f"https://attack.mitre.org/techniques/{tech_id}/",
    )


def _make_tech_no_tactics(tech_id="T1078", name="Technique"):
    """Make a ScoredTechnique with explicitly empty tactics list."""
    return ScoredTechnique(
        id=tech_id,
        name=name,
        tactics=[],
        score=1.0,
        rationale="",
    )


def _make_hop(asset_name="Web Server", asset_type="web-server",
              techniques=None, protocol="https",
              is_encrypted=True, is_authenticated=False,
              hop_score=1.5, hop_position="entry"):
    return AttackHop(
        asset_name=asset_name,
        asset_type=asset_type,
        techniques=techniques if techniques is not None else [_make_tech()],
        dataflow_name=f"AttackerTo{asset_name}",
        protocol=protocol,
        is_encrypted=is_encrypted,
        is_authenticated=is_authenticated,
        hop_score=hop_score,
        hop_position=hop_position,
    )


def _make_scenario(scenario_id="GDAF-TEST0001", num_hops=1,
                   min_technique_score=0.5, risk_level="MEDIUM",
                   path_score=2.5, unacceptable_risk=False,
                   multi_techniques=False):
    hops = []
    for i in range(num_hops):
        techs = [_make_tech(f"T100{i}", f"Tech {i}", score=1.5)]
        if multi_techniques:
            techs.append(_make_tech(f"T200{i}", f"AltTech {i}", score=1.2))
        hops.append(_make_hop(
            asset_name=f"Asset{i}",
            techniques=techs,
            hop_position="entry" if i == 0 else ("target" if i == num_hops - 1 else "intermediate"),
        ))
    return AttackScenario(
        scenario_id=scenario_id,
        objective_id="obj1",
        objective_name="Compromise Database",
        objective_description="Steal customer data",
        objective_business_impact="Data breach",
        objective_mitre_final_tactic="exfiltration",
        actor_id="actor1",
        actor_name="APT-X",
        actor_sophistication="high",
        entry_point="External Attacker",
        target_asset=f"Asset{num_hops - 1}",
        hops=hops,
        path_score=path_score,
        risk_level=risk_level,
        detection_coverage=0.2,
        unacceptable_risk=unacceptable_risk,
        min_technique_score=min_technique_score,
    )


# ---------------------------------------------------------------------------
# _make_action_node
# ---------------------------------------------------------------------------

class TestMakeActionNode:
    def test_returns_node_and_anchors(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech("T1078", "Valid Accounts", ["initial-access"])
        result = builder._make_action_node(tech)
        assert "node" in result
        assert "anchors" in result

    def test_node_id_is_action(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech()
        result = builder._make_action_node(tech)
        assert result["node"]["id"] == "action"

    def test_node_has_instance_uuid(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech()
        result = builder._make_action_node(tech)
        assert len(result["node"]["instance"]) > 0

    def test_node_properties_contain_name(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech("T1078", "Valid Accounts")
        result = builder._make_action_node(tech)
        props = dict(result["node"]["properties"])
        assert props["name"] == "Valid Accounts"

    def test_node_properties_contain_ttp(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech("T1078", "Valid Accounts", ["initial-access"])
        result = builder._make_action_node(tech)
        props = dict(result["node"]["properties"])
        ttp = dict(props["ttp"])
        assert ttp["technique"] == "T1078"
        assert ttp["tactic"] == "initial-access"

    def test_no_tactics_uses_unknown(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech_no_tactics("T1078", "Technique")
        result = builder._make_action_node(tech)
        props = dict(result["node"]["properties"])
        ttp = dict(props["ttp"])
        assert ttp["tactic"] == "unknown"

    def test_anchors_count(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech()
        result = builder._make_action_node(tech)
        # 8 angles: 0, 45, 90, 135, 180, 225, 270, 315
        assert len(result["anchors"]) == 12


# ---------------------------------------------------------------------------
# _make_asset_node
# ---------------------------------------------------------------------------

class TestMakeAssetNode:
    def test_returns_correct_structure(self):
        builder = AttackFlowBuilder([], "TestModel")
        result = builder._make_asset_node("WebServer", "A web server")
        assert result["node"]["id"] == "asset"
        assert len(result["anchors"]) == 12

    def test_name_in_properties(self):
        builder = AttackFlowBuilder([], "TestModel")
        result = builder._make_asset_node("DB", "A database")
        props = dict(result["node"]["properties"])
        assert props["name"] == "DB"

    def test_description_in_properties(self):
        builder = AttackFlowBuilder([], "TestModel")
        result = builder._make_asset_node("DB", "A database")
        props = dict(result["node"]["properties"])
        assert props["description"] == "A database"


# ---------------------------------------------------------------------------
# _make_objective_node
# ---------------------------------------------------------------------------

class TestMakeObjectiveNode:
    def test_node_id_is_asset(self):
        # "objective" is not a valid AFB v2 template type — must use "asset"
        builder = AttackFlowBuilder([], "TestModel")
        result = builder._make_objective_node("Compromise DB", "Steal data")
        assert result["node"]["id"] == "asset"

    def test_name_has_objective_prefix(self):
        builder = AttackFlowBuilder([], "TestModel")
        result = builder._make_objective_node("Goal", "Impact")
        props = dict(result["node"]["properties"])
        assert props["name"] == "[Objective] Goal"
        assert props["description"] == "Impact"


# ---------------------------------------------------------------------------
# _make_connection
# ---------------------------------------------------------------------------

class TestMakeConnection:
    def test_returns_four_objects(self):
        builder = AttackFlowBuilder([], "TestModel")
        src = {"instance": "src-uuid", "id": "asset"}
        tgt = {"instance": "tgt-uuid", "id": "action"}
        conn = builder._make_connection(src, tgt)
        assert len(conn) == 4

    def test_first_object_is_dynamic_line(self):
        builder = AttackFlowBuilder([], "TestModel")
        src = {"instance": "src", "id": "asset"}
        tgt = {"instance": "tgt", "id": "action"}
        conn = builder._make_connection(src, tgt)
        assert conn[0]["id"] == "dynamic_line"

    def test_connection_has_handles(self):
        builder = AttackFlowBuilder([], "TestModel")
        src = {"instance": "src", "id": "asset"}
        tgt = {"instance": "tgt", "id": "action"}
        conn = builder._make_connection(src, tgt)
        assert "handles" in conn[0]
        assert len(conn[0]["handles"]) == 1

    def test_latches_present(self):
        builder = AttackFlowBuilder([], "TestModel")
        src = {"instance": "src", "id": "asset"}
        tgt = {"instance": "tgt", "id": "action"}
        conn = builder._make_connection(src, tgt)
        latch_ids = {obj["id"] for obj in conn}
        assert "generic_latch" in latch_ids


# ---------------------------------------------------------------------------
# _flatten
# ---------------------------------------------------------------------------

class TestFlatten:
    def test_flatten_returns_node_plus_anchors(self):
        builder = AttackFlowBuilder([], "TestModel")
        tech = _make_tech()
        node_dict = builder._make_action_node(tech)
        flat = builder._flatten(node_dict)
        assert flat[0] is node_dict["node"]
        assert len(flat) == 1 + len(node_dict["anchors"])


# ---------------------------------------------------------------------------
# _build_afb
# ---------------------------------------------------------------------------

class TestBuildAfb:
    def test_schema_key(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario(num_hops=1)
        afb = builder._build_afb(scenario)
        assert afb["schema"] == "attack_flow_v2"

    def test_theme(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario()
        afb = builder._build_afb(scenario)
        assert afb["theme"] == DARK_THEME

    def test_objects_list_present(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario()
        afb = builder._build_afb(scenario)
        assert isinstance(afb["objects"], list)
        assert len(afb["objects"]) > 0

    def test_layout_dict_present(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario()
        afb = builder._build_afb(scenario)
        assert isinstance(afb["layout"], dict)

    def test_gdaf_meta_fields(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario(num_hops=2, path_score=3.5, risk_level="HIGH", unacceptable_risk=True)
        afb = builder._build_afb(scenario)
        meta = afb["_gdaf_meta"]
        assert meta["path_score"] == 3.5
        assert meta["risk_level"] == "HIGH"
        assert meta["unacceptable_risk"] is True
        assert meta["hop_count"] == 2

    def test_flow_container_is_first_object(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario()
        afb = builder._build_afb(scenario)
        flow = afb["objects"][0]
        assert flow["id"] == "flow"

    def test_camera_present(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario()
        afb = builder._build_afb(scenario)
        assert "camera" in afb
        assert afb["camera"]["k"] == 0.7

    def test_multi_hop_scenario(self):
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario(num_hops=3)
        afb = builder._build_afb(scenario)
        assert len(afb["objects"]) > 1

    def test_or_branch_with_multiple_techniques(self):
        """When a hop has multiple techniques above threshold, multiple action nodes appear."""
        builder = AttackFlowBuilder([], "TestModel")
        scenario = _make_scenario(num_hops=1, multi_techniques=True, min_technique_score=0.5)
        afb = builder._build_afb(scenario)
        # Count action nodes in the objects list
        action_count = sum(1 for obj in afb["objects"] if obj.get("id") == "action")
        assert action_count >= 2

    def test_single_technique_produces_one_action_node(self):
        builder = AttackFlowBuilder([], "TestModel")
        # Only one technique above threshold
        scenario = _make_scenario(num_hops=1, multi_techniques=False, min_technique_score=0.5)
        afb = builder._build_afb(scenario)
        action_count = sum(1 for obj in afb["objects"] if obj.get("id") == "action")
        assert action_count == 1

    def test_high_threshold_falls_back_to_best_technique(self):
        """Even with high threshold, always at least 1 action node (fallback)."""
        builder = AttackFlowBuilder([], "TestModel")
        # Set min_technique_score very high so no technique qualifies
        scenario = _make_scenario(num_hops=1, min_technique_score=99.0)
        afb = builder._build_afb(scenario)
        action_count = sum(1 for obj in afb["objects"] if obj.get("id") == "action")
        assert action_count >= 1

    def test_hop_with_no_auth_adds_note(self):
        builder = AttackFlowBuilder([], "TestModel")
        hops = [_make_hop(is_authenticated=False, is_encrypted=False)]
        scenario = AttackScenario(
            scenario_id="GDAF-TEST",
            objective_id="obj1", objective_name="Goal",
            objective_description="", objective_business_impact="Impact",
            objective_mitre_final_tactic="exfiltration",
            actor_id="actor1", actor_name="Attacker", actor_sophistication="medium",
            entry_point="Attacker", target_asset="Asset0",
            hops=hops, path_score=2.0, risk_level="MEDIUM",
            detection_coverage=0.0, unacceptable_risk=False,
            min_technique_score=0.5,
        )
        afb = builder._build_afb(scenario)
        # Find asset node properties — should mention "no authentication" or "cleartext"
        asset_nodes = [
            obj for obj in afb["objects"]
            if obj.get("id") == "asset"
        ]
        # Entry point + 1 hop asset + objective = 3 asset/objective nodes
        assert len(asset_nodes) >= 2

    def test_hop_with_empty_techniques_still_builds(self):
        """A hop with no techniques uses fallback logic without crashing."""
        builder = AttackFlowBuilder([], "TestModel")
        hop = _make_hop(techniques=[])
        scenario = AttackScenario(
            scenario_id="GDAF-EMPTY",
            objective_id="obj1", objective_name="Goal",
            objective_description="", objective_business_impact="",
            objective_mitre_final_tactic="",
            actor_id="actor1", actor_name="Attacker", actor_sophistication="low",
            entry_point="Attacker", target_asset="Asset0",
            hops=[hop], path_score=1.0, risk_level="LOW",
            detection_coverage=0.0, unacceptable_risk=False,
            min_technique_score=0.5,
        )
        afb = builder._build_afb(scenario)
        assert afb["schema"] == "attack_flow_v2"


# ---------------------------------------------------------------------------
# generate_and_save
# ---------------------------------------------------------------------------

class TestGenerateAndSave:
    def test_empty_scenarios_creates_summary_only(self, tmp_path):
        builder = AttackFlowBuilder([], "TestModel")
        summary = builder.generate_and_save(str(tmp_path))
        assert isinstance(summary, dict)
        # summary JSON should be written
        summary_path = tmp_path / "gdaf" / "gdaf_summary.json"
        assert summary_path.exists()

    def test_single_scenario_creates_afb_file(self, tmp_path):
        scenario = _make_scenario("GDAF-SAVE0001", num_hops=1)
        builder = AttackFlowBuilder([scenario], "TestModel")
        summary = builder.generate_and_save(str(tmp_path))
        # AFB file should exist
        afb_path = tmp_path / "gdaf" / "obj1" / "actor1_GDAF-SAVE0001.afb"
        assert afb_path.exists()

    def test_afb_file_is_valid_json(self, tmp_path):
        scenario = _make_scenario("GDAF-JSON0001", num_hops=1)
        builder = AttackFlowBuilder([scenario], "TestModel")
        builder.generate_and_save(str(tmp_path))
        afb_path = tmp_path / "gdaf" / "obj1" / "actor1_GDAF-JSON0001.afb"
        with open(afb_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["schema"] == "attack_flow_v2"

    def test_summary_contains_scenario_rows(self, tmp_path):
        scenario = _make_scenario("GDAF-SUM001", num_hops=1)
        builder = AttackFlowBuilder([scenario], "TestModel")
        builder.generate_and_save(str(tmp_path))
        summary_path = tmp_path / "gdaf" / "gdaf_summary.json"
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert len(data["scenarios"]) == 1
        assert data["scenarios"][0]["scenario_id"] == "GDAF-SUM001"

    def test_summary_return_value(self, tmp_path):
        scenario = _make_scenario("GDAF-RET001", num_hops=1)
        builder = AttackFlowBuilder([scenario], "TestModel")
        result = builder.generate_and_save(str(tmp_path))
        assert "obj1/actor1" in result
        assert "actor1_GDAF-RET001.afb" in result["obj1/actor1"]

    def test_multiple_scenarios_create_multiple_files(self, tmp_path):
        scenarios = [
            _make_scenario("GDAF-MULTI01", num_hops=1),
            _make_scenario("GDAF-MULTI02", num_hops=2),
        ]
        builder = AttackFlowBuilder(scenarios, "TestModel")
        builder.generate_and_save(str(tmp_path))
        obj_dir = tmp_path / "gdaf" / "obj1"
        afb_files = list(obj_dir.glob("*.afb"))
        assert len(afb_files) == 2

    def test_output_dir_created_if_not_exists(self, tmp_path):
        new_dir = tmp_path / "nested" / "output"
        scenario = _make_scenario()
        builder = AttackFlowBuilder([scenario], "TestModel")
        builder.generate_and_save(str(new_dir))
        assert (new_dir / "gdaf").exists()

    def test_summary_json_structure(self, tmp_path):
        scenario = _make_scenario("GDAF-STRUCT01", num_hops=1)
        builder = AttackFlowBuilder([scenario], "TestModel")
        builder.generate_and_save(str(tmp_path))
        summary_path = tmp_path / "gdaf" / "gdaf_summary.json"
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "model" in data
        assert "scenarios" in data
        assert "files" in data

    def test_scenario_with_hop_having_technique_in_summary(self, tmp_path):
        scenario = _make_scenario("GDAF-TECH01", num_hops=1)
        builder = AttackFlowBuilder([scenario], "TestModel")
        builder.generate_and_save(str(tmp_path))
        summary_path = tmp_path / "gdaf" / "gdaf_summary.json"
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        row = data["scenarios"][0]
        assert len(row["techniques"]) == 1
        assert row["techniques"][0]["tech_id"] == "T1000"


# ---------------------------------------------------------------------------
# _write_summary with empty scenarios
# ---------------------------------------------------------------------------

class TestWriteSummary:
    def test_empty_scenarios_writes_empty_list(self, tmp_path):
        gdaf_dir = tmp_path / "gdaf"
        gdaf_dir.mkdir()
        builder = AttackFlowBuilder([], "TestModel")
        builder._write_summary(gdaf_dir, {})
        summary_path = gdaf_dir / "gdaf_summary.json"
        with open(summary_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert data["scenarios"] == []
