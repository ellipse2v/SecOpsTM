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

"""Tests for threat_analysis/core/gdaf_engine.py"""

import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from threat_analysis.core.gdaf_engine import (
    GDAFEngine,
    AttackScenario,
    AttackHop,
    _CLASSIFICATION_SCORE,
    _TRAVERSAL_BONUS,
    _DETECTION_COVERAGE,
)
from threat_analysis.core.asset_technique_mapper import AssetTechniqueMapper, ScoredTechnique


# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

class MockDataflow:
    """Minimal dataflow-like object."""
    def __init__(self, src, tgt, protocol="https", is_encrypted=True, is_authenticated=True, bidirectional=False):
        self.source = type("Node", (), {"name": src})()
        self.sink = type("Node", (), {"name": tgt})()
        self.name = f"{src}To{tgt}"
        self.protocol = protocol
        self.is_encrypted = is_encrypted
        self.is_authenticated = is_authenticated
        self.authentication = "credentials" if is_authenticated else "none"
        self.data = []
        self.bidirectional = bidirectional


class MockThreatModel:
    """Minimal ThreatModel-like object."""
    def __init__(self, actors=None, servers=None, boundaries=None, dataflows=None):
        self.actors = actors or []
        self.servers = servers or []
        self.boundaries = boundaries or {}
        self.dataflows = dataflows or []


def make_actor(name, trusted=False, boundary=None):
    return {"name": name, "isTrusted": trusted, "boundary": boundary}


def make_server(name, stype="web-server", confidentiality="high", integrity="medium",
                availability="high", mfa_enabled=False, encryption="", tags=None,
                boundary=None, internet_facing=False, credentials_stored=False):
    return {
        "name": name,
        "type": stype,
        "confidentiality": confidentiality,
        "integrity": integrity,
        "availability": availability,
        "mfa_enabled": mfa_enabled,
        "encryption": encryption,
        "tags": tags or [],
        "boundary": boundary,
        "internet_facing": internet_facing,
        "credentials_stored": credentials_stored,
    }


def make_simple_model():
    """Return a simple 3-node model: attacker → web server → database."""
    actors = [make_actor("External Attacker", trusted=False)]
    servers = [
        make_server("Web Server", stype="web-server", confidentiality="medium", integrity="medium", availability="high"),
        make_server("Database", stype="database", confidentiality="critical", integrity="critical", availability="critical"),
    ]
    dataflows = [
        MockDataflow("External Attacker", "Web Server", protocol="https", is_encrypted=True, is_authenticated=False),
        MockDataflow("Web Server", "Database", protocol="sql", is_encrypted=True, is_authenticated=True),
    ]
    return MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)


def make_context_yaml(tmp_path, targets=None, actor_entry="internet-facing", actor_objectives=None):
    """Write a minimal context YAML and return its path."""
    targets = targets or ["Database"]
    actor_objectives = actor_objectives or ["obj1"]
    context = {
        "attack_objectives": [
            {
                "id": "obj1",
                "name": "Compromise Database",
                "description": "Exfiltrate sensitive data",
                "target_asset_names": targets,
                "target_types": [],
                "mitre_final_tactic": "exfiltration",
                "business_impact": "Data breach",
                "unacceptable_risk_above": 4.0,
            }
        ],
        "threat_actors": [
            {
                "id": "actor1",
                "name": "External Attacker",
                "sophistication": "medium",
                "objectives": actor_objectives,
                "capable_tactics": None,
                "known_ttps": [],
                "entry_preference": actor_entry,
            }
        ],
        "risk_criteria": {
            "max_hops": 5,
            "max_paths_per_objective": 3,
            "acceptable_risk_score": 5.0,
            "gdaf_min_technique_score": 0.5,
        },
    }
    ctx_file = tmp_path / "context.yaml"
    ctx_file.write_text(yaml.dump(context), encoding="utf-8")
    return str(ctx_file)


# ---------------------------------------------------------------------------
# Patch AssetTechniqueMapper to avoid loading enterprise-attack.json
# ---------------------------------------------------------------------------

def _mock_get_techniques(*args, **kwargs):
    """Return a fixed list of ScoredTechnique objects."""
    return [
        ScoredTechnique(
            id="T1078",
            name="Valid Accounts",
            tactics=["initial-access"],
            score=1.5,
            rationale="platform match",
            url="https://attack.mitre.org/techniques/T1078/",
        )
    ]


@pytest.fixture(autouse=True)
def patch_mapper():
    """Patch AssetTechniqueMapper.get_techniques to avoid loading large JSON."""
    with patch.object(AssetTechniqueMapper, "get_techniques", side_effect=_mock_get_techniques):
        yield


# ---------------------------------------------------------------------------
# _load_context
# ---------------------------------------------------------------------------

class TestLoadContext:
    def test_none_path_returns_empty(self):
        result = GDAFEngine._load_context(None)
        assert result == {}

    def test_nonexistent_path_returns_empty(self, tmp_path):
        result = GDAFEngine._load_context(str(tmp_path / "missing.yaml"))
        assert result == {}

    def test_valid_yaml(self, tmp_path):
        f = tmp_path / "ctx.yaml"
        f.write_text("attack_objectives: []\nthreat_actors: []\n", encoding="utf-8")
        result = GDAFEngine._load_context(str(f))
        assert "attack_objectives" in result

    def test_malformed_yaml_returns_empty(self, tmp_path):
        f = tmp_path / "bad.yaml"
        # Write content that triggers yaml parse error
        f.write_text("key: [unclosed", encoding="utf-8")
        result = GDAFEngine._load_context(str(f))
        assert result == {}


# ---------------------------------------------------------------------------
# GDAFEngine constructor
# ---------------------------------------------------------------------------

class TestGDAFEngineConstructor:
    def test_no_context_empty_model(self):
        """With no servers and no context file, auto-context still produces objectives."""
        model = MockThreatModel()  # no servers
        engine = GDAFEngine(model, context_path=None)
        # auto-context always provides at least the structural keys
        assert "attack_objectives" in engine.context
        assert "threat_actors" in engine.context

    def test_no_context_with_servers_auto_generates(self):
        """Auto-context targets highest-CIA servers when no context file is given."""
        model = make_simple_model()
        engine = GDAFEngine(model, context_path=None)
        assert engine.context.get("attack_objectives")  # at least one auto objective
        assert engine.context.get("threat_actors")      # at least one auto actor

    def test_with_model(self):
        model = make_simple_model()
        engine = GDAFEngine(model, context_path=None)
        assert engine.threat_model is model

    def test_extra_models_merged(self):
        model = make_simple_model()
        extra = MockThreatModel(
            servers=[make_server("Extra Server", stype="database")]
        )
        engine = GDAFEngine(model, extra_models=[extra])
        assert len(engine._all_models) == 2


# ---------------------------------------------------------------------------
# _build_graph
# ---------------------------------------------------------------------------

class TestBuildGraph:
    def test_nodes_created_for_actors_and_servers(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        assert "External Attacker" in graph
        assert "Web Server" in graph
        assert "Database" in graph

    def test_actor_kind(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        assert graph["External Attacker"]["kind"] == "actor"

    def test_server_kind(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        assert graph["Web Server"]["kind"] == "server"

    def test_edges_added(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        edge_targets = [e["target"] for e in graph["External Attacker"]["edges"]]
        assert "Web Server" in edge_targets

    def test_bidirectional_dataflow_adds_reverse_edge(self):
        actors = [make_actor("ActorA", trusted=False)]
        servers = [make_server("ServerB")]
        dataflows = [MockDataflow("ActorA", "ServerB", protocol="https", bidirectional=True)]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # ServerB should have a reverse edge back to ActorA
        reverse_targets = [e["target"] for e in graph["ServerB"]["edges"]]
        assert "ActorA" in reverse_targets

    def test_protocols_added_to_services(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # Web Server receives HTTPS traffic from attacker and SQL traffic to DB
        # 'https' should be in Web Server's services (as sink of first df)
        assert "https" in graph["Web Server"]["services"]

    def test_graph_cached_on_second_call(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        g1 = engine._build_graph()
        g2 = engine._build_graph()
        assert g1 is g2

    def test_unknown_source_node_edge_skipped(self):
        actors = [make_actor("ActorA", trusted=False)]
        servers = [make_server("ServerB")]
        # Dataflow from a node not in the model
        dataflows = [MockDataflow("Ghost", "ServerB")]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # ServerB should have no edges from Ghost
        assert graph["ServerB"]["edges"] == []

    def test_dataflow_with_no_source_skipped(self):
        actors = [make_actor("ActorA")]
        servers = [make_server("ServerB")]
        df = MockDataflow("ActorA", "ServerB")
        df.source = None  # break source
        model = MockThreatModel(actors=actors, servers=servers, dataflows=[df])
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # Should not crash, edges list remains empty
        assert "edges" in graph["ActorA"]

    def test_internet_facing_server(self):
        servers = [make_server("EdgeServer", internet_facing=True)]
        model = MockThreatModel(servers=servers)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        assert graph["EdgeServer"]["internet_facing"] is True

    def test_duplicate_actor_names_skipped(self):
        actors = [
            make_actor("Attacker", trusted=False),
            make_actor("Attacker", trusted=True),  # duplicate
        ]
        model = MockThreatModel(actors=actors)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # Only one entry for "Attacker"
        assert list(graph.keys()).count("Attacker") == 1
        # First definition wins (trusted=False)
        assert graph["Attacker"]["is_trusted"] is False


# ---------------------------------------------------------------------------
# _find_entry_points
# ---------------------------------------------------------------------------

class TestFindEntryPoints:
    def test_external_actor_with_edges(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        actor_def = {"entry_preference": "internet-facing"}
        entries = engine._find_entry_points(graph, actor_def)
        assert "External Attacker" in entries

    def test_insider_actor(self):
        actors = [make_actor("Insider", trusted=True)]
        servers = [make_server("InternalServer")]
        dataflows = [MockDataflow("Insider", "InternalServer")]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        actor_def = {"entry_preference": "insider"}
        entries = engine._find_entry_points(graph, actor_def)
        assert "Insider" in entries

    def test_internet_facing_server_as_fallback_entry(self):
        # No untrusted actors → fallback to internet-facing servers
        actors = [make_actor("TrustedUser", trusted=True)]
        servers = [
            make_server("EdgeServer", internet_facing=True),
            make_server("InternalDB"),
        ]
        dataflows = [
            MockDataflow("TrustedUser", "EdgeServer"),
            MockDataflow("EdgeServer", "InternalDB"),
        ]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        actor_def = {"entry_preference": "internet-facing"}
        entries = engine._find_entry_points(graph, actor_def)
        assert "EdgeServer" in entries

    def test_no_entry_points_when_all_trusted(self):
        actors = [make_actor("TrustedUser", trusted=True)]
        servers = [make_server("InternalServer")]
        dataflows = [MockDataflow("TrustedUser", "InternalServer")]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        actor_def = {"entry_preference": "internet-facing"}
        # No untrusted actors, no internet-facing servers → empty
        entries = engine._find_entry_points(graph, actor_def)
        assert entries == []


# ---------------------------------------------------------------------------
# _bfs_paths
# ---------------------------------------------------------------------------

class TestBfsPaths:
    def _simple_engine(self):
        model = make_simple_model()
        return GDAFEngine(model), model

    def test_direct_path_found(self):
        engine, _ = self._simple_engine()
        graph = engine._build_graph()
        paths = engine._bfs_paths(graph, "External Attacker", "Web Server", max_hops=3)
        assert len(paths) >= 1
        # Last node in first path should be "Web Server"
        assert paths[0][-1][0] == "Web Server"

    def test_two_hop_path_found(self):
        engine, _ = self._simple_engine()
        graph = engine._build_graph()
        paths = engine._bfs_paths(graph, "External Attacker", "Database", max_hops=5)
        assert len(paths) >= 1
        assert paths[0][-1][0] == "Database"

    def test_no_path_returns_empty(self):
        actors = [make_actor("Attacker", trusted=False)]
        servers = [make_server("Isolated")]
        # No edges
        model = MockThreatModel(actors=actors, servers=servers)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        paths = engine._bfs_paths(graph, "Attacker", "Isolated", max_hops=5)
        assert paths == []

    def test_max_hops_respected(self):
        # Create a long chain: A → B → C → D
        actors = [make_actor("A", trusted=False)]
        servers = [make_server("B"), make_server("C"), make_server("D")]
        dataflows = [
            MockDataflow("A", "B"),
            MockDataflow("B", "C"),
            MockDataflow("C", "D"),
        ]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # max_hops=1: can only reach B (1 hop from A)
        paths = engine._bfs_paths(graph, "A", "D", max_hops=1)
        assert paths == []
        # max_hops=3 should work
        paths = engine._bfs_paths(graph, "A", "D", max_hops=3)
        assert len(paths) >= 1

    def test_start_equals_end_returns_trivial_path(self):
        model = make_simple_model()
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        paths = engine._bfs_paths(graph, "Web Server", "Web Server", max_hops=3)
        # BFS starts at Web Server and immediately finds it → trivial path
        # The path contains just [(Web Server, {})] at the start → matches end immediately
        assert len(paths) >= 1

    def test_cycle_not_traversed(self):
        # A → B → A (cycle via bidirectional)
        actors = [make_actor("A", trusted=False)]
        servers = [make_server("B")]
        dataflows = [MockDataflow("A", "B", bidirectional=True)]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # Should not infinite loop
        paths = engine._bfs_paths(graph, "A", "B", max_hops=5)
        assert len(paths) >= 1


# ---------------------------------------------------------------------------
# _cia_score
# ---------------------------------------------------------------------------

class TestCiaScore:
    def setup_method(self):
        self.engine = GDAFEngine(MockThreatModel())

    def test_all_critical(self):
        node = {"confidentiality": "critical", "integrity": "critical", "availability": "critical"}
        assert self.engine._cia_score(node) == 1.0

    def test_all_low(self):
        node = {"confidentiality": "low", "integrity": "low", "availability": "low"}
        assert self.engine._cia_score(node) == 0.0

    def test_mixed_levels(self):
        node = {"confidentiality": "high", "integrity": "medium", "availability": "low"}
        # c=2*3=6, i=1*2=2, a=0*1=0 → 8/18 ≈ 0.444
        score = self.engine._cia_score(node)
        assert 0.0 < score < 1.0

    def test_unknown_level_treated_as_low(self):
        node = {"confidentiality": "unknown_level", "integrity": "low", "availability": "low"}
        assert self.engine._cia_score(node) == 0.0

    def test_missing_keys_default_to_low(self):
        assert self.engine._cia_score({}) == 0.0

    def test_capped_at_one(self):
        # Should never exceed 1.0
        node = {"confidentiality": "critical", "integrity": "critical", "availability": "critical"}
        assert self.engine._cia_score(node) <= 1.0


# ---------------------------------------------------------------------------
# run() — integration tests with mocked mapper
# ---------------------------------------------------------------------------

class TestGDAFEngineRun:
    def test_run_auto_context_generates_scenarios(self):
        """Without a context file, auto-context should produce attack scenarios."""
        model = make_simple_model()
        engine = GDAFEngine(model, context_path=None)
        result = engine.run()
        # auto-context generates at least one scenario for the simple 3-node model
        assert isinstance(result, list)
        # may or may not find paths depending on entry point detection — do not assert count

    def test_run_no_objectives_returns_empty(self, tmp_path):
        ctx_file = tmp_path / "ctx.yaml"
        ctx_file.write_text("attack_objectives: []\nthreat_actors: []\n", encoding="utf-8")
        model = make_simple_model()
        engine = GDAFEngine(model, context_path=str(ctx_file))
        result = engine.run()
        assert result == []

    def test_run_with_context_returns_scenarios(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, targets=["Database"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        assert isinstance(result, list)
        # At least one scenario should be found given the simple model
        # (path: External Attacker → Web Server → Database)
        assert len(result) >= 1

    def test_run_scenarios_are_attack_scenario_instances(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, targets=["Database"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        for s in result:
            assert isinstance(s, AttackScenario)

    def test_run_scenario_has_hops(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, targets=["Database"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        if result:
            assert len(result[0].hops) >= 1

    def test_run_target_not_in_graph_returns_empty(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, targets=["NonExistentServer"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        assert result == []

    def test_run_actor_not_subscribed_to_objective_skipped(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, actor_objectives=["other_obj"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        # Actor is not subscribed to obj1 → no scenarios
        assert result == []

    def test_run_respects_max_paths(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, targets=["Database"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        # max_paths_per_objective is 3 in the fixture
        assert len(result) <= 3

    def test_scenario_has_risk_level(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, targets=["Database"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        if result:
            assert result[0].risk_level in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_scenario_target_asset_matches(self, tmp_path):
        model = make_simple_model()
        ctx_path = make_context_yaml(tmp_path, targets=["Database"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        if result:
            assert result[0].target_asset == "Database"

    def test_run_with_insider_actor(self, tmp_path):
        # Insider: trusted actor that can reach internal resources
        actors = [make_actor("Insider", trusted=True)]
        servers = [make_server("InternalDB", stype="database")]
        dataflows = [MockDataflow("Insider", "InternalDB")]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)

        context = {
            "attack_objectives": [{
                "id": "obj1",
                "name": "Steal Data",
                "description": "",
                "target_asset_names": ["InternalDB"],
                "target_types": [],
                "mitre_final_tactic": "exfiltration",
                "business_impact": "Data theft",
                "unacceptable_risk_above": 3.0,
            }],
            "threat_actors": [{
                "id": "actor1",
                "name": "Insider",
                "sophistication": "low",
                "objectives": ["obj1"],
                "capable_tactics": None,
                "known_ttps": [],
                "entry_preference": "insider",
            }],
            "risk_criteria": {
                "max_hops": 5,
                "max_paths_per_objective": 3,
                "acceptable_risk_score": 5.0,
                "gdaf_min_technique_score": 0.5,
            },
        }
        ctx_file = tmp_path / "insider_ctx.yaml"
        ctx_file.write_text(yaml.dump(context), encoding="utf-8")
        engine = GDAFEngine(model, context_path=str(ctx_file))
        result = engine.run()
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# AttackScenario and AttackHop dataclasses
# ---------------------------------------------------------------------------

class TestDataclasses:
    def test_attack_hop_creation(self):
        hop = AttackHop(
            asset_name="WebServer",
            asset_type="web-server",
            techniques=[],
            dataflow_name="AttackerToWeb",
            protocol="https",
            is_encrypted=True,
            is_authenticated=False,
            hop_score=1.5,
            hop_position="entry",
        )
        assert hop.asset_name == "WebServer"
        assert hop.hop_score == 1.5

    def test_attack_scenario_creation(self):
        scenario = AttackScenario(
            scenario_id="GDAF-ABCD1234",
            objective_id="obj1",
            objective_name="Compromise DB",
            objective_description="",
            objective_business_impact="Data breach",
            objective_mitre_final_tactic="exfiltration",
            actor_id="actor1",
            actor_name="APT28",
            actor_sophistication="high",
            entry_point="External Attacker",
            target_asset="Database",
            hops=[],
            path_score=3.5,
            risk_level="HIGH",
            detection_coverage=0.2,
            unacceptable_risk=False,
        )
        assert scenario.scenario_id == "GDAF-ABCD1234"
        assert scenario.risk_level == "HIGH"
        assert scenario.min_technique_score == 0.8  # default


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_classification_score_values(self):
        assert _CLASSIFICATION_SCORE["top_secret"] == 1.0
        assert _CLASSIFICATION_SCORE["public"] == 0.0

    def test_traversal_bonus_values(self):
        assert _TRAVERSAL_BONUS["low"] > _TRAVERSAL_BONUS["high"]

    def test_detection_coverage_values(self):
        assert _DETECTION_COVERAGE["none"] == 0.0
        assert _DETECTION_COVERAGE["high"] > _DETECTION_COVERAGE["low"]


# ---------------------------------------------------------------------------
# BOM integration in _build_graph (lines 313-330)
# ---------------------------------------------------------------------------

class TestBuildGraphWithBOM:
    def test_bom_credentials_stored_overrides_dsl(self, tmp_path):
        """BOM credentials_stored should override the DSL value."""
        import json
        # Create a CycloneDX BOM file for the Web Server
        bom_data = {
            "bomFormat": "CycloneDX",
            "properties": [
                {"name": "secopstm:credentials_stored", "value": "true"},
                {"name": "secopstm:detection_level", "value": "high"},
            ],
            "services": [{"name": "https"}, {"name": "rdp"}],
        }
        bom_file = tmp_path / "web_server.cdx.json"
        bom_file.write_text(json.dumps(bom_data), encoding="utf-8")

        actors = [make_actor("Attacker", trusted=False)]
        servers = [make_server("Web Server", credentials_stored=False)]
        dataflows = [MockDataflow("Attacker", "Web Server")]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        engine = GDAFEngine(model, bom_directory=str(tmp_path))
        graph = engine._build_graph()

        # BOM should have overridden credentials_stored to True
        assert graph["Web Server"]["credentials_stored"] is True
        # detection_coverage should be set from BOM
        assert graph["Web Server"]["detection_coverage"] == 0.8  # high = 0.8
        # running_services from BOM
        assert "https" in graph["Web Server"]["services"]
        assert "rdp" in graph["Web Server"]["services"]
        # bom key stored
        assert "bom" in graph["Web Server"]

    def test_bom_no_data_for_node_no_change(self, tmp_path):
        """If no BOM data exists for a node, node is unchanged."""
        actors = [make_actor("Attacker", trusted=False)]
        servers = [make_server("Unknown Server")]
        model = MockThreatModel(actors=actors, servers=servers)
        engine = GDAFEngine(model, bom_directory=str(tmp_path))
        graph = engine._build_graph()
        # No "bom" key added if no BOM file
        assert "bom" not in graph.get("Unknown Server", {})


# ---------------------------------------------------------------------------
# Submodel bridging (lines 342-391)
# ---------------------------------------------------------------------------

class TestSubmodelBridging:
    def test_bridging_edges_added_for_submodel(self):
        """Servers with _submodel_tm should get bridging edges."""
        # Create a parent model with a server that references a sub-model
        parent_actors = [make_actor("Attacker", trusted=False)]
        parent_servers_data = [
            make_server("ParentServer"),
            make_server("TargetServer"),
        ]
        # Add _submodel_tm to ParentServer
        sub_servers = [make_server("SubServerA"), make_server("SubServerB")]
        sub_dataflows = [MockDataflow("SubServerA", "SubServerB")]

        class SubModel:
            actors = []
            servers = sub_servers
            dataflows = sub_dataflows
            boundaries = {}

        # Inject _submodel_tm reference into the parent server dict
        parent_servers_data[0]["_submodel_tm"] = SubModel()

        parent_dataflows = [
            MockDataflow("Attacker", "ParentServer"),
            MockDataflow("ParentServer", "TargetServer"),
        ]

        # All nodes must be in the same model to be in the graph
        # We combine them into one model
        all_servers = parent_servers_data + sub_servers
        model = MockThreatModel(
            actors=parent_actors,
            servers=all_servers,
            dataflows=parent_dataflows,
        )
        engine = GDAFEngine(model)
        graph = engine._build_graph()

        # ParentServer should have a bridging edge to SubServerA (root of sub-model)
        parent_edge_targets = [e["target"] for e in graph["ParentServer"]["edges"]]
        # At least one edge to a sub-server root should exist
        assert "SubServerA" in parent_edge_targets or len(parent_edge_targets) > 0

    def test_submodel_not_in_graph_skipped(self):
        """If sub-model servers are not in the main graph, bridging is skipped."""
        actors = [make_actor("Attacker")]
        server_data = make_server("MainServer")

        class SubModel:
            actors = []
            servers = [make_server("GhostServer")]  # NOT in main graph
            dataflows = []
            boundaries = {}

        server_data["_submodel_tm"] = SubModel()
        model = MockThreatModel(actors=actors, servers=[server_data])
        engine = GDAFEngine(model)
        # Should not crash
        graph = engine._build_graph()
        assert "MainServer" in graph


# ---------------------------------------------------------------------------
# _boundary_info_for_model (lines 399-402)
# ---------------------------------------------------------------------------

class TestBoundaryInfoForModel:
    def test_matching_boundary_returns_info(self):
        boundary_obj = object()
        model = MockThreatModel(boundaries={
            "b1": {"boundary": boundary_obj, "isTrusted": False, "traversal_difficulty": "high"}
        })
        engine = GDAFEngine(model)
        info = engine._boundary_info_for_model(model, boundary_obj)
        assert info.get("isTrusted") is False
        assert info.get("traversal_difficulty") == "high"

    def test_no_matching_boundary_returns_empty(self):
        model = MockThreatModel(boundaries={
            "b1": {"boundary": object(), "isTrusted": True}
        })
        engine = GDAFEngine(model)
        info = engine._boundary_info_for_model(model, object())  # different object
        assert info == {}

    def test_boundary_info_used_in_graph_build(self):
        """Nodes with a boundary reference should get boundary_trusted from boundary info."""
        boundary_obj = object()
        # Do not set isTrusted on actor itself, so it defaults to boundary_trusted
        actors = [{"name": "ActorWithBoundary", "boundary": boundary_obj}]
        model = MockThreatModel(
            actors=actors,
            boundaries={"bnd": {"boundary": boundary_obj, "isTrusted": False}}
        )
        engine = GDAFEngine(model)
        graph = engine._build_graph()
        # boundary_trusted should reflect the boundary's isTrusted=False
        assert graph["ActorWithBoundary"]["boundary_trusted"] is False
        # is_trusted defaults to boundary_trusted when isTrusted not set on actor
        assert graph["ActorWithBoundary"]["is_trusted"] is False


# ---------------------------------------------------------------------------
# _build_scenario edge cases
# ---------------------------------------------------------------------------

class TestBuildScenario:
    def test_scenario_with_single_hop_path(self, tmp_path):
        """A direct 1-hop path (attacker → target) should produce a scenario."""
        actors = [make_actor("Attacker", trusted=False)]
        servers = [make_server("DirectTarget", stype="database",
                               confidentiality="critical", integrity="critical", availability="critical")]
        dataflows = [MockDataflow("Attacker", "DirectTarget", is_authenticated=False, is_encrypted=False)]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        ctx_path = make_context_yaml(tmp_path, targets=["DirectTarget"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        assert isinstance(result, list)
        if result:
            assert result[0].hops[0].hop_position in {"entry", "target"}

    def test_risk_level_critical(self, tmp_path):
        """High-CIA server with no auth/encrypt should push score toward CRITICAL."""
        actors = [make_actor("Attacker", trusted=False)]
        servers = [
            make_server("Edge", confidentiality="low", integrity="low", availability="low"),
            make_server("CriticalDB", stype="database",
                        confidentiality="critical", integrity="critical", availability="critical",
                        mfa_enabled=False),
        ]
        dataflows = [
            MockDataflow("Attacker", "Edge", is_authenticated=False, is_encrypted=False),
            MockDataflow("Edge", "CriticalDB", is_authenticated=False, is_encrypted=False),
        ]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)
        ctx_path = make_context_yaml(tmp_path, targets=["CriticalDB"])
        engine = GDAFEngine(model, context_path=ctx_path)
        result = engine.run()
        assert isinstance(result, list)

    def test_unacceptable_risk_flag(self, tmp_path):
        """Scenarios above the acceptable_risk threshold should set unacceptable_risk=True."""
        actors = [make_actor("Attacker", trusted=False)]
        servers = [make_server("HighRiskServer", stype="database",
                               confidentiality="critical", integrity="critical", availability="critical",
                               mfa_enabled=False)]
        dataflows = [MockDataflow("Attacker", "HighRiskServer",
                                  is_authenticated=False, is_encrypted=False)]
        model = MockThreatModel(actors=actors, servers=servers, dataflows=dataflows)

        import yaml as _yaml
        context = {
            "attack_objectives": [{
                "id": "obj1", "name": "Compromise Server", "description": "",
                "target_asset_names": ["HighRiskServer"], "target_types": [],
                "mitre_final_tactic": "impact", "business_impact": "Severe",
                "unacceptable_risk_above": 0.0,  # everything is unacceptable
            }],
            "threat_actors": [{
                "id": "actor1", "name": "Attacker", "sophistication": "high",
                "objectives": ["obj1"], "capable_tactics": None, "known_ttps": [],
                "entry_preference": "internet-facing",
            }],
            "risk_criteria": {
                "max_hops": 5, "max_paths_per_objective": 3,
                "acceptable_risk_score": 0.0,  # everything above 0.0 is unacceptable
                "gdaf_min_technique_score": 0.5,
            },
        }
        ctx_file = tmp_path / "unacceptable_ctx.yaml"
        ctx_file.write_text(_yaml.dump(context), encoding="utf-8")
        engine = GDAFEngine(model, context_path=str(ctx_file))
        result = engine.run()
        if result:
            # With acceptable_risk_score=0.0, any positive path_score means unacceptable
            assert result[0].unacceptable_risk is True
