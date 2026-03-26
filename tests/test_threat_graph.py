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

"""Tests for ReportGenerator._build_threat_graph_data."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from threat_analysis.generation.report_generator import ReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_rg() -> ReportGenerator:
    rg = object.__new__(ReportGenerator)
    rg.ai_provider = None
    rg.ai_context = None
    return rg


def _make_actor(name: str, boundary=None) -> dict:
    obj = SimpleNamespace(name=name)
    return {"name": name, "object": obj, "boundary": boundary}


def _make_server(name: str, boundary=None) -> dict:
    obj = SimpleNamespace(name=name)
    return {"name": name, "object": obj, "boundary": boundary}


def _make_df(src_name: str, dst_name: str, protocol: str = "",
             encrypted: bool = False, authenticated: bool = False) -> SimpleNamespace:
    src = SimpleNamespace(name=src_name)
    dst = SimpleNamespace(name=dst_name)
    return SimpleNamespace(
        source=src,
        sink=dst,
        protocol=protocol,
        is_encrypted=encrypted,
        is_authenticated=authenticated,
        name=f"{src_name}->{dst_name}",
    )


def _make_model(actors=None, servers=None, dataflows=None) -> SimpleNamespace:
    return SimpleNamespace(
        actors=actors or [],
        servers=servers or [],
        dataflows=dataflows or [],
        boundaries={},
    )


def _make_threat(target: str, tid: str = "T-0001",
                 severity: str = "HIGH", stride: str = "Spoofing") -> dict:
    return {
        "id": tid,
        "name": "Test threat",
        "target": target,
        "severity": {"level": severity},
        "stride_category": stride,
        "source": "pytm",
    }


# ---------------------------------------------------------------------------
# Empty / no components
# ---------------------------------------------------------------------------

class TestEmptyModel:
    def test_no_components_returns_empty_dict(self):
        rg = _make_rg()
        result = rg._build_threat_graph_data(_make_model(), [])
        assert result == {}

    def test_no_threats_returns_nodes_and_edges(self):
        rg = _make_rg()
        m = _make_model(
            actors=[_make_actor("Browser")],
            servers=[_make_server("API")],
            dataflows=[_make_df("Browser", "API")],
        )
        result = rg._build_threat_graph_data(m, [])
        assert len(result["nodes"]) == 2
        assert len(result["edges"]) == 1


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------

class TestNodes:
    def test_actors_and_servers_become_nodes(self):
        rg = _make_rg()
        m = _make_model(
            actors=[_make_actor("User")],
            servers=[_make_server("WebApp"), _make_server("DB")],
        )
        result = rg._build_threat_graph_data(m, [])
        ids = {n["id"] for n in result["nodes"]}
        assert ids == {"User", "WebApp", "DB"}

    def test_node_type_set_correctly(self):
        rg = _make_rg()
        m = _make_model(
            actors=[_make_actor("User")],
            servers=[_make_server("WebApp")],
        )
        result = rg._build_threat_graph_data(m, [])
        types = {n["id"]: n["type"] for n in result["nodes"]}
        assert types["User"] == "Actor"
        assert types["WebApp"] == "Server"

    def test_duplicate_names_deduplicated(self):
        rg = _make_rg()
        m = _make_model(
            actors=[_make_actor("Shared")],
            servers=[_make_server("Shared")],
        )
        result = rg._build_threat_graph_data(m, [])
        assert len(result["nodes"]) == 1

    def test_node_severity_from_threats(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        threats = [_make_threat("WebApp", severity="CRITICAL")]
        result = rg._build_threat_graph_data(m, threats)
        node = next(n for n in result["nodes"] if n["id"] == "WebApp")
        assert node["severity"] == "CRITICAL"

    def test_node_with_no_threats_has_empty_severity(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        result = rg._build_threat_graph_data(m, [])
        node = next(n for n in result["nodes"] if n["id"] == "WebApp")
        assert node["severity"] == ""

    def test_node_highest_severity_wins(self):
        """When a node has HIGH and CRITICAL threats, severity=CRITICAL."""
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        threats = [
            _make_threat("WebApp", tid="T-0001", severity="HIGH"),
            _make_threat("WebApp", tid="T-0002", severity="CRITICAL"),
        ]
        result = rg._build_threat_graph_data(m, threats)
        node = next(n for n in result["nodes"] if n["id"] == "WebApp")
        assert node["severity"] == "CRITICAL"

    def test_n_threats_count(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        threats = [
            _make_threat("WebApp", tid="T-0001"),
            _make_threat("WebApp", tid="T-0002"),
            _make_threat("WebApp", tid="T-0003"),
        ]
        result = rg._build_threat_graph_data(m, threats)
        node = next(n for n in result["nodes"] if n["id"] == "WebApp")
        assert node["n_threats"] == 3

    def test_boundary_name_propagated(self):
        rg = _make_rg()
        bnd = SimpleNamespace(name="DMZ")
        m = _make_model(servers=[_make_server("WebApp", boundary=bnd)])
        result = rg._build_threat_graph_data(m, [])
        node = next(n for n in result["nodes"] if n["id"] == "WebApp")
        assert node["boundary"] == "DMZ"


# ---------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------

class TestEdges:
    def test_dataflow_becomes_edge(self):
        rg = _make_rg()
        m = _make_model(
            actors=[_make_actor("Browser")],
            servers=[_make_server("API")],
            dataflows=[_make_df("Browser", "API", protocol="HTTPS", encrypted=True)],
        )
        result = rg._build_threat_graph_data(m, [])
        assert len(result["edges"]) == 1
        e = result["edges"][0]
        assert e["source"] == "Browser"
        assert e["target"] == "API"
        assert e["protocol"] == "HTTPS"
        assert e["encrypted"] is True

    def test_multiple_edges(self):
        rg = _make_rg()
        m = _make_model(
            actors=[_make_actor("User")],
            servers=[_make_server("A"), _make_server("B")],
            dataflows=[_make_df("User", "A"), _make_df("A", "B")],
        )
        result = rg._build_threat_graph_data(m, [])
        assert len(result["edges"]) == 2

    def test_dataflow_without_source_or_sink_name_skipped(self):
        rg = _make_rg()
        df = SimpleNamespace(source=None, sink=None,
                              protocol="", is_encrypted=False,
                              is_authenticated=False, name="x")
        m = _make_model(
            servers=[_make_server("A")],
            dataflows=[df],
        )
        result = rg._build_threat_graph_data(m, [])
        assert len(result["edges"]) == 0

    def test_encrypted_flag_on_edge(self):
        rg = _make_rg()
        m = _make_model(
            servers=[_make_server("A"), _make_server("B")],
            dataflows=[_make_df("A", "B", encrypted=True)],
        )
        result = rg._build_threat_graph_data(m, [])
        assert result["edges"][0]["encrypted"] is True

    def test_authenticated_flag_on_edge(self):
        rg = _make_rg()
        m = _make_model(
            servers=[_make_server("A"), _make_server("B")],
            dataflows=[_make_df("A", "B", authenticated=True)],
        )
        result = rg._build_threat_graph_data(m, [])
        assert result["edges"][0]["authenticated"] is True


# ---------------------------------------------------------------------------
# threats_by_node
# ---------------------------------------------------------------------------

class TestThreatsByNode:
    def test_threats_indexed_by_target(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        threats = [_make_threat("WebApp", tid="T-0001")]
        result = rg._build_threat_graph_data(m, threats)
        assert "WebApp" in result["threats_by_node"]
        assert result["threats_by_node"]["WebApp"][0]["id"] == "T-0001"

    def test_unspecified_target_excluded(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        threats = [
            {"id": "T-0001", "name": "x", "target": "Unspecified",
             "severity": {"level": "HIGH"}, "stride_category": "Spoofing", "source": "pytm"},
            _make_threat("WebApp", tid="T-0002"),
        ]
        result = rg._build_threat_graph_data(m, threats)
        assert "Unspecified" not in result["threats_by_node"]

    def test_threats_capped_at_20_per_node(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("BigServer")])
        threats = [_make_threat("BigServer", tid=f"T-{i:04d}") for i in range(30)]
        result = rg._build_threat_graph_data(m, threats)
        assert len(result["threats_by_node"]["BigServer"]) == 20

    def test_threats_sorted_by_severity_desc(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        threats = [
            _make_threat("WebApp", tid="T-0001", severity="LOW"),
            _make_threat("WebApp", tid="T-0002", severity="CRITICAL"),
            _make_threat("WebApp", tid="T-0003", severity="HIGH"),
        ]
        result = rg._build_threat_graph_data(m, threats)
        sevs = [t["sev"] for t in result["threats_by_node"]["WebApp"]]
        assert sevs[0] == "CRITICAL"

    def test_threat_name_truncated_at_80(self):
        rg = _make_rg()
        m = _make_model(servers=[_make_server("WebApp")])
        long_name = "A" * 100
        threat = {"id": "T-0001", "name": long_name, "target": "WebApp",
                  "severity": {"level": "HIGH"}, "stride_category": "Spoofing", "source": "pytm"}
        result = rg._build_threat_graph_data(m, [threat])
        stored = result["threats_by_node"]["WebApp"][0]["name"]
        assert len(stored) <= 80
