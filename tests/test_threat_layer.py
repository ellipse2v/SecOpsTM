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

"""Threat layer of the HTML diagram (threat badges toggled from the legend)."""

import json
import re
from types import SimpleNamespace

import pytest

from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.generation.threat_layer import (
    MAX_THREATS_PER_ELEMENT,
    build_threat_layer,
)


def _model():
    web = SimpleNamespace(name="Web Server")
    db = SimpleNamespace(name="1st DB")
    user = SimpleNamespace(name="User")
    return SimpleNamespace(
        boundaries={"DMZ": {}},
        actors=[{"name": "User", "object": user}],
        servers=[{"name": "Web Server", "object": web}, {"name": "1st DB", "object": db}],
        dataflows=[
            SimpleNamespace(name="Login", source=user, sink=web),
            SimpleNamespace(name="Query", source=web, sink=db),
        ],
    )


def _threat(target, level, score=5.0, tid="", desc="t", stride="Tampering"):
    return {"id": tid, "target": target, "description": desc, "stride_category": stride,
            "severity": {"level": level, "score": score}, "source": "pytm"}


def test_threats_land_on_the_svg_ids_of_their_elements():
    layer = build_threat_layer(_model(), [
        _threat("Web Server", "HIGH"),
        _threat("1st DB", "LOW"),
        _threat("DMZ", "MEDIUM"),
        _threat("User → Web Server", "CRITICAL"),
        _threat("Web Server -> 1st DB", "MEDIUM"),
        _threat("Query", "LOW"),
    ])
    assert set(layer) == {"Web_Server", "_1st_DB", "cluster_DMZ",
                          "edge_User_Web_Server", "edge_Web_Server__1st_DB"}
    assert layer["cluster_DMZ"]["kind"] == "boundary"
    assert layer["edge_User_Web_Server"]["kind"] == "dataflow"
    assert layer["edge_User_Web_Server"]["label"] == "User → Web Server"
    # "Web Server -> 1st DB" and the dataflow named "Query" are the same edge.
    edge = layer["edge_Web_Server__1st_DB"]
    assert edge["total"] == 2 and edge["max"] == "MEDIUM"
    assert edge["counts"] == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 1}


def test_counts_max_and_worst_first_order():
    layer = build_threat_layer(_model(), [
        _threat("Web Server", "LOW", 2.0, "T-0003"),
        _threat("Web Server", "CRITICAL", 9.5, "T-0001"),
        _threat("Web Server", "HIGH", 7.1, "T-0004"),
        _threat("Web Server", "HIGH", 8.0, "T-0002"),
    ])
    entry = layer["Web_Server"]
    assert entry["total"] == 4
    assert entry["max"] == "CRITICAL"
    assert [t["id"] for t in entry["threats"]] == ["T-0001", "T-0002", "T-0004", "T-0003"]
    assert entry["anchor"] == "component-Web_Server"


def test_unknown_targets_and_unscored_threats_are_skipped():
    layer = build_threat_layer(_model(), [
        _threat("Unspecified", "HIGH"),
        _threat("Not in model", "HIGH"),
        {"target": "Web Server", "severity": {}},
        "not a dict",
    ])
    assert layer == {}


def test_severity_fallbacks():
    layer = build_threat_layer(_model(), [
        _threat("Web Server", "INFORMATIONAL", 1.0),
        {"target": "Web Server", "severity": {"score": 9.2}},
        {"target": "Web Server", "severity": "medium"},
        {"target": "Web Server", "impact": 4},
    ])
    assert layer["Web_Server"]["counts"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}


def test_flow_without_drawn_edge_is_pinned_on_its_source():
    layer = build_threat_layer(_model(), [_threat("User → 1st DB", "HIGH")])
    assert list(layer) == ["User"]


def test_threat_list_is_capped_but_counts_are_not():
    threats = [_threat("Web Server", "LOW", tid=f"T-{i:04d}") for i in range(MAX_THREATS_PER_ELEMENT + 5)]
    entry = build_threat_layer(_model(), threats)["Web_Server"]
    assert entry["total"] == MAX_THREATS_PER_ELEMENT + 5
    assert len(entry["threats"]) == MAX_THREATS_PER_ELEMENT


def test_long_titles_are_truncated():
    entry = build_threat_layer(_model(), [_threat("Web Server", "LOW", desc="x" * 500)])["Web_Server"]
    assert len(entry["threats"][0]["title"]) <= 160


def test_defaults_to_the_report_threat_list():
    model = _model()
    model._report_all_detailed_threats = [_threat("Web Server", "HIGH", tid="T-0001", stride="Spoofing")]
    entry = build_threat_layer(model)["Web_Server"]
    assert entry["threats"][0]["id"] == "T-0001"
    assert entry["threats"][0]["stride"] == "Spoofing"


def test_default_survives_a_model_without_threat_details():
    model = _model()
    model.get_all_threats_details = lambda: (_ for _ in ()).throw(RuntimeError("no analysis"))
    assert build_threat_layer(model) == {}


# --- HTML wiring ---------------------------------------------------------------------

def _layer_json_in(html_out: str) -> dict:
    m = re.search(r"state\.layer = JSON\.parse\((\".*?\")\) \|\| \{\}", html_out)
    assert m, "threat layer data not injected"
    return json.loads(json.loads(m.group(1)))


@pytest.mark.parametrize("template_name", ["diagram_template.html", "navigable_diagram_template.html"])
def test_templates_embed_the_layer_and_panel(template_name):
    gen = DiagramGenerator()
    layer = build_threat_layer(_model(), [_threat("Web Server", "HIGH", desc="</script><b>x</b>")])
    html_out = gen.template_env.get_template(template_name).render(
        title="t", svg_content="<svg></svg>", legend_html=gen._generate_legend_html(_model()),
        graph_metadata_json="{}", severity_map_json="{}", report_url="r.html",
        threat_layer_json=json.dumps(layer), breadcrumb=[], parent_link=None, current_dir_depth=0,
    )
    assert 'id="threat-panel"' in html_out
    assert 'id="threat-layer-toggle"' in html_out
    assert html_out.count('class="legend-item threat-sev-filter"') == 4
    assert "window.refreshThreatBadges()" in html_out
    # Model text cannot close the script block it is embedded in.
    assert "</script><b>" not in html_out
    assert _layer_json_in(html_out) == layer


def test_create_complete_html_passes_the_layer():
    gen = DiagramGenerator()
    layer = build_threat_layer(_model(), [_threat("DMZ", "LOW")])
    html_out = gen._create_complete_html("<svg></svg>", "", _model(), threat_layer=layer)
    assert _layer_json_in(html_out) == layer


def test_create_complete_html_without_layer_is_empty():
    html_out = DiagramGenerator()._create_complete_html("<svg></svg>", "", _model())
    assert _layer_json_in(html_out) == {}


def test_generate_html_with_legend_builds_layer_from_model(tmp_path):
    model = _model()
    model._report_all_detailed_threats = [_threat("Web Server", "CRITICAL")]
    svg = tmp_path / "d.svg"
    svg.write_text("<svg></svg>", encoding="utf-8")
    out = DiagramGenerator()._generate_html_with_legend(svg, tmp_path / "d.html", model)
    assert _layer_json_in(out.read_text(encoding="utf-8"))["Web_Server"]["max"] == "CRITICAL"


def test_editor_legend_has_no_threat_section():
    legend = DiagramGenerator()._generate_legend_html(_model(), show_severity_section=False)
    assert "threat-layer-toggle" not in legend


def test_boundary_keyed_lower_case_matches_its_cluster_and_original_name():
    model = _model()
    model.boundaries = {"public zone": {"original_name": "Public Zone"}}
    layer = build_threat_layer(model, [_threat("Public Zone", "HIGH")])
    assert list(layer) == ["cluster_public_zone"]
    assert layer["cluster_public_zone"]["label"] == "Public Zone"


def test_by_stride_counts_threats_per_category_and_severity():
    layer = build_threat_layer(_model(), [
        _threat("Web Server", "HIGH", stride="Spoofing"),
        _threat("Web Server", "LOW", stride="Spoofing"),
        _threat("Web Server", "HIGH", stride="information_disclosure"),
        _threat("Web Server", "MEDIUM", stride="Prompt injection"),
        _threat("Web Server", "LOW", stride=""),
    ])
    entry = layer["Web_Server"]
    assert entry["by_stride"] == {
        "Spoofing": {"HIGH": 1, "LOW": 1},
        "Information Disclosure": {"HIGH": 1},
        "Other": {"MEDIUM": 1, "LOW": 1},
    }
    # The panel shows the normalized category, the one the legend filters on.
    assert {t["stride"] for t in entry["threats"]} == {"Spoofing", "Information Disclosure", "Other"}


def test_legend_has_one_stride_chip_per_category():
    legend = DiagramGenerator()._generate_legend_html(_model())
    chips = re.findall(r'class="threat-stride-filter" data-stride="([^"]+)"', legend)
    assert chips == ["Spoofing", "Tampering", "Repudiation", "Information Disclosure",
                     "Denial of Service", "Elevation of Privilege"]


def test_reverse_flows_merged_into_one_arrow_share_its_badge():
    model = _model()
    user, web = model.dataflows[0].source, model.dataflows[0].sink
    model.dataflows[0].protocol = "HTTPS"
    model.dataflows.append(SimpleNamespace(name="Reply", source=web, sink=user, protocol="HTTPS"))
    layer = build_threat_layer(model, [_threat("Login", "HIGH"), _threat("Reply", "LOW")])
    assert list(layer) == ["edge_User_Web_Server"]
    assert layer["edge_User_Web_Server"]["total"] == 2
    assert layer["edge_User_Web_Server"]["label"] == "User ↔ Web Server"
