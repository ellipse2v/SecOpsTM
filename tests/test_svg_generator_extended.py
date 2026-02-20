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
import subprocess
from threat_analysis.generation.svg_generator import CustomSVGGenerator

@pytest.fixture
def generator():
    return CustomSVGGenerator()

def test_sanitize_name(generator):
    assert generator._sanitize_name("valid_name") == "valid_name"
    assert generator._sanitize_name("name with spaces") == "name_with_spaces"
    assert generator._sanitize_name("1name_starts_with_digit") == "_1name_starts_with_digit"
    assert generator._sanitize_name("") == "unnamed"
    assert generator._sanitize_name(None) == "unnamed"
    assert generator._sanitize_name("special-chars!@#$%^&*()") == "special_chars__________"

def test_generate_graph_json_from_dot_success(generator):
    with patch("subprocess.run") as mock_run:
        mock_run.return_value.stdout = '{"objects": []}'
        mock_run.return_value.returncode = 0
        result = generator._generate_graph_json_from_dot("dot code")
        assert result == {"objects": []}

def test_generate_graph_json_from_dot_failure(generator):
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, "cmd", stderr="error")
        result = generator._generate_graph_json_from_dot("dot code")
        assert result is None

def test_generate_node_svg_server_layout(generator):
    node = {
        "name": "server_node",
        "pos": "100,100",
        "width": "2", # 144 points
        "label": '<TABLE ALIGN="LEFT"><TR><TD>...IMG...</TD></TR></TABLE>',
        "_ldraw_": [
            {"op": "t", "align": "l", "pt": [100, 100], "text": "server"}
        ]
    }
    generator._generate_node_svg(node)
    # Check that the x coordinate of the text has been shifted
    assert node["_ldraw_"][0]["pt"][0] == 78.0

def test_generate_node_svg_y_offset(generator):
    node = {
        "name": "actor_node",
        "pos": "100,100",
        "shape": "circle",
        "label": 'Actor',
        "_ldraw_": [
            {"op": "t", "align": "c", "pos": [100, 100], "text": "actor"}
        ]
    }
    generator._generate_node_svg(node)
    # Check that the y coordinate of the text has been shifted down
    assert node["_ldraw_"][0]["pos"][1] < 100

def test_generate_edge_svg_protocol_class(generator):
    objects = [
        {"name": "a"},
        {"name": "b"}
    ]
    edge = {
        "tail": 0,
        "head": 1,
        "label": '<<TABLE><TR><TD>Protocol: HTTP</TD></TR></TABLE>>'
    }
    svg = generator._generate_edge_svg(edge, objects)
    assert 'class="edge protocol-HTTP"' in "".join(svg)

def test_convert_draw_op_to_svg(generator):
    style = {}
    # Test polyline
    op_l = {"op": "l", "points": [[0,0], [10,10]]}
    assert 'polyline' in generator._convert_draw_op_to_svg(op_l, style)
    # Test polygon
    op_p = {"op": "p", "points": [[0,0], [10,10], [0,10]]}
    assert 'polyline' in generator._convert_draw_op_to_svg(op_p, style)
    # Test missing points
    op_missing_points = {"op": "l"}
    assert generator._convert_draw_op_to_svg(op_missing_points, style) == ''
    # Test missing pos/pt/rect for text
    op_text_missing_pos = {"op": "t", "text": "hello"}
    assert generator._convert_draw_op_to_svg(op_text_missing_pos, style) == ''

def test_extract_image_from_html_label(generator):
    with patch.object(generator, "_load_image") as mock_load_image:
        # Test SVG extraction
        mock_load_image.return_value = '<svg width="50" height="50"></svg>'
        node_svg = {
            "label": '<IMG SRC="icon.svg"/>',
            "width": "2"
        }
        result_svg = generator._extract_image_from_html_label(node_svg, True, 100, 100)
        assert '<g transform' in result_svg
        assert 'scale(0.6,-0.6)' in result_svg # 30 / 50 = 0.6

        # Test Base64 extraction
        mock_load_image.return_value = 'data:image/png;base64,...'
        node_base64 = {
            "label": '<IMG SRC="icon.png"/>'
        }
        result_base64 = generator._extract_image_from_html_label(node_base64, False, 100, 100)
        assert '<image href="data:image/png;base64,..."' in result_base64

        # Test no image found
        node_no_image = {
            "label": 'no image'
        }
        result_no_image = generator._extract_image_from_html_label(node_no_image, False, 100, 100)
        assert result_no_image is None
