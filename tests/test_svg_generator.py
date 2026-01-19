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
from unittest.mock import patch, MagicMock
import json
import base64
from pathlib import Path

from threat_analysis.generation.svg_generator import CustomSVGGenerator

@pytest.fixture
def generator():
    return CustomSVGGenerator()

def test_generate_svg_from_dot_success(generator, tmp_path):
    """Test successful SVG generation from a simple DOT string."""
    dot_code = 'digraph G { a -> b; }'
    output_file = tmp_path / "output.svg"
    
    # Mock the subprocess call to dot
    mock_stdout = {
        "bb": "0,0,100,100",
        "objects": [
            {"name": "a", "pos": "25,50"},
            {"name": "b", "pos": "75,50"}
        ],
        "edges": [
            {"tail": 0, "head": 1, "_draw_": [{"op": "b", "points": [[25,50], [50,50], [75,50]]}]}
        ]
    }
    
    # Mock the _generate_graph_json_from_dot method to return our test data
    with patch.object(generator, '_generate_graph_json_from_dot', return_value=mock_stdout):
        result = generator.generate_svg_from_dot(dot_code, str(output_file))

    assert result == str(output_file)
    assert output_file.exists()
    svg_content = output_file.read_text()
    assert '<svg' in svg_content
    assert 'id="a"' in svg_content
    assert 'id="b"' in svg_content
    assert 'id="edge_0_1"' in svg_content

def test_generate_svg_from_dot_json_fail(generator, tmp_path):
    """Test failure when dot command fails to generate JSON."""
    dot_code = 'digraph G { a -> b; }'
    output_file = tmp_path / "output.svg"
    
    with patch.object(generator, '_generate_graph_json_from_dot', return_value=None):
        result = generator.generate_svg_from_dot(dot_code, str(output_file))
        assert result is None

def test_load_image(generator, tmp_path):
    """Test loading of different image types."""
    # Test with a dummy SVG file
    svg_file = tmp_path / "test.svg"
    svg_file.write_text("<svg></svg>")
    svg_content = generator._load_image(str(svg_file))
    assert svg_content == "<svg></svg>"

    # Test with a dummy PNG file
    png_file = tmp_path / "test.png"
    png_file.write_bytes(b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89')
    png_content = generator._load_image(str(png_file))
    assert png_content.startswith("data:image/png;base64,")

    # Test with a dummy JPG file
    jpg_file = tmp_path / "test.jpg"
    jpg_file.write_bytes(b'\xff\xd8\xff\xe0\x00\x10JFIF')
    jpg_content = generator._load_image(str(jpg_file))
    assert jpg_content.startswith("data:image/jpeg;base64,")

    # Test file not found
    content = generator._load_image("nonexistent.file")
    assert content is None

def test_node_with_image(generator, tmp_path):
    """Test generation of a node with an image."""
    # Create a dummy image file
    img_file = tmp_path / "icon.svg"
    img_file.write_text("<svg></svg>")

    mock_json = {
        "bb": "0,0,100,100",
        "objects": [
            {
                "name": "node_with_image",
                "pos": "50,50",
                "width": "1",
                "height": "1",
                "label": f'<<TABLE BORDER="0" CELLBORDER="0" CELLSPACING="0"><TR><TD WIDTH="30" HEIGHT="30" FIXEDSIZE="TRUE"><IMG SRC="{img_file}" SCALE="TRUE"/></TD></TR><TR><TD>Test Node</TD></TR></TABLE>>',
                "_ldraw_": [
                    {"op": "F", "size": 14.0, "face": "sans-serif"},
                    {"op": "c", "color": "#000000"},
                    {"op": "T", "pt": [50, 30], "align": "c", "width": 80, "text": "Test Node"}
                ]
            }
        ]
    }
    svg_content = generator._generate_svg(mock_json)
    assert f'<g id="{generator._escape_html("node_with_image")}"' in svg_content
    assert '<svg' in svg_content  # Should contain the inline SVG
    assert 'Test Node' in svg_content  # Should contain the text

def test_shapes_and_styles(generator):
    """Test rendering of different shapes and line styles."""
    mock_json = {
        "bb": "0,0,200,200",
        "objects": [
            {
                "name": "polygon_node", "pos": "50,50",
                "_draw_": [{"op": "P", "points": [[0,0],[50,0],[25,50]]}]
            },
            {
                "name": "ellipse_node", "pos": "150,150",
                "_draw_": [{"op": "E", "rect": [150,150,20,40]}]
            }
        ],
        "edges": [
            {
                "tail": 0, "head": 1,
                "_draw_": [
                    {"op": "S", "style": "dashed"},
                    {"op": "b", "points": [[50,50], [100,100], [150,150]]}
                ]
            }
        ]
    }
    svg_content = generator._generate_svg(mock_json)
    assert '<polygon' in svg_content
    assert '<ellipse' in svg_content
    assert 'stroke-dasharray="5,2"' in svg_content

def test_text_rendering(generator):
    """Test rendering of text labels."""
    mock_json = {
        "bb": "0,0,100,100",
        "objects": [
            {
                "name": "text_node", "pos": "50,50",
                "_ldraw_": [
                    {"op": "F", "size": 18.0, "face": "Arial"},
                    {"op": "c", "color": "#ff0000"},
                    {"op": "T", "pt": [50, 40], "align": "c", "width": 80, "text": "Hello"}
                ]
            }
        ]
    }
    svg_content = generator._generate_svg(mock_json)
    assert '<text' in svg_content
    assert 'font-family="Arial"' in svg_content
    assert 'font-size="18.0"' in svg_content
    assert 'fill="#ff0000"' in svg_content
    assert '>Hello</text>' in svg_content
