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
import json
from unittest.mock import MagicMock, patch

from threat_analysis.server.diagram_service import DiagramService

@pytest.fixture
def diagram_service():
    cve_service = MagicMock()
    diagram_generator = MagicMock()
    return DiagramService(cve_service, diagram_generator)

def test_update_diagram_logic_empty_markdown(diagram_service):
    with pytest.raises(ValueError, match="Markdown content is empty"):
        diagram_service.update_diagram_logic("")

@patch('threat_analysis.server.diagram_service.create_threat_model', return_value=None)
def test_update_diagram_logic_failed_threat_model_creation(mock_create_threat_model, diagram_service):
    with pytest.raises(RuntimeError, match="Failed to create threat model"):
        diagram_service.update_diagram_logic("some markdown")

@pytest.mark.parametrize("markdown_content", [
    "# Threat Model: Test\n## Boundaries\n- **B1**: description=\"desc\"\n## Actors\n- **A1**: boundary=B1\n## Servers\n- **S1**: boundary=B1\n## Dataflows\n- **F1**: from=A1, to=S1"
])
def test_markdown_to_json_for_gui(diagram_service, markdown_content):
    with patch('threat_analysis.server.diagram_service.create_threat_model') as mock_create:
        tm = MagicMock()
        b1 = MagicMock()
        b1.inBoundary = None
        tm.boundaries = {'b1': {'boundary': b1, 'description': 'desc'}}
        
        actor = MagicMock()
        actor.name = "A1"
        tm.actors = [{'object': actor, 'name': 'A1', 'boundary': b1}]
        
        server = MagicMock()
        server.name = "S1"
        tm.servers = [{'object': server, 'name': 'S1', 'boundary': b1}]
        
        tm.data_objects = {}
        
        df = MagicMock()
        df.source = actor
        df.sink = server
        df.name = "F1"
        df.protocol = "HTTPS"
        tm.dataflows = [df]
        
        mock_create.return_value = tm
        
        result = diagram_service.markdown_to_json_for_gui(markdown_content)
        
        assert len(result["boundaries"]) == 1
        assert len(result["actors"]) == 1
        assert len(result["servers"]) == 1
        assert len(result["dataflows"]) == 1
        assert result["dataflows"][0]["from"] == "A1"
        assert result["dataflows"][0]["to"] == "S1"

def test_extract_graph_metadata_for_frontend(diagram_service):
    tm = MagicMock()
    tm.boundaries = {'b1': {}}
    tm.actors = [{'name': 'A1'}]
    tm.servers = [{'name': 'S1'}]
    
    df = MagicMock()
    df.source.name = "A1"
    df.sink.name = "S1"
    df.name = "F1"
    df.protocol = "HTTPS"
    tm.dataflows = [df]
    
    metadata = diagram_service._extract_graph_metadata_for_frontend(tm)
    
    assert "cluster_b1" in metadata["nodes"]
    assert "A1" in metadata["nodes"]
    assert "S1" in metadata["nodes"]
    assert len(metadata["edges"]) == 1

@patch('subprocess.run')
def test_generate_positions_from_graphviz(mock_run, diagram_service):
    tm = MagicMock()
    diagram_service.diagram_generator._generate_manual_dot.return_value = "dot code"
    
    mock_run.return_value = MagicMock(stdout=json.dumps({"objects": []}))
    
    with patch('threat_analysis.server.diagram_service.GraphvizToJsonMetadataConverter') as mock_conv:
        mock_conv.return_value.convert.return_value = {"pos": "data"}
        positions = diagram_service._generate_positions_from_graphviz(tm)
        assert positions == {"pos": "data"}

def test_merge_with_ui_positions(diagram_service):
    base = {
        'boundaries': {'b1': {}},
        'actors': {'a1': {}},
        'servers': {'s1': {}},
        'dataflows': {'f1': {}}
    }
    ui = {
        'boundaries': {'b1': {'x': 10, 'y': 20, 'width': 100, 'height': 200}},
        'actors': {'a1': {'x': 30, 'y': 40}},
        'servers': {'s1': {'x': 50, 'y': 60}},
        'dataflows': {'f1': {'points': [1, 2, 3, 4]}}
    }
    
    merged = diagram_service._merge_with_ui_positions(base, ui)
    assert merged['boundaries']['b1']['x'] == 10
    assert merged['actors']['a1']['x'] == 30
    assert merged['servers']['s1']['x'] == 50
    assert merged['dataflows']['f1']['points'] == [1, 2, 3, 4]

def test_get_element_positions(diagram_service):
    diagram_service.element_positions = {"a": 1}
    assert diagram_service.get_element_positions() == {"a": 1}

@patch('threat_analysis.server.diagram_service.create_threat_model')
def test_update_diagram_logic_success(mock_create, diagram_service):
    tm = MagicMock()
    mock_create.return_value = tm
    diagram_service.diagram_generator._generate_manual_dot.return_value = "dot code"
    diagram_service.diagram_generator.generate_diagram_from_dot.return_value = "path/to/svg"
    diagram_service.diagram_generator._generate_legend_html.return_value = "legend"
    diagram_service.diagram_generator._create_complete_html.return_value = "html"
    
    with patch("builtins.open", MagicMock()):
        with patch("os.path.exists", return_value=True):
            with patch.object(diagram_service, '_generate_positions_from_graphviz', return_value={}):
                result = diagram_service.update_diagram_logic("markdown")
                assert result["diagram_html"] == "html"
