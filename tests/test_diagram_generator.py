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
# 

import pytest
from unittest.mock import MagicMock, patch, mock_open
import subprocess

from threat_analysis.generation.diagram_generator import DiagramGenerator

@pytest.fixture
def diagram_generator():
    return DiagramGenerator()

def test_check_graphviz_installation_success(diagram_generator):
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        assert diagram_generator.check_graphviz_installation() is True

def test_check_graphviz_installation_failure_filenotfound(diagram_generator):
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = FileNotFoundError
        assert diagram_generator.check_graphviz_installation() is False

def test_check_graphviz_installation_failure_calledprocesserror(diagram_generator):
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, 'dot')
        assert diagram_generator.check_graphviz_installation() is False

def test_get_installation_instructions(diagram_generator):
    instructions = diagram_generator.get_installation_instructions()
    assert "Graphviz 'dot' command not found" in instructions
    assert "Windows:" in instructions
    assert "macOS:" in instructions
    assert "Linux (Ubuntu/Debian):" in instructions

def test_sanitize_name(diagram_generator):
    assert diagram_generator._sanitize_name("My Test Name") == "My_Test_Name"
    assert diagram_generator._sanitize_name("Another-Name.123") == "Another_Name_123"
    assert diagram_generator._sanitize_name("123Name") == "_123Name"
    assert diagram_generator._sanitize_name("") == "unnamed"
    assert diagram_generator._sanitize_name(None) == "unnamed"

def test_clean_dot_code(diagram_generator):
    assert diagram_generator._clean_dot_code("test\r\ncode") == "test\ncode"
    assert diagram_generator._clean_dot_code(b"\xef\xbb\xbfgraph {}".decode('utf-8')) == "graph {}"
    assert diagram_generator._clean_dot_code(None) == ""

def test_get_element_name(diagram_generator):
    mock_element_obj = MagicMock()
    mock_element_obj.name = "Object Name"
    mock_element_dict = {'name': "Dict Name"}
    assert diagram_generator._get_element_name(mock_element_obj) == "Object Name"
    assert diagram_generator._get_element_name(mock_element_dict) == "Dict Name"
    assert diagram_generator._get_element_name("String Name") == "String Name"
    assert diagram_generator._get_element_name(None) is None

def test_extract_data_info(diagram_generator):
    # Test with single Data object
    mock_data_single = MagicMock(spec=[])
    mock_data_single.name = "SensitiveData"
    mock_dataflow_single = MagicMock(data=mock_data_single)
    assert diagram_generator._extract_data_info(mock_dataflow_single) == "Data: SensitiveData"

    # Test with list of Data objects (DataSet)
    mock_data_list = [MagicMock(spec=[]), MagicMock(spec=[])]
    mock_data_list[0].name = "Data1"
    mock_data_list[1].name = "Data2"
    mock_dataflow_list = MagicMock(data=mock_data_list)
    assert diagram_generator._extract_data_info(mock_dataflow_list) == "Data: Data1, Data2"

    # Test with dataflow having no data attribute
    mock_dataflow_no_data = MagicMock(spec=[])
    assert diagram_generator._extract_data_info(mock_dataflow_no_data) is None

    # Test with dataflow.data being None
    mock_dataflow_none_data = MagicMock(data=None)
    assert diagram_generator._extract_data_info(mock_dataflow_none_data) is None

    # Test with data having a 'value' attribute (varData wrapper)
    mock_var_data = MagicMock(value=MagicMock(spec=[]))
    mock_var_data.value.name = "WrappedData"
    mock_dataflow_var_data = MagicMock(data=mock_var_data)
    assert diagram_generator._extract_data_info(mock_dataflow_var_data) == "Data: WrappedData"

    

def test_get_edge_attributes_for_protocol(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.get_protocol_style.return_value = {
        'color': 'red',
        'line_style': 'dashed',
        'width': 2.0,
        'arrow_style': 'dot',
        'arrow_size': 1.5,
        'font_size': 12,
        'font_color': 'blue',
        'custom_attr': 'value'
    }
    attributes = diagram_generator._get_edge_attributes_for_protocol(mock_threat_model, "HTTPS")
    assert 'color="red"' in attributes
    assert 'style="dashed"' in attributes
    assert 'penwidth=2.0' in attributes
    assert 'arrowhead="dot"' in attributes
    assert 'arrowsize=1.5' in attributes
    assert 'fontsize=12' in attributes
    assert 'fontcolor="blue"' in attributes
    assert 'custom_attr="value"' in attributes

    # Test with no protocol
    attributes = diagram_generator._get_edge_attributes_for_protocol(mock_threat_model, None)
    assert attributes == ""

    # Test with no protocol style found
    mock_threat_model.get_protocol_style.return_value = None
    attributes = diagram_generator._get_edge_attributes_for_protocol(mock_threat_model, "HTTP")
    assert attributes == ""

    # Test with invalid width
    mock_threat_model.get_protocol_style.return_value = {'width': 'invalid'}
    attributes = diagram_generator._get_edge_attributes_for_protocol(mock_threat_model, "HTTP")
    assert "penwidth" not in attributes

    # Test with invalid arrow_size
    mock_threat_model.get_protocol_style.return_value = {'arrow_size': 'invalid'}
    attributes = diagram_generator._get_edge_attributes_for_protocol(mock_threat_model, "HTTP")
    assert "arrowsize" not in attributes

    # Test with invalid font_size
    mock_threat_model.get_protocol_style.return_value = {'font_size': 'invalid'}
    attributes = diagram_generator._get_edge_attributes_for_protocol(mock_threat_model, "HTTP")
    assert "fontsize" not in attributes

def test_get_node_attributes_actor_no_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        actor_dict = {'name': 'User', 'color': 'red', 'is_filled': True, 'type': 'actor'}
        attrs = diagram_generator._get_node_attributes(actor_dict, 'actor')
        assert 'shape=circle' in attrs
        assert 'fillcolor="red"' in attrs
        assert 'label=<👤 <br/>User>' in attrs
        assert 'style=filled' in attrs
        assert 'image=' not in attrs

def test_get_node_attributes_actor_with_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=True):
        actor_dict = {'name': 'User', 'color': 'red', 'is_filled': True, 'type': 'actor'}
        attrs = diagram_generator._get_node_attributes(actor_dict, 'actor')
        assert 'shape=circle' in attrs
        assert 'label=<<TABLE' in attrs
        assert 'User' in attrs
        assert '<IMG SRC=' in attrs

def test_get_node_attributes_firewall_no_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        firewall_dict = {'name': 'External Firewall', 'type': 'firewall'}
        attrs = diagram_generator._get_node_attributes(firewall_dict, 'server')
        assert 'shape=hexagon' in attrs
        assert 'label=<🔥 <br/>External Firewall>' in attrs

def test_get_node_attributes_firewall_with_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=True):
        firewall_dict = {'name': 'External Firewall', 'type': 'firewall'}
        attrs = diagram_generator._get_node_attributes(firewall_dict, 'server')
        assert 'shape=hexagon' in attrs
        assert 'label=<<TABLE' in attrs
        assert 'External Firewall' in attrs
        assert '<IMG SRC=' in attrs

def test_get_node_attributes_database_no_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        db_dict = {'name': 'App Database', 'type': 'database'}
        attrs = diagram_generator._get_node_attributes(db_dict, 'server')
        assert 'shape=cylinder' in attrs
        assert 'label=<🗄️ <br/>App Database>' in attrs

def test_get_node_attributes_database_with_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=True):
        db_dict = {'name': 'App Database', 'type': 'database'}
        attrs = diagram_generator._get_node_attributes(db_dict, 'server')
        assert 'shape=cylinder' in attrs
        assert 'label=<<TABLE' in attrs
        assert 'App Database' in attrs
        assert '<IMG SRC=' in attrs

def test_get_node_attributes_web_server_no_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        web_server_dict = {'name': 'Web Server', 'type': 'web_server'}
        attrs = diagram_generator._get_node_attributes(web_server_dict, 'server')
        assert 'shape=box' in attrs
        assert 'label=<🖥️ <br/>Web Server>' in attrs

def test_get_node_attributes_web_server_with_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=True):
        web_server_dict = {'name': 'Web Server', 'type': 'web_server'}
        attrs = diagram_generator._get_node_attributes(web_server_dict, 'server')
        assert 'shape=box' in attrs
        assert 'label=<<TABLE' in attrs
        assert 'Web Server' in attrs
        assert '<IMG SRC=' in attrs

def test_get_node_attributes_api_no_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        api_dict = {'name': 'Payment API', 'type': 'api_gateway'}
        attrs = diagram_generator._get_node_attributes(api_dict, 'server')
        assert 'shape=box' in attrs
        assert 'label=<🖥️ <br/>Payment API>' in attrs

def test_get_node_attributes_api_with_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=True):
        api_dict = {'name': 'Payment API', 'type': 'api_gateway'}
        attrs = diagram_generator._get_node_attributes(api_dict, 'server')
        assert 'shape=box' in attrs
        assert 'label=<<TABLE' in attrs
        assert 'Payment API' in attrs
        assert '<IMG SRC=' in attrs

def test_get_node_attributes_default(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        default_dict = {'name': 'Generic Node'}
        attrs = diagram_generator._get_node_attributes(default_dict, 'unknown')
        assert 'shape=box' in attrs
        assert 'label="Generic Node"' in attrs

def test_get_node_attributes_string_format_no_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        attrs = diagram_generator._get_node_attributes("MyStringNode", 'actor')
        assert 'shape=circle' in attrs
        assert 'label=<👤 <br/>MyStringNode>' in attrs

def test_get_node_attributes_string_format_with_image(diagram_generator):
    # This case is less likely as a string can't have a 'type' to find an icon,
    # but we test for completeness. The 'actor' node_type gives it a fallback icon path.
    with patch('pathlib.Path.exists', return_value=True):
        attrs = diagram_generator._get_node_attributes("MyStringNode", 'actor')
        assert 'shape=circle' in attrs
        assert 'label=<<TABLE' in attrs
        assert 'MyStringNode' in attrs
        assert '<IMG SRC=' in attrs

def test_get_node_attributes_dict_with_object_no_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=False):
        mock_pytm_obj = MagicMock()
        mock_pytm_obj.name = "PyTM Object Name"
        element_dict = {'object': mock_pytm_obj, 'color': 'orange', 'is_filled': True}
        attrs = diagram_generator._get_node_attributes(element_dict, 'server')
        assert 'shape=box' in attrs
        assert 'label=<🖥️ <br/>PyTM Object Name>' in attrs

def test_get_node_attributes_dict_with_object_with_image(diagram_generator):
    with patch('pathlib.Path.exists', return_value=True):
        mock_pytm_obj = MagicMock()
        mock_pytm_obj.name = "PyTM Object Name"
        element_dict = {'object': mock_pytm_obj, 'color': 'orange', 'is_filled': True, 'type': 'server'}
        attrs = diagram_generator._get_node_attributes(element_dict, 'server')
        assert 'shape=box' in attrs
        assert 'label=<<TABLE' in attrs
        assert 'PyTM Object Name' in attrs
        assert '<IMG SRC=' in attrs

def test_get_protocol_styles_from_model_get_all_protocol_styles(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.get_all_protocol_styles.return_value = {'HTTPS': {'color': 'green'}}
    styles = diagram_generator._get_protocol_styles_from_model(mock_threat_model)
    assert styles == {'HTTPS': {'color': 'green'}}

def test_get_protocol_styles_from_model_protocol_styles_attribute(diagram_generator):
    mock_threat_model = MagicMock()
    del mock_threat_model.get_all_protocol_styles # Simulate absence of method
    mock_threat_model.protocol_styles = {'HTTP': {'color': 'blue'}}
    styles = diagram_generator._get_protocol_styles_from_model(mock_threat_model)
    assert styles == {'HTTP': {'color': 'blue'}}

def test_get_protocol_styles_from_model_dataflows(diagram_generator):
    mock_threat_model = MagicMock()
    del mock_threat_model.get_all_protocol_styles
    del mock_threat_model.protocol_styles
    mock_dataflow1 = MagicMock(protocol='TCP')
    mock_dataflow2 = MagicMock(protocol='UDP')
    mock_threat_model.dataflows = [mock_dataflow1, mock_dataflow2]
    styles = diagram_generator._get_protocol_styles_from_model(mock_threat_model)
    assert styles == {}

def test_get_protocol_styles_from_model_no_dataflows(diagram_generator):
    mock_threat_model = MagicMock()
    del mock_threat_model.get_all_protocol_styles
    del mock_threat_model.protocol_styles
    mock_threat_model.dataflows = []
    styles = diagram_generator._get_protocol_styles_from_model(mock_threat_model)
    assert styles == {}

def test_get_protocol_styles_from_model_error_handling(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.get_all_protocol_styles.side_effect = Exception("Test Error")
    styles = diagram_generator._get_protocol_styles_from_model(mock_threat_model)
    assert styles == {}

def test_generate_manual_dot_basic(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.boundaries = {}
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    dot_code = diagram_generator._generate_manual_dot(mock_threat_model)
    assert "digraph ThreatModel" in dot_code
    assert "rankdir=LR;" in dot_code
    assert "node [shape=box]" in dot_code
    assert "edge [fontsize=10];" in dot_code
    assert "}" in dot_code

def test_generate_manual_dot_with_boundaries(diagram_generator):
    mock_threat_model = MagicMock()
    mock_boundary_obj = MagicMock()
    mock_boundary_obj.name = "Internet"
    mock_threat_model.boundaries = {
        "Internet": {'boundary': mock_boundary_obj, 'color': 'lightcoral', 'isTrusted': False, 'isFilled': True, 'line_style': 'solid'}
    }
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    dot_code = diagram_generator._generate_manual_dot(mock_threat_model)
    assert 'subgraph cluster_Internet {' in dot_code
    assert 'label="Internet"' in dot_code
    assert 'fillcolor="lightcoral"' in dot_code
    assert 'style="rounded,filled,solid"' in dot_code
    # B1: untrusted boundary → red border
    assert 'color="#c62828";' in dot_code








def test_generate_dot_file_from_model_empty_dot_code(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.boundaries = {}
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    # Mock _generate_manual_dot to return empty string
    with patch.object(diagram_generator, '_generate_manual_dot', return_value=""):
        output_file = "test_output.dot"
        result = diagram_generator.generate_dot_file_from_model(mock_threat_model, output_file)
        assert result is None

def test_generate_dot_file_from_model_exception(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.boundaries = {}
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    # Mock _generate_manual_dot to raise an exception
    with patch.object(diagram_generator, '_generate_manual_dot', side_effect=Exception("Test Error")):
        output_file = "test_output.dot"
        result = diagram_generator.generate_dot_file_from_model(mock_threat_model, output_file)
        assert result is None

def test_generate_dot_file_from_model_returns_content(diagram_generator):
    mock_threat_model = MagicMock()
    # Mock the necessary attributes on the threat model
    mock_threat_model.boundaries = {}
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []

    dot_content = "digraph G {}"
    with patch.object(diagram_generator, '_generate_manual_dot', return_value=dot_content):
        with patch('builtins.open', mock_open()):
            result = diagram_generator.generate_dot_file_from_model(mock_threat_model, "dummy_path.dot")
            assert result == dot_content

def test_generate_diagram_from_dot_success(diagram_generator):
    with patch.object(diagram_generator, 'check_graphviz_installation', return_value=True):
        # Mock the SVG generator's generate_svg_from_dot method
        with patch('threat_analysis.generation.svg_generator.CustomSVGGenerator.generate_svg_from_dot') as mock_svg_gen:
            mock_svg_gen.return_value = "output.svg"
            
            result = diagram_generator.generate_diagram_from_dot("digraph G {}", "output.svg", "svg")
            mock_svg_gen.assert_called_once()
            # The result should be the path to the output file
            assert result == "output.svg"

def test_generate_diagram_from_dot_unsupported_format(diagram_generator):
    result = diagram_generator.generate_diagram_from_dot("digraph G {}", "output", "unsupported")
    assert result is None

def test_generate_diagram_from_dot_graphviz_not_found(diagram_generator):
    with patch.object(diagram_generator, 'check_graphviz_installation', return_value=False):
        result = diagram_generator.generate_diagram_from_dot("digraph G {}", "output", "svg")
        assert result is None

def test_generate_diagram_from_dot_subprocess_error(diagram_generator):
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(1, 'dot', stderr="Graphviz error")
        with patch.object(diagram_generator, 'check_graphviz_installation', return_value=True):
            result = diagram_generator.generate_diagram_from_dot("digraph G {}", "output", "svg")
            assert result is None

def test_generate_diagram_from_dot_output_file_not_created(diagram_generator):
    with patch('subprocess.run') as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch('pathlib.Path.exists', return_value=False):
            with patch.object(diagram_generator, 'check_graphviz_installation', return_value=True):
                result = diagram_generator.generate_diagram_from_dot("digraph G {}", "output", "svg")
                assert result is None

def test_generate_diagram_from_dot_unexpected_error(diagram_generator):
    with patch('subprocess.run') as mock_run:
        mock_run.side_effect = Exception("Unexpected error")
        with patch.object(diagram_generator, 'check_graphviz_installation', return_value=True):
            result = diagram_generator.generate_diagram_from_dot("digraph G {}", "output", "svg")
            assert result is None

def test_generate_legend_html_basic(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    mock_threat_model.dataflows = []
    mock_threat_model.get_all_protocol_styles.return_value = {}
    legend_html = diagram_generator._generate_legend_html(mock_threat_model)
    assert "👤" in legend_html
    assert "🖥️" in legend_html
    assert "🔥" in legend_html
    assert "🗄️" in legend_html
    assert "🌐" in legend_html
    assert "🔀" in legend_html
    assert "🔌" in legend_html
    # B1: updated boundary legend labels
    assert "Trusted Zone" in legend_html
    assert "Untrusted Zone" in legend_html

def test_generate_legend_html_with_actors_and_servers(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.actors = [{'name': 'User', 'color': 'yellow'}]
    mock_threat_model.servers = [
        {'name': 'WebServer', 'color': 'green', 'type': 'web_server'},
        {'name': 'Firewall', 'color': 'red', 'type': 'firewall'},
        {'name': 'Database', 'color': 'blue', 'type': 'database'}
    ]
    mock_threat_model.dataflows = []
    mock_threat_model.get_all_protocol_styles.return_value = {}
    legend_html = diagram_generator._generate_legend_html(mock_threat_model)
    assert '👤' in legend_html
    assert '🖥️' in legend_html
    assert '🔥' in legend_html
    assert '🗄️' in legend_html

def test_generate_legend_html_with_protocol_styles(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    # Add a mock dataflow using the 'HTTPS' protocol
    mock_dataflow = MagicMock()
    mock_dataflow.protocol = 'HTTPS'
    mock_threat_model.dataflows = [mock_dataflow]
    mock_threat_model.get_all_protocol_styles.return_value = {'HTTPS': {'color': 'purple'}}

    # Mock the _get_used_protocols method to return the used protocol
    with patch.object(diagram_generator, '_get_used_protocols', return_value={'HTTPS'}):
        legend_html = diagram_generator._generate_legend_html(mock_threat_model)
        assert "Protocoles:" in legend_html
        assert "HTTPS" in legend_html
        assert "purple" in legend_html

def test_generate_legend_html_with_line_styles(diagram_generator):
    mock_threat_model = MagicMock()
    mock_threat_model.actors = []
    mock_threat_model.servers = []
    mock_dataflow = MagicMock()
    mock_dataflow.protocol = 'TCP'
    mock_threat_model.dataflows = [mock_dataflow]
    mock_threat_model.get_all_protocol_styles.return_value = {'TCP': {'color': 'blue', 'line_style': 'dashed'}}

    with patch.object(diagram_generator, '_get_used_protocols', return_value={'TCP'}):
        legend_html = diagram_generator._generate_legend_html(mock_threat_model)
        assert "Protocoles:" in legend_html
        assert "TCP" in legend_html
        assert "border-top: 2px dashed blue;" in legend_html

def test_generate_html_with_legend(diagram_generator):
    with patch('builtins.open', mock_open()) as mock_file_open:
        with patch.object(diagram_generator, '_generate_legend_html', return_value="<legend>Legend Content</legend>"):
            with patch.object(diagram_generator, '_create_complete_html', return_value="<html></html>"):
                svg_path = "test.svg"
                html_output_path = "test.html"
                mock_threat_model = MagicMock()
                result = diagram_generator._generate_html_with_legend(svg_path, html_output_path, mock_threat_model)
                mock_file_open.assert_called() # Changed from assert_called_once_with
                assert result == html_output_path

def test_generate_html_with_legend_exception(diagram_generator):
    with patch('builtins.open', side_effect=Exception("Test Error")):
        svg_path = "test.svg"
        html_output_path = "test.html"
        mock_threat_model = MagicMock()
        result = diagram_generator._generate_html_with_legend(svg_path, html_output_path, mock_threat_model)
        assert result is None


