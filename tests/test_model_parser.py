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
from unittest.mock import MagicMock, patch
from threat_analysis.core.model_parser import ModelParser
from threat_analysis.core.models_module import ThreatModel, CustomThreat, CVEService
from threat_analysis.core.mitre_mapping_module import MitreMapping
from pytm import Classification, Lifetime
from pathlib import Path

@pytest.fixture
def cve_service(tmp_path: Path) -> CVEService:
    """Provides a CVEService instance for testing."""
    project_root = tmp_path
    cve_definitions_path = project_root / "cve_definitions.yml"
    return CVEService(project_root, cve_definitions_path)

@pytest.fixture
def threat_model(cve_service):
    tm = ThreatModel(name="Test Threat Model", cve_service=cve_service)
    tm.add_boundary("Default Boundary") # Add a default boundary
    return tm

@pytest.fixture
def mitre_mapping():
    return MitreMapping()

@pytest.fixture
def model_parser(threat_model, mitre_mapping):
    return ModelParser(threat_model, mitre_mapping)

def test_parse_markdown_empty(model_parser, threat_model):
    model_parser.parse_markdown("")
    assert len(threat_model.actors) == 0
    assert len(threat_model.servers) == 0
    assert len(threat_model.dataflows) == 0

def test_parse_markdown_unrecognized_section(model_parser, threat_model):
    markdown = "## Unknown Section\n- some content"
    model_parser.parse_markdown(markdown)
    assert model_parser.current_section is None

def test_parse_boundary(model_parser, threat_model):
    markdown = """
## Boundaries
- **Internet**: color=red, isTrusted=False, isFilled=True, line_style=dashed
"""
    model_parser.parse_markdown(markdown)
    assert len(threat_model.boundaries) == 2 # Default boundary + Internet
    boundary = threat_model.boundaries["internet"]["boundary"]
    assert boundary.name == "Internet"
    assert threat_model.boundaries["internet"]["color"] == "red"
    assert threat_model.boundaries["internet"]["isTrusted"] is False
    assert threat_model.boundaries["internet"]["isFilled"] is True
    assert threat_model.boundaries["internet"]["line_style"] == "dashed"

def test_parse_boundary_default_color(model_parser, threat_model):
    markdown = """
## Boundaries
- **Internal Network**: isTrusted=True
"""
    model_parser.parse_markdown(markdown)
    assert len(threat_model.boundaries) == 2 # Default boundary + Internal Network
    assert threat_model.boundaries["internal network"]["color"] == "lightgray"

def test_parse_actor(model_parser, threat_model):
    threat_model.add_boundary("Internet")
    line = "- **User**: boundary=Internet, color=blue, isFilled=True"
    model_parser._parse_actor(line)
    assert len(threat_model.actors) == 1
    actor = threat_model.actors[0]
    assert actor['object'].name == "User"
    assert actor['boundary'].name.lower() == "internet"
    assert actor['color'] == "blue"
    assert actor['isFilled'] is True

def test_parse_server(model_parser, threat_model):
    threat_model.add_boundary("Internal Network")
    line = "- **WebServer**: boundary=\"Internal Network\", color=green, isFilled=False"
    model_parser._parse_server(line)
    assert len(threat_model.servers) == 1
    server_info = threat_model.servers[0]
    server = server_info["object"]
    assert server.name == "WebServer"
    assert server_info['boundary'].name == "Internal Network"
    assert server_info["color"] == "green"
    assert server_info["isFilled"] is False

def test_parse_data(model_parser, threat_model):
    line = "- **CreditCardData**: classification=TOP_SECRET, credentialsLife=LONG"
    model_parser._parse_data(line)
    assert len(threat_model.data_objects) == 1
    data_obj = threat_model.data_objects["creditcarddata"]
    assert data_obj.name == "CreditCardData"
    assert data_obj.classification == Classification.TOP_SECRET
    assert data_obj.credentialsLife == Lifetime.LONG

def test_parse_data_unrecognized_enum(model_parser, threat_model):
    with patch('logging.warning') as mock_warn:
        line = "- **InvalidData**: classification=INVALID_CLASS, credentialsLife=INVALID_LIFE"
        model_parser._parse_data(line)
        assert len(threat_model.data_objects) == 1
        data_obj = threat_model.data_objects["invaliddata"]
        assert data_obj.name == "InvalidData"
        assert data_obj.classification == Classification.UNKNOWN
        assert data_obj.credentialsLife == Lifetime.UNKNOWN
        assert mock_warn.call_count == 2

def test_parse_dataflow(model_parser, threat_model):
    # Add source and sink elements first
    threat_model.add_actor("User", "Default Boundary")
    threat_model.add_server("WebServer", "Default Boundary")
    threat_model.add_data("Credentials")
    line = "- **LoginFlow**: from=\"User\", to=\"WebServer\", protocol=\"HTTPS\", data=\"Credentials\", is_authenticated=True, is_encrypted=True"
    model_parser._parse_dataflow(line)
    assert len(threat_model.dataflows) == 1
    dataflow = threat_model.dataflows[0]
    assert dataflow.name == "LoginFlow"
    assert dataflow.source.name == "User"
    assert dataflow.sink.name == "WebServer"
    assert dataflow.protocol == "HTTPS"
    assert list(dataflow.data)[0].name == "Credentials"
    assert dataflow.is_encrypted is True
    assert dataflow.is_authenticated is True

def test_parse_dataflow_missing_elements(model_parser, threat_model):
    with patch('logging.warning') as mock_warn:
        line = "- **MissingFlow**: from=\"NonExistent\", to=\"AlsoNonExistent\", protocol=\"HTTP\""
        model_parser._parse_dataflow(line)
        assert len(threat_model.dataflows) == 0
        mock_warn.assert_called_once()

def test_parse_dataflow_missing_data_object(model_parser, threat_model):
    with patch('logging.warning') as mock_warn:
        # Source and sink elements exist, but data object does not
        threat_model.add_actor("User", "Default Boundary")
        threat_model.add_server("WebServer", "Default Boundary")
        line = "- **FlowWithMissingData**: from=\"User\", to=\"WebServer\", protocol=\"HTTP\", data=\"NonExistentData\""
        model_parser._parse_dataflow(line)
        assert len(threat_model.dataflows) == 1 # Dataflow should still be added
        dataflow = threat_model.dataflows[0]
        assert dataflow.name == "FlowWithMissingData"
        assert not dataflow.data # Data list should be empty
        mock_warn.assert_called_once_with("⚠️ Warning: Data object 'nonexistentdata' not found for dataflow 'FlowWithMissingData'.")

def test_parse_dataflow_malformed(model_parser, threat_model):
    with patch('logging.warning') as mock_warn:
        line = "- **MalformedFlow**: to=\"MyServer\", protocol=\"TCP\""
        model_parser._parse_dataflow(line)
        assert len(threat_model.dataflows) == 0
        mock_warn.assert_called_once()

def test_parse_protocol_style(model_parser, threat_model):
    line = "- **HTTPS**: color=blue, line_style=dotted, width=2.0"
    model_parser._parse_protocol_style(line)
    styles = threat_model.get_all_protocol_styles()
    assert "HTTPS" in styles
    assert styles["HTTPS"]["color"] == "blue"
    assert styles["HTTPS"]["line_style"] == "dotted"
    assert styles["HTTPS"]["width"] == 2.0

def test_parse_severity_multiplier(model_parser, threat_model):
    line = "- **CriticalData**: 2.5"
    model_parser._parse_severity_multiplier(line)
    assert threat_model.severity_multipliers["CriticalData"] == 2.5

def test_parse_severity_multiplier_with_comment(model_parser, threat_model):
    """Tests that commented lines are ignored when parsing severity multipliers."""
    line = "# - **CommentedMultiplier**: 3.0"
    model_parser._parse_severity_multiplier(line)
    assert not threat_model.severity_multipliers

def test_parse_custom_mitre(model_parser, threat_model):
    line = "- **Phishing**: {'tactics':['Initial Access'], 'techniques':[{'id': 'T1566', 'name': 'Phishing'}]}"
    model_parser._parse_custom_mitre(line)
    assert len(threat_model.custom_mitre_mappings) == 1
    mapping = threat_model.custom_mitre_mappings["Phishing"]
    assert mapping['tactics'] == ['Initial Access']
    assert mapping['techniques'] == [{'id': 'T1566', 'name': 'Phishing'}]

def test_parse_custom_mitre_with_comment(model_parser, threat_model):
    """Tests that commented lines are ignored when parsing custom MITRE mappings."""
    line = "# - **CommentedMapping**: {'tactics':['Initial Access'], 'techniques':[{'id': 'T1566', 'name': 'Phishing'}]}"
    model_parser._parse_custom_mitre(line)
    assert not threat_model.custom_mitre_mappings

def test_parse_key_value_params(model_parser):
    params_str = 'key1="value one", key2=True, key3=123, key4=#FF00FF, key5=unquoted_string'
    params = model_parser._parse_key_value_params(params_str)
    assert params["key1"] == "value one"
    assert params["key2"] is True
    assert params["key3"] == 123.0
    assert params["key4"] == "#FF00FF"
    assert params["key5"] == "unquoted_string"

@patch('threat_analysis.core.models_module.get_custom_threats')
def test_apply_custom_threats_servers(mock_get_custom_threats, threat_model, mitre_mapping):
    # Test case 1: Server matches condition
    threat_model.add_server("WebServer", "Default Boundary", type="web_server")
    mock_get_custom_threats.return_value = [
        {
            "component": "WebServer",
            "description": "Web Server Threat",
            "stride_category": "T",
            "impact": 4,
            "likelihood": 3
        }
    ]
    
    with patch('sys.argv', ['']):
        threat_model.process_threats()
    
    threat_model.threats_raw = [t for t in threat_model.threats_raw if isinstance(t[0], CustomThreat)]
    assert len(threat_model.threats_raw) >= 1
    assert any(t[0].description == "Web Server Threat" for t in threat_model.threats_raw)
    assert any(t[1].name == "WebServer" for t in threat_model.threats_raw if not isinstance(t[1], tuple))

    threat_model_no_match = ThreatModel(name="Test Threat Model No Match", cve_service=threat_model.cve_service)
    threat_model_no_match.add_boundary("Default Boundary")
    threat_model_no_match.add_server("DatabaseServer", "Default Boundary", type="database")
    mock_get_custom_threats.return_value = []
    
    with patch('sys.argv', ['']):
        threat_model_no_match.process_threats()
    
    threat_model_no_match.threats_raw = [t for t in threat_model_no_match.threats_raw if isinstance(t[0], CustomThreat)]
    assert len(threat_model_no_match.threats_raw) == 0

    # Test case 3: Server with no specific type, and a general rule
    threat_model_general = ThreatModel(name="Test Threat Model General", cve_service=threat_model.cve_service)
    threat_model_general.add_boundary("Default Boundary")
    threat_model_general.add_server("GenericServer", "Default Boundary") # No type specified
    mock_get_custom_threats.return_value = [
        {
            "component": "GenericServer",
            "description": "General Server Threat",
            "stride_category": "T",
            "impact": 1,
            "likelihood": 1
        }
    ]
    
    with patch('sys.argv', ['']):
        threat_model_general.process_threats()
    
    threat_model_general.threats_raw = [t for t in threat_model_general.threats_raw if isinstance(t[0], CustomThreat)]
    assert len(threat_model_general.threats_raw) >= 1
    assert any(t[0].description == "General Server Threat" for t in threat_model_general.threats_raw)
    assert any(t[1].name == "GenericServer" for t in threat_model_general.threats_raw if not isinstance(t[1], tuple))


@patch('threat_analysis.core.models_module.get_custom_threats')
def test_apply_custom_threats_dataflows_new(mock_get_custom_threats, threat_model, mitre_mapping):
    # Setup elements
    threat_model.add_actor("User", "Default Boundary")
    threat_model.add_server("WebServer", "Default Boundary", type="web_server")
    threat_model.add_data("SensitiveData", classification=Classification.SECRET)

    # Add a dataflow that matches the custom threat conditions
    threat_model.add_dataflow(
        threat_model.get_element_by_name("User"),
        threat_model.get_element_by_name("WebServer"),
        "SecureSensitiveDataFlow",
        "HTTPS",
        data_name="SensitiveData",
        is_encrypted=True
    )

    # Define a custom threat for dataflows
    mock_get_custom_threats.return_value = [
        {
            "component": "SecureSensitiveDataFlow",
            "description": "Sensitive Data Flow Threat",
            "stride_category": "ID",
            "impact": 5,
            "likelihood": 1
        }
    ]

    # Apply custom threats
    with patch('sys.argv', ['']):
        threat_model.process_threats()

    # Assertions
    threat_model.threats_raw = [t for t in threat_model.threats_raw if isinstance(t[0], CustomThreat)]
    assert len(threat_model.threats_raw) >= 1
    assert any(t[0].description == "Sensitive Data Flow Threat" for t in threat_model.threats_raw)
    assert any(t[1].name == "SecureSensitiveDataFlow" for t in threat_model.threats_raw if not isinstance(t[1], tuple))

    # Test case where dataflow does NOT match conditions
    threat_model_no_match = ThreatModel(name="Test Threat Model No Match", cve_service=threat_model.cve_service)
    threat_model_no_match.add_boundary("Default Boundary")
    threat_model_no_match.add_actor("User2", "Default Boundary")
    threat_model_no_match.add_server("WebServer2", "Default Boundary")
    threat_model_no_match.add_data("NonSensitiveData", classification=Classification.PUBLIC)
    threat_model_no_match.add_dataflow(
        threat_model_no_match.get_element_by_name("User2"),
        threat_model_no_match.get_element_by_name("WebServer2"),
        "InsecureNonSensitiveDataFlow",
        "HTTP",
        data_name="NonSensitiveData",
        is_encrypted=False
    )
    mock_get_custom_threats.return_value = []
    
    with patch('sys.argv', ['']):
        threat_model_no_match.process_threats()
    
    threat_model_no_match.threats_raw = [t for t in threat_model_no_match.threats_raw if isinstance(t[0], CustomThreat)]
    assert len(threat_model_no_match.threats_raw) == 0
