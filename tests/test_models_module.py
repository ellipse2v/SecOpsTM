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
import logging
from threat_analysis.core.models_module import ThreatModel, CustomThreat
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.severity_calculator_module import SeverityCalculator
from pytm import TM, Boundary, Actor, Server, Dataflow, Data, Classification, Lifetime

from threat_analysis.core.cve_service import CVEService
from pathlib import Path

# --- Fixtures ---

@pytest.fixture
def cve_service():
    """Provides a mocked CVEService instance for testing."""
    return MagicMock(spec=CVEService)

@pytest.fixture
def threat_model_instance(cve_service):
    with patch('threat_analysis.core.models_module.MitreMapping') as MockMitreMapping:
        with patch('threat_analysis.core.models_module.TM') as MockTM:
            with patch('threat_analysis.core.models_module.SeverityCalculator') as MockSeverityCalculator:
                tm = ThreatModel(name="Test Model", description="A model for testing", cve_service=cve_service)
                # Add some basic elements for general testing
                tm.add_boundary("Internet", isTrusted=False)
                tm.add_boundary("Internal Network", isTrusted=True)
                tm.add_actor("User", boundary_name="Internet", isHuman=True)
                tm.add_server("WebServer", boundary_name="Internal Network", stereotype="Server", type="web_server")
                tm.add_data("Credentials", classification=Classification.RESTRICTED, lifetime=Lifetime.LONG)
                tm.add_dataflow(
                    tm.get_element_by_name("User"),
                    tm.get_element_by_name("WebServer"),
                    "Login Flow",
                    "HTTPS",
                    data_name="Credentials",
                    is_authenticated=True,
                    is_encrypted=True
                )
                yield tm, MockSeverityCalculator.return_value # Return the mocked instance

# --- CustomThreat Tests ---

def test_custom_threat_initialization():
    mock_target = MagicMock()
    mock_target.name = "Database"
    threat = CustomThreat(
        name="SQL Injection",
        description="SQL injection vulnerability",
        stride_category="Tampering",
        impact=5,
        likelihood=4,
        target=mock_target
    )
    assert threat.name == "SQL Injection"
    assert threat.description == "SQL injection vulnerability"
    assert threat.stride_category == "Tampering"
    assert threat.impact == 5
    assert threat.likelihood == 4
    assert threat.target.name == "Database"
    assert threat.severity_info is None

def test_custom_threat_str_representation():
    threat = CustomThreat(
        name="XSS Vulnerability",
        description="Cross-site scripting",
        stride_category="Tampering",
        impact=3,
        likelihood=2,
        target=MagicMock(name="Frontend")
    )
    assert str(threat) == "XSS Vulnerability"

# --- ThreatModel Initialization Tests ---

def test_threat_model_init(cve_service):
    with patch('threat_analysis.core.models_module.MitreMapping'):
        with patch('threat_analysis.core.models_module.TM') as MockTM:
            with patch('threat_analysis.core.models_module.SeverityCalculator'):
                tm = ThreatModel(name="My Model", description="A description", cve_service=cve_service)

                MockTM.assert_called_once_with("My Model")
                assert tm.tm.description == "A description"
                
                assert tm.boundaries == {}
                assert tm.actors == []
                assert tm.servers == []
                assert tm.dataflows == []
                assert tm.severity_multipliers == {}
                assert tm.custom_mitre_mappings == {}
                assert tm.protocol_styles == {}
                assert tm.threats_raw == []
                assert tm.grouped_threats == {}
                assert tm.data_objects == {}
                assert tm._elements_by_name == {}
                assert tm.mitre_analysis_results == {}
                assert tm.threat_mitre_mapping == {}

# --- ThreatModel add_boundary Tests ---

def test_add_boundary_simple(threat_model_instance):
    tm = threat_model_instance[0]
    boundary = tm.add_boundary("New Boundary")
    assert isinstance(boundary, Boundary)
    assert boundary.name == "New Boundary"
    assert "new boundary" in tm.boundaries
    assert tm.boundaries["new boundary"]["color"] == "lightgray"
    assert tm.boundaries["new boundary"]["boundary"] == boundary
    assert tm._elements_by_name["new boundary"] == boundary

def test_add_boundary_with_properties(threat_model_instance):
    tm = threat_model_instance[0]
    boundary = tm.add_boundary("Secure Zone", color="blue", isTrusted=True, isFilled=False, line_style="dotted", custom_prop="value")
    assert boundary.name == "Secure Zone"
    assert tm.boundaries["secure zone"]["color"] == "blue"
    assert tm.boundaries["secure zone"]["isTrusted"] is True
    assert tm.boundaries["secure zone"]["isFilled"] is False
    assert tm.boundaries["secure zone"]["line_style"] == "dotted"
    assert tm.boundaries["secure zone"]["custom_prop"] == "value"

def test_add_boundary_nested(threat_model_instance):
    tm = threat_model_instance[0]
    parent_boundary = tm.add_boundary("Parent Zone")
    child_boundary = tm.add_boundary("Child Zone", parent_boundary_obj=parent_boundary)
    assert child_boundary.inBoundary == parent_boundary
    assert "child zone" in tm.boundaries

# --- ThreatModel add_actor Tests ---

def test_add_actor_no_boundary(threat_model_instance):
    tm = threat_model_instance[0]
    actor = tm.add_actor("New Actor")
    assert isinstance(actor, Actor)
    assert actor.name == "New Actor"
    assert actor.inBoundary is None
    assert len(tm.actors) == 2 # User + New Actor
    assert tm._elements_by_name["new actor"] == actor

def test_add_actor_with_boundary(threat_model_instance):
    tm = threat_model_instance[0]
    actor = tm.add_actor("Admin", boundary_name="Internal Network", isHuman=False)
    assert actor.name == "Admin"
    assert actor.inBoundary.name == "Internal Network"
    assert tm.actors[1]["isHuman"] is False # User + Admin
    assert tm._elements_by_name["admin"] == actor

# --- ThreatModel add_server Tests ---

def test_add_server_no_boundary(threat_model_instance):
    tm = threat_model_instance[0]
    server = tm.add_server("DB Server")
    assert isinstance(server, Server)
    assert server.name == "DB Server"
    assert server.inBoundary is None
    assert len(tm.servers) == 2 # WebServer + DB Server
    assert tm._elements_by_name["db server"] == server

def test_add_server_with_boundary(threat_model_instance):
    tm = threat_model_instance[0]
    server = tm.add_server("API Gateway", boundary_name="Internet", is_public=True, type="api_gateway")
    assert server.name == "API Gateway"
    assert server.inBoundary.name == "Internet"
    assert tm.servers[1]["is_public"] is True
    assert tm.servers[1]["type"] == "api_gateway" # New assertion
    assert tm._elements_by_name["api gateway"] == server

# --- ThreatModel add_data Tests ---

def test_add_data_with_classification_and_lifetime(threat_model_instance):
    tm = threat_model_instance[0]
    data = tm.add_data("PII", classification=Classification.SECRET, lifetime=Lifetime.SHORT)
    assert isinstance(data, Data)
    assert data.name == "PII"
    assert data.classification == Classification.SECRET
    assert data.lifetime == Lifetime.SHORT
    assert "pii" in tm.data_objects
    assert tm.data_objects["pii"] == data

def test_add_data_with_other_kwargs(threat_model_instance):
    tm = threat_model_instance[0]
    data = tm.add_data("Log Data", format="JSON", retention_days=90)
    assert data.name == "Log Data"
    assert data.format == "JSON"
    assert data.retention_days == 90

# --- ThreatModel add_protocol_style Tests ---

def test_add_protocol_style(threat_model_instance):
    tm = threat_model_instance[0]
    tm.add_protocol_style("TCP", color="red", line_style="solid", width=2)
    styles = tm.get_all_protocol_styles()
    assert "TCP" in styles
    assert styles["TCP"]["color"] == "red"
    assert styles["TCP"]["line_style"] == "solid"
    assert styles["TCP"]["width"] == 2

def test_get_protocol_style(threat_model_instance):
    tm = threat_model_instance[0]
    tm.add_protocol_style("UDP", color="green")
    style = tm.get_protocol_style("UDP")
    assert style == {"color": "green"}
    assert tm.get_protocol_style("NonExistent") is None

def test_get_all_protocol_styles_coverage(threat_model_instance):
    tm = threat_model_instance[0]
    tm.add_protocol_style("HTTP", color="orange")
    tm.add_protocol_style("FTP", line_style="dashed")
    all_styles = tm.get_all_protocol_styles()
    assert "HTTP" in all_styles
    assert all_styles["HTTP"] == {"color": "orange"}
    assert "FTP" in all_styles
    assert all_styles["FTP"] == {"line_style": "dashed"}
    assert len(all_styles) == 2
    # Ensure it's a copy and not the original dictionary
    all_styles["NEW"] = {"test": "value"}
    assert "NEW" not in tm.protocol_styles

# --- ThreatModel get_element_by_name Tests ---

def test_get_element_by_name_actor(threat_model_instance):
    tm = threat_model_instance[0]
    user = tm.get_element_by_name("User")
    assert isinstance(user, Actor)
    assert user.name == "User"

def test_get_element_by_name_server(threat_model_instance):
    tm = threat_model_instance[0]
    webserver = tm.get_element_by_name("WebServer")
    assert isinstance(webserver, Server)
    assert webserver.name == "WebServer"

def test_get_element_by_name_boundary(threat_model_instance):
    tm = threat_model_instance[0]
    internet = tm.get_element_by_name("Internet")
    assert isinstance(internet, Boundary)
    assert internet.name == "Internet"

def test_get_element_by_name_data(threat_model_instance):
    tm = threat_model_instance[0]
    credentials = tm.get_element_by_name("Credentials")
    assert isinstance(credentials, Data)
    assert credentials.name == "Credentials"

def test_get_element_by_name_non_existent(threat_model_instance):
    tm = threat_model_instance[0]
    assert tm.get_element_by_name("NonExistent") is None

# --- ThreatModel process_threats Tests ---

@patch('threat_analysis.core.models_module.ModelValidator')
def test_process_threats_validation_fails(MockModelValidator, threat_model_instance):
    tm = threat_model_instance[0]
    mock_validator_instance = MockModelValidator.return_value
    mock_validator_instance.validate.return_value = ["Error 1", "Error 2"] # Validation errors

    grouped_threats = tm.process_threats()

    MockModelValidator.assert_called_once_with(tm)
    mock_validator_instance.validate.assert_called_once()
    assert grouped_threats == {} # Should return empty if validation fails

@patch('threat_analysis.core.models_module.get_custom_threats')
@patch('threat_analysis.core.models_module.ModelValidator')
def test_process_threats_with_custom_threats(MockModelValidator, MockGetCustomThreats, threat_model_instance):
    tm, mock_severity_calculator_instance = threat_model_instance

    # Mock ModelValidator to always pass
    mock_validator_instance = MockModelValidator.return_value
    mock_validator_instance.validate.return_value = [] # No validation errors

    # Mock SeverityCalculator to return a predictable value
    mock_severity_calculator_instance.get_severity_info.return_value = {"score": 7.0, "level": "HIGH"}

    # Define mock custom threats
    mock_custom_threats_data = [
        {
            "description": "Custom SQL Injection",
            "stride_category": "Tampering",
            "impact": 5,
            "likelihood": 4,
            "component": "WebServer" # Use existing WebServer from fixture
        },
        {
            "description": "Custom XSS",
            "stride_category": "Spoofing",
            "impact": 3,
            "likelihood": 2,
            "component": "User" # Use existing User from fixture
        }
    ]
    MockGetCustomThreats.return_value = mock_custom_threats_data

    # No need to add WebServer and User, they are in the fixture
    with patch('sys.argv', ['']):
        grouped_threats = tm.process_threats()

    MockGetCustomThreats.assert_called_once_with(tm)
    assert "Tampering" in grouped_threats
    assert "Spoofing" in grouped_threats
    assert len(grouped_threats["Tampering"]) >= 1
    assert len(grouped_threats["Spoofing"]) >= 1

    # Check the custom threat details and severity info
    sql_injection_threat = grouped_threats["Tampering"][0][0]
    assert isinstance(sql_injection_threat, CustomThreat)
    assert sql_injection_threat.name == "Custom SQL Injection"
    assert sql_injection_threat.severity_info == {"score": 7.0, "level": "HIGH"}

    xss_threat = grouped_threats["Spoofing"][0][0]
    assert isinstance(xss_threat, CustomThreat)
    assert xss_threat.name == "Custom XSS"
    assert xss_threat.severity_info == {"score": 7.0, "level": "HIGH"}

    # Test case for dataflow target and classification
    tm.add_data("SensitiveData", classification=Classification.RESTRICTED)
    dataflow_obj = tm.add_dataflow(
        tm.get_element_by_name("User"),
        tm.get_element_by_name("WebServer"),
        "DataTransfer",
        "HTTPS",
        data_name="SensitiveData"
    )
    mock_custom_threats_data_dataflow = [
        {
            "description": "Dataflow Threat",
            "stride_category": "Disclosure",
            "impact": 5,
            "likelihood": 5,
            "component": "DataTransfer" # This should map to the dataflow
        }
    ]
    MockGetCustomThreats.return_value = mock_custom_threats_data_dataflow
    with patch('sys.argv', ['']):
        grouped_threats_dataflow = tm.process_threats()
    
    # Assert that get_severity_info was called with correct classification for dataflow
    mock_severity_calculator_instance.get_severity_info.assert_called_with(
        threat_type="Disclosure",
        target_name="DataTransfer",
        protocol="HTTPS",
        classification="RESTRICTED",
        impact=5,
        likelihood=5
    )

# --- ThreatModel _group_threats Tests ---

def test_group_threats_basic(threat_model_instance):
    tm = threat_model_instance[0]
    tm.threats_raw = [
        (MagicMock(stride_category="Spoofing"), MagicMock(name="Target1")),
        (MagicMock(stride_category="Tampering"), MagicMock(name="Target2")),
        (MagicMock(stride_category="Spoofing"), MagicMock(name="Target3"))
    ]
    grouped = tm._group_threats()
    assert "Spoofing" in grouped
    assert len(grouped["Spoofing"]) == 2
    assert "Tampering" in grouped
    assert len(grouped["Tampering"]) == 1

def test_group_threats_unresolved_targets(threat_model_instance):
    tm = threat_model_instance[0]
    tm.threats_raw = [
        (MagicMock(stride_category="Spoofing"), MagicMock(name="Target1")),
        (MagicMock(stride_category="Unresolved"), None), # Unresolved target
        (MagicMock(stride_category="Tampering"), MagicMock(name="Target2"))
    ]
    grouped = tm._group_threats()
    assert "Spoofing" in grouped
    assert "Tampering" in grouped
    assert "Unresolved" not in grouped # Unresolved threats should be skipped

# --- ThreatModel _perform_mitre_analysis Tests ---

def test_perform_mitre_analysis(threat_model_instance):
    tm = threat_model_instance[0]
    tm.threats_raw = [
        (MagicMock(description="Phishing attack", stride_category="Spoofing", name="Phishing Threat"), tm.get_element_by_name("User")),
        (MagicMock(description="Data tampering", stride_category="Tampering", name="Tampering Threat"), tm.get_element_by_name("WebServer"))
    ]
    
    tm.mitre_mapper.analyze_pytm_threats_list.return_value = {
        "total_threats": 2,
        "stride_distribution": {"Spoofing": 1, "Tampering": 1},
        "mitre_techniques_count": 2,
        "processed_threats": [
            {"threat_name": "Phishing Threat", "description": "Phishing attack", "target": tm.get_element_by_name("User"), "stride_category": "Spoofing", "mitre_tactics": ["Initial Access"], "mitre_techniques": [{"id": "T1566", "name": "Phishing"}], "severity_info": {"score": 7.0, "level": "HIGH"}},
            {"threat_name": "Tampering Threat", "description": "Data tampering", "target": tm.get_element_by_name("WebServer"), "stride_category": "Tampering", "mitre_tactics": ["Impact"], "mitre_techniques": [{"id": "T1565", "name": "Data Manipulation"}], "severity_info": {"score": 8.0, "level": "HIGH"}}
        ]
    }

    tm._perform_mitre_analysis()

    tm.mitre_mapper.analyze_pytm_threats_list.assert_called_once_with(tm.threats_raw)
    assert tm.mitre_analysis_results["total_threats"] == 2
    assert tm.mitre_analysis_results["mitre_techniques_count"] == 2
    assert "Phishing Threat_User" in tm.threat_mitre_mapping
    assert tm.threat_mitre_mapping["Phishing Threat_User"]["stride_category"] == "Spoofing"

# --- ThreatModel get_statistics Tests ---

def test_get_statistics(threat_model_instance):
    tm = threat_model_instance[0]
    tm.threats_raw = [MagicMock(), MagicMock()]
    tm.grouped_threats = {"Spoofing": [MagicMock()]}
    tm.actors = [MagicMock()]
    tm.servers = [MagicMock()]
    tm.dataflows = [MagicMock()]
    tm.boundaries = {"Boundary1": MagicMock()}
    tm.protocol_styles = {"HTTPS": MagicMock()}
    tm.mitre_analysis_results = {"mitre_techniques_count": 5}

    stats = tm.get_statistics()

    assert stats["total_threats"] == 2
    assert stats["threat_types"] == 1
    assert stats["actors"] == 1
    assert stats["servers"] == 1
    assert stats["dataflows"] == 1
    assert stats["boundaries"] == 1
    assert stats["protocol_styles"] == 1
    assert stats["mitre_techniques_count"] == 5

# --- ThreatModel add_severity_multiplier Tests ---

def test_add_severity_multiplier(threat_model_instance):
    tm = threat_model_instance[0]
    tm.add_severity_multiplier("WebServer", 1.5)
    assert tm.severity_multipliers["WebServer"] == 1.5

# --- ThreatModel add_custom_mitre_mapping Tests ---

def test_add_custom_mitre_mapping(threat_model_instance):
    tm = threat_model_instance[0]
    tm.add_custom_mitre_mapping(
        "My Custom Attack",
        ["Reconnaissance"],
        [{"id": "T9999", "name": "Custom Technique"}]
    )
    assert "My Custom Attack" in tm.custom_mitre_mappings
    assert tm.custom_mitre_mappings["My Custom Attack"]["tactics"] == ["Reconnaissance"]
    assert tm.custom_mitre_mappings["My Custom Attack"]["techniques"] == [{"id": "T9999", "name": "Custom Technique"}]
