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
# See the License for the specific language governing permissions and_limitations under the License.

"""
Tests for the ModelValidator.
"""

from unittest.mock import MagicMock
from pathlib import Path
import pytest
from threat_analysis.core.cve_service import CVEService
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.model_validator import ModelValidator
from pytm import Actor, Server, Dataflow, Boundary

@pytest.fixture
def cve_service():
    """Provides a mocked CVEService instance for testing."""
    return MagicMock(spec=CVEService)

@pytest.fixture
def sample_threat_model(cve_service):
    """Provides a sample ThreatModel for testing."""
    tm = ThreatModel("Test Model", "A model for testing validation", cve_service=cve_service)
    tm.add_boundary("Internet")
    tm.add_boundary("DMZ")
    tm.add_actor("User", "Internet")
    tm.add_server("WebServer", "DMZ")
    return tm

def test_validator_with_valid_model(sample_threat_model):
    """Tests that a valid model passes validation."""
    # Add a valid dataflow
    user = sample_threat_model.get_element_by_name("User")
    webserver = sample_threat_model.get_element_by_name("WebServer")
    sample_threat_model.add_dataflow(user, webserver, "Valid Flow", "HTTPS")

    validator = ModelValidator(sample_threat_model)
    assert not validator.validate()
    assert not validator.errors

def test_validator_with_invalid_dataflow_source(sample_threat_model):
    """Tests that a dataflow with an undefined source fails validation."""
    # Create a fake source that is not in the model
    fake_source = Actor("Fake Actor")
    webserver = sample_threat_model.get_element_by_name("WebServer")
    
    # Manually create and add the invalid dataflow
    invalid_df = Dataflow(fake_source, webserver, "Invalid Source Flow")
    sample_threat_model.dataflows.append(invalid_df)

    validator = ModelValidator(sample_threat_model)
    errors = validator.validate()
    assert errors
    assert "Dataflow 'Invalid Source Flow' refers to a non-existent 'from' element: 'Fake Actor'." in errors

def test_validator_with_invalid_dataflow_sink(sample_threat_model):
    """Tests that a dataflow with an undefined sink fails validation."""
    user = sample_threat_model.get_element_by_name("User")
    # Create a fake sink that is not in the model
    fake_sink = Server("Fake Server")

    # Manually create and add the invalid dataflow
    invalid_df = Dataflow(user, fake_sink, "Invalid Sink Flow")
    sample_threat_model.dataflows.append(invalid_df)

    validator = ModelValidator(sample_threat_model)
    errors = validator.validate()
    assert errors
    assert "Dataflow 'Invalid Sink Flow' refers to a non-existent 'to' element: 'Fake Server'." in errors

def test_validator_with_invalid_flow_to_boundary(sample_threat_model):
    """Tests that a dataflow from a component to a boundary fails validation."""
    user = sample_threat_model.get_element_by_name("User")
    boundary = sample_threat_model.boundaries['internet']['boundary']

    valid_df = Dataflow(user, boundary, "Valid Boundary Flow")
    sample_threat_model.dataflows.append(valid_df)
    sample_threat_model._elements_by_name[valid_df.name.lower()] = valid_df

    validator = ModelValidator(sample_threat_model)
    errors = validator.validate()
    assert errors
    assert "Dataflow 'Valid Boundary Flow' cannot terminate directly at a boundary. The destination must be an actor or a server." in errors

def test_validator_with_invalid_flow_from_boundary(sample_threat_model):
    """Tests that a dataflow from a boundary to a component fails validation."""
    boundary = sample_threat_model.boundaries['internet']['boundary']
    webserver = sample_threat_model.get_element_by_name("WebServer")

    valid_df = Dataflow(boundary, webserver, "Valid Boundary Source Flow")
    sample_threat_model.dataflows.append(valid_df)
    sample_threat_model._elements_by_name[valid_df.name.lower()] = valid_df

    validator = ModelValidator(sample_threat_model)
    errors = validator.validate()
    assert errors
    assert "Dataflow 'Valid Boundary Source Flow' cannot originate directly from a boundary. The source must be an actor or a server." in errors

def test_validator_with_invalid_flow_between_boundaries(sample_threat_model):
    """Tests that a dataflow between two boundaries fails validation."""
    boundary1 = sample_threat_model.boundaries['internet']['boundary']
    boundary2 = sample_threat_model.boundaries['dmz']['boundary']

    valid_df = Dataflow(boundary1, boundary2, "Valid Boundary Flow")
    sample_threat_model.dataflows.append(valid_df)
    sample_threat_model._elements_by_name[valid_df.name.lower()] = valid_df

    validator = ModelValidator(sample_threat_model)
    errors = validator.validate()
    assert errors
    assert "Dataflow 'Valid Boundary Flow' cannot originate directly from a boundary. The source must be an actor or a server." in errors
    assert "Dataflow 'Valid Boundary Flow' cannot terminate directly at a boundary. The destination must be an actor or a server." in errors
