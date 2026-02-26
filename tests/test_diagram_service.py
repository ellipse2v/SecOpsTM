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

@patch('threat_analysis.generation.diagram_generator.DiagramGenerator._generate_manual_dot', return_value="")
@patch('threat_analysis.server.diagram_service.create_threat_model', return_value=MagicMock())
def test_update_diagram_logic_failed_dot_generation(mock_create_threat_model, mock_generate_manual_dot, diagram_service):
    diagram_service.diagram_generator._generate_manual_dot = mock_generate_manual_dot
    with pytest.raises(RuntimeError, match="Failed to generate DOT code from model"):
        diagram_service.update_diagram_logic("some markdown")
