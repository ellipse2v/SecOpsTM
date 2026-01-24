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
import os
from unittest.mock import MagicMock, patch, mock_open, ANY
from io import BytesIO
import datetime
import sys
import shutil
import zipfile

from threat_analysis.server.threat_model_service import ThreatModelService
from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.core.models_module import ThreatModel, CustomThreat
from pytm import TM, Boundary, Actor, Server, Dataflow, Data
from pathlib import Path
import datetime

# Mock the OUTPUT_BASE_DIR for testing purposes
@pytest.fixture(autouse=True)
def mock_output_base_dir(tmp_path):
    original_output_base_dir = Path("output") / datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    # For testing, we'll use tmp_path / "output" instead
    import sys
    # We'll mock this by setting an environment variable or using a different approach
    # Since we're removing config.py, we need to handle this differently
    # For now, let's just use tmp_path directly in tests
    yield

@pytest.fixture
def service():
    return ThreatModelService()

# Test cases for update_diagram_logic
def test_update_diagram_logic_empty_markdown(service):
    with pytest.raises(ValueError, match="Markdown content is empty"):
        service.update_diagram_logic("")

@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=None)
def test_update_diagram_logic_failed_threat_model_creation(mock_create_threat_model, service):
    with pytest.raises(RuntimeError, match="Failed to create threat model"):
        service.update_diagram_logic("some markdown")

@patch('threat_analysis.server.threat_model_service.DiagramGenerator._generate_manual_dot', return_value="")
@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=MagicMock())
def test_update_diagram_logic_failed_dot_generation(mock_create_threat_model, mock_generate_manual_dot, service):
    with pytest.raises(RuntimeError, match="Failed to generate DOT code from model"):
        service.update_diagram_logic("some markdown")

@patch('threat_analysis.server.threat_model_service.DiagramGenerator.generate_diagram_from_dot', return_value=None)
@patch('threat_analysis.server.threat_model_service.DiagramGenerator._generate_manual_dot', return_value="dot code")
@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=MagicMock())
def test_update_diagram_logic_failed_svg_generation(mock_create_threat_model, mock_generate_manual_dot, mock_generate_diagram_from_dot, service):
    with pytest.raises(RuntimeError, match="Failed to generate SVG diagram"):
        service.update_diagram_logic("some markdown")

@patch('threat_analysis.server.threat_model_service.os.path.exists', return_value=False)
@patch('threat_analysis.server.threat_model_service.DiagramGenerator.generate_diagram_from_dot', return_value="/tmp/test.svg")
@patch('threat_analysis.server.threat_model_service.DiagramGenerator._generate_manual_dot', return_value="dot code")
@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=MagicMock())
def test_update_diagram_logic_svg_file_not_found(mock_create_threat_model, mock_generate_manual_dot, mock_generate_diagram_from_dot, mock_os_path_exists, service):
    with pytest.raises(RuntimeError, match="Failed to generate SVG diagram"):
        service.update_diagram_logic("some markdown")

# Test cases for export_files_logic
def test_export_files_logic_invalid_format(service):
    """Test export_files_logic with an invalid format."""
    mock_markdown = """# Valid Model
## Boundaries
- **Boundary**:"""
    with pytest.raises(ValueError, match="Invalid export format"):
        service.export_files_logic(mock_markdown, "invalid_format")

def test_export_files_logic_missing_data(service):
    """Test export_files_logic with missing markdown or format."""
    with pytest.raises(ValueError, match="Missing markdown content or export format"):
        service.export_files_logic("", "svg")
    with pytest.raises(ValueError, match="Missing markdown content or export format"):
        service.export_files_logic("# Test", "")

@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=None)
def test_export_files_logic_failed_threat_model_creation(mock_create_threat_model, service):
    with pytest.raises(RuntimeError, match="Failed to create or validate threat model"):
        service.export_files_logic("some markdown", "svg")

@patch('threat_analysis.server.threat_model_service.DiagramGenerator.generate_custom_svg_export', return_value=None)
@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=MagicMock())
def test_export_files_logic_failed_svg_generation(mock_create_threat_model, mock_generate_custom_svg_export, service):
    with pytest.raises(RuntimeError, match="Failed to generate SVG file"):
        service.export_files_logic("some markdown", "svg")

@patch('threat_analysis.server.threat_model_service.DiagramGenerator.generate_custom_svg_export', return_value="/tmp/test.svg")
@patch('threat_analysis.server.threat_model_service.DiagramGenerator._generate_manual_dot', return_value="dot code")
@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=MagicMock())
def test_export_files_logic_svg_success(mock_create_threat_model, mock_generate_manual_dot, mock_generate_custom_svg_export, service):
    output_path, output_filename = service.export_files_logic("some markdown", "svg")
    assert output_filename == "diagram.svg"
    assert output_path.endswith("diagram.svg")

@patch('threat_analysis.server.threat_model_service.DiagramGenerator._generate_html_with_legend')
@patch('threat_analysis.server.threat_model_service.DiagramGenerator.generate_diagram_from_dot', return_value="/tmp/test.svg")
@patch('threat_analysis.server.threat_model_service.DiagramGenerator._generate_manual_dot', return_value="dot code")
@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=MagicMock())
def test_export_files_logic_diagram_success(mock_create_threat_model, mock_generate_manual_dot, mock_generate_diagram_from_dot, mock_generate_html_with_legend, service):
    output_path, output_filename = service.export_files_logic("some markdown", "diagram")
    assert output_filename == "diagram.html"
    assert output_path.endswith("diagram.html")
    mock_generate_html_with_legend.assert_called_once()

@patch('threat_analysis.server.threat_model_service.ReportGenerator.generate_html_report')
@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=MagicMock(process_threats=MagicMock(return_value=[])))
def test_export_files_logic_report_success(mock_create_threat_model, mock_generate_html_report, service):
    output_path, output_filename = service.export_files_logic("some markdown", "report")
    assert output_filename == "threat_report.html"
    assert output_path.endswith("threat_report.html")
    mock_generate_html_report.assert_called_once()


# Test cases for export_all_files_logic
def test_export_all_files_logic_missing_markdown(service):
    with pytest.raises(ValueError, match="Missing markdown content"):
        service.export_all_files_logic("")

@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=None)
def test_export_all_files_logic_failed_threat_model_creation(mock_create_threat_model, service):
    with pytest.raises(RuntimeError, match="Failed to create or validate threat model"):
        service.export_all_files_logic("some markdown")


def test_export_all_files_logic_missing_markdown(service):
    with pytest.raises(ValueError, match="Missing markdown content"):
        service.export_all_files_logic("")

@patch('threat_analysis.server.threat_model_service.create_threat_model', return_value=None)
def test_export_all_files_logic_failed_threat_model_creation(mock_create_threat_model, service):
    with pytest.raises(RuntimeError, match="Failed to create or validate threat model"):
        service.export_all_files_logic("some markdown")





