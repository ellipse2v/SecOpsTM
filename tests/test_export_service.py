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
from pathlib import Path
from unittest.mock import MagicMock, patch

from threat_analysis.server.export_service import ExportService

@pytest.fixture
def export_service():
    cve_service = MagicMock()
    diagram_generator = MagicMock()
    report_generator = MagicMock()
    ai_service = MagicMock()
    diagram_service = MagicMock()
    return ExportService(cve_service, diagram_generator, report_generator, ai_service, diagram_service)

def test_export_files_logic_invalid_format(export_service):
    """Test export_files_logic with an invalid format."""
    mock_markdown = """# Valid Model
## Boundaries
- **Boundary**:"""
    with patch('threat_analysis.server.export_service.create_threat_model', return_value=MagicMock()):
        with pytest.raises(ValueError, match="Invalid export format"):
            export_service.export_files_logic(mock_markdown, "invalid_format")

def test_export_files_logic_missing_data(export_service):
    """Test export_files_logic with missing markdown or format."""
    with pytest.raises(ValueError, match="Missing markdown content or export format"):
        export_service.export_files_logic("", "svg")
    with pytest.raises(ValueError, match="Missing markdown content or export format"):
        export_service.export_files_logic("# Test", "")

@patch('threat_analysis.server.export_service.ModelValidator')
@patch('threat_analysis.server.export_service.create_threat_model')
def test_export_files_logic_svg(mock_create, mock_validator, export_service):
    tm = MagicMock()
    mock_create.return_value = tm
    mock_validator.return_value.validate.return_value = []
    
    export_service.diagram_generator._generate_manual_dot.return_value = "dot"
    export_service.diagram_generator.generate_custom_svg_export.return_value = "path"
    
    with patch('os.makedirs'):
        path, filename = export_service.export_files_logic("md", "svg")
        assert filename == "diagram.svg"

@patch('threat_analysis.server.export_service.ModelValidator')
@patch('threat_analysis.server.export_service.create_threat_model')
def test_export_files_logic_markdown(mock_create, mock_validator, export_service):
    tm = MagicMock()
    mock_create.return_value = tm
    mock_validator.return_value.validate.return_value = []
    
    with patch('os.makedirs'):
        with patch('builtins.open', MagicMock()):
            path, filename = export_service.export_files_logic("md", "markdown")
            assert filename == "threat_model.md"

@patch('threat_analysis.server.export_service.ModelValidator')
@patch('threat_analysis.server.export_service.create_threat_model')
def test_generate_full_project_export_single(mock_create, mock_validator, export_service):
    tm = MagicMock()
    tm.tm.name = "TestModel"
    tm.get_all_threats_details.return_value = []
    mock_create.return_value = tm
    mock_validator.return_value.validate.return_value = []
    
    with patch('pathlib.Path.write_text'):
        with patch('threat_analysis.server.export_service.AttackNavigatorGenerator') as mock_nav:
            mock_nav.return_value.save_layer_to_file.return_value = None
            with patch('threat_analysis.server.export_service.StixGenerator') as mock_stix:
                mock_stix.return_value.generate_stix_bundle.return_value = {"type": "bundle"}
                res = export_service.generate_full_project_export("md", Path("/tmp"))
                assert "reports" in res
                assert res["reports"]["html"] == "stride_mitre_report.html"

def test_export_all_files_logic(export_service):
    with patch.object(export_service, 'generate_full_project_export'):
        with patch('threat_analysis.server.export_service.create_threat_model') as mock_create:
            tm = MagicMock()
            tm.tm.name = "Test"
            mock_create.return_value = tm
            with patch('os.makedirs'):
                with patch('pathlib.Path.write_text'):
                    with patch('zipfile.ZipFile'):
                        with patch('shutil.rmtree'):
                            export_service.diagram_service._generate_positions_from_graphviz.return_value = {"a": 1}
                            buf, ts = export_service.export_all_files_logic("md")
                            assert ts is not None

def test_export_navigator_stix_logic(export_service):
    with patch('threat_analysis.server.export_service.create_threat_model') as mock_create:
        tm = MagicMock()
        tm.tm.name = "Test"
        tm.get_all_threats_details.return_value = []
        mock_create.return_value = tm
        with patch('os.makedirs'):
            with patch('threat_analysis.server.export_service.ModelValidator') as mock_val:
                mock_val.return_value.validate.return_value = []
                with patch('threat_analysis.server.export_service.AttackNavigatorGenerator') as mock_nav:
                    mock_nav.return_value.save_layer_to_file.return_value = None
                    with patch('threat_analysis.server.export_service.StixGenerator') as mock_stix:
                        mock_stix.return_value.generate_stix_bundle.return_value = {"type": "bundle"}
                        with patch('pathlib.Path.write_text'):
                            with patch('zipfile.ZipFile'):
                                with patch('shutil.rmtree'):
                                    buf, ts = export_service.export_navigator_stix_logic("md")
                                    assert ts is not None

def test_export_attack_flow_logic(export_service):
    with patch('threat_analysis.server.export_service.create_threat_model') as mock_create:
        tm = MagicMock()
        tm.tm.name = "Test"
        tm.get_all_threats_details.return_value = []
        mock_create.return_value = tm
        with patch('threat_analysis.server.export_service.AttackFlowGenerator') as mock_afg:
            with patch('os.path.exists', return_value=True):
                with patch('os.listdir', return_value=['file1']):
                    with patch('zipfile.ZipFile'):
                        buf, ts = export_attack_flow_logic = export_service.export_attack_flow_logic("md")
                        assert ts is not None
