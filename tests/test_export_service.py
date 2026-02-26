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

@patch('threat_analysis.server.export_service.create_threat_model', return_value=None)
def test_export_files_logic_failed_threat_model_creation(mock_create_threat_model, export_service):
    with pytest.raises(RuntimeError, match="Failed to create or validate threat model"):
        export_service.export_files_logic("some markdown", "svg")
