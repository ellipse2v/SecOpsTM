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

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from threat_analysis.server.threat_model_service import ThreatModelService

@pytest.fixture
def threat_model_service():
    return ThreatModelService()

def test_init(threat_model_service):
    assert threat_model_service.ai_service is not None
    assert threat_model_service.diagram_service is not None
    assert threat_model_service.export_service is not None
    assert threat_model_service.model_management_service is not None

def test_init_ai(threat_model_service):
    async def _run():
        with patch.object(threat_model_service.ai_service, 'init_ai', new_callable=AsyncMock) as mock_init_ai:
            await threat_model_service.init_ai()
            mock_init_ai.assert_awaited_once()
    asyncio.run(_run())

def test_check_version_compatibility(threat_model_service):
    with patch.object(threat_model_service.model_management_service, 'check_version_compatibility') as mock_check:
        threat_model_service.check_version_compatibility("path1", "path2")
        mock_check.assert_called_once_with("path1", "path2")

def test_update_diagram_logic(threat_model_service):
    with patch.object(threat_model_service.diagram_service, 'update_diagram_logic') as mock_update:
        threat_model_service.update_diagram_logic("markdown")
        mock_update.assert_called_once_with("markdown", None, model_file_path=None)

def test_export_files_logic(threat_model_service):
    with patch.object(threat_model_service.export_service, 'export_files_logic') as mock_export:
        threat_model_service.export_files_logic("markdown", "svg")
        mock_export.assert_called_once_with("markdown", "svg", model_file_path=None)
