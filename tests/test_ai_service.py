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
from unittest.mock import MagicMock, AsyncMock, patch

from threat_analysis.server.ai_service import AIService

@pytest.fixture
def ai_service():
    return AIService()

@pytest.mark.asyncio
async def test_init_ai(ai_service):
    with patch("importlib.import_module") as mock_import:
        mock_litellm_client_module = MagicMock()
        mock_litellm_client = MagicMock()
        mock_litellm_client.create = AsyncMock(return_value=MagicMock(ai_online=True))
        mock_litellm_client_module.LiteLLMClient = mock_litellm_client
        mock_import.return_value = mock_litellm_client_module
        
        await ai_service.init_ai()
        
        assert ai_service.ai_online is True
        mock_import.assert_called_once_with("threat_analysis.ai_engine.providers.litellm_client")
        mock_litellm_client.create.assert_awaited_once()
