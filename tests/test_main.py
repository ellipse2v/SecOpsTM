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

"""Tests for threat_analysis/__main__.py"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from threat_analysis.__main__ import _build_project_ai_service


class TestBuildProjectAiService:
    """secopstm --project mode must build an AIService so cross-model RAG threat
    generation (Decision A2) runs — previously only the web UI (export_service.py)
    passed ai_service to generate_project_reports(), so the CLI silently skipped it.
    """

    def test_builds_and_initializes_ai_service(self):
        mock_ai_service_instance = MagicMock()
        mock_ai_service_instance.init_ai = AsyncMock()
        mock_ai_service_cls = MagicMock(return_value=mock_ai_service_instance)
        mock_module = MagicMock(AIService=mock_ai_service_cls)

        with patch("importlib.import_module", return_value=mock_module):
            result = _build_project_ai_service(Path("/some/ai_config.yaml"))

        mock_ai_service_cls.assert_called_once_with(
            config_path=str(Path("/some/ai_config.yaml")), force_disable_rag=False
        )
        mock_ai_service_instance.init_ai.assert_awaited_once()
        assert result is mock_ai_service_instance

    def test_passes_force_disable_rag_through(self):
        mock_ai_service_instance = MagicMock()
        mock_ai_service_instance.init_ai = AsyncMock()
        mock_ai_service_cls = MagicMock(return_value=mock_ai_service_instance)
        mock_module = MagicMock(AIService=mock_ai_service_cls)

        with patch("importlib.import_module", return_value=mock_module):
            _build_project_ai_service(Path("/some/ai_config.yaml"), force_disable_rag=True)

        mock_ai_service_cls.assert_called_once_with(
            config_path=str(Path("/some/ai_config.yaml")), force_disable_rag=True
        )

    def test_returns_none_on_import_failure(self):
        with patch("importlib.import_module", side_effect=ImportError("no module")):
            result = _build_project_ai_service(Path("/some/ai_config.yaml"))
        assert result is None

    def test_returns_none_on_init_ai_failure(self):
        mock_ai_service_instance = MagicMock()
        mock_ai_service_instance.init_ai = AsyncMock(side_effect=RuntimeError("boom"))
        mock_ai_service_cls = MagicMock(return_value=mock_ai_service_instance)
        mock_module = MagicMock(AIService=mock_ai_service_cls)

        with patch("importlib.import_module", return_value=mock_module):
            result = _build_project_ai_service(Path("/some/ai_config.yaml"))

        assert result is None
