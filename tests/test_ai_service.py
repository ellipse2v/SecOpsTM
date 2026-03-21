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
from unittest.mock import MagicMock, AsyncMock, patch, mock_open

from threat_analysis.server.ai_service import AIService

AI_CONFIG_WITH_RAG = """
ai_providers: {}
rag:
  enabled: true
"""

@pytest.fixture
def ai_service():
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=AI_CONFIG_WITH_RAG)):
            return AIService(config_path="dummy_config.yaml")

def test_init_ai(ai_service):
    async def _run():
        with patch("threat_analysis.server.ai_service.LiteLLMProvider") as mock_provider_class, \
             patch("threat_analysis.server.ai_service.RAGThreatGenerator") as mock_rag:

            mock_provider = MagicMock()
            mock_provider.check_connection = AsyncMock(return_value=True)
            mock_provider_class.return_value = mock_provider

            await ai_service.init_ai()

            assert ai_service.ai_online is True
            mock_provider.check_connection.assert_awaited_once()
            mock_rag.assert_called_once()
    asyncio.run(_run())

def test_generate_markdown_from_prompt(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()

        async def mock_gen(**kwargs):
            yield "chunk 1 "
            yield "chunk 2"

        ai_service.provider.generate_markdown.return_value = mock_gen()

        chunks = []
        async for chunk in ai_service.generate_markdown_from_prompt("test prompt", "existing markdown"):
            chunks.append(chunk)

        assert chunks == ["chunk 1 ", "chunk 2"]
        ai_service.provider.generate_markdown.assert_called_once()
    asyncio.run(_run())

def test_generate_markdown_from_prompt_sync(ai_service):
    ai_service.ai_online = True
    ai_service.provider = MagicMock()

    async def mock_gen(**kwargs):
        yield "chunk 1 "
        yield "chunk 2"

    ai_service.provider.generate_markdown.return_value = mock_gen()

    chunks = list(ai_service.generate_markdown_from_prompt_sync("test prompt"))
    assert chunks == ["chunk 1 ", "chunk 2"]

def test_enrich_with_ai_threats(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()
        ai_service.provider.check_connection = AsyncMock(return_value=True)

        class MockElement:
            def __init__(self, name, description, stereotype):
                self.name = name
                self.description = description
                self.stereotype = stereotype
                self.threats = []

        actor = MockElement("Actor 1", "Actor desc", "Actor")

        # Mock threat model
        threat_model = MagicMock()
        threat_model.actors = [{'object': actor}]
        threat_model.servers = []
        threat_model.dataflows = []
        threat_model.tm.description = "System desc"

        ai_service.provider.generate_threats = AsyncMock(return_value=[
            {
                "title": "SQLi",
                "description": "SQL injection",
                "category": "Information Disclosure",
                "likelihood": "high",
                "business_impact": {"severity": "critical", "details": "bad"}
            }
        ])

        await ai_service._enrich_with_ai_threats(threat_model)

        assert len(actor.threats) == 1
        assert "SQLi" in actor.threats[0].description
    asyncio.run(_run())

def test_load_ai_config_not_found(ai_service):
    with patch("os.path.exists", return_value=False):
        config = ai_service._load_ai_config("nonexistent.yaml")
        assert config == {}

def test_load_ai_config_parse_error(ai_service):
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data="{invalid: yaml")):
            config = ai_service._load_ai_config("bad.yaml")
            assert config == {}

def test_generate_rag_threats(ai_service):
    async def _run():
        ai_service.rag_generator = MagicMock()
        ai_service.rag_generator.generate_threats.return_value = [
            {"name": "RAG Threat", "description": "rag desc", "category": "Tampering", "likelihood": "high", "impact": "high"}
        ]

        threat_model = MagicMock()
        threat_model.tm.name = "Test TM"
        threat_model.tm.description = "Test desc"
        threat_model.actors = []
        threat_model.servers = []
        threat_model.dataflows = []

        threats = await ai_service._generate_rag_threats(threat_model)

        assert len(threats) == 1
        assert "RAG Threat" in threats[0].description
        assert threats[0].source == "LLM"
    asyncio.run(_run())

def test_enrich_with_ai_threats_rag_enabled(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()
        ai_service.provider.check_connection = AsyncMock(return_value=True)
        ai_service.rag_generator = MagicMock()
        ai_service.rag_generator.generate_threats.return_value = []

        # Mock threat model
        threat_model = MagicMock()
        threat_model.actors = []
        threat_model.servers = []
        threat_model.dataflows = []
        threat_model.tm.description = "System desc"
        threat_model.tm.global_threats_llm = []

        await ai_service._enrich_with_ai_threats(threat_model)

        ai_service.rag_generator.generate_threats.assert_called_once()
    asyncio.run(_run())

def test_enrich_with_ai_threats_json_fallback(ai_service):
    async def _run():
        ai_service.ai_online = True
        ai_service.provider = MagicMock()
        ai_service.provider.check_connection = AsyncMock(return_value=True)

        class MockElement:
            def __init__(self, name, description, stereotype):
                self.name = name
                self.description = description
                self.stereotype = stereotype
                self.threats = []

        actor = MockElement("Actor 1", "Actor desc", "Actor")
        threat_model = MagicMock()
        threat_model.actors = [{'object': actor}]
        threat_model.servers = []
        threat_model.dataflows = []
        threat_model.tm.description = "System desc"

        ai_service.provider.generate_threats = AsyncMock(return_value=[
            {"title": "Fenced", "description": "desc"}
        ])

        await ai_service._enrich_with_ai_threats(threat_model)
        assert len(actor.threats) == 1
        assert "Fenced" in actor.threats[0].description
    asyncio.run(_run())
