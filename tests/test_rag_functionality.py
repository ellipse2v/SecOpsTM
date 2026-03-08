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
import json
import shutil
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

# --- Pre-emptive Mocking to avoid litellm/dotenv crashes ---
# This must happen before any imports that might trigger litellm
mock_litellm = MagicMock()
mock_langchain_litellm = MagicMock()
sys.modules['dotenv'] = MagicMock()
sys.modules['litellm'] = mock_litellm
sys.modules['litellm.types'] = MagicMock()
sys.modules['litellm.types.utils'] = MagicMock()
sys.modules['langchain_litellm'] = mock_langchain_litellm
sys.modules['langchain_chroma'] = MagicMock()
sys.modules['langchain_huggingface'] = MagicMock()
sys.modules['chromadb'] = MagicMock()
sys.modules['chromadb.config'] = MagicMock()
sys.modules['langchain_core'] = MagicMock()
sys.modules['langchain_core.prompts'] = MagicMock()
sys.modules['langchain_core.output_parsers'] = MagicMock()
sys.modules['langchain_core.runnables'] = MagicMock()
sys.modules['threat_analysis.ai_engine.embedding_factory'] = MagicMock()

# Now we can safely import our modules
from threat_analysis.ai_engine.rag_service import RAGThreatGenerator
from threat_analysis.server.ai_service import AIService
from threat_analysis.core.models_module import ThreatModel, ExtendedThreat
from pytm import Actor, Server

# Define paths for test data
TEST_DIR = Path(__file__).parent / "test_rag_data"
TEST_VECTOR_STORE_DIR = TEST_DIR / "vector_store"
TEST_USER_CONTEXT_PATH = TEST_DIR / "user_context.json"
TEST_AI_CONFIG_PATH = TEST_DIR / "ai_config.yaml"

@pytest.fixture(scope="module", autouse=True)
def setup_test_environment():
    """Sets up a temporary test environment for RAG functionality."""
    # Create test directory
    TEST_DIR.mkdir(exist_ok=True)
    TEST_VECTOR_STORE_DIR.mkdir(exist_ok=True)

    # Create dummy ai_config.yaml
    ai_config_content = """
ai_providers:
  ollama:
    enabled: true
    model: "test-llama3"
    host: "http://localhost:11434"
    temperature: 0.5
embedding:
  provider: huggingface
  model: "test-embedding-model"
  device: cpu
rag:
  enabled: true
"""
    with open(TEST_AI_CONFIG_PATH, "w", encoding="utf-8") as f:
        f.write(ai_config_content)

    # Create dummy user_context.json
    user_context_content = """
{
  "system_description": "Test e-commerce application.",
  "threat_intelligence": [
    "Test phishing attacks.",
    "Test SQL injection vulnerabilities."
  ]
}
"""
    with open(TEST_USER_CONTEXT_PATH, "w", encoding="utf-8") as f:
        f.write(user_context_content)

    yield

    # Teardown: Clean up test directory
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)


class AsyncIterator:
    def __init__(self, items):
        self.items = items
        self.index = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.index < len(self.items):
            item = self.items[self.index]
            self.index += 1
            return item
        else:
            raise StopAsyncIteration

@pytest.fixture
def mock_provider():
    """Mocks the LiteLLMProvider for AIService."""
    mock_provider = MagicMock()
    mock_provider.check_connection = AsyncMock(return_value=True)
    
    # Mock for generate_threats (component-level threats)
    mock_provider.generate_threats = AsyncMock(return_value=[
        {
            "title": "SQL Injection",
            "description": "SQL Injection vulnerability in payment module.",
            "category": "Tampering",
            "likelihood": "high",
            "business_impact": {"severity": "critical", "details": "Data breach"},
            "confidence": 0.9
        }
    ])
    return mock_provider

@pytest.fixture
def mock_chat_litellm():
    """Mocks ChatLiteLLM for RAGThreatGenerator."""
    mock_llm = MagicMock()
    # The generator expects a response object with a .content attribute that is a JSON string
    threats_json = json.dumps([
        {
            "name": "Global Phishing Threat",
            "description": "Advanced phishing attacks targeting employees of the e-commerce platform.",
            "category": "Spoofing",
            "likelihood": "high",
            "impact": "critical",
            "source": "LLM"
        },
        {
            "name": "Supply Chain Compromise",
            "description": "Compromise of a third-party payment processing library.",
            "category": "Tampering",
            "likelihood": "medium",
            "impact": "high",
            "source": "LLM"
        }
    ])
    mock_response = MagicMock()
    mock_response.content = f"```json\n{threats_json}\n```"
    mock_llm.invoke.return_value = mock_response
    
    # Set it in the sys.modules mock
    mock_langchain_litellm.ChatLiteLLM.return_value = mock_llm
    return mock_llm


@pytest.mark.asyncio
async def test_rag_threat_generator_initialization(mock_chat_litellm):
    """Test RAGThreatGenerator initialization."""
    with patch('os.path.exists', side_effect=lambda x: x == str(TEST_VECTOR_STORE_DIR) or x == str(TEST_AI_CONFIG_PATH) or x == str(TEST_USER_CONTEXT_PATH)):
        rag_generator = RAGThreatGenerator(
            vector_store_dir=str(TEST_VECTOR_STORE_DIR),
            user_context_path=str(TEST_USER_CONTEXT_PATH),
            ai_config_path=str(TEST_AI_CONFIG_PATH)
        )
        assert rag_generator is not None
        assert rag_generator.vector_store is not None
        # Check that ChatLiteLLM was called
        assert mock_langchain_litellm.ChatLiteLLM.called


@pytest.mark.asyncio
async def test_rag_threat_generator_generates_threats(mock_chat_litellm):
    """Test RAGThreatGenerator generates threats in the correct format."""
    with patch('os.path.exists', side_effect=lambda x: x == str(TEST_VECTOR_STORE_DIR) or x == str(TEST_AI_CONFIG_PATH) or x == str(TEST_USER_CONTEXT_PATH)):
        with patch.object(RAGThreatGenerator, '_initialize_components'):
            rag_generator = RAGThreatGenerator(
                vector_store_dir=str(TEST_VECTOR_STORE_DIR),
                user_context_path=str(TEST_USER_CONTEXT_PATH),
                ai_config_path=str(TEST_AI_CONFIG_PATH)
            )
            rag_generator.vector_store = MagicMock()
            rag_generator.vector_store.similarity_search.return_value = [MagicMock(page_content="context")]

            expected_threats = [
                {"name": "T1", "category": "Spoofing", "source": "LLM"},
                {"name": "T2", "category": "Tampering", "source": "LLM"},
            ]
            # Mock the fully-assembled chain stored on the instance
            rag_generator.rag_chain = MagicMock()
            rag_generator.rag_chain.invoke.return_value = expected_threats

            threats = rag_generator.generate_threats("This is a test threat model.")

            assert isinstance(threats, list)
            assert len(threats) == 2
            rag_generator.rag_chain.invoke.assert_called_once()


@pytest.mark.asyncio
async def test_aiservice_integrates_rag_threats(mock_provider, mock_chat_litellm):
    """Test AIService successfully integrates RAG-generated threats."""
    # Mock dependencies for AIService
    mock_ai_config_path_exists = lambda x: x == str(TEST_AI_CONFIG_PATH) or x == str(TEST_VECTOR_STORE_DIR) or x == str(TEST_USER_CONTEXT_PATH)

    with patch('threat_analysis.server.ai_service.LiteLLMProvider') as MockProvider, \
         patch('os.path.exists', side_effect=mock_ai_config_path_exists), \
         patch('threat_analysis.server.ai_service.RAGThreatGenerator') as MockRAG:
        
        MockProvider.return_value = mock_provider
        
        # Configure the MockRAG to return our desired threats
        mock_rag_instance = MockRAG.return_value
        mock_rag_instance.generate_threats.return_value = [
            {
                "name": "Global Phishing Threat",
                "description": "Advanced phishing attacks.",
                "category": "Spoofing",
                "likelihood": "high",
                "impact": "critical",
                "source": "LLM"
            },
            {
                "name": "Supply Chain Compromise",
                "description": "Compromise of a third-party library.",
                "category": "Tampering",
                "likelihood": "medium",
                "impact": "high",
                "source": "LLM"
            }
        ]

        ai_service = AIService(config_path=str(TEST_AI_CONFIG_PATH))
        await ai_service.init_ai() # This should now use the mocked RAGThreatGenerator

        assert ai_service.rag_generator is not None

        # Mock a cve_service if needed by ThreatModel creation
        mock_cve_service = MagicMock()
        mock_cve_service.get_cves_for_equipment.return_value = []
        mock_cve_service.get_capecs_for_cve.return_value = []

        # Use a name that avoids any global TM naming conflicts in tests
        threat_model = ThreatModel(name="RAGTestModelFinal", description="Test", cve_service=mock_cve_service)

        # Add dummy elements for component-level AI threats
        actor_data = {'object': Actor("UserRAGFinal"), 'name': "UserRAGFinal"}
        server_data = {'object': Server("WebAppRAGFinal"), 'name': "WebAppRAGFinal"}

        threat_model.actors.append(actor_data)
        threat_model.servers.append(server_data)

        # Call the enrich method
        await ai_service._enrich_with_ai_threats(threat_model)

        # Assert RAG-generated threats are added globally
        assert hasattr(threat_model.tm, 'global_threats_llm')
        assert len(threat_model.tm.global_threats_llm) == 2
        assert all(isinstance(t, ExtendedThreat) for t in threat_model.tm.global_threats_llm)
        assert all(t.source == "LLM" for t in threat_model.tm.global_threats_llm)

        # Assert component-level AI threats are added
        assert len(threat_model.servers[0]['object'].threats) == 1
        assert threat_model.servers[0]['object'].threats[0].source == "AI"
        assert "(AI) SQL Injection" in threat_model.servers[0]['object'].threats[0].description
        assert threat_model.servers[0]['object'].threats[0].category == "Tampering"

