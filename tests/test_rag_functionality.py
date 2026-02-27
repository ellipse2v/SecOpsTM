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
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from threat_analysis.ai_engine.rag_service import RAGThreatGenerator
from threat_analysis.server.ai_service import AIService
from threat_analysis.core.models_module import ThreatModel, ExtendedThreat
from pytm import TM, Threat, Actor # Import base Threat and TM from pytm

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
rag:
  enabled: true
  embedding_model: "test-embedding-model"
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

    # Mock Chroma and HuggingFaceEmbeddings to prevent actual network calls/file operations
    with patch('langchain_chroma.Chroma') as MockChroma, \
         patch('langchain_huggingface.HuggingFaceEmbeddings') as MockEmbeddings:
        
        # Configure MockEmbeddings
        mock_embedding_instance = MockEmbeddings.return_value
        mock_embedding_instance.embed_documents.return_value = [[0.1]*768] * 10
        mock_embedding_instance.embed_query.return_value = [0.1]*768

        # Configure MockChroma
        mock_vector_store_instance = MockChroma.return_value
        mock_vector_store_instance.similarity_search.return_value = [
            MagicMock(page_content="Retrieved document 1 about phishing"),
            MagicMock(page_content="Retrieved document 2 about SQLi")
        ]
        
        # Yield to allow tests to run
        yield

    # Teardown: Clean up test directory
    shutil.rmtree(TEST_DIR)


@pytest.fixture
def mock_litellm_client():
    """Mocks the LiteLLMClient for AIService."""
    mock_client = AsyncMock()
    mock_client.ai_online = True
    
    # Mock for generate_content (component-level threats)
    mock_client.generate_content.return_value.__aiter__.return_value = [
        [ # First iteration: for element 1
            {
                "title": "SQL Injection",
                "description": "SQL Injection vulnerability in payment module.",
                "category": "Tampering",
                "likelihood": "high",
                "business_impact": {"severity": "critical", "details": "Data breach"},
                "confidence": 0.9
            }
        ],
        [ # Second iteration: for element 2
            {
                "title": "XSS Vulnerability",
                "description": "Cross-Site Scripting in user profile.",
                "category": "Tampering",
                "likelihood": "medium",
                "business_impact": {"severity": "high", "details": "Session hijacking"},
                "confidence": 0.8
            }
        ]
    ]
    return mock_client

@pytest.fixture
def mock_chat_litellm():
    """Mocks ChatLiteLLM for RAGThreatGenerator."""
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = [
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
    ]
    with patch('langchain_litellm.ChatLiteLLM', return_value=mock_llm):
        yield mock_llm


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
        mock_chat_litellm.assert_called_once()
        # Check that ChatLiteLLM was called with the correct model and params from config
        call_args, call_kwargs = mock_chat_litellm.call_args
        assert call_kwargs['model'] == 'ollama/test-llama3'
        assert call_kwargs['temperature'] == 0.5
        assert call_kwargs['api_base'] == 'http://localhost:11434'


@pytest.mark.asyncio
async def test_rag_threat_generator_generates_threats(mock_chat_litellm):
    """Test RAGThreatGenerator generates threats in the correct format."""
    with patch('os.path.exists', side_effect=lambda x: x == str(TEST_VECTOR_STORE_DIR) or x == str(TEST_AI_CONFIG_PATH) or x == str(TEST_USER_CONTEXT_PATH)):
        rag_generator = RAGThreatGenerator(
            vector_store_dir=str(TEST_VECTOR_STORE_DIR),
            user_context_path=str(TEST_USER_CONTEXT_PATH),
            ai_config_path=str(TEST_AI_CONFIG_PATH)
        )
        example_threat_model_md = "This is a test threat model for a web application."
        threats = rag_generator.generate_threats(example_threat_model_md)

        assert isinstance(threats, list)
        assert len(threats) == 2
        assert threats[0]["source"] == "LLM"
        assert threats[0]["category"] == "Spoofing"
        assert "name" in threats[0]
        assert "description" in threats[0]


@pytest.mark.asyncio
async def test_aiservice_integrates_rag_threats(mock_litellm_client, mock_chat_litellm):
    """Test AIService successfully integrates RAG-generated threats."""
    # Mock dependencies for AIService
    mock_ai_config_path_exists = lambda x: x == str(TEST_AI_CONFIG_PATH) or x == str(TEST_VECTOR_STORE_DIR) or x == str(TEST_USER_CONTEXT_PATH)

    with patch('threat_analysis.server.ai_service.LiteLLMClient.create', new=AsyncMock(return_value=mock_litellm_client)), \
         patch('os.path.exists', side_effect=mock_ai_config_path_exists):
        
        ai_service = AIService()
        await ai_service.init_ai() # This should also initialize RAGThreatGenerator

        assert ai_service.rag_generator is not None

        # Create a dummy threat_model object
        mock_tm = TM("Test Threat Model")
        mock_tm.description = "A simple test threat model."
        mock_tm.name = "Test Model"

        # Mock a cve_service if needed by ThreatModel creation
        mock_cve_service = MagicMock()
        mock_cve_service.get_cves_for_equipment.return_value = []
        mock_cve_service.get_capecs_for_cve.return_value = []

        threat_model = ThreatModel(name="Test Model", description="Test", cve_service=mock_cve_service)
        threat_model.tm = mock_tm # Assign the mock TM

        # Add dummy elements for component-level AI threats
        actor_data = {'object': Actor("User"), 'name': "User"}
        server_data = {'object': MagicMock(name="WebApp", stereotype="Web Server", description="E-commerce frontend"), 'name': "WebApp"}
        dataflow_data = MagicMock(name="Login Flow", protocol="HTTPS", description="User login")

        threat_model.actors.append(actor_data)
        threat_model.servers.append(server_data)
        threat_model.dataflows.append(dataflow_data)

        # Call the enrich method
        await ai_service._enrich_with_ai_threats(threat_model)

        # Assert RAG-generated threats are added globally
        assert hasattr(threat_model.tm, 'global_threats_llm')
        assert len(threat_model.tm.global_threats_llm) == 2
        assert all(isinstance(t, ExtendedThreat) for t in threat_model.tm.global_threats_llm)
        assert all(t.source == "LLM" for t in threat_model.tm.global_threats_llm)

        # Assert component-level AI threats are added
        # Check the threats of the mocked WebApp server (from mock_litellm_client)
        assert len(threat_model.servers[0]['object'].threats) == 1
        assert threat_model.servers[0]['object'].threats[0].source == "AI"
        assert threat_model.servers[0]['object'].threats[0].description.startswith("(AI) SQL Injection")
        assert threat_model.servers[0]['object'].threats[0].category == "Tampering"
