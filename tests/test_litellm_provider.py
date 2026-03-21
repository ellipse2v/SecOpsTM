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
from unittest.mock import MagicMock, patch, AsyncMock, mock_open
import asyncio
import os
import sys
from pathlib import Path

# Mock litellm
sys.modules['litellm'] = MagicMock()

from threat_analysis.ai_engine.providers.litellm_client import LiteLLMClient
from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider

# --- LiteLLMClient Tests ---

def test_litellm_client_load_config_success():
    mock_config_yaml = """
ai_providers:
  openai:
    enabled: true
    model: "gpt-4"
    api_key_env: "OPENAI_API_KEY"
    api_base: "http://proxy.internal"
"""
    async def _run():
        with patch("builtins.open", mock_open(read_data=mock_config_yaml)), \
             patch("threat_analysis.ai_engine.providers.litellm_client.PROJECT_ROOT", Path("/tmp")), \
             patch("importlib.import_module"), \
             patch.object(LiteLLMClient, "check_connection", return_value=True), \
             patch("os.getenv", return_value="sk-test"):

            client = LiteLLMClient()
            await client._load_ai_config()

            assert client.model_name == "openai/gpt-4"
            assert client.api_base == "http://proxy.internal"
            assert client.ai_online is True
    asyncio.run(_run())

def test_litellm_client_check_connection_fail():
    async def _run():
        client = LiteLLMClient()
        client.model_name = "test"
        client._litellm_module = MagicMock()
        client._litellm_module.acompletion = AsyncMock(side_effect=Exception("Failed"))

        result = await client.check_connection()
        assert result is False
    asyncio.run(_run())

def test_litellm_client_generate_content_no_ai():
    async def _run():
        client = LiteLLMClient()
        client.ai_online = False
        with pytest.raises(RuntimeError, match="AI server is not available"):
            async for chunk in client.generate_content("p", "s"):
                pass
    asyncio.run(_run())

def test_litellm_client_generate_content_success():
    async def _run():
        client = LiteLLMClient()
        client.ai_online = True
        client.model_name = "openai/test"
        client._litellm_module = MagicMock()

        mock_response = MagicMock()
        mock_response.choices[0].message.content = "AI Response"
        client._litellm_module.acompletion = AsyncMock(return_value=mock_response)

        responses = []
        async for chunk in client.generate_content("p", "s", stream=False):
            responses.append(chunk)

        assert responses == ["AI Response"]
    asyncio.run(_run())

def test_litellm_client_generate_content_json():
    async def _run():
        client = LiteLLMClient()
        client.ai_online = True
        client.model_name = "openai/test"
        client._litellm_module = MagicMock()

        mock_response = MagicMock()
        mock_response.choices[0].message.content = '```json\n{"result": "ok"}\n```'
        client._litellm_module.acompletion = AsyncMock(return_value=mock_response)

        responses = []
        with patch("threat_analysis.ai_engine.providers.litellm_client.extract_json_from_llm_response", return_value='{"result": "ok"}'):
            async for chunk in client.generate_content("p", "s", stream=False, output_format="json"):
                responses.append(chunk)

        assert responses == [{"result": "ok"}]
    asyncio.run(_run())

def test_litellm_client_ollama_config():
    mock_config_yaml = """
ai_providers:
  ollama:
    enabled: true
    model: "llama3"
    host: "http://ollama:11434"
"""
    async def _run():
        with patch("builtins.open", mock_open(read_data=mock_config_yaml)), \
             patch("threat_analysis.ai_engine.providers.litellm_client.PROJECT_ROOT", Path("/tmp")), \
             patch("importlib.import_module"), \
             patch.object(LiteLLMClient, "check_connection", return_value=True):

            client = LiteLLMClient()
            await client._load_ai_config()
            assert client.model_name == "ollama/llama3"
            assert os.environ.get("OLLAMA_API_BASE") == "http://ollama:11434"
    asyncio.run(_run())

def test_litellm_client_gemini_api_key():
    mock_config_yaml = """
ai_providers:
  gemini:
    enabled: true
    model: "flash"
    api_key_env: "GEMINI_API_KEY"
"""
    # Set env vars directly before asyncio.run() — patch.dict inside async context
    # is unreliable in Python 3.14 where asyncio.run() may isolate the environment.
    saved_gemini = os.environ.pop("GEMINI_API_KEY", None)
    saved_google = os.environ.pop("GOOGLE_API_KEY", None)
    os.environ["GEMINI_API_KEY"] = "gemini-key"
    try:
        async def _run():
            with patch("builtins.open", mock_open(read_data=mock_config_yaml)), \
                 patch("threat_analysis.ai_engine.providers.litellm_client.PROJECT_ROOT", Path("/tmp")), \
                 patch("importlib.import_module"), \
                 patch.object(LiteLLMClient, "check_connection", return_value=True):

                client = LiteLLMClient()
                await client._load_ai_config()
                assert os.environ.get("GEMINI_API_KEY") == "gemini-key"
                assert os.environ.get("GOOGLE_API_KEY") == "gemini-key"
        asyncio.run(_run())
    finally:
        os.environ.pop("GEMINI_API_KEY", None)
        os.environ.pop("GOOGLE_API_KEY", None)
        if saved_gemini is not None:
            os.environ["GEMINI_API_KEY"] = saved_gemini
        if saved_google is not None:
            os.environ["GOOGLE_API_KEY"] = saved_google

def test_litellm_client_no_provider():
    mock_config_yaml = "ai_providers: {}"
    async def _run():
        with patch("builtins.open", mock_open(read_data=mock_config_yaml)), \
             patch("threat_analysis.ai_engine.providers.litellm_client.PROJECT_ROOT", Path("/tmp")):
            client = LiteLLMClient()
            await client._load_ai_config()
            assert client.provider_config == {}
    asyncio.run(_run())

def test_litellm_client_file_not_found():
    async def _run():
        with patch("builtins.open", side_effect=FileNotFoundError()), \
             patch("threat_analysis.ai_engine.providers.litellm_client.PROJECT_ROOT", Path("/tmp")):
            client = LiteLLMClient()
            await client._load_ai_config()
            assert client.ai_config == {}
    asyncio.run(_run())

# --- LiteLLMProvider Tests ---

def test_litellm_provider_check_connection():
    async def _run():
        with patch("threat_analysis.ai_engine.providers.litellm_client.LiteLLMClient.create", new_callable=AsyncMock) as mock_create:
            mock_client = MagicMock()
            mock_client.check_connection = AsyncMock(return_value=True)
            mock_create.return_value = mock_client

            provider = LiteLLMProvider({})
            result = await provider.check_connection()
            assert result is True
    asyncio.run(_run())

def test_litellm_provider_generate_threats():
    async def _run():
        with patch("threat_analysis.ai_engine.providers.litellm_client.LiteLLMClient.create", new_callable=AsyncMock) as mock_create:
            mock_client = MagicMock()
            async def mock_gen(**kwargs):
                yield {"threats": [{"id": "T1"}]}
            mock_client.generate_content = mock_gen
            mock_create.return_value = mock_client

            provider = LiteLLMProvider({})
            result = await provider.generate_threats({}, {})
            assert result == [{"id": "T1"}]
    asyncio.run(_run())

def test_litellm_provider_generate_attack_flow():
    async def _run():
        with patch("threat_analysis.ai_engine.providers.litellm_client.LiteLLMClient.create", new_callable=AsyncMock) as mock_create:
            mock_client = MagicMock()
            async def mock_gen(**kwargs):
                yield {"flow": "steps"}
            mock_client.generate_content = mock_gen
            mock_create.return_value = mock_client

            provider = LiteLLMProvider({})
            result = await provider.generate_attack_flow({}, {}, {})
            assert result == {"flow": "steps"}
    asyncio.run(_run())
