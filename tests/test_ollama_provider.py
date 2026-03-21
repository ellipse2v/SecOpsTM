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
import json
from unittest.mock import MagicMock, AsyncMock, patch
from threat_analysis.ai_engine.providers.ollama_provider import OllamaProvider

@pytest.fixture
def config():
    return {
        "host": "http://localhost:11434",
        "model": "mistral",
        "temperature": 0.3,
        "num_ctx": 4096,
        "num_predict": 4096
    }

@pytest.fixture
def provider(config):
    # Manually provide the missing abstract method implementation
    def dummy_gen(*args, **kwargs):
        yield "dummy"

    # We must set it on the class, and potentially remove it from __abstractmethods__
    # if the metaclass has already computed it.
    original_methods = OllamaProvider.__abstractmethods__
    OllamaProvider.__abstractmethods__ = set(m for m in original_methods if m != "generate_markdown")
    OllamaProvider.generate_markdown = dummy_gen

    return OllamaProvider(config)

def test_ollama_provider_check_connection(provider):
    async def _run():
        with patch("aiohttp.ClientSession.get") as mock_get:
            # Success case
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_get.return_value.__aenter__.return_value = mock_response

            assert await provider.check_connection() is True

            # Failure case
            mock_response.status = 500
            assert await provider.check_connection() is False

            # Exception case
            mock_get.side_effect = Exception("Connection failed")
            assert await provider.check_connection() is False
    asyncio.run(_run())

def test_ollama_provider_generate_threats(provider):
    async def _run():
        with patch("aiohttp.ClientSession.post") as mock_post:
            # Success case
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.raise_for_status = MagicMock()
            mock_response.text.return_value = json.dumps({
                "response": json.dumps({
                    "threats": [
                        {"category": "Spoofing", "title": "Test Threat"}
                    ]
                })
            })
            mock_post.return_value.__aenter__.return_value = mock_response

            threats = await provider.generate_threats({}, {})
            assert len(threats) == 1
            assert threats[0]["title"] == "Test Threat"

            # Error case - ClientError
            from aiohttp import ClientError
            mock_post.side_effect = ClientError("Post failed")
            threats = await provider.generate_threats({}, {})
            assert threats == []

            # Error case - JSONDecodeError
            mock_post.side_effect = None
            mock_response.text.return_value = "invalid json"
            threats = await provider.generate_threats({}, {})
            assert threats == []
    asyncio.run(_run())

def test_ollama_provider_generate_attack_flow(provider):
    async def _run():
        with patch("aiohttp.ClientSession.post") as mock_post:
            # Success case
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.raise_for_status = MagicMock()
            mock_response.text.return_value = json.dumps({
                "response": json.dumps({
                    "type": "attack-flow",
                    "name": "Test Flow"
                })
            })
            mock_post.return_value.__aenter__.return_value = mock_response

            flow = await provider.generate_attack_flow({}, {}, {})
            assert flow["name"] == "Test Flow"

            # Error case - ClientError
            from aiohttp import ClientError
            mock_post.side_effect = ClientError("Post failed")
            flow = await provider.generate_attack_flow({}, {}, {})
            assert flow == {}

            # Error case - JSONDecodeError
            mock_post.side_effect = None
            mock_response.text.return_value = "invalid json"
            flow = await provider.generate_attack_flow({}, {}, {})
            assert flow == {}
    asyncio.run(_run())
