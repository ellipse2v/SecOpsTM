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
import sys

# Mock modules that might be missing
sys.modules['langchain_google_genai'] = MagicMock()
sys.modules['langchain_mistralai'] = MagicMock()
sys.modules['langchain_ollama'] = MagicMock()
sys.modules['langchain_huggingface'] = MagicMock()

from threat_analysis.ai_engine.embedding_factory import get_embeddings

def test_get_embeddings_huggingface():
    ai_config = {
        "embedding": {
            "provider": "huggingface",
            "model": "test-model",
            "device": "cpu"
        }
    }
    with patch("langchain_huggingface.HuggingFaceEmbeddings") as mock_hf:
        get_embeddings(ai_config)
        mock_hf.assert_called_once_with(
            model_name="test-model",
            model_kwargs={"device": "cpu"}
        )

def test_get_embeddings_google():
    ai_config = {"embedding": {"provider": "google", "model": "test-google"}}
    with patch("langchain_google_genai.GoogleGenerativeAIEmbeddings") as mock_google:
        get_embeddings(ai_config)
        mock_google.assert_called_once_with(model="test-google")

def test_get_embeddings_mistral():
    ai_config = {"embedding": {"provider": "mistral", "model": "test-mistral"}}
    with patch("langchain_mistralai.MistralAIEmbeddings") as mock_mistral:
        get_embeddings(ai_config)
        mock_mistral.assert_called_once_with(model="test-mistral")

def test_get_embeddings_ollama():
    ai_config = {"embedding": {"provider": "ollama", "model": "test-ollama"}}
    with patch("langchain_ollama.OllamaEmbeddings") as mock_ollama:
        get_embeddings(ai_config)
        # api_base defaults to "http://localhost:11434" when not set
        mock_ollama.assert_called_once_with(model="test-ollama", base_url="http://localhost:11434")

def test_get_embeddings_unknown():
    ai_config = {"embedding": {"provider": "unknown"}}
    with pytest.raises(ValueError, match="Unknown embedding provider"):
        get_embeddings(ai_config)
