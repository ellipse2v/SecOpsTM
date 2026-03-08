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

import logging

logger = logging.getLogger(__name__)

def get_embeddings(ai_config: dict):
    """Returns the correct embedding model according to the configuration."""
    cfg = ai_config.get("embedding", {})
    provider = cfg.get("provider", "huggingface")
    model = cfg.get("model", "all-MiniLM-L6-v2")

    logger.info(f"Initializing embedding provider: {provider} with model: {model}")

    if provider == "huggingface":
        from langchain_huggingface import HuggingFaceEmbeddings
        device = cfg.get("device", "cpu")
        return HuggingFaceEmbeddings(
            model_name=model,
            model_kwargs={"device": device}
        )
    elif provider == "google":
        from langchain_google_genai import GoogleGenerativeAIEmbeddings
        return GoogleGenerativeAIEmbeddings(model=model)
    elif provider == "mistral":
        from langchain_mistralai import MistralAIEmbeddings
        return MistralAIEmbeddings(model=model)
    elif provider == "ollama":
        from langchain_ollama import OllamaEmbeddings
        return OllamaEmbeddings(model=model)
    else:
        raise ValueError(f"Unknown embedding provider: {provider}")
