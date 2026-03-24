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
from typing import AsyncGenerator, Dict, List, Optional
from .base_provider import BaseLLMProvider
from .litellm_client import LiteLLMClient
from ..prompts.stride_prompts import build_component_prompt
from ..prompts.attack_flow_prompts import build_attack_flow_prompt
from threat_analysis.ai_engine.prompt_loader import get as _get_prompt
import json

class LiteLLMProvider(BaseLLMProvider):
    """Provider for multiple LLMs via LiteLLM"""

    def __init__(self, config: Dict):
        # We don't use the config directly here, as LiteLLMClient loads it from ai_config.yaml
        # But we might want to override some settings if needed.
        self._client = None
        self._config = config

    async def _get_client(self):
        if self._client is None:
            self._client = await LiteLLMClient.create()
        return self._client

    async def check_connection(self) -> bool:
        client = await self._get_client()
        return await client.check_connection()

    async def generate_threats(self, component: Dict, context: Dict) -> List[Dict]:
        client = await self._get_client()
        prompt = build_component_prompt(component, context)
        
        try:
            # generate_content is an async generator
            full_response = ""
            async for chunk in client.generate_content(
                prompt=prompt,
                system_prompt=_get_prompt("stride_analysis", "system"),
                output_format="json"
            ):
                if isinstance(chunk, dict):
                    return chunk.get('threats', [])
                full_response += str(chunk)
            
            # Fallback if it didn't return a dict directly
            return []
        except Exception as e:
            logging.error(f"Error generating threats via LiteLLM: {e}")
            return []

    async def generate_attack_flow(self, threat: Dict, component: Dict, context: Dict) -> Dict:
        client = await self._get_client()
        prompt = build_attack_flow_prompt(threat, component, context)

        try:
            async for chunk in client.generate_content(
                prompt=prompt,
                system_prompt=_get_prompt("attack_flow", "system"),
                output_format="json"
            ):
                if isinstance(chunk, dict):
                    return chunk
            return {}
        except Exception as e:
            logging.error(f"Error generating attack flow via LiteLLM: {e}")
            return {}

    async def generate_ciso_triage(self, prompt: str, system_prompt: str) -> Dict:
        """Calls the LLM with the CISO persona and returns the parsed briefing."""
        client = await self._get_client()
        try:
            async for chunk in client.generate_content(
                prompt=prompt,
                system_prompt=system_prompt,
                output_format="json",
            ):
                if isinstance(chunk, dict) and "posture_score" in chunk:
                    return chunk
                if isinstance(chunk, dict):
                    return chunk
            return {}
        except Exception as exc:
            logging.error("CISO triage generation failed: %s", exc)
            return {}

    async def generate_soc_analysis(self, batch_prompt: str, system_prompt: str) -> List[Dict]:
        """Calls the LLM with the SOC analyst persona and returns parsed results."""
        client = await self._get_client()
        try:
            async for chunk in client.generate_content(
                prompt=batch_prompt,
                system_prompt=system_prompt,
                output_format="json",
            ):
                if isinstance(chunk, list):
                    return chunk
                if isinstance(chunk, dict):
                    # Some providers may wrap the array in a dict
                    return chunk.get("results", chunk.get("threats", []))
            return []
        except Exception as exc:
            logging.error("SOC analysis generation failed: %s", exc)
            return []

    async def generate_markdown(
        self,
        prompt: str,
        markdown: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Streams DSL Markdown from a natural language prompt."""
        client = await self._get_client()
        user_prompt = f"User request: {prompt}"
        if markdown:
            user_prompt += f"\n\nExisting Threat Model to update/expand:\n{markdown}"
        try:
            async for chunk in client.generate_content(
                prompt=user_prompt,
                system_prompt=_get_prompt("dsl_generation", "system"),
                stream=True,
            ):
                yield chunk
        except Exception as e:
            logging.error(f"Error generating markdown via LiteLLM: {e}")
            yield f"Error: {e}"
