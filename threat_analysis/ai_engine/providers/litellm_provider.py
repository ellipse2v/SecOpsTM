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
from typing import Dict, List
from .base_provider import BaseLLMProvider
from .litellm_client import LiteLLMClient
from ..prompts.stride_prompts import STRIDE_SYSTEM_PROMPT, build_component_prompt
from ..prompts.attack_flow_prompts import ATTACK_FLOW_SYSTEM_PROMPT, build_attack_flow_prompt
import asyncio
import json

class LiteLLMProvider(BaseLLMProvider):
    """Provider for multiple LLMs via LiteLLM"""

    def __init__(self, config: Dict):
        # We don't use the config directly here, as LiteLLMClient loads it from ai_config.yaml
        # But we might want to override some settings if needed.
        self._client = None
        self._config = config
        self._loop = asyncio.get_event_loop()

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
                system_prompt=STRIDE_SYSTEM_PROMPT,
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
                system_prompt=ATTACK_FLOW_SYSTEM_PROMPT,
                output_format="json"
            ):
                if isinstance(chunk, dict):
                    return chunk
            return {}
        except Exception as e:
            logging.error(f"Error generating attack flow via LiteLLM: {e}")
            return {}
