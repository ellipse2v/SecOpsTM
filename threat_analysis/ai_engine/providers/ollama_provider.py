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

import aiohttp
import json
import logging
import asyncio
from typing import Dict, List
from .base_provider import BaseLLMProvider
from ..prompts.stride_prompts import build_component_prompt
from ..prompts.attack_flow_prompts import build_attack_flow_prompt
from threat_analysis.ai_engine.prompt_loader import get as _get_prompt

class OllamaProvider(BaseLLMProvider):
    """Provider for local deployment with Ollama"""

    def __init__(self, config: Dict):
        self.host = config.get("host", "http://localhost:11434")
        self.model = config.get("model", "mistral")
        self.temperature = config.get("temperature", 0.3)
        self.num_ctx = config.get("num_ctx", 4096)
        self.num_predict = config.get("num_predict", 4096)
        self.timeout = aiohttp.ClientTimeout(total=120) # Increased timeout for potentially longer generation

    async def check_connection(self) -> bool:
        """Checks if Ollama server is running and reachable."""
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            try:
                async with session.get(f"{self.host}/api/tags") as response:
                    return response.status == 200
            except Exception:
                return False

    async def generate_threats(self, component: Dict, context: Dict) -> List[Dict]:
        prompt = build_component_prompt(component, context)
        result_text = ""
        
        max_retries = 3
        for attempt in range(max_retries):
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                try:
                    async with session.post(
                        f"{self.host}/api/generate",
                        json={
                            "model": self.model,
                            "prompt": f"{_get_prompt('stride_analysis', 'system')}\n\n{prompt}",
                            "format": "json",
                            "stream": False,
                            "options": {
                                "temperature": self.temperature,
                                "num_ctx": self.num_ctx,
                                "num_predict": self.num_predict
                            }
                        }
                    ) as response:
                        response.raise_for_status()
                        result_text = await response.text()
                        result = json.loads(result_text)
                        # The actual response is a JSON string inside the 'response' key
                        return json.loads(result.get('response', '{}')).get('threats', [])
                except aiohttp.ClientError as e:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logging.warning(f"Error connecting to Ollama (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue
                    logging.error(f"Error connecting to Ollama after {max_retries} attempts: {e}")
                    return []
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON from Ollama: {e}")
                    logging.error(f"Received text: {result_text}")
                    return []
        return []

    async def generate_attack_flow(self, threat: Dict, component: Dict, context: Dict) -> Dict:
        prompt = build_attack_flow_prompt(threat, component, context)
        result_text = ""
        
        max_retries = 3
        for attempt in range(max_retries):
            async with aiohttp.ClientSession(timeout=self.timeout) as session:
                try:
                    async with session.post(
                        f"{self.host}/api/generate",
                        json={
                            "model": self.model,
                            "prompt": f"{_get_prompt('attack_flow', 'system')}\n\n{prompt}",
                            "format": "json",
                            "stream": False,
                            "options": {
                                "temperature": 0.2, # More deterministic for structured format
                                "num_ctx": self.num_ctx,
                                "num_predict": self.num_predict
                            }
                        }
                    ) as response:
                        response.raise_for_status()
                        result_text = await response.text()
                        result = json.loads(result_text)
                        # The actual response is a JSON string inside the 'response' key
                        return json.loads(result.get('response', '{}'))
                except aiohttp.ClientError as e:
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt
                        logging.warning(f"Error connecting to Ollama for attack flow generation (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {wait_time}s...")
                        await asyncio.sleep(wait_time)
                        continue
                    logging.error(f"Error connecting to Ollama for attack flow generation after {max_retries} attempts: {e}")
                    return {}
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding JSON from Ollama for attack flow generation: {e}")
                    logging.error(f"Received text: {result_text}")
                    return {}
        return {}
