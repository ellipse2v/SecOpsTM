import aiohttp
import json
import logging
from typing import Dict, List
from .base_provider import BaseLLMProvider
from ..prompts.stride_prompts import STRIDE_SYSTEM_PROMPT, build_component_prompt
from ..prompts.attack_flow_prompts import ATTACK_FLOW_SYSTEM_PROMPT, build_attack_flow_prompt

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
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            try:
                async with session.post(
                    f"{self.host}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": f"{STRIDE_SYSTEM_PROMPT}\\n\\n{prompt}",
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
                logging.error(f"Error connecting to Ollama: {e}")
                return []
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from Ollama: {e}")
                logging.error(f"Received text: {result_text}")
                return []

    async def generate_attack_flow(self, threat: Dict, component: Dict, context: Dict) -> Dict:
        prompt = build_attack_flow_prompt(threat, component, context)
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            try:
                async with session.post(
                    f"{self.host}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": f"{ATTACK_FLOW_SYSTEM_PROMPT}\\n\\n{prompt}",
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
                logging.error(f"Error connecting to Ollama for attack flow generation: {e}")
                return {}
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON from Ollama for attack flow generation: {e}")
                logging.error(f"Received text: {result_text}")
                return {}
