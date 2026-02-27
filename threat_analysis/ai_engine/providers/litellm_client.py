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
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
import os
import json
import time
import importlib
import re

PROJECT_ROOT = Path(__file__).resolve().parents[3]

class LiteLLMClient:
    def __init__(self):
        self.ai_config = {}
        self.model_name = ""
        self.stream = False
        self.ai_online = False
        self.client = None # litellm doesn\'t require a client object for its main completion function
        self.provider_config = {}
        self._litellm_module = None # To hold the dynamically imported litellm module

    def _extract_json_from_response(self, text: str) -> str:
        """Extracts a JSON object from a string that might be wrapped in markdown or have other text."""
        # First, try to find JSON within markdown code fences
        pattern = r"```(?:json)?\s*(\{.*?\})\s*```"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            return match.group(1)

        # If no fences, find the first '{' and last '}' as a fallback for models that don't use fences
        try:
            start = text.find('{')
            end = text.rfind('}')
            if start != -1 and end != -1 and end > start:
                potential_json = text[start:end+1]
                # A simple check to see if it's likely a JSON object
                json.loads(potential_json)
                return potential_json
        except (json.JSONDecodeError, TypeError):
             # Not a valid JSON object, return None to indicate failure.
             return None

        return None # No JSON found or extracted.

    @staticmethod
    async def create():
        """Creates and asynchronously initializes the LiteLLMClient."""
        client = LiteLLMClient()
        await client._load_ai_config()
        return client

    async def _load_ai_config(self):
        """Loads AI configuration from ai_config.yaml and initializes LiteLLM."""
        start_time = time.time()
        logging.info(f"[{time.time() - start_time:.4f}s] Loading AI configuration...")
        try:
            with open(PROJECT_ROOT / "config/ai_config.yaml", 'r') as f:
                self.ai_config = yaml.safe_load(f)
            logging.info(f"[{time.time() - start_time:.4f}s] AI configuration loaded.")
            
            provider_name = None
            for name, provider_config in self.ai_config.get("ai_providers", {}).items():
                if provider_config.get('enabled', False):
                    self.provider_config = provider_config
                    provider_name = name
                    break
            
            if self.provider_config:
                # Dynamically import litellm only if an AI provider is enabled
                try:
                    self._litellm_module = importlib.import_module("litellm")
                    logging.debug(f"[{time.time() - start_time:.4f}s] litellm module dynamically imported.")
                except ImportError as e:
                    logging.error(f"[{time.time() - start_time:.4f}s] Failed to import litellm: {e}. AI features disabled.")
                    return

                self.model_name = f"{provider_name}/{self.provider_config.get('model')}"
                if provider_name == "ollama":
                    self.model_name = f"ollama/{self.provider_config.get('model')}"

                self.stream = self.provider_config.get('stream', False)
                
                if provider_name == "ollama":
                    ollama_host = self.provider_config.get('host', 'http://localhost:11434')
                    os.environ['OLLAMA_API_BASE'] = ollama_host
                    logging.debug(f"[{time.time() - start_time:.4f}s] LiteLLM configured for Ollama at {ollama_host} using model {self.model_name}")

                logging.info(f"[{time.time() - start_time:.4f}s] Checking AI server status...")
                self.ai_online = await self.check_connection()
                if self.ai_online:
                    logging.info(f"[{time.time() - start_time:.4f}s] AI server (LiteLLM via {provider_name}) is online. AI features enabled.")
                else:
                    logging.warning(f"[{time.time() - start_time:.4f}s] AI server (LiteLLM via {provider_name}) is offline. AI features disabled.")
            else:
                logging.warning(f"[{time.time() - start_time:.4f}s] No enabled AI provider found in ai_config.yaml. AI features disabled.")

        except FileNotFoundError:
            logging.error(f"[{time.time() - start_time:.4f}s] config/ai_config.yaml not found. AI features disabled.")
        except Exception as e:
            logging.error(f"[{time.time() - start_time:.4f}s] Error initializing LiteLLMClient: {e}", exc_info=True)

    async def check_connection(self) -> bool:
        """Checks if the configured AI model is available via LiteLLM."""
        check_start_time = time.time()
        if not self.model_name or not self._litellm_module:
            return False
        try:
            logging.debug(f"[{time.time() - check_start_time:.4f}s] Pinging AI model {self.model_name}...")
            await self._litellm_module.acompletion(
                model=self.model_name, 
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=1, 
                timeout=self.provider_config.get('timeout', 10),    
                stream=False  
            )
            logging.debug(f"[{time.time() - check_start_time:.4f}s] AI model {self.model_name} responded successfully.")
            return True
        except Exception as e:
            logging.error(f"[{time.time() - check_start_time:.4f}s] LiteLLM health check failed for model {self.model_name}: {e}")
            return False

    async def generate_content(self, prompt: str, system_prompt: str, stream: Optional[bool] = None, output_format: str = "text"):
        """
        Generates content using LiteLLM.
        Can yield chunks if streaming is enabled.
        output_format can be "text" or "json".
        """
        if not self.ai_online or not self._litellm_module:
            raise RuntimeError("AI server is not available or litellm not loaded. This feature is disabled.")

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ]
        
        completion_params = {
            "model": self.model_name,
            "messages": messages,
            "stream": self.stream if stream is None else stream,
            "temperature": self.provider_config.get('temperature', 0.7),
            "max_tokens": self.provider_config.get('max_tokens', 4096),
            "timeout": self.provider_config.get('timeout', 30)
        }

        if output_format == "json":
            messages[0]["content"] += "\n\nYour output MUST be a valid JSON object."
            
            provider_name = self.model_name.split('/')[0]
            if provider_name in ["openai", "azure", "groq"]:
                completion_params["response_format"] = {"type": "json_object"}

        use_stream = self.stream if stream is None else stream
        completion_params["stream"] = use_stream

        try:
            llm_call_start_time = time.time()
            response = await self._litellm_module.acompletion(**completion_params)
            llm_call_end_time = time.time()
            logging.debug(f"[LLM Response Time: {llm_call_end_time - llm_call_start_time:.4f}s] Model: {self.model_name}")
            
            full_response_content = ""
            if use_stream:
                async for chunk in response:
                    if chunk.choices and chunk.choices[0].delta.content:
                        content_chunk = chunk.choices[0].delta.content
                        full_response_content += content_chunk
                        yield content_chunk
            else:
                full_response_content = response.choices[0].message.content
            
            if output_format == "json":
                cleaned_content = self._extract_json_from_response(full_response_content)
                if cleaned_content:
                    try:
                        yield json.loads(cleaned_content)
                    except json.JSONDecodeError as e:
                        logging.error(f"Failed to decode JSON from AI response: {e}")
                        yield f"Error: Failed to decode JSON from AI response. Raw output: {full_response_content}"
                else:
                    yield f"Error: No valid JSON found in AI response. Raw output: {full_response_content}"
            else:
                yield full_response_content




        except Exception as e:
            logging.error(f"Error during LiteLLM generation: {e}", exc_info=True)
            yield f"Error: An error occurred during generation: {e}"
