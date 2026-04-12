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
from threat_analysis.utils import extract_json_from_llm_response

PROJECT_ROOT = Path(__file__).resolve().parents[3]

class LiteLLMClient:
    def __init__(self):
        self.ai_config = {}
        self.model_name = ""
        self.stream = False
        self.ai_online = False
        self.client = None
        self.provider_config = {}
        self.api_base = None
        self.ssl_verify = True
        self._litellm_module = None

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
                # Prevent LiteLLM from fetching the model cost map from the internet.
                # Must be set BEFORE importing litellm so it is picked up during module init.
                os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

                # Propagate SSL certificate to the underlying HTTP transports (httpx / requests)
                # used by LiteLLM internally (e.g. for any residual network calls).
                _ssl_cert = self.ai_config.get("ssl_cert_file") or self.provider_config.get("ssl_verify")
                if isinstance(_ssl_cert, str) and os.path.isfile(_ssl_cert):
                    os.environ.setdefault("SSL_CERT_FILE", _ssl_cert)
                    os.environ.setdefault("REQUESTS_CA_BUNDLE", _ssl_cert)
                    logging.info("Enterprise SSL cert applied to HTTP transports: %s", _ssl_cert)

                # Dynamically import litellm only if an AI provider is enabled
                try:
                    self._litellm_module = importlib.import_module("litellm")
                    # Suppress LiteLLM's startup noise and telemetry-style network calls.
                    self._litellm_module.suppress_debug_info = True
                    self._litellm_module.set_verbose = False
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
                
                # Handle API keys from environment variables
                api_key_env = self.provider_config.get('api_key_env')
                if api_key_env:
                    api_key = os.getenv(api_key_env)
                    if api_key:
                        # LiteLLM uses environment variables for many providers (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)
                        # but we can also pass it explicitly if needed, or just ensure it's in os.environ.
                        # For Gemini via LiteLLM, it usually expects GEMINI_API_KEY or GOOGLE_API_KEY.
                        # We ensure it's set in the environment if it's not already the standard name.
                        os.environ[api_key_env] = api_key
                        if provider_name == "gemini":
                            os.environ["GEMINI_API_KEY"] = api_key
                            os.environ["GOOGLE_API_KEY"] = api_key
                        
                        logging.debug(f"[{time.time() - start_time:.4f}s] API key set from environment variable: {api_key_env}")
                    else:
                        logging.warning(f"[{time.time() - start_time:.4f}s] API key environment variable {api_key_env} is not set.")

                # Handle Custom API Base (Internal enterprise host)
                self.api_base = self.provider_config.get('api_base')
                if self.api_base:
                    logging.info(f"[{time.time() - start_time:.4f}s] Custom API base configured for {provider_name}: {self.api_base}")

                # Handle SSL verification setting
                self.ssl_verify = self.provider_config.get('ssl_verify', True)
                if self.ssl_verify is False:
                    logging.warning("SSL verification DISABLED for %s (ssl_verify: false in ai_config.yaml).", provider_name)
                elif isinstance(self.ssl_verify, str):
                    logging.info("Using custom SSL certificate: %s", self.ssl_verify)

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

    @staticmethod
    def _log_ssl_error(e: Exception, context: str) -> None:
        """Logs SSL/TLS errors with diagnostic details to help trace enterprise certificate issues."""
        import ssl as _ssl
        err_str = str(e)
        err_type = type(e).__name__
        # Detect SSL-related exceptions by type name or message content
        ssl_keywords = ("ssl", "certificate", "cert", "tls", "handshake", "verify", "x509", "hostname")
        is_ssl = any(kw in err_str.lower() or kw in err_type.lower() for kw in ssl_keywords)
        if is_ssl:
            logging.error(
                "[SSL] %s — %s: %s", context, err_type, err_str,
                stack_info=False,
            )
            # Log environment CA bundle settings to confirm which cert file is in use
            for env_var in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
                val = os.environ.get(env_var)
                if val:
                    logging.error("[SSL] %s=%s", env_var, val)
                else:
                    logging.warning("[SSL] %s not set (system default CA bundle will be used)", env_var)
            # Log Python's default CA file for comparison
            try:
                logging.error("[SSL] Python default cafile: %s", _ssl.get_default_verify_paths().cafile)
                logging.error("[SSL] Python default capath: %s", _ssl.get_default_verify_paths().capath)
            except Exception:
                pass
        else:
            logging.error("[SSL-check] %s — %s: %s", context, err_type, err_str)

    async def check_connection(self) -> bool:
        """Checks if the configured AI model is available via LiteLLM."""
        check_start_time = time.time()
        if not self.model_name or not self._litellm_module:
            return False
        target = self.api_base or f"(provider default for {self.model_name})"
        logging.info("AI health check — model=%s  url=%s  ssl_verify=%s",
                     self.model_name, target, self.ssl_verify)
        try:
            if self.ssl_verify is not True:
                self._litellm_module.ssl_verify = self.ssl_verify
            await self._litellm_module.acompletion(
                model=self.model_name,
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=1,
                timeout=self.provider_config.get('timeout', 10),
                stream=False,
                api_base=self.api_base,
            )
            logging.info("[%.3fs] AI health check OK — %s", time.time() - check_start_time, self.model_name)
            self.ai_online = True
            return True
        except Exception as e:
            logging.error("[%.3fs] AI health check FAILED — model=%s url=%s",
                          time.time() - check_start_time, self.model_name, target)
            self._log_ssl_error(e, f"check_connection({self.model_name})")
            self.ai_online = False
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
            "timeout": self.provider_config.get('timeout', 30),
            "num_retries": 3, # Automatically retry on rate limits
            "api_base": self.api_base
        }
        if "top_p" in self.provider_config:
            completion_params["top_p"] = self.provider_config["top_p"]

        if self.ssl_verify is not True:
            self._litellm_module.ssl_verify = self.ssl_verify

        if output_format == "json":
            messages[0]["content"] += "\n\nYour output MUST be a valid JSON object."

            provider_name = self.model_name.split('/')[0]
            if provider_name in ["openai", "azure", "groq"]:
                completion_params["response_format"] = {"type": "json_object"}

        use_stream = self.stream if stream is None else stream
        completion_params["stream"] = use_stream

        logging.debug("LLM request — model=%s  url=%s  ssl_verify=%s  stream=%s  max_tokens=%s",
                      self.model_name,
                      completion_params.get("api_base") or "(provider default)",
                      self.ssl_verify,
                      completion_params.get("stream"),
                      completion_params.get("max_tokens"))
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
                cleaned_content = extract_json_from_llm_response(full_response_content)
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
            logging.error("LLM generation failed — model=%s url=%s",
                          self.model_name,
                          completion_params.get("api_base") or "(provider default)")
            self._log_ssl_error(e, f"generate_content({self.model_name})")
            yield f"Error: An error occurred during generation: {e}"
