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
from ..prompts.stride_prompts import build_component_prompt, build_batch_prompt
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
            async for chunk in client.generate_content(
                prompt=prompt,
                system_prompt=_get_prompt("stride_analysis", "system"),
                output_format="json"
            ):
                if isinstance(chunk, list):
                    # Model returned a JSON array directly — each element is a threat.
                    return chunk
                if isinstance(chunk, dict):
                    # Model wrapped threats under a key — try common keys.
                    for key in ("threats", "threat_list", "results", "items"):
                        if key in chunk and isinstance(chunk[key], list):
                            return chunk[key]
                    # Dict with no known list key — treat it as a single threat.
                    return [chunk]
            return []
        except Exception as e:
            logging.error(f"Error generating threats via LiteLLM: {e}")
            return []

    async def generate_threats_batch(
        self,
        components: List[Dict],
        context: Dict,
    ) -> Dict[str, List[Dict]]:
        """Generates STRIDE threats for multiple components in a single LLM call.

        Returns a dict mapping ``component_name`` → ``list[threat_dict]``.
        Components whose names are absent from the LLM response get empty lists
        (handled by the caller).  Returns an empty dict on hard failure so the
        caller can fall back to individual calls.
        """
        client = await self._get_client()
        prompt = build_batch_prompt(components, context)

        def _parse_batch(raw) -> Dict[str, List[Dict]]:
            """Turn a list-of-dicts response into a name→threats mapping.

            Handles three response shapes:
            1. A bare JSON array: ``[{"component": ..., "threats": [...]}, ...]``
            2. A dict with a known wrapper key: ``{"components": [...]}`` or ``{"results": [...]}``
            3. A dict with any single list value (arbitrary wrapper key from LLM): ``{"data": [...]}``
            """
            result: Dict[str, List[Dict]] = {}
            if isinstance(raw, list):
                items = raw
            elif isinstance(raw, dict):
                # Try known wrapper keys first
                items = raw.get("components") or raw.get("results")
                if not isinstance(items, list):
                    # Fallback: look for the first list value in the dict (handles arbitrary wrappers)
                    items = next(
                        (v for v in raw.values() if isinstance(v, list)),
                        []
                    )
            else:
                items = []
            for item in items:
                if not isinstance(item, dict):
                    continue
                name = item.get("component", "")
                threats = item.get("threats", [])
                if name and isinstance(threats, list):
                    result[name] = threats
            if not result:
                logging.debug("_parse_batch: no component entries found in response (raw type=%s)", type(raw).__name__)
            return result

        # Budget ~2 000 tokens per component for the JSON response (threats are verbose).
        # Never go below the provider's own max_tokens setting.
        try:
            provider_max = int(client.provider_config.get("max_tokens", 4096))
        except (TypeError, ValueError):
            provider_max = 4096
        batch_max_tokens = max(len(components) * 2000, provider_max)

        try:
            async for chunk in client.generate_content(
                prompt=prompt,
                system_prompt=_get_prompt("stride_analysis", "system"),
                output_format="json",
                max_tokens=batch_max_tokens,
            ):
                if isinstance(chunk, (list, dict)):
                    parsed = _parse_batch(chunk)
                    logging.debug(
                        "generate_threats_batch: chunk type=%s keys=%s → %d components parsed",
                        type(chunk).__name__,
                        list(chunk.keys()) if isinstance(chunk, dict) else "N/A (list)",
                        len(parsed),
                    )
                    return parsed
                elif isinstance(chunk, str) and chunk.startswith("Error:"):
                    logging.warning("generate_threats_batch: LLM returned error string: %s", chunk[:200])
            logging.warning("generate_threats_batch: no parseable chunk received — returning {}")
            return {}
        except Exception as e:
            logging.error("Error in batch threat generation: %s", e)
            return {}

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
        # CISO triage response is a single JSON object — 2 000 tokens is ample.
        try:
            provider_max = int(client.provider_config.get("max_tokens", 4096))
        except (TypeError, ValueError):
            provider_max = 4096
        ciso_max_tokens = max(2000, provider_max)
        try:
            async for chunk in client.generate_content(
                prompt=prompt,
                system_prompt=system_prompt,
                output_format="json",
                max_tokens=ciso_max_tokens,
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
