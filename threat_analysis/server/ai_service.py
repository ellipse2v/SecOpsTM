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

import os
import yaml
import logging
import queue
import json
import asyncio
import concurrent.futures
from pathlib import Path
from typing import Optional, List, Dict, Any
from threat_analysis.utils import extract_json_from_llm_response
from pytm import Threat  # Keep original Threat import for direct pytm usage where needed
from threat_analysis.core.models_module import ExtendedThreat
from threat_analysis.ai_engine.rag_service import RAGThreatGenerator
from threat_analysis.ai_engine.providers.base_provider import BaseLLMProvider
from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider


class AIService:
    def __init__(self, config_path: str, ai_status_event_queue: Optional[queue.Queue] = None):
        self.provider: Optional[BaseLLMProvider] = None
        self.rag_generator = None
        self.ai_online = False
        self.ai_config = self._load_ai_config(config_path)
        self.ai_status_event_queue = ai_status_event_queue
        self.rate_limit_sleep: float = self.ai_config.get(
            "threat_generation", {}
        ).get("rate_limit_sleep", 0.0)


    def _load_ai_config(self, config_path: str) -> Dict[str, Any]:
        """Loads AI configuration from ai_config.yaml."""
        if not os.path.exists(config_path):
            logging.error(f"AI config file not found: {config_path}. Cannot initialize AI features.")
            return {}
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            logging.error(f"Error parsing AI config YAML from {config_path}: {e}")
            return {}

    def _load_context(self) -> Dict[str, Any]:
        """Loads config/context.yaml to enrich component prompts with business context."""
        context_path = Path(__file__).resolve().parents[2] / "config" / "context.yaml"
        if not context_path.exists():
            return {}
        try:
            with open(context_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logging.warning(f"Could not load context.yaml: {e}")
            return {}

    async def init_ai(self):
        """Initializes the AI services."""
        logging.info("Initializing AI services...")

        # Resolve enabled provider config and instantiate LiteLLMProvider
        providers = self.ai_config.get("ai_providers", {})
        enabled_config: Dict[str, Any] = {}
        for _name, cfg in providers.items():
            if cfg.get("enabled"):
                enabled_config = cfg
                break

        self.provider = LiteLLMProvider(enabled_config)
        self.ai_online = await self.provider.check_connection()

        # Initialize RAG only if enabled in config AND AI provider is reachable
        rag_enabled = self.ai_config.get("rag", {}).get("enabled", False)
        if rag_enabled and self.ai_online:
            try:
                self.rag_generator = RAGThreatGenerator()
                logging.info("RAG service initialized.")
            except Exception as e:
                logging.error(f"Failed to initialize RAG service: {e}")
                self.rag_generator = None
        else:
            if rag_enabled and not self.ai_online:
                logging.info("RAG service skipped: AI provider is offline.")
            else:
                logging.info("RAG service disabled in config.")
            self.rag_generator = None

        if self.ai_status_event_queue:
            data = {"ai_online": self.ai_online}
            self.ai_status_event_queue.put(f"event: ai_status\ndata: {json.dumps(data)}\n\n")

        logging.info(f"AI services initialized. Online: {self.ai_online}")

    async def generate_markdown_from_prompt(self, prompt: str, markdown: Optional[str] = None):
        """Streams DSL Markdown from a natural language prompt (async generator)."""
        if not self.ai_online or not self.provider:
            yield "Error: AI server is offline."
            return
        async for chunk in self.provider.generate_markdown(prompt, markdown):
            yield chunk

    def generate_markdown_from_prompt_sync(self, prompt: str, markdown: Optional[str] = None):
        """Sync wrapper around generate_markdown_from_prompt.

        Runs the async generator in a dedicated thread with its own event loop.
        This avoids the RuntimeError('This event loop is already running') that
        occurs when calling loop.run_until_complete() from inside a Flask async
        context or any other already-running loop.
        """
        logging.debug("Generating markdown from prompt (sync)...")

        async def _collect() -> List[str]:
            chunks: List[str] = []
            async for chunk in self.generate_markdown_from_prompt(prompt, markdown):
                chunks.append(chunk)
            return chunks

        def _run_in_new_loop() -> List[str]:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(_collect())
            finally:
                loop.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            chunks = executor.submit(_run_in_new_loop).result()

        return iter(chunks)

    async def _generate_rag_threats(self, threat_model) -> List[ExtendedThreat]: # Return List[ExtendedThreat]
        """
        Generates system-level threats using the RAG service.
        """
        if not self.rag_generator:
            return []

        logging.debug("Generating system-level threats using RAG...")

        # Construct a Markdown representation of the entire threat model
        tm_markdown_content = f"# Threat Model: {threat_model.tm.name}\n\n"
        tm_markdown_content += f"## Description\n\n{threat_model.tm.description}\n\n"
        tm_markdown_content += "## Components\n\n"
        
        all_elements = [a['object'] for a in threat_model.actors] + \
                       [s['object'] for s in threat_model.servers] + \
                       threat_model.dataflows
                       
        for element in all_elements:
            tm_markdown_content += f"### {element.name}\n\n"
            tm_markdown_content += f"- **Type:** {element.stereotype if hasattr(element, 'stereotype') else element.__class__.__name__}\n"
            tm_markdown_content += f"- **Description:** {element.description}\n"
            if hasattr(element, 'protocol'):
                tm_markdown_content += f"- **Protocol:** {element.protocol}\n"
            tm_markdown_content += "\n"

        rag_generated_threats_json = self.rag_generator.generate_threats(tm_markdown_content)
        
        pytm_rag_threats = []
        severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        likelihood_map = {"high": 5, "medium": 3, "low": 1}

        for threat_json in rag_generated_threats_json:
            description = f"(RAG-LLM) {threat_json.get('name', 'N/A')}: {threat_json.get('description', '')}"
            
            # Map likelihood and impact strings to numerical values expected by PyTM
            likelihood = likelihood_map.get(threat_json.get('likelihood', 'medium').lower(), 3)
            impact = severity_map.get(threat_json.get('impact', 'medium').lower(), 3) # Using severity_map for impact
            
            new_threat = ExtendedThreat( # Use ExtendedThreat here
                SID=threat_json.get('name', 'Generic RAG Threat'),
                description=description,
                category=threat_json.get('category', 'Generic RAG Threat'),
                likelihood=likelihood,
                impact=impact,
                source="LLM" # Explicitly set source
            )
            new_threat.ai_details = threat_json # Store original AI details
            new_threat.confidence = float(threat_json.get('confidence', 0.75))
            pytm_rag_threats.append(new_threat)

        logging.debug(f"Generated {len(pytm_rag_threats)} system-level RAG threats.")
        return pytm_rag_threats

    async def _enrich_with_ai_threats(self, threat_model, ai_status_event_queue: Optional[queue.Queue] = None):
        """
        Iterates through model components and enriches them with AI-generated threats.
        Also adds RAG-generated system-level threats if RAG is enabled.
        """
        # Generate system-level RAG threats first
        if self.ai_online and self.rag_generator:
            system_rag_threats = await self._generate_rag_threats(threat_model)
            if not hasattr(threat_model.tm, 'global_threats_llm'):
                threat_model.tm.global_threats_llm = []
            threat_model.tm.global_threats_llm.extend(system_rag_threats)
            logging.debug(f"Appended {len(system_rag_threats)} global RAG threats to threat_model.tm.global_threats_llm.")

        # Build context from context.yaml (base) + runtime-derived values (override)
        yaml_ctx = self._load_context()
        context: Dict[str, Any] = {
            **yaml_ctx,
            "system_description": threat_model.tm.description or yaml_ctx.get("system_description", ""),
            "internet_facing": any(s.get('is_public') for s in threat_model.servers),
        }
        # Keep data_sensitivity from context.yaml if set; fall back to "High"
        context.setdefault("data_sensitivity", "High")

        all_elements = [a['object'] for a in threat_model.actors] + \
                       [s['object'] for s in threat_model.servers] + \
                       threat_model.dataflows

        # Ensure all elements have a 'threats' attribute to append to.
        for element in all_elements:
            if not hasattr(element, 'threats'):
                element.threats = []

        total_elements = len(all_elements)
        processed_elements = 0

        for element in all_elements:
            processed_elements += 1
            progress = (processed_elements / total_elements) * 100

            if ai_status_event_queue:
                data = {
                    "status": "ai_enrichment_progress",
                    "progress": progress,
                    "message": f"Enriching {element.name} ({processed_elements}/{total_elements})...",
                }
                ai_status_event_queue.put(f"event: ai_progress\ndata: {json.dumps(data)}\n\n")

            if not self.provider:
                logging.error("AI provider not initialized.")
                continue

            if not await self.provider.check_connection():
                logging.warning("AI enrichment stopped: provider is offline.")
                self.ai_online = False
                return

            component_details = {
                "name": element.name,
                "type": element.stereotype if hasattr(element, "stereotype") else element.__class__.__name__,
                "description": element.description,
                "protocol": getattr(element, "protocol", None),
            }
            logging.debug(f"Generating AI threats for component: {element.name}")

            ai_threats_json = await self.provider.generate_threats(component_details, context)

            # Rate-limit pause (configurable via ai_config.yaml threat_generation.rate_limit_sleep)
            if self.rate_limit_sleep > 0:
                await asyncio.sleep(self.rate_limit_sleep)

            if not ai_threats_json:
                continue

            for threat_json in ai_threats_json:
                # Convert the JSON threat to an ExtendedThreat object
                description = f"(AI) {threat_json.get('title', 'N/A')}: {threat_json.get('description', '')}"
                
                severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                likelihood_map = {"high": 5, "medium": 3, "low": 1}

                business_impact = threat_json.get('business_impact', {})
                severity = severity_map.get(business_impact.get('severity', 'medium').lower(), 3)
                likelihood = likelihood_map.get(threat_json.get('likelihood', 'medium').lower(), 3)

                new_threat = ExtendedThreat( # Use ExtendedThreat here
                    SID=threat_json.get('title', 'Unknown AI Threat'),
                    description=description,
                    category=threat_json.get('category', 'Unknown'),
                    likelihood=likelihood,
                    impact=severity,
                    source="AI" # Explicitly mark source for component-level AI threats
                )
                # Add extra details for reporting if needed
                new_threat.ai_details = threat_json

                # Append the new threat to the element's threats list
                element.threats.append(new_threat)
                logging.info(f"Added AI threat '{threat_json.get('title')}' to {element.name}")
