import json
import re

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

import asyncio
import importlib
import logging
from typing import Optional
from pytm import Threat

class AIService:
    def __init__(self):
        self.litellm_client = None
        self.ai_online = False

    def generate_markdown_from_prompt_sync(self, prompt, markdown):
        async def runner():
            async for chunk in self.generate_markdown_from_prompt(prompt, markdown):
                yield chunk

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        agen = runner()
        while True:
            try:
                yield loop.run_until_complete(agen.__anext__())
            except StopAsyncIteration:
                break


    async def init_ai(self):
        """Asynchronously initializes AI components."""
        # Lazy import LiteLLMClient
        LiteLLMClientModule = importlib.import_module("threat_analysis.ai_engine.providers.litellm_client")
        LiteLLMClient = LiteLLMClientModule.LiteLLMClient
        self.litellm_client = await LiteLLMClient.create()
        self.ai_online = self.litellm_client.ai_online
        logging.info(f"AIService AI online status: {self.ai_online}")

    async def _enrich_with_ai_threats(self, threat_model):
        """
        Iterates through model components and enriches them with AI-generated threats.
        """
        # from threat_analysis.ai_engine.providers.ollama_provider import OllamaProvider # Removed
        from pytm import Threat

        # Define system prompt for JSON threat generation
        threat_system_prompt = """You are an expert cybersecurity analyst. Your task is to identify potential threats for a given system component and context.
Your output MUST be a JSON array of threat objects. Each threat object MUST have the following structure:
{
    "title": "Short title of the threat",
    "description": "Detailed description of the threat, including how it might be exploited.",
    "category": "STRIDE category (e.g., Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)",
    "likelihood": "Likelihood of exploitation (high, medium, low)",
    "business_impact": {
        "severity": "Severity of impact (critical, high, medium, low)",
        "details": "Details on the business impact."
    }
}
Generate only threats relevant to the provided component details and system context.
Ensure the output is a valid JSON array.
"""
        # Create a general context for the AI
        context = {
            "system_description": threat_model.tm.description,
            "data_sensitivity": "High", # Placeholder, this could be inferred
            "internet_facing": any(s.get('is_public') for s in threat_model.servers),
        }

        all_elements = [a['object'] for a in threat_model.actors] + \
                       [s['object'] for s in threat_model.servers] + \
                       threat_model.dataflows

        for element in all_elements:
            component_details = {
                "name": element.name,
                "type": element.stereotype if hasattr(element, 'stereotype') else element.__class__.__name__,
                "description": element.description,
                "protocol": getattr(element, 'protocol', None),
            }

            logging.info(f"Generating AI threats for component: {element.name}")
            
            # Call LiteLLMClient to generate JSON threats
            if not self.litellm_client:
                logging.error("LiteLLM client not initialized.")
                continue # Skip to next element

            if not await self.litellm_client.check_connection():
                logging.warning("AI enrichment skipped for this component: LiteLLM client is offline.")
                # We could potentially break here if we assume the whole server is down
                self.ai_online = False
                return 

            user_prompt_content = f"""System Description: {context["system_description"]}
Component Type: {component_details["type"]}
Component Name: {component_details["name"]}
Component Description: {component_details["description"]}
Protocol: {component_details["protocol"]}
Internet Facing: {context["internet_facing"]}
"""

            threat_json_generator = self.litellm_client.generate_content(
                prompt=user_prompt_content,
                system_prompt=threat_system_prompt,
                stream=False, # We want the full JSON before parsing
                output_format="json"
            )

            threat_json_output = None
            async for chunk in threat_json_generator:
                threat_json_output = chunk # Should be the parsed JSON object if output_format="json"
            
            if threat_json_output is None or (isinstance(threat_json_output, str) and threat_json_output.startswith("Error:")):
                logging.error(f"AI threat generation failed or returned an error: {threat_json_output}")
                continue # Skip to next element
            
            # Ensure the output is a list, even if the LLM sometimes outputs a single dict
            if isinstance(threat_json_output, dict):
                ai_threats_json = [threat_json_output]
            elif isinstance(threat_json_output, list):
                ai_threats_json = threat_json_output
            else:
                logging.error(f"Unexpected output format from AI for threats: {type(threat_json_output)}. Raw: {threat_json_output}")
                continue


            for threat_json in ai_threats_json:
                # Convert the JSON threat to a PyTM Threat object
                # This assumes a certain structure from the AI response
                description = f"(AI) {threat_json.get('title', 'N/A')}: {threat_json.get('description', '')}"
                
                # Simple mapping, can be improved
                severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                likelihood_map = {"high": 5, "medium": 3, "low": 1}

                business_impact = threat_json.get('business_impact', {})
                severity = severity_map.get(business_impact.get('severity', 'medium').lower(), 3)
                likelihood = likelihood_map.get(threat_json.get('likelihood', 'medium').lower(), 3)

                new_threat = Threat(
                    description=description,
                    category=threat_json.get('category', 'Unknown'),
                    likelihood=likelihood,
                    impact=severity
                )
                # Add extra details for reporting if needed
                new_threat.ai_details = threat_json

                # Append the new threat to the element's threats list
                element.threats.append(new_threat)
                logging.info(f"Added AI threat '{threat_json.get('title')}' to {element.name}")

    async def generate_markdown_from_prompt(self, prompt: str, markdown: Optional[str] = None):
        """
        Uses AI to generate or modify a threat model in Markdown DSL from a natural language prompt.
        This is a generator function that yields the response chunks as they are received.
        """
        if not self.ai_online:
            raise RuntimeError("AI server is not available. This feature is disabled.")

        logging.info(f"Generating/modifying markdown from prompt: {prompt[:100]}...")

        if markdown:
            system_prompt = """You are an expert system architect and cybersecurity analyst. Your task is to update an existing Threat Model DSL based on a user's request.

You MUST return the ENTIRE threat model, with the user's changes applied. Do NOT use placeholders like '... (rest of the file unchanged)'.
Your output should be ONLY the markdown DSL, starting with '# Threat Model:'."""
            user_prompt_content = f"Here is the existing threat model:\n\n```markdown\n{markdown}\n```\n\nApply the following change: {prompt}"
        else:
            # Generation from scratch
            system_prompt = """You are an expert system architect and cybersecurity analyst. 
            Your task is to create a complete Threat Model DSL in Markdown from a user's request.
            The output should be only the Markdown DSL, starting with '# Threat Model:'."""
            user_prompt_content = prompt

        try:
            if not self.litellm_client:
                logging.error("LiteLLM client not initialized.")
                yield "# An error occurred: AI client not initialized."
                return

            async for chunk in self.litellm_client.generate_content(
                prompt=user_prompt_content,
                system_prompt=system_prompt,
                output_format="text"
            ):
                yield chunk

        except Exception as e:
            logging.error(f"Error calling AI for markdown generation: {e}", exc_info=True)
            yield f"# An error occurred during generation: {e}"
