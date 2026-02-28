import os
import yaml
import logging
import queue
import json
import re
from typing import Optional, List, Dict, Any
from pytm import Threat # Keep original Threat import for direct pytm usage where needed
from threat_analysis.core.models_module import ExtendedThreat # Import ExtendedThreat
from threat_analysis.ai_engine.rag_service import RAGThreatGenerator # Re-add this import
from threat_analysis.ai_engine.providers.litellm_client import LiteLLMClient


class AIService:
    def __init__(self, config_path: str):
        self.litellm_client = None
        self.rag_generator = None
        self.ai_online = False
        self.ai_config = self._load_ai_config(config_path) # Load config in __init__


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

    async def init_ai(self):
        """Initializes the AI services."""
        logging.info("Initializing AI services...")
        self.litellm_client = await LiteLLMClient.create()
        self.rag_generator = RAGThreatGenerator()
        if self.litellm_client:
            self.ai_online = self.litellm_client.ai_online
        else:
            self.ai_online = False
        logging.info("AI services initialized.")

    async def generate_markdown_from_prompt(self, prompt: str, markdown: Optional[str] = None):
        """Generates markdown from a prompt asynchronously."""
        if not self.ai_online or not self.litellm_client:
             yield "Error: AI server is offline."
             return

        system_prompt = """You are an expert cybersecurity architect. Your task is to generate a comprehensive threat model in a specific Markdown-based Domain Specific Language (DSL).

The DSL structure is as follows:

# Threat Model: [Model Name]

## Description
[A brief description of the system]

## Boundaries
- **[Boundary Name]**: color=[color_name_or_hex], description="[Description]"

## Actors
- **[Actor Name]**: boundary=[Boundary Name], description="[Description]"

## Servers
- **[Server Name]**: boundary=[Boundary Name], description="[Description]"

## Data
- **[Data Name]**: description="[Description]", classification="[public/internal/restricted/confidential]"

## Dataflows
- **[Flow Name]**: from="[Source Name]", to="[Destination Name]", protocol="[Protocol]", description="[Description]"

Rules:
1. Components (Actors, Servers) MUST be assigned to a Boundary.
2. Dataflows MUST refer to existing Actors or Servers by name.
3. Use realistic protocols (e.g., HTTPS, SQL, SSH, gRPC).
4. Output ONLY the Markdown DSL. Do not add conversational text before or after the markdown block. Use ```markdown fences.
"""
        user_prompt = f"User request: {prompt}"
        if markdown:
            user_prompt += f"\n\nExisting Threat Model to update/expand:\n{markdown}"

        async for chunk in self.litellm_client.generate_content(
            prompt=user_prompt,
            system_prompt=system_prompt,
            stream=True
        ):
            yield chunk

    def generate_markdown_from_prompt_sync(self, prompt: str, markdown: Optional[str] = None):
        """Generates markdown from a prompt synchronously by bridging the async generator."""
        logging.debug("Generating markdown from prompt (sync)...")
        
        async_gen = self.generate_markdown_from_prompt(prompt, markdown)
        
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        # Helper to consume async generator synchronously
        def iter_async(gen):
            while True:
                try:
                    # In a threaded environment like Flask, we might need a more robust way to run async code
                    # but for now, run_until_complete on the anext should work if there's no running loop.
                    yield loop.run_until_complete(gen.__anext__())
                except StopAsyncIteration:
                    break

        return iter_async(async_gen)

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
            # new_threat.source = "LLM" # This is now set in the constructor
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
                    "message": f"Enriching {element.name} ({processed_elements}/{total_elements})..."
                }
                ai_status_event_queue.put(f"event: ai_progress\ndata: {json.dumps(data)}\n\n")

            component_details = {
                "name": element.name,
                "type": element.stereotype if hasattr(element, 'stereotype') else element.__class__.__name__,
                "description": element.description,
                "protocol": getattr(element, 'protocol', None),
            }

            logging.debug(f"Generating AI threats for component: {element.name}")
            
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
            
            # Call LiteLLMClient to generate JSON threats
            if not self.ai_online or not self.litellm_client:
                logging.error("LiteLLM client not initialized or AI is offline.")
                continue # Skip to next element

            threat_json_generator = self.litellm_client.generate_content(
                prompt=user_prompt_content,
                system_prompt=threat_system_prompt,
                stream=False, # We want the full JSON before parsing
                output_format="json"
            )

            raw_response = ""
            is_pre_parsed = False
            async for chunk in threat_json_generator:
                if isinstance(chunk, str):
                    raw_response += chunk
                elif isinstance(chunk, (dict, list)):
                    raw_response = chunk
                    is_pre_parsed = True
                    break

            if is_pre_parsed:
                threat_json_output = raw_response
            elif isinstance(raw_response, str):
                parsed_json = None
                match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```', raw_response, re.DOTALL)
                if match:
                    json_str = match.group(1).strip()
                    try:
                        parsed_json = json.loads(json_str)
                    except json.JSONDecodeError as e:
                        logging.error(f"Failed to parse JSON from extracted markdown block: {e}. Content: '{json_str}'")
                else:
                    # Fallback for responses that might just contain JSON without markdown fences
                    try:
                        start_bracket = raw_response.find('[')
                        start_brace = raw_response.find('{')

                        if start_bracket == -1 and start_brace == -1:
                            logging.debug("No JSON start token ('[' or '{') found in response.")
                            parsed_json = None
                        else:
                            if start_bracket != -1 and (start_bracket < start_brace or start_brace == -1):
                                start_index = start_bracket
                                end_char = ']'
                            else:
                                start_index = start_brace
                                end_char = '}'
                            
                            end_index = raw_response.rfind(end_char)
                            
                            if end_index > start_index:
                                json_candidate = raw_response[start_index : end_index + 1]
                                try:
                                    parsed_json = json.loads(json_candidate)
                                except json.JSONDecodeError as e:
                                    logging.error(f"Failed to parse extracted JSON candidate: {e}")
                                    logging.debug(f"Candidate: {json_candidate}")
                                    parsed_json = None
                            else:
                                parsed_json = None
                                
                    except Exception as e:
                        logging.error(f"Error during fallback JSON parsing: {e}")
                        parsed_json = None

                threat_json_output = parsed_json
            else:
                threat_json_output = raw_response

            if threat_json_output is None or (isinstance(threat_json_output, str) and threat_json_output.startswith("Error:")):
                logging.error(f"AI threat generation failed or returned an error. Raw output: {raw_response}")
                continue
            
            # Ensure the output is a list, even if the LLM sometimes outputs a single dict
            if isinstance(threat_json_output, dict):
                ai_threats_json = [threat_json_output]
            elif isinstance(threat_json_output, list):
                ai_threats_json = threat_json_output
            else:
                logging.error(f"Unexpected output format from AI for threats: {type(threat_json_output)}. Raw: {threat_json_output}")
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
