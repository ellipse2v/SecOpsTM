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
import json
import logging
from typing import List, Dict, Any, Optional
import yaml
from threat_analysis.utils import extract_json_from_llm_response

logger = logging.getLogger(__name__)


def _parse_threat_list(text: str) -> List[Dict[str, Any]]:
    """Output parser step: converts a raw LLM string into a list of threat dicts.

    Designed for use as a ``RunnableLambda`` at the end of a LangChain LCEL chain,
    after ``StrOutputParser`` has already extracted the plain text from the AIMessage.
    """
    extracted = extract_json_from_llm_response(text)
    if not extracted:
        raise ValueError(f"No valid JSON found in LLM response. Raw: {text[:300]}")
    return json.loads(extracted)


class RAGThreatGenerator:
    def __init__(
        self,
        vector_store_dir: str = "threat_analysis/vector_store",
        user_context_path: str = "config/user_context.example.json",
        ai_config_path: str = "config/ai_config.yaml",
    ):
        self.vector_store_dir = vector_store_dir
        self.user_context_path = user_context_path
        self.ai_config_path = ai_config_path

        self._initialize_components()

    def _load_ai_config(self) -> Dict[str, Any]:
        """Loads AI configuration from ai_config.yaml."""
        if not os.path.exists(self.ai_config_path):
            logger.error(f"AI config file not found: {self.ai_config_path}. Cannot initialize LLM.")
            return {}
        try:
            with open(self.ai_config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing AI config YAML from {self.ai_config_path}: {e}")
            return {}

    def _initialize_components(self):
        """Initializes the embedding model, vector store, and LLM."""
        logger.info("Initializing RAGThreatGenerator components...")
        
        # Lazy imports
        from langchain_chroma import Chroma
        from threat_analysis.ai_engine.embedding_factory import get_embeddings
        from langchain_litellm import ChatLiteLLM
        from chromadb.config import Settings
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import StrOutputParser
        from langchain_core.runnables import RunnableLambda

        # Initialize LLM using ai_config.yaml
        ai_config = self._load_ai_config()

        # Initialize Embeddings
        self.embeddings = get_embeddings(ai_config)

        # Initialize Vector Store and disable telemetry
        if not os.path.exists(self.vector_store_dir):
            logger.error(f"Vector store directory not found: {self.vector_store_dir}. "
                          "Please run tooling/build_vector_store.py first.")
            raise FileNotFoundError(f"Vector store not found at {self.vector_store_dir}")
        
        self.vector_store = Chroma(
            persist_directory=self.vector_store_dir,
            embedding_function=self.embeddings,
            client_settings=Settings(anonymized_telemetry=False)
        )
        
        providers = ai_config.get('ai_providers', {})
        llm_params = {}
        llm_model = None

        # Find the first enabled provider
        active_provider_name = None
        active_provider_config = None
        
        for name, config in providers.items():
            if config.get('enabled'):
                active_provider_name = name
                active_provider_config = config
                break
        
        if active_provider_name and active_provider_config:
            # Map common names to LiteLLM prefixes if necessary
            prefix = "ollama" if active_provider_name == "ollama" else active_provider_name.split('_')[0]
            llm_model = f"{prefix}/{active_provider_config.get('model')}"
            
            llm_params['temperature'] = active_provider_config.get('temperature', 0.5)
            
            if active_provider_name == "ollama":
                llm_params['api_base'] = active_provider_config.get('host', 'http://localhost:11434')
            
            # Handle API key if environment variable is specified
            api_key_env = active_provider_config.get('api_key_env')
            if api_key_env:
                llm_params['api_key'] = os.getenv(api_key_env)
            
            logger.info(f"Using {active_provider_name} LLM: {llm_model}")
        
        if llm_model:
            self.llm = ChatLiteLLM(model=llm_model, **llm_params)
            logger.info(f"LLM initialized with model: {llm_model}")
        else:
            logger.error("No enabled LLM provider found in ai_config.yaml. RAG functionality will be limited.")
            raise ValueError("No active LLM configuration found.")
        
        # Load prompt templates from config/prompts.yaml
        from threat_analysis.ai_engine.prompt_loader import get as _get_prompt
        rag_system = _get_prompt("rag", "system")
        rag_human = _get_prompt("rag", "human_template")

        # Define Prompt Template
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", rag_system),
            ("human", rag_human),
        ])

        # Build the full LCEL chain:
        #   prompt → llm → StrOutputParser (AIMessage → str) → _parse_threat_list (str → List[Dict])
        self.rag_chain = (
            self.prompt
            | self.llm
            | StrOutputParser()
            | RunnableLambda(_parse_threat_list)
        )

        logger.info("RAGThreatGenerator components initialized.")

    def _load_user_context(self) -> Dict[str, Any]:
        """Loads user-defined system description and threat intelligence."""
        if not os.path.exists(self.user_context_path):
            logger.warning(f"User context file not found: {self.user_context_path}. Returning empty context.")
            return {"system_description": "N/A", "user_threat_intelligence": "N/A"}
        try:
            with open(self.user_context_path, 'r', encoding='utf-8') as f:
                context_data = json.load(f)
                system_desc = context_data.get("system_description", "N/A")
                threat_intel = "\n".join(context_data.get("threat_intelligence", []))
                return {
                    "system_description": system_desc,
                    "user_threat_intelligence": threat_intel
                }
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding user context JSON from {self.user_context_path}: {e}")
            return {"system_description": "N/A", "user_threat_intelligence": "N/A"}
        except Exception as e:
            logger.error(f"An unexpected error occurred loading user context from {self.user_context_path}: {e}")
            return {"system_description": "N/A", "user_threat_intelligence": "N/A"}


    def generate_threats(self, threat_model_markdown: str, k: int = 5) -> List[Dict[str, str]]:
        """
        Generates contextualized threats using RAG.

        Args:
            threat_model_markdown: The content of the threat model in Markdown format.
            k: The number of relevant documents to retrieve from the vector store.

        Returns:
            A list of dictionaries, each representing a generated threat.
        """
        logger.debug("Generating threats using RAG...")

        user_context = self._load_user_context()
        system_description = user_context["system_description"]
        user_threat_intelligence = user_context["user_threat_intelligence"]

        # Formulate query for retriever
        query = f"System: {system_description}\nThreat Model:\n{threat_model_markdown}\nUser Threat Intel:\n{user_threat_intelligence}"
        
        # Retrieve relevant documents
        logger.debug(f"Retrieving {k} relevant documents from vector store...")
        retrieved_docs = self.vector_store.similarity_search(query, k=k)
        context_text = "\n\n".join([doc.page_content for doc in retrieved_docs])
        logger.debug(f"Retrieved {len(retrieved_docs)} documents.")

        try:
            generated_threats = self.rag_chain.invoke({
                "system_description": system_description,
                "user_threat_intelligence": user_threat_intelligence,
                "threat_model_markdown": threat_model_markdown,
                "context": context_text,
            })

            if not isinstance(generated_threats, list):
                logger.error(f"RAG chain returned unexpected type: {type(generated_threats)}")
                return []

            logger.debug(f"Threat generation completed: {len(generated_threats)} threats.")
            return generated_threats
        except ValueError as e:
            logger.error(f"RAG chain output parsing failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Error during RAG threat generation: {e}")
            return []
