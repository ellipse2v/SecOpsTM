import os
import json
import logging
import re
from typing import List, Dict, Any, Optional
import yaml
from langchain_core.runnables import RunnablePassthrough


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RAGThreatGenerator:
    def _extract_json_from_response(self, text: str) -> Optional[str]:
        """Extracts a JSON object or array from a string that might be wrapped in markdown or have other text."""
        # First, try to find JSON within markdown code fences (handles both objects and arrays)
        pattern = r"```(?:json)?\s*([\s\S]*?)\s*```"
        match = re.search(pattern, text, re.DOTALL)
        if match:
            # The content inside the fences is our best bet for valid JSON
            return match.group(1).strip()

        # If no fences, find the first '[' or '{' and the last ']' or '}' as a fallback
        start_char, end_char = None, None
        if '[' in text and ']' in text:
            start_char, end_char = '[', ']'
        elif '{' in text and '}' in text:
            start_char, end_char = '{', '}'
        
        if start_char:
            try:
                start_index = text.find(start_char)
                end_index = text.rfind(end_char)
                if start_index != -1 and end_index != -1 and end_index > start_index:
                    potential_json = text[start_index : end_index + 1]
                    # Validate that this substring is valid JSON
                    json.loads(potential_json)
                    return potential_json
            except (json.JSONDecodeError, TypeError):
                # This substring was not valid JSON, so we return None
                return None

        return None # No valid JSON found

    def __init__(
        self,
        vector_store_dir: str = "threat_analysis/vector_store",
        embedding_model_name: str = "all-MiniLM-L6-v2",
        user_context_path: str = "config/user_context.example.json",
        ai_config_path: str = "config/ai_config.yaml",
    ):
        self.vector_store_dir = vector_store_dir
        self.embedding_model_name = embedding_model_name
        self.user_context_path = user_context_path
        self.ai_config_path = ai_config_path

        self._initialize_components()

    def _load_ai_config(self) -> Dict[str, Any]:
        """Loads AI configuration from ai_config.yaml."""
        if not os.path.exists(self.ai_config_path):
            logging.error(f"AI config file not found: {self.ai_config_path}. Cannot initialize LLM.")
            return {}
        try:
            with open(self.ai_config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            logging.error(f"Error parsing AI config YAML from {self.ai_config_path}: {e}")
            return {}

    def _initialize_components(self):
        """Initializes the embedding model, vector store, and LLM."""
        logging.info("Initializing RAGThreatGenerator components...")
        
        # Lazy imports
        from langchain_chroma import Chroma
        from langchain_huggingface import HuggingFaceEmbeddings
        from langchain_litellm import ChatLiteLLM
        from chromadb.config import Settings
        from langchain_core.prompts import ChatPromptTemplate
        from langchain_core.output_parsers import JsonOutputParser
        from langchain_core.runnables import RunnablePassthrough

        # Initialize Embeddings
        self.embeddings = HuggingFaceEmbeddings(model_name=self.embedding_model_name)
        
        # Initialize Vector Store and disable telemetry
        if not os.path.exists(self.vector_store_dir):
            logging.error(f"Vector store directory not found: {self.vector_store_dir}. "
                          "Please run tooling/build_vector_store.py first.")
            raise FileNotFoundError(f"Vector store not found at {self.vector_store_dir}")
        
        self.vector_store = Chroma(
            persist_directory=self.vector_store_dir,
            embedding_function=self.embeddings,
            client_settings=Settings(anonymized_telemetry=False)
        )
        
        # Initialize LLM using ai_config.yaml
        ai_config = self._load_ai_config()
        providers = ai_config.get('ai_providers', {})
        llm_params = {}
        llm_model = None

        # Prioritize Ollama, then Mistral, then OpenAI
        if providers:
            if providers.get('ollama', {}).get('enabled'):
                ollama_config = providers['ollama']
                llm_model = f"ollama/{ollama_config.get('model')}" # Prepend 'ollama/'
                llm_params['temperature'] = ollama_config.get('temperature', 0.5)
                # For ChatLiteLLM, the API base for Ollama is passed differently
                llm_params['api_base'] = ollama_config.get('host', 'http://localhost:11434')
                logging.info(f"Using Ollama LLM: {llm_model} at {llm_params.get('api_base')}")
            elif providers.get('mistral_api', {}).get('enabled'):
                mistral_config = providers['mistral_api']
                llm_model = f"mistral/{mistral_config.get('model')}"
                llm_params['temperature'] = mistral_config.get('temperature', 0.5)
                llm_params['api_key'] = os.getenv(mistral_config.get('api_key_env', 'MISTRAL_API_KEY'))
                logging.debug(f"Using Mistral LLM: {llm_model}")
            elif providers.get('openai', {}).get('enabled'):
                openai_config = providers['openai']
                llm_model = f"openai/{openai_config.get('model')}"
                llm_params['temperature'] = openai_config.get('temperature', 0.5)
                llm_params['api_key'] = os.getenv(openai_config.get('api_key_env', 'OPENAI_API_KEY'))
                logging.debug(f"Using OpenAI LLM: {llm_model}")

        if llm_model:
            self.llm = ChatLiteLLM(model=llm_model, **llm_params)
            logging.info(f"LLM initialized with model: {llm_model}")
        else:
            logging.error("No enabled LLM provider found in ai_config.yaml. RAG functionality will be limited.")
            raise ValueError("No active LLM configuration found.")
        
        # Define Prompt Template
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "You are an expert cybersecurity analyst. Your task is to identify potential security threats based on a system's description, user-provided threat intelligence, and retrieved general threat knowledge. Focus on relevant and actionable threats."),
            ("human", """
            System Description:
            {system_description}

            User-Provided Threat Intelligence:
            {user_threat_intelligence}

            Threat Model Document (Markdown):
            {threat_model_markdown}

            Retrieved General Threat Knowledge:
            {context}

            Based on the provided information, generate a list of distinct and pertinent security threats. For each threat, provide:
            - **name**: A concise name for the threat.
            - **description**: A detailed description of the threat, explaining how it applies to the system.
            - **category**: The STRIDE category that best fits the threat (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege).
            - **likelihood**: The likelihood of exploitation (high, medium, low).
            - **impact**: The impact of exploitation (high, medium, low).
            - **source**: Always \"LLM\".

            Format your response as a JSON array of objects, like this:
            [
              {{
                "name": "Threat Name 1",
                "description": "Detailed description of Threat 1, explaining how it applies to the system.",
                "category": "Spoofing",
                "likelihood": "medium",
                "impact": "high",
                "source": "LLM"
              }},
              {{
                "name": "Threat Name 2",
                "description": "Detailed description of Threat 2, explaining how it applies to the system.",
                "category": "Tampering",
                "likelihood": "low",
                "impact": "medium",
                "source": "LLM"
              }}
            ]
            """
        )])
        
        # Define Output Parser
        self.output_parser = JsonOutputParser()

        logging.info("RAGThreatGenerator components initialized.")

    def _load_user_context(self) -> Dict[str, Any]:
        """Loads user-defined system description and threat intelligence."""
        if not os.path.exists(self.user_context_path):
            logging.warning(f"User context file not found: {self.user_context_path}. Returning empty context.")
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
            logging.error(f"Error decoding user context JSON from {self.user_context_path}: {e}")
            return {"system_description": "N/A", "user_threat_intelligence": "N/A"}
        except Exception as e:
            logging.error(f"An unexpected error occurred loading user context from {self.user_context_path}: {e}")
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
        logging.debug("Generating threats using RAG...")

        user_context = self._load_user_context()
        system_description = user_context["system_description"]
        user_threat_intelligence = user_context["user_threat_intelligence"]

        # Formulate query for retriever
        query = f"System: {system_description}\nThreat Model:\n{threat_model_markdown}\nUser Threat Intel:\n{user_threat_intelligence}"
        
        # Retrieve relevant documents
        logging.debug(f"Retrieving {k} relevant documents from vector store...")
        retrieved_docs = self.vector_store.similarity_search(query, k=k)
        context_text = "\n\n".join([doc.page_content for doc in retrieved_docs])
        logging.debug(f"Retrieved {len(retrieved_docs)} documents.")

        # Construct the RAG chain
        rag_chain = (
            RunnablePassthrough.assign(context=lambda x: context_text)
            | self.prompt
            | self.llm
        )

        try:
            # Invoke the RAG chain to get the raw string response
            raw_llm_response = rag_chain.invoke({
                "system_description": system_description,
                "user_threat_intelligence": user_threat_intelligence,
                "threat_model_markdown": threat_model_markdown,
                "context": context_text # This context will be passed to the prompt
            })
            
            # Extract JSON from the raw response
            cleaned_json_string = self._extract_json_from_response(raw_llm_response.content)
            
            if not cleaned_json_string:
                logging.error(f"Invalid json output: No valid JSON found in LLM response. Raw output: {raw_llm_response}")
                return []
            
            # Parse the extracted JSON
            generated_threats = json.loads(cleaned_json_string)

            logging.debug("Threat generation completed successfully.")
            return generated_threats
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding JSON from RAG LLM response: {e}. Raw output: {cleaned_json_string}")
            return []
        except Exception as e:
            logging.error(f"Error during RAG threat generation: {e}")
            return []

if __name__ == "__main__":
    # Example Usage
    # Ensure you have a vector store built and user_context.example.json present.
    # python tooling/build_vector_store.py
    # Then run this example.
    
    example_threat_model = """
    # Threat Model for E-commerce Backend API

    ## System Overview
    The system is a Python Flask backend API serving an e-commerce platform. It handles user authentication, product catalog management, order processing, and payment integration (via a third-party service). Data is stored in a PostgreSQL database. Communication with the frontend is via RESTful API calls over HTTPS.

    ## Components
    - **Flask API**: Handles business logic, API endpoints.
    - **PostgreSQL Database**: Stores user data, product info, order history.
    - **Payment Gateway Integration**: External API for processing payments.
    - **Load Balancer/API Gateway**: Distributes traffic, provides initial security.
    """

    try:
        # Before running this, ensure:
        # 1. tooling/build_vector_store.py has been run successfully.
        # 2. config/user_context.example.json exists.
        # 3. An LLM provider (e.g., Ollama) is enabled in config/ai_config.yaml and accessible.
        rag_generator = RAGThreatGenerator(
            user_context_path="config/user_context.example.json",
            ai_config_path="config/ai_config.yaml"
        )
        threats = rag_generator.generate_threats(example_threat_model)
        print("\n--- Generated Threats ---")
        if threats:
            for i, threat in enumerate(threats):
                print(f"Threat {i+1}: {threat.get('name', 'N/A')}")
                print(f"  Description: {threat.get('description', 'N/A')}")
                print(f"  Source: {threat.get('source', 'N/A')}")
        else:
            print("No threats generated.")
    except Exception as e:
        logging.error(f"Failed to initialize or run RAGThreatGenerator: {e}")