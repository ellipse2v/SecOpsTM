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
import threading
from typing import List, Dict, Any, Optional
import yaml
from threat_analysis.utils import extract_json_from_llm_response

logger = logging.getLogger(__name__)

# Default chromadb collection name created by langchain_chroma.Chroma.from_documents()
_CHROMA_COLLECTION_NAME = "langchain"


class RAGThreatGenerator:
    """Generates contextualized threats using Retrieval-Augmented Generation.

    Uses chromadb and litellm directly — no langchain_core / langchain_chroma imports —
    to avoid the 270–310 s cold-start penalty those packages incur on WSL2 due to
    network calls (LangSmith telemetry, model pricing fetch) at import time.

    The chromadb PersistentClient and its collection are shared across all instances
    via class-level singletons protected by a threading.Lock.  This avoids re-opening
    the SQLite database on every instantiation in multi-request server scenarios.
    """

    _chroma_client = None
    _chroma_collection = None
    _chroma_lock = threading.Lock()

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

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_ai_config(self) -> Dict[str, Any]:
        """Loads AI configuration from ai_config.yaml."""
        if not os.path.exists(self.ai_config_path):
            logger.error(f"AI config file not found: {self.ai_config_path}.")
            return {}
        try:
            with open(self.ai_config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except yaml.YAMLError as e:
            logger.error(f"Error parsing AI config YAML from {self.ai_config_path}: {e}")
            return {}

    def _initialize_components(self):
        """Initializes the embedding model, chromadb collection, and LLM config.

        Only chromadb (fast) and the embedding provider are imported here.
        langchain_chroma and langchain_core are NOT imported — they cause 270–310 s
        of cold-start delay on WSL2 due to network calls at import time.
        """
        import time as _time
        logger.info("Initializing RAGThreatGenerator components...")

        _t = _time.monotonic()
        import chromadb
        from chromadb.config import Settings
        logger.debug("Import chromadb: %.1fs", _time.monotonic() - _t); _t = _time.monotonic()

        from threat_analysis.ai_engine.embedding_factory import get_embeddings
        logger.debug("Import embedding_factory: %.1fs", _time.monotonic() - _t); _t = _time.monotonic()

        ai_config = self._load_ai_config()
        logger.debug("Load ai_config: %.1fs", _time.monotonic() - _t); _t = _time.monotonic()

        # Initialize Embeddings
        self.embeddings = get_embeddings(ai_config)
        logger.debug("Embeddings initialized: %.1fs", _time.monotonic() - _t); _t = _time.monotonic()

        # Initialize chromadb directly (no langchain_chroma wrapper).
        # Use a class-level singleton so the PersistentClient (SQLite) is opened only
        # once, even when RAGThreatGenerator is instantiated multiple times (e.g. in
        # multi-request server mode).
        if not os.path.exists(self.vector_store_dir):
            raise FileNotFoundError(
                f"Vector store not found at {self.vector_store_dir}. "
                "Please run tooling/build_vector_store.py first."
            )

        with RAGThreatGenerator._chroma_lock:
            if RAGThreatGenerator._chroma_client is None:
                RAGThreatGenerator._chroma_client = chromadb.PersistentClient(
                    path=self.vector_store_dir,
                    settings=Settings(anonymized_telemetry=False),
                )
                # langchain_chroma builds the collection named "langchain" by default
                RAGThreatGenerator._chroma_collection = (
                    RAGThreatGenerator._chroma_client.get_collection(_CHROMA_COLLECTION_NAME)
                )
                logger.info(
                    "Vector store loaded (singleton): collection '%s' (%d docs)",
                    _CHROMA_COLLECTION_NAME,
                    RAGThreatGenerator._chroma_collection.count(),
                )
            else:
                logger.debug("Reusing existing ChromaDB singleton for collection '%s'.", _CHROMA_COLLECTION_NAME)
        self.collection = RAGThreatGenerator._chroma_collection
        logger.debug("Vector store ready: %.1fs", _time.monotonic() - _t); _t = _time.monotonic()

        # LLM configuration
        providers = ai_config.get('ai_providers', {})
        llm_params: Dict[str, Any] = {}
        llm_model: Optional[str] = None

        for name, config in providers.items():
            if config.get('enabled'):
                # Use the full provider name as the LiteLLM prefix so that
                # compound names like "nvidia_nim" are preserved intact.
                prefix = "ollama" if name == "ollama" else name
                llm_model = f"{prefix}/{config.get('model')}"
                llm_params['temperature'] = config.get('temperature', 0.5)
                if name == "ollama":
                    llm_params['api_base'] = config.get('host', 'http://localhost:11434')
                elif config.get('api_base'):
                    llm_params['api_base'] = config['api_base']
                api_key_env = config.get('api_key_env')
                if api_key_env:
                    llm_params['api_key'] = os.getenv(api_key_env)
                ssl_verify = config.get('ssl_verify', True)
                if ssl_verify is not True:
                    llm_params['ssl_verify'] = ssl_verify
                    if ssl_verify is False:
                        logger.warning("SSL verification DISABLED for RAG LLM calls.")
                    else:
                        logger.warning("Using custom SSL cert for RAG LLM: %s", ssl_verify)
                logger.info(f"Using {name} LLM: {llm_model}")
                break

        if not llm_model:
            raise ValueError("No active LLM configuration found in ai_config.yaml.")

        self._llm_model = llm_model
        self._llm_params = llm_params

        # Load prompt templates (plain strings — no langchain_core dependency)
        from threat_analysis.ai_engine.prompt_loader import get as _get_prompt
        self._rag_system_prompt: str = _get_prompt("rag", "system")
        self._rag_human_template: str = _get_prompt("rag", "human_template")

        logger.info("RAGThreatGenerator components initialized.")

    def _load_user_context(self) -> Dict[str, Any]:
        """Loads user-defined system description and threat intelligence."""
        _empty = {"system_description": "", "user_threat_intelligence": ""}
        if not os.path.exists(self.user_context_path):
            logger.info(
                "No user context loaded (file not found: %s). "
                "RAG threats will be based on architecture only.",
                self.user_context_path,
            )
            return _empty
        try:
            with open(self.user_context_path, 'r', encoding='utf-8') as f:
                context_data = json.load(f)
                system_desc = context_data.get("system_description", "")
                threat_intel = "\n".join(context_data.get("threat_intelligence", []))
                if not system_desc and not threat_intel:
                    logger.info(
                        "User context file loaded but contains no description or threat intelligence: %s",
                        self.user_context_path,
                    )
                return {
                    "system_description": system_desc,
                    "user_threat_intelligence": threat_intel,
                }
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding user context JSON from {self.user_context_path}: {e}")
            return _empty
        except Exception as e:
            logger.error(f"Unexpected error loading user context: {e}")
            return _empty

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_threats(self, threat_model_markdown: str, k: int = 5) -> List[Dict[str, str]]:
        """Generates contextualized threats using RAG.

        Args:
            threat_model_markdown: Threat model content in Markdown format.
            k: Number of documents to retrieve from the vector store.

        Returns:
            A list of dicts, each representing a generated threat.
        """
        logger.debug("Generating threats using RAG...")

        user_context = self._load_user_context()
        system_description = user_context["system_description"]
        user_threat_intelligence = user_context["user_threat_intelligence"]

        # --- Retrieval ---
        # Only include context fields in the query when they carry real content.
        query_parts = [f"Threat Model:\n{threat_model_markdown}"]
        if system_description:
            query_parts.insert(0, f"System: {system_description}")
        if user_threat_intelligence:
            query_parts.append(f"User Threat Intel:\n{user_threat_intelligence}")
        query = "\n".join(query_parts)
        logger.debug("Retrieving %d relevant documents from vector store...", k)

        # Embed the query and search chromadb directly (no langchain wrapper)
        query_embedding = self.embeddings.embed_query(query)
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=k,
        )
        documents: List[str] = results.get("documents", [[]])[0]
        context_text = "\n\n".join(documents)
        logger.debug("Retrieved %d documents.", len(documents))

        # --- Generation ---
        # Escape braces in user-provided values so str.format() doesn't misinterpret
        # JSON-like content (e.g. {"key": "value"} in descriptions) as format specifiers.
        def _esc(s: str) -> str:
            return s.replace("{", "{{").replace("}", "}}")

        # Build optional context sections — omit entirely when empty to avoid
        # sending meaningless placeholder text to the LLM.
        ctx_sections: List[str] = []
        if system_description:
            ctx_sections.append(f"## System Description\n{_esc(system_description)}")
        if user_threat_intelligence:
            ctx_sections.append(f"## User Threat Intelligence\n{_esc(user_threat_intelligence)}")

        human_message = self._rag_human_template.format(
            optional_context="\n\n".join(ctx_sections),
            threat_model_markdown=_esc(threat_model_markdown),
            context=_esc(context_text),
        )
        messages = [
            {"role": "system", "content": self._rag_system_prompt},
            {"role": "user", "content": human_message},
        ]

        try:
            os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")
            import litellm
            litellm.suppress_debug_info = True
            litellm.set_verbose = False
            response = litellm.completion(
                model=self._llm_model,
                messages=messages,
                **self._llm_params,
            )
            raw_text: str = response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error during LLM call in RAG generation: {e}")
            return []

        # --- Parsing ---
        try:
            extracted = extract_json_from_llm_response(raw_text)
            if not extracted:
                raise ValueError(f"No valid JSON found in LLM response. Raw: {raw_text[:300]}")
            generated_threats = json.loads(extracted)
            if not isinstance(generated_threats, list):
                logger.error("RAG LLM returned unexpected type: %s", type(generated_threats))
                return []
            logger.debug("Threat generation completed: %d threats.", len(generated_threats))
            return generated_threats
        except ValueError as e:
            logger.error(f"RAG output parsing failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error parsing RAG output: {e}")
            return []
