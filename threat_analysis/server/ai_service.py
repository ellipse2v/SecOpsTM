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
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from threat_analysis.utils import extract_json_from_llm_response
from pytm import Threat  # Keep original Threat import for direct pytm usage where needed
from threat_analysis.core.models_module import ExtendedThreat
from threat_analysis.ai_engine.rag_service import RAGThreatGenerator
from threat_analysis.ai_engine.providers.base_provider import BaseLLMProvider
from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider


class AIService:
    # Class-level persistent background event loop for sync wrappers (P2).
    _sync_loop: Optional[asyncio.AbstractEventLoop] = None
    _sync_loop_lock = threading.Lock()

    def __init__(self, config_path: str, ai_status_event_queue: Optional[queue.Queue] = None):
        self.provider: Optional[BaseLLMProvider] = None
        self.rag_generator = None
        self.ai_online = False
        self.ai_config = self._load_ai_config(config_path)
        self.ai_status_event_queue = ai_status_event_queue
        self.rate_limit_sleep: float = self.ai_config.get(
            "threat_generation", {}
        ).get("rate_limit_sleep", 0.0)
        self.max_concurrent: int = self.ai_config.get(
            "threat_generation", {}
        ).get("max_concurrent_ai_requests", 1)
        # Semaphore is created in init_ai() where the event loop is active.
        self._ai_semaphore: Optional[asyncio.Semaphore] = None


    @staticmethod
    def _validate_ai_config(config: Dict[str, Any]) -> List[str]:
        """Validates AI configuration structure and returns a list of warning messages.

        Uses only stdlib Python — no jsonschema dependency.
        Designed for graceful degradation: warnings are logged, no exceptions raised.

        Args:
            config: Parsed ai_config.yaml as a dict.

        Returns:
            A list of human-readable warning strings (empty list means config is valid).
        """
        warnings: List[str] = []

        providers = config.get("ai_providers")
        if not isinstance(providers, dict) or not providers:
            warnings.append(
                "ai_providers is missing or empty — no LLM provider is configured."
            )
        else:
            enabled_providers = [
                name for name, cfg in providers.items()
                if isinstance(cfg, dict) and cfg.get("enabled")
            ]
            if not enabled_providers:
                warnings.append(
                    "No provider has 'enabled: true' — AI features will be unavailable."
                )
            for name in enabled_providers:
                cfg = providers[name]
                if not cfg.get("model"):
                    warnings.append(
                        f"Provider '{name}' is enabled but has no 'model' defined."
                    )

        threat_gen = config.get("threat_generation", {})
        if isinstance(threat_gen, dict):
            rate_sleep = threat_gen.get("rate_limit_sleep")
            if rate_sleep is not None:
                try:
                    if float(rate_sleep) < 0:
                        warnings.append(
                            f"threat_generation.rate_limit_sleep={rate_sleep!r} is negative; "
                            "expected a non-negative number."
                        )
                except (TypeError, ValueError):
                    warnings.append(
                        f"threat_generation.rate_limit_sleep={rate_sleep!r} is not a valid number."
                    )

            max_concurrent = threat_gen.get("max_concurrent_ai_requests")
            if max_concurrent is not None:
                try:
                    if int(max_concurrent) < 1:
                        warnings.append(
                            f"threat_generation.max_concurrent_ai_requests={max_concurrent!r} "
                            "must be >= 1."
                        )
                except (TypeError, ValueError):
                    warnings.append(
                        f"threat_generation.max_concurrent_ai_requests={max_concurrent!r} "
                        "is not a valid integer."
                    )

        return warnings

    def _load_ai_config(self, config_path: str) -> Dict[str, Any]:
        """Loads AI configuration from ai_config.yaml."""
        if not os.path.exists(config_path):
            logging.error(f"AI config file not found: {config_path}. Cannot initialize AI features.")
            return {}
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logging.error(f"Error parsing AI config YAML from {config_path}: {e}")
            return {}

        for warning in self._validate_ai_config(config or {}):
            logging.warning("[ai_config] %s", warning)

        return config or {}

    def _load_context(self, threat_model=None) -> Dict[str, Any]:
        """Build global AI context from the DSL ## Context keys on the threat model.

        Keys accepted directly in ## Context (priority: DSL > context/*.yaml):
          system_description, sector, deployment_environment, data_sensitivity,
          internet_facing, user_base, compliance_requirements, integrations

        config/context.yaml has been removed — all context is now per-model.
        """
        if threat_model is None:
            return {}
        ctx_cfg = getattr(threat_model, "context_config", {})
        _AI_KEYS = {
            "system_description", "sector", "deployment_environment",
            "data_sensitivity", "internet_facing", "user_base",
            "compliance_requirements", "integrations",
        }
        return {k: v for k, v in ctx_cfg.items() if k in _AI_KEYS}

    def _load_model_context(self, threat_model) -> Dict[str, Any]:
        """Load the model-specific GDAF context file and extract AI-relevant fields.

        Uses the same resolution order as ExportService._resolve_gdaf_context():
          1. gdaf_context key in ## Context DSL section (relative to model file)
          2. {model_dir}/context/*.yaml auto-discovery
          3. Returns {} if nothing found (no fallback to config/context.yaml —
             that is loaded separately by _load_context()).

        Extracted fields merged into the AI prompt context:
          sector, compliance_requirements, data_sensitivity,
          deployment_environment, internet_facing,
          threat_actor_profiles (formatted summary), business_goals_to_protect.
        """
        ctx_cfg = getattr(threat_model, "context_config", {})
        dsl_path = ctx_cfg.get("gdaf_context")
        model_path = getattr(threat_model, "_model_file_path", None)

        context_path = None
        if dsl_path:
            if model_path:
                p = Path(model_path).parent / dsl_path
                if p.exists():
                    context_path = p
            if context_path is None:
                p = Path(dsl_path)
                if p.exists():
                    context_path = p
            if context_path is None:
                logging.debug("AI: gdaf_context '%s' declared but not found; skipping model context enrichment.", dsl_path)
        if context_path is None and model_path:
            context_dir = Path(model_path).parent / "context"
            if context_dir.exists():
                yaml_files = sorted(context_dir.glob("*.yaml")) + sorted(context_dir.glob("*.yml"))
                if yaml_files:
                    context_path = yaml_files[0]

        if context_path is None:
            return {}

        try:
            with open(context_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
            logging.info("AI: enriching prompts with model context from %s", context_path)

            # Format threat actor profiles as a concise block for the prompt
            threat_actors = data.get("threat_actors", [])
            actor_lines: List[str] = []
            for ta in threat_actors:
                name = ta.get("name", "Unknown")
                soph = ta.get("sophistication", "medium")
                entry = ta.get("entry_preference", "")
                ttps = ta.get("known_ttps", [])
                ttp_str = (", ".join(ttps[:6]) + ("…" if len(ttps) > 6 else "")) if ttps else "all techniques"
                line = f"- **{name}** (sophistication: {soph}"
                if entry:
                    line += f", entry: {entry}"
                line += f") — TTPs: {ttp_str}"
                actor_lines.append(line)

            goals = data.get("business_goals_to_protect", [])
            goals_str = "\n".join(f"- {g}" for g in goals) if goals else ""

            return {
                "sector": data.get("sector", ""),
                "compliance_requirements": data.get("compliance_requirements", []),
                "data_sensitivity": data.get("data_sensitivity", ""),
                "deployment_environment": data.get("deployment_environment", ""),
                "internet_facing": data.get("internet_facing"),
                "threat_actor_profiles": "\n".join(actor_lines),
                "business_goals_to_protect": goals_str,
            }
        except Exception as e:
            logging.warning("AI: could not load model context from %s: %s", context_path, e)
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

        # Pre-warm RAG in a background thread immediately, in parallel with the AI connection
        # check.  RAGThreatGenerator loads chromadb + embeddings (~26s cold) which is independent
        # of litellm being available (~64s cold import).  By the time check_connection() returns,
        # RAG components will already be loaded — net savings ≈ 26s on first startup.
        # run_in_executor returns an asyncio.Future that can be awaited without blocking the loop.
        rag_enabled = self.ai_config.get("rag", {}).get("enabled", False)
        rag_task: Optional[asyncio.Future] = None
        if rag_enabled:
            logging.info("RAG pre-warm started (parallel to AI connection check).")
            loop = asyncio.get_running_loop()
            rag_task = loop.run_in_executor(None, RAGThreatGenerator)

        self.provider = LiteLLMProvider(enabled_config)
        self.ai_online = await self.provider.check_connection()

        # Semaphore must be created inside the active event loop (not in __init__).
        self._ai_semaphore = asyncio.Semaphore(self.max_concurrent)
        logging.info("AI semaphore initialized with max_concurrent=%d.", self.max_concurrent)

        # Collect RAG pre-warm result (or fall back to synchronous init)
        if rag_enabled and self.ai_online:
            if rag_task is not None:
                try:
                    self.rag_generator = await asyncio.wait_for(rag_task, timeout=300)
                    logging.info("RAG service initialized (pre-warmed).")
                except Exception as e:
                    logging.error(f"RAG pre-warm failed ({e}); retrying synchronously.")
                    try:
                        self.rag_generator = RAGThreatGenerator()
                        logging.info("RAG service initialized (synchronous fallback).")
                    except Exception as e2:
                        logging.error(f"Failed to initialize RAG service: {e2}")
                        self.rag_generator = None
            else:
                try:
                    self.rag_generator = RAGThreatGenerator()
                    logging.info("RAG service initialized.")
                except Exception as e:
                    logging.error(f"Failed to initialize RAG service: {e}")
                    self.rag_generator = None
        else:
            if rag_task is not None:
                rag_task.cancel()
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

    @classmethod
    def _get_sync_loop(cls) -> asyncio.AbstractEventLoop:
        """Returns (or lazily starts) a persistent background event loop.

        A single daemon thread running loop.run_forever() is reused across all
        calls, avoiding the overhead of creating a new thread + event loop per
        invocation (P2 fix).
        """
        if cls._sync_loop is None or cls._sync_loop.is_closed():
            with cls._sync_loop_lock:
                if cls._sync_loop is None or cls._sync_loop.is_closed():
                    loop = asyncio.new_event_loop()
                    t = threading.Thread(
                        target=loop.run_forever,
                        daemon=True,
                        name="ai-sync-loop",
                    )
                    t.start()
                    cls._sync_loop = loop
        return cls._sync_loop

    async def _collect_markdown_chunks(self, prompt: str, markdown: Optional[str]) -> List[str]:
        """Collects all streamed chunks from generate_markdown_from_prompt into a list."""
        chunks: List[str] = []
        async for chunk in self.generate_markdown_from_prompt(prompt, markdown):
            chunks.append(chunk)
        return chunks

    def generate_rag_threats_sync(self, threat_model) -> List[ExtendedThreat]:
        """Sync wrapper around _generate_rag_threats.

        Submits the coroutine to the persistent background event loop and blocks
        until the result is ready.  Safe to call from sync Flask routes.
        Returns an empty list when the RAG generator is unavailable.
        """
        if not self.rag_generator:
            return []
        future = asyncio.run_coroutine_threadsafe(
            self._generate_rag_threats(threat_model),
            self._get_sync_loop(),
        )
        try:
            return future.result(timeout=120)
        except Exception as exc:
            logging.warning("generate_rag_threats_sync failed: %s", exc)
            return []

    def generate_markdown_from_prompt_sync(self, prompt: str, markdown: Optional[str] = None):
        """Sync wrapper around generate_markdown_from_prompt.

        Submits the coroutine to the persistent background event loop via
        run_coroutine_threadsafe(), then blocks until the result is ready.
        This is safe to call from inside an already-running asyncio loop
        (e.g. Flask async routes) because the coroutine runs in a separate loop.
        """
        logging.debug("Generating markdown from prompt (sync)...")
        future = asyncio.run_coroutine_threadsafe(
            self._collect_markdown_chunks(prompt, markdown),
            self._get_sync_loop(),
        )
        chunks = future.result()
        return iter(chunks)

    async def _generate_rag_threats(self, threat_model) -> List[ExtendedThreat]: # Return List[ExtendedThreat]
        """
        Generates system-level threats using the RAG service.

        A2: includes sub-model content so RAG receives the full project context
        and can identify cross-model / cross-boundary threats.
        """
        if not self.rag_generator:
            return []

        logging.debug("Generating system-level threats using RAG...")

        def _model_markdown(tm, label: str = "") -> str:
            """Render a single ThreatModel as Markdown for RAG context."""
            header = label or tm.tm.name
            md = f"# Threat Model: {header}\n\n"
            md += f"## Description\n\n{tm.tm.description}\n\n"
            md += "## Components\n\n"
            # Actors and servers may be stored as dicts (with 'object' key) or as objects
            def _to_obj(item):
                if isinstance(item, dict):
                    return item.get('object') or item.get('name')
                return item

            actors_objs = [_to_obj(a) for a in tm.actors]
            servers_objs = [_to_obj(s) for s in tm.servers]
            elements = [e for e in (actors_objs + servers_objs + list(tm.dataflows)) if e is not None]
            for element in elements:
                name = getattr(element, 'name', str(element))
                md += f"### {name}\n\n"
                md += f"- **Type:** {element.stereotype if hasattr(element, 'stereotype') else element.__class__.__name__}\n"
                md += f"- **Description:** {getattr(element, 'description', '')}\n"
                if hasattr(element, 'protocol'):
                    md += f"- **Protocol:** {element.protocol}\n"
                md += "\n"
            return md

        # Main model markdown
        tm_markdown_content = _model_markdown(threat_model)

        # Append sub-model content when running in project mode (cross-model context)
        for sub in getattr(threat_model, "sub_models", []):
            try:
                tm_markdown_content += "\n---\n\n" + _model_markdown(sub, label=f"Sub-model: {sub.tm.name}")
            except Exception as exc:
                logging.warning("Could not append sub-model to RAG context: %s", exc)

        rag_generated_threats_json = self.rag_generator.generate_threats(tm_markdown_content)
        
        pytm_rag_threats = []
        severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        likelihood_map = {"high": 5, "medium": 3, "low": 1}

        for threat_json in rag_generated_threats_json:
            if not isinstance(threat_json, dict):
                logging.warning("RAG: skipping non-dict item in threat list: %r", threat_json)
                continue
            try:
                description = f"(RAG-LLM) {threat_json.get('name', 'N/A')}: {threat_json.get('description', '')}"
                likelihood = likelihood_map.get(threat_json.get('likelihood', 'medium').lower(), 3)
                impact = severity_map.get(threat_json.get('impact', 'medium').lower(), 3)
                new_threat = ExtendedThreat(
                    SID=threat_json.get('name', 'Generic RAG Threat'),
                    description=description,
                    category=threat_json.get('category', 'Generic RAG Threat'),
                    likelihood=likelihood,
                    impact=impact,
                    source="LLM",
                )
                new_threat.capec_ids = [
                    c for c in threat_json.get('capec_ids', [])
                    if isinstance(c, str) and c.upper().startswith('CAPEC-')
                ]
                new_threat.ai_details = threat_json
                new_threat.confidence = float(threat_json.get('confidence', 0.75))
                pytm_rag_threats.append(new_threat)
            except Exception as exc:
                logging.warning("RAG: failed to build ExtendedThreat from %r: %s", threat_json, exc)

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

        # Build context: DSL ## Context keys (base) ← per-model context/*.yaml ← runtime
        # Priority: DSL context_config > context/*.yaml
        dsl_ctx = self._load_context(threat_model)
        model_ctx = self._load_model_context(threat_model)

        # DSL wins over context/*.yaml; runtime internet_facing takes final precedence
        # only when neither source has an explicit value.
        has_internet_facing = (
            dsl_ctx.get("internet_facing") is not None
            or model_ctx.get("internet_facing") is not None
        )
        context: Dict[str, Any] = {
            **{k: v for k, v in model_ctx.items() if v not in (None, "", [], {})},
            **{k: v for k, v in dsl_ctx.items() if v not in (None, "", [], {})},
            "system_description": (
                dsl_ctx.get("system_description")
                or model_ctx.get("system_description", "")
                or threat_model.tm.description
            ),
            "internet_facing": (
                dsl_ctx.get("internet_facing") or model_ctx.get("internet_facing")
                if has_internet_facing
                else any(s.get('is_public') for s in threat_model.servers)
            ),
        }
        context.setdefault("data_sensitivity", "High")
        if model_ctx.get("sector"):
            logging.info("AI: prompt context enriched — sector=%s  compliance=%s  actors=%d",
                         model_ctx["sector"],
                         model_ctx.get("compliance_requirements", []),
                         len(model_ctx.get("threat_actor_profiles", "").splitlines()))

        all_elements = (
            [a['object'] for a in threat_model.actors]
            + [s['object'] for s in threat_model.servers]
            + threat_model.dataflows
        )

        # A3: include trust boundaries as AI threat targets
        boundary_objects = [
            b_info['boundary']
            for b_info in threat_model.boundaries.values()
            if b_info.get('boundary') is not None
        ]
        all_elements = all_elements + boundary_objects

        # Ensure all elements have a 'threats' attribute to append to.
        for element in all_elements:
            if not hasattr(element, 'threats'):
                element.threats = []

        total_elements = len(all_elements)
        processed_elements = 0

        # Build lookup: object → props dict for rich attribute extraction
        _server_props_map = {s['object']: s for s in threat_model.servers}
        _actor_props_map = {a['object']: a for a in threat_model.actors}
        _boundary_props_map = {
            b_info['boundary']: b_info
            for b_info in threat_model.boundaries.values()
            if b_info.get('boundary') is not None
        }

        # Keys already handled explicitly — remaining props go to extra_properties
        _KNOWN_PROPS = {
            'name', 'object', 'boundary', 'business_value', 'type', 'machine',
            'waf', 'ids', 'ips', 'redundant', 'confidentiality', 'integrity',
            'availability', 'encryption', 'auth_protocol', 'mfa_enabled', 'tags',
            'description', 'submodel', 'color', 'isTrusted', 'authenticity',
            'businessValue', 'is_public', 'is_authenticated', 'is_encrypted',
            'protocol', 'type_',
        }

        def _flow_desc(df) -> str:
            """Rich single-line description of a dataflow including all security attributes."""
            parts = [f"{df.source.name} \u2192 {df.sink.name}"]
            if getattr(df, 'protocol', None):
                parts.append(f"[{df.protocol}]")
            flags = []
            if getattr(df, 'is_encrypted', False):
                flags.append("encrypted")
            if getattr(df, 'vpn', False):
                flags.append("VPN")
            # Prefer detailed auth type over binary boolean
            auth_type = getattr(df, 'authentication', None)
            if auth_type and str(auth_type).lower() not in ('none', 'false', ''):
                flags.append(f"auth={auth_type}")
            elif getattr(df, 'is_authenticated', False):
                flags.append("authenticated")
            authz_type = getattr(df, 'authorization', None)
            if authz_type and str(authz_type).lower() not in ('none', 'false', ''):
                flags.append(f"authz={authz_type}")
            if getattr(df, 'ip_filtered', False):
                flags.append("IP-filtered")
            if getattr(df, 'readonly', False):
                flags.append("read-only")
            if flags:
                parts.append(f"({', '.join(flags)})")
            # Data objects with classification
            data_objs = getattr(df, 'data', []) or []
            if data_objs:
                labels = []
                for d in data_objs:
                    cls = getattr(d, 'classification', None)
                    if cls is not None:
                        cls_name = cls.name if hasattr(cls, 'name') else str(cls)
                        labels.append(f"{d.name}:{cls_name}")
                    else:
                        labels.append(d.name)
                parts.append(f"data=[{', '.join(labels)}]")
            # Trust crossing
            src_trusted = getattr(getattr(df.source, 'inBoundary', None), 'isTrusted', None)
            sink_trusted = getattr(getattr(df.sink, 'inBoundary', None), 'isTrusted', None)
            if src_trusted is not None and sink_trusted is not None and src_trusted != sink_trusted:
                direction = "trusted\u2192untrusted" if src_trusted else "untrusted\u2192trusted"
                parts.append(f"[TRUST CROSSING: {direction}]")
            return " ".join(parts)

        # P1 fix: single connection check before the loop instead of one per element.
        if not self.provider:
            logging.error("AI provider not initialized.")
            return
        if not await self.provider.check_connection():
            logging.warning("AI enrichment stopped: provider is offline.")
            self.ai_online = False
            return

        # Ensure semaphore is available (fallback in case init_ai was not awaited).
        if self._ai_semaphore is None:
            self._ai_semaphore = asyncio.Semaphore(self.max_concurrent)

        # Counter lock for thread-safe progress tracking across concurrent tasks.
        _progress_lock = asyncio.Lock()

        async def _enrich_one(element) -> None:
            """Enriches a single element with AI-generated threats.

            Uses _ai_semaphore to cap concurrent LLM requests (respects rate limits).
            The rate_limit_sleep is intentionally kept INSIDE the semaphore block so
            that the configured delay is always honoured even under concurrency.
            """
            nonlocal processed_elements

            # Pull rich attributes from props dict (server/actor/boundary) or object (dataflow)
            props = (
                _server_props_map.get(element)
                or _actor_props_map.get(element)
                or _boundary_props_map.get(element)
                or {}
            )

            # A1 + A3: enrich with boundary context.
            # For boundary objects themselves, isTrusted is a direct attribute.
            is_boundary_element = element.__class__.__name__ in ("SecOpsBoundary", "Boundary")
            if is_boundary_element:
                trusted = getattr(element, 'isTrusted', False)
                b_type = props.get('type', '')
                type_prefix = f"{b_type}, " if b_type else ""
                trust_boundary_str = f"Self ({type_prefix}{'TRUSTED' if trusted else 'UNTRUSTED'})"
                elem_type = f"Trust Boundary ({type_prefix}{'Trusted' if trusted else 'Untrusted'})"
            else:
                boundary_obj = getattr(element, 'inBoundary', None)
                if boundary_obj:
                    trusted = getattr(boundary_obj, 'isTrusted', False)
                    trust_boundary_str = (
                        f"{boundary_obj.name} ({'TRUSTED' if trusted else 'UNTRUSTED'})"
                    )
                else:
                    trust_boundary_str = "None assigned"
                # Critical fix: use DSL type= first, then pytm stereotype, then class name
                elem_type = (
                    props.get('type')
                    or (element.stereotype if getattr(element, 'stereotype', None) else None)
                    or element.__class__.__name__
                )

            # Machine type
            machine_type = str(props.get('machine', getattr(element, 'machine', 'unknown')))

            # CIA triad
            conf = str(props.get('confidentiality', getattr(element, 'confidentiality', 'unknown')))
            integ = str(props.get('integrity', getattr(element, 'integrity', 'unknown')))
            avail = str(props.get('availability', getattr(element, 'availability', 'unknown')))
            cia_triad = f"Confidentiality: {conf} | Integrity: {integ} | Availability: {avail}"

            # Security controls
            waf = props.get('waf', getattr(element, 'waf', False))
            ids_ctrl = props.get('ids', getattr(element, 'ids', False))
            ips_ctrl = props.get('ips', getattr(element, 'ips', False))
            redundant = props.get('redundant', getattr(element, 'redundant', False))
            enc_rest = str(props.get('encryption', getattr(element, 'encryption', 'unknown')))
            auth_proto = str(props.get('auth_protocol', getattr(element, 'auth_protocol', 'N/A')))
            mfa = props.get('mfa_enabled', getattr(element, 'mfa_enabled', None))
            controls_parts = [
                f"WAF: {'Yes' if waf else 'No'}",
                f"IDS: {'Yes' if ids_ctrl else 'No'}",
                f"IPS: {'Yes' if ips_ctrl else 'No'}",
                f"Redundant: {'Yes' if redundant else 'No'}",
                f"Encryption at rest: {enc_rest}",
                f"Auth protocol: {auth_proto}",
            ]
            if mfa is not None:
                controls_parts.append(f"MFA: {'Yes' if mfa else 'No'}")
            security_controls = " | ".join(controls_parts)

            # Technology tags
            raw_tags = props.get('tags', getattr(element, 'tags', None))
            if isinstance(raw_tags, list):
                technology_tags = ", ".join(str(t) for t in raw_tags) if raw_tags else "N/A"
            elif isinstance(raw_tags, str):
                technology_tags = raw_tags.strip('[]') or "N/A"
            else:
                technology_tags = "N/A"

            # Authentication detail (prefer actor authenticity or dataflow auth type over bool)
            authenticity = props.get('authenticity', None)
            auth_detail = (
                authenticity
                if authenticity
                else ("Yes" if getattr(element, 'is_authenticated', False) else "No")
            )

            # Business value
            business_value = props.get('business_value', getattr(element, 'businessValue', None))

            # Extra properties: all remaining DSL kwargs not already explicitly handled
            extra_props = {k: v for k, v in props.items() if k not in _KNOWN_PROPS}
            extra_properties = (
                " | ".join(f"{k}={v}" for k, v in extra_props.items())
                if extra_props else "None"
            )

            # Description: props first (server/actor description kwarg), then pytm attribute
            description = (
                props.get('description', '')
                or getattr(element, 'description', '')
                or ""
            )

            # Connected dataflows
            inbound = [_flow_desc(df) for df in threat_model.dataflows
                       if getattr(df, 'sink', None) is element]
            outbound = [_flow_desc(df) for df in threat_model.dataflows
                        if getattr(df, 'source', None) is element]

            component_details = {
                "name": element.name,
                "type": elem_type,
                "machine_type": machine_type,
                "technology_tags": technology_tags,
                "description": description,
                "protocol": getattr(element, "protocol", None),
                "trust_boundary": trust_boundary_str,
                "is_public": getattr(element, 'is_public', False),
                "authentication": auth_detail,
                "cia_triad": cia_triad,
                "security_controls": security_controls,
                "business_value": str(business_value) if business_value else "Not specified",
                "extra_properties": extra_properties,
                "inbound_flows": "\n".join(f"  - {f}" for f in inbound) if inbound else "  None",
                "outbound_flows": "\n".join(f"  - {f}" for f in outbound) if outbound else "  None",
            }
            logging.debug(f"Generating AI threats for component: {element.name}")

            async with self._ai_semaphore:
                ai_threats_json = await self.provider.generate_threats(component_details, context)

                # Rate-limit pause (configurable via ai_config.yaml threat_generation.rate_limit_sleep).
                # Kept inside the semaphore block to honour the delay even under concurrency.
                if self.rate_limit_sleep > 0:
                    await asyncio.sleep(self.rate_limit_sleep)

            # Update progress counter and emit SSE event (outside semaphore to avoid blocking).
            async with _progress_lock:
                processed_elements += 1
                progress = (processed_elements / total_elements) * 100

            if ai_status_event_queue:
                data = {
                    "status": "ai_enrichment_progress",
                    "progress": progress,
                    "message": f"Enriching {element.name} ({processed_elements}/{total_elements})...",
                }
                ai_status_event_queue.put(f"event: ai_progress\ndata: {json.dumps(data)}\n\n")

            if not ai_threats_json:
                return

            for threat_json in ai_threats_json:
                # Convert the JSON threat to an ExtendedThreat object
                threat_desc = f"(AI) {threat_json.get('title', 'N/A')}: {threat_json.get('description', '')}"

                severity_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
                likelihood_map = {"high": 5, "medium": 3, "low": 1}

                business_impact = threat_json.get('business_impact', {})
                severity = severity_map.get(business_impact.get('severity', 'medium').lower(), 3)
                likelihood = likelihood_map.get(threat_json.get('likelihood', 'medium').lower(), 3)

                new_threat = ExtendedThreat(  # Use ExtendedThreat here
                    SID=threat_json.get('title', 'Unknown AI Threat'),
                    description=threat_desc,
                    category=threat_json.get('category', 'Unknown'),
                    likelihood=likelihood,
                    impact=severity,
                    source="AI"  # Explicitly mark source for component-level AI threats
                )
                # Store CAPEC IDs from LLM — used by map_threat_to_mitre() to derive
                # ATT&CK technique IDs from the validated static mapping (no hallucinated T-IDs).
                new_threat.capec_ids = [
                    c for c in threat_json.get('capec_ids', [])
                    if isinstance(c, str) and c.upper().startswith('CAPEC-')
                ]
                # Add extra details for reporting if needed
                new_threat.ai_details = threat_json

                # Append the new threat to the element's threats list
                element.threats.append(new_threat)
                logging.info(f"Added AI threat '{threat_json.get('title')}' to {element.name}")

        # Launch all element enrichments concurrently; _ai_semaphore limits actual parallelism.
        await asyncio.gather(*[_enrich_one(elem) for elem in all_elements])

        # SOC persona pass — runs after component enrichment so all AI threats are available.
        await self._enrich_with_soc_analysis(threat_model, ai_status_event_queue)

    # ------------------------------------------------------------------
    # SOC Analyst enrichment
    # ------------------------------------------------------------------

    @staticmethod
    def _compress_model_for_soc(threat_model) -> str:
        """Returns a compact JSON string digest of the model for SOC prompt context.

        Includes boundary trust, key dataflows, and component types — enough for
        the SOC persona to reason about log sources without sending the full markdown.
        """
        boundaries = [
            {"name": name, "trusted": b_info.get("isTrusted", True)}
            for name, b_info in threat_model.boundaries.items()
        ]
        flows = []
        for df in threat_model.dataflows:
            src = getattr(df.source, "name", "?")
            dst = getattr(df.sink, "name", "?")
            proto = getattr(df, "protocol", "") or ""
            flags = []
            if getattr(df, "is_encrypted", False):
                flags.append("enc")
            if getattr(df, "is_authenticated", False):
                flags.append("auth")
            flag_str = "+" + "+".join(flags) if flags else ""
            flows.append(f"{src} → {dst} [{proto}{flag_str}]")
        def _name_from(d: dict) -> str:
            if isinstance(d, dict):
                if "name" in d:
                    return d["name"]
                obj = d.get("object")
                if obj is not None:
                    return getattr(obj, "name", "")
            return getattr(d, "name", "")

        components = (
            [{"name": _name_from(a), "type": "Actor"} for a in threat_model.actors]
            + [{"name": _name_from(s), "type": "Server"} for s in threat_model.servers]
        )
        digest = {
            "boundaries": boundaries,
            "flows": flows[:20],  # cap to avoid token overflow
            "components": components[:30],
        }
        return json.dumps(digest, separators=(",", ":"))

    async def _enrich_with_soc_analysis(
        self,
        threat_model,
        ai_status_event_queue: Optional[queue.Queue] = None,
        batch_size: int = 8,
    ) -> None:
        """Adds SOC detection analysis to each AI-generated threat.

        Collects all ExtendedThreat objects with source="AI" from the model,
        batches them, calls the SOC analyst persona, and stores the result in
        ``threat.ai_details["soc_analysis"]``.  Silently skipped when:
        - AI is offline
        - provider does not implement generate_soc_analysis (returns [])
        - no AI threats are present
        """
        if not self.ai_online or not self.provider:
            return

        from threat_analysis.ai_engine.prompt_loader import get as _get_prompt

        # Collect all AI threats across all model elements
        all_ai_threats = []
        elements = (
            [a["object"] for a in threat_model.actors]
            + [s["object"] for s in threat_model.servers]
            + threat_model.dataflows
            + [
                b_info["boundary"]
                for b_info in threat_model.boundaries.values()
                if b_info.get("boundary") is not None
            ]
        )
        for elem in elements:
            for t in getattr(elem, "threats", []):
                if getattr(t, "source", "pytm") == "AI":
                    all_ai_threats.append(t)

        if not all_ai_threats:
            logging.debug("SOC pass: no AI threats found — skipping.")
            return

        try:
            system_prompt = _get_prompt("soc_analyst", "system")
            batch_template = _get_prompt("soc_analyst", "batch_template")
        except KeyError as exc:
            logging.warning("SOC pass: prompt key missing (%s) — skipping.", exc)
            return

        model_digest = self._compress_model_for_soc(threat_model)
        total_batches = (len(all_ai_threats) + batch_size - 1) // batch_size
        logging.info(
            "SOC pass: %d AI threats → %d batch(es) of %d",
            len(all_ai_threats),
            total_batches,
            batch_size,
        )

        for batch_idx in range(total_batches):
            batch = all_ai_threats[batch_idx * batch_size:(batch_idx + 1) * batch_size]
            # Build a compact representation of this batch for the prompt
            threats_list = []
            for i, t in enumerate(batch):
                ai_det = getattr(t, "ai_details", {}) or {}
                threats_list.append({
                    "id": f"t-{batch_idx * batch_size + i}",
                    "title": ai_det.get("title", getattr(t, "description", "")[:80]),
                    "stride_category": getattr(t, "category", "Unknown"),
                    "target": getattr(
                        getattr(t, "target", None), "name",
                        ai_det.get("target", "Unknown"),
                    ),
                    "description": ai_det.get("description", "")[:200],
                    "attack_scenario": ai_det.get("attack_scenario", "")[:300],
                })

            batch_prompt = (
                batch_template
                .replace("<<model_digest>>", model_digest)
                .replace("<<threats_batch>>", json.dumps(threats_list, indent=2))
            )

            try:
                async with self._ai_semaphore:
                    soc_results = await self.provider.generate_soc_analysis(
                        batch_prompt, system_prompt
                    )
                    if self.rate_limit_sleep > 0:
                        await asyncio.sleep(self.rate_limit_sleep)
            except Exception as exc:
                logging.warning("SOC pass: batch %d failed: %s", batch_idx, exc)
                continue

            if not isinstance(soc_results, list):
                logging.warning("SOC pass: unexpected response type %s for batch %d", type(soc_results), batch_idx)
                continue

            # Map results back to threats by position (threat_id = "t-N")
            result_by_id = {
                r.get("threat_id", ""): r
                for r in soc_results
                if isinstance(r, dict)
            }
            for i, t in enumerate(batch):
                threat_id = f"t-{batch_idx * batch_size + i}"
                soc = result_by_id.get(threat_id)
                if soc:
                    if not hasattr(t, "ai_details") or t.ai_details is None:
                        t.ai_details = {}
                    t.ai_details["soc_analysis"] = {
                        "detectability": soc.get("detectability", "unknown"),
                        "missing_logs": soc.get("missing_logs", []),
                        "siem_rules": soc.get("siem_rules", []),
                        "iocs": soc.get("iocs", []),
                    }
                    logging.debug(
                        "SOC pass: enriched '%s' — detectability=%s",
                        getattr(t, "SID", threat_id),
                        soc.get("detectability"),
                    )

            if ai_status_event_queue:
                data = {
                    "status": "soc_enrichment_progress",
                    "progress": ((batch_idx + 1) / total_batches) * 100,
                    "message": f"SOC analysis: batch {batch_idx + 1}/{total_batches}",
                }
                ai_status_event_queue.put(f"event: ai_progress\ndata: {json.dumps(data)}\n\n")
