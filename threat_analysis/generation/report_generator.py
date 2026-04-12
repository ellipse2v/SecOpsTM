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

"""
Report generation module
"""
import csv
import shutil
import re
import json
import logging
import sys
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import webbrowser
from jinja2 import Environment, FileSystemLoader
import os
from pathlib import Path
from collections import defaultdict
from threat_analysis.utils import _validate_path_within_project
from threat_analysis.mitigation_suggestions import get_framework_mitigation_suggestions
from threat_analysis.core.cve_service import CVEService
from threat_analysis.core.threat_ranker import rank_and_trim
from threat_analysis.core.accepted_risks import AcceptedRiskLoader, compute_threat_key
from .utils import extract_name_from_object, get_target_name
import yaml
import asyncio


project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.generation.stix_generator import StixGenerator
from threat_analysis.generation.attack_navigator_generator import AttackNavigatorGenerator
from threat_analysis.generation.attack_flow_generator import AttackFlowGenerator
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.core.attack_chain import AttackChainAnalyzer
from threat_analysis.core.threat_consolidator import ThreatConsolidator
from threat_analysis.core.model_completeness import score_model as _score_model_completeness
from threat_analysis.core.attack_id_validator import AttackIdValidator
from threat_analysis.core.report_serializer import ReportSerializer
from threat_analysis.severity_calculator_module import RiskContext

def _resolve_active_cves(
    component_name: str,
    vex_loader: Optional[Any],
    bom_loader: Optional[Any],
    cve_service: Any,
) -> List[str]:
    """
    Return the list of active CVE IDs for a component, using the best available source.

    Priority:
    1. Standalone VEX file (via VEXLoader)
    2. BOM file with VEX state data (active_cves parsed from analysis.state)
    3. BOM file known_cves (no state — treat all as active, legacy)
    4. cve_definitions.yml via CVEService (last resort)
    """
    if vex_loader:
        return vex_loader.get_active_cves(component_name)
    if bom_loader:
        bom_data = bom_loader.get(component_name)
        if bom_data:
            # Prefer state-aware list when BOM contains VEX assertions
            if bom_data.get("active_cves") is not None:
                return bom_data["active_cves"]
            return bom_data.get("known_cves") or []
    return list(cve_service.get_cves_for_equipment(component_name))


def _resolve_has_fixed_cves(
    component_name: str,
    vex_loader: Optional[Any],
    bom_loader: Optional[Any],
) -> bool:
    """Return True when VEX or BOM data indicates at least one CVE has been fixed."""
    if vex_loader:
        return bool(vex_loader.get_fixed_cves(component_name))
    if bom_loader:
        bom_data = bom_loader.get(component_name)
        if bom_data:
            return bool(bom_data.get("fixed_cves"))
    return False


def _get_vex_loader(threat_model: Any) -> Optional[Any]:
    """Return a VEXLoader for the model's VEX data, or None if unavailable.

    Resolution order:
    1. ``threat_model.context_config['vex_file']``      — single file (DSL ## Context)
    2. ``threat_model.context_config['vex_directory']`` — directory  (DSL ## Context)
    3. Auto-discovery from ``_model_file_path`` (VEX/ dir or vex.json sibling)
    """
    try:
        from threat_analysis.core.vex_loader import VEXLoader
    except ImportError:
        return None

    ctx_cfg = getattr(threat_model, "context_config", {})
    model_path = getattr(threat_model, "_model_file_path", None)

    # 1. Explicit single file
    vex_file = ctx_cfg.get("vex_file")
    if vex_file:
        candidates = []
        if model_path:
            candidates.append(Path(model_path).parent / vex_file)
        candidates.append(Path(vex_file))
        for p in candidates:
            if p.is_file():
                logging.info("VEX (scoring): using file from DSL ## Context: %s", p)
                return VEXLoader.from_file(p)

    # 2. Explicit directory
    vex_dir = ctx_cfg.get("vex_directory")
    if vex_dir:
        candidates = []
        if model_path:
            candidates.append(Path(model_path).parent / vex_dir)
        candidates.append(Path(vex_dir))
        for p in candidates:
            if p.is_dir():
                logging.info("VEX (scoring): using directory from DSL ## Context: %s", p)
                return VEXLoader.from_directory(p)

    # 3. Auto-discovery
    if model_path:
        loader = VEXLoader.from_model_path(model_path)
        if loader:
            logging.info("VEX (scoring): auto-discovered VEX data from %s", model_path)
            return loader

    return None


def _get_bom_loader(threat_model: Any) -> Optional[Any]:
    """Return a BOMLoader for the model's BOM directory, or None if unavailable.

    Resolution order (mirrors ExportService._resolve_bom_directory):
    1. ``threat_model.context_config['bom_directory']`` (DSL ## Context key)
    2. ``{model_parent}/BOM/`` auto-discovered from ``_model_file_path``
    """
    try:
        from threat_analysis.core.bom_loader import BOMLoader
    except ImportError:
        return None

    ctx_cfg = getattr(threat_model, "context_config", {})
    dsl_path = ctx_cfg.get("bom_directory")
    model_path = getattr(threat_model, "_model_file_path", None)
    if dsl_path:
        # Resolve relative to model file directory first (fixes CLI single-model mode)
        if model_path:
            p = Path(model_path).parent / dsl_path
            if p.is_dir():
                logging.info("BOM (scoring): using directory from DSL ## Context: %s", p)
                return BOMLoader(str(p))
        if Path(dsl_path).is_dir():
            logging.info("BOM (scoring): using directory from DSL ## Context: %s", dsl_path)
            return BOMLoader(dsl_path)

    if model_path:
        bom_dir = Path(model_path).parent / "BOM"
        if bom_dir.is_dir():
            n_files = len(list(bom_dir.glob("*.json")) + list(bom_dir.glob("*.yaml")) + list(bom_dir.glob("*.yml")))
            logging.info("BOM (scoring): auto-discovered %s (%d asset file(s)) — known_cves will augment CVE scoring", bom_dir, n_files)
            return BOMLoader(str(bom_dir))

    return None


def _warn_bom_mismatches(bom_loader: Any, threat_model: Any) -> None:
    """Warn when BOM files have no matching component in the model.

    A BOM file named 'WebApp.yaml' that does not match any actor/server name
    (case-insensitive, punctuation-normalised) is silently ignored during scoring.
    This warning surfaces those mismatches so the user can fix the naming.
    """
    if bom_loader is None:
        return
    try:
        bom_dir = Path(bom_loader.directory)
    except AttributeError:
        return

    # Build the set of normalised component names from the model
    def _norm(s: str) -> str:
        import re as _re
        return _re.sub(r'[^a-z0-9]', '', str(s).lower())

    model_names = set()
    for s in getattr(threat_model, "servers", []):
        model_names.add(_norm(s.get("name", "")))
    for a in getattr(threat_model, "actors", []):
        model_names.add(_norm(a.get("name", "")))

    # Check each BOM file
    bom_stems = [
        f.stem.replace(".cdx", "") if f.name.endswith(".cdx.json") else f.stem
        for f in bom_dir.glob("*")
        if f.suffix in (".json", ".yaml", ".yml")
    ]
    unmatched = [stem for stem in bom_stems if _norm(stem) not in model_names]
    if unmatched:
        known = sorted(
            [s.get("name", "") for s in getattr(threat_model, "servers", [])]
            + [a.get("name", "") for a in getattr(threat_model, "actors", [])]
        )
        logging.warning(
            "BOM: %d file(s) have no matching component in the model and will be ignored: %s\n"
            "  Known component names: %s\n"
            "  Rename the BOM file(s) to match exactly (case-insensitive).",
            len(unmatched),
            ", ".join(f"'{s}'" for s in unmatched),
            ", ".join(f"'{n}'" for n in known),
        )


def _is_network_exposed(target: Any) -> bool:
    """Return True when the target is reachable without authentication or encryption.

    Heuristics (offline, no network calls):
    - Dataflow: not authenticated OR not encrypted.
    - Actor / Server: boundary is absent or explicitly untrusted.
    - Tuple (source, sink): either endpoint in an untrusted boundary.
    """
    from pytm import Dataflow as _Dataflow
    if isinstance(target, _Dataflow):
        return not getattr(target, 'is_authenticated', False) or \
               not getattr(target, 'is_encrypted', False)
    if isinstance(target, tuple):
        return any(_boundary_untrusted(obj) for obj in target if obj is not None)
    return _boundary_untrusted(target)


def _boundary_untrusted(element: Any) -> bool:
    boundary = getattr(element, 'inBoundary', None)
    if boundary is None:
        return True  # no boundary → implicitly exposed
    return not getattr(boundary, 'isTrusted', True)


def load_implemented_mitigations(mitigations_file: Optional[Path]) -> Set[str]:
    """Loads implemented mitigation IDs from a file."""
    if not mitigations_file or not mitigations_file.exists():
        return set()
    with open(mitigations_file, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip() and not line.strip().startswith("#")}

class ReportGenerator:
    """Class for generating HTML and JSON reports"""

    def __init__(self, severity_calculator, mitre_mapping,
                 implemented_mitigations_path: Optional[Path] = None,
                 cve_service: Optional[CVEService] = None,
                 ai_config_path: Optional[Path] = None,
                 context_path: Optional[Path] = None,  # kept for backwards compat, unused
                 threat_model_ref: Optional[ThreatModel] = None):
        self.severity_calculator = severity_calculator
        self.mitre_mapping = mitre_mapping
        self.env = Environment(loader=FileSystemLoader(Path(__file__).parent.parent / 'templates'), extensions=['jinja2.ext.do'])
        # B2: sanitize_id filter — same algo as DiagramService._sanitize_name_for_id
        self.env.filters['sid'] = lambda s: (
            lambda san: f'_{san}' if san and san[0].isdigit() else san or 'unnamed'
        )(__import__('re').sub(r'[^a-zA-Z0-9_]', '_', str(s or '')))
        self.implemented_mitigations = load_implemented_mitigations(implemented_mitigations_path)
        self.all_detailed_threats = []
        self.cve_service = cve_service if cve_service else CVEService(project_root, project_root / "cve_definitions.yml")
        self.ai_provider = None
        self.ai_context = None
        self.threat_model_ref = threat_model_ref # Store the reference
        # Threat ranking / volume control — defaults (overridden from ai_config below)
        self._ranking_max_total: int = 0
        self._ranking_min_stride: bool = True
        self._ranking_weights: Dict[str, float] = {}
        self._enrich_batch_size: int = 5
        self._enrich_max_concurrent: int = 3

        if ai_config_path and ai_config_path.exists():
            with open(ai_config_path, "r", encoding="utf-8") as f:
                ai_config = yaml.safe_load(f)

            # Look for enabled provider (lazy imports to avoid ~64s cold start in CLI)
            providers = ai_config.get("ai_providers", {})
            for provider_name, provider_config in providers.items():
                if provider_config.get("enabled"):
                    logging.info(f"AI Provider '{provider_name}' enabled for report enrichment.")
                    if provider_name in ["ollama", "mistral_local"]:
                        from threat_analysis.ai_engine.providers.ollama_provider import OllamaProvider  # noqa: PLC0415
                        self.ai_provider = OllamaProvider(provider_config)
                    else:
                        logging.info(f"Initializing LiteLLMProvider for '{provider_name}'")
                        from threat_analysis.ai_engine.providers.litellm_provider import LiteLLMProvider  # noqa: PLC0415
                        self.ai_provider = LiteLLMProvider(provider_config)
                    break
            
            if self.ai_provider:
                # ai_context is built lazily from threat_model.context_config when
                # _enrich_threats_with_ai() is called (context is not available at init time).
                pass
            else:
                logging.warning("No enabled AI provider found in config for report enrichment.")

            # Threat ranking / volume control
            tg = ai_config.get("threat_generation", {})
            self._ranking_max_total = int(tg.get("max_total_threats", 0))
            self._ranking_min_stride = bool(tg.get("min_stride_coverage", True))
            rw = tg.get("ranking_weights") or {}
            self._ranking_weights = {k: float(v) for k, v in rw.items() if isinstance(v, (int, float))}
            self._enrich_batch_size: int = int(tg.get("batch_size", 5))
            self._enrich_max_concurrent: int = int(tg.get("max_concurrent_ai_requests", 3))

    async def _run_ciso_triage(self, all_threats: List[Dict]) -> Dict:
        """Generates a CISO-level risk briefing via the AI provider.

        Returns an empty dict when AI is unavailable or the provider does not
        implement ``generate_ciso_triage``.  Never raises.
        """
        if not self.ai_provider:
            return {}
        # Use cached ai_online flag when available (avoids a second network round-trip).
        # Fall back to check_connection() for providers that don't expose _get_client.
        try:
            _client = await self.ai_provider._get_client()
            if not _client.ai_online:
                return {}
        except Exception:
            try:
                if not await self.ai_provider.check_connection():
                    return {}
            except Exception:
                pass  # proceed; generate_ciso_triage() will fail safely if offline

        from threat_analysis.ai_engine.prompt_loader import get as _get_prompt
        try:
            system_prompt = _get_prompt("ciso_triage", "system")
            template = _get_prompt("ciso_triage", "template")
        except KeyError as exc:
            logging.warning("CISO triage: prompt key missing (%s) — skipping.", exc)
            return {}

        # Build compact threat summary (top 20 by ranking score)
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        counts: Dict[str, int] = {}
        for t in all_threats:
            sev = str(t.get("severity") or "").upper()
            counts[sev] = counts.get(sev, 0) + 1

        stride_counts: Dict[str, int] = {}
        for t in all_threats:
            cat = t.get("stride_category", "Unknown")
            stride_counts[cat] = stride_counts.get(cat, 0) + 1

        top20 = sorted(
            all_threats,
            key=lambda x: (sev_order.get(str(x.get("severity") or "").upper(), 0),
                           x.get("_ranking_score", 0.0)),
            reverse=True,
        )[:20]

        threats_summary_lines = []
        for t in top20:
            tid = t.get("id", "?")
            sev = t.get("severity", "?")
            stride = t.get("stride_category", "?")
            target = t.get("target", "?")
            name = t.get("name") or t.get("description", "?")
            threats_summary_lines.append(f"- [{sev}] {tid} | {stride} | {target} | {name[:80]}")

        stride_breakdown = ", ".join(f"{cat}={cnt}" for cat, cnt in sorted(stride_counts.items()))
        prompt = (
            template
            .replace("<<total>>", str(len(all_threats)))
            .replace("<<n_critical>>", str(counts.get("CRITICAL", 0)))
            .replace("<<n_high>>", str(counts.get("HIGH", 0)))
            .replace("<<n_medium>>", str(counts.get("MEDIUM", 0)))
            .replace("<<n_low>>", str(counts.get("LOW", 0)))
            .replace("<<stride_breakdown>>", stride_breakdown)
            .replace("<<threats_summary>>", "\n".join(threats_summary_lines))
        )

        try:
            result = await self.ai_provider.generate_ciso_triage(prompt, system_prompt)
        except Exception as exc:
            logging.warning("CISO triage call failed: %s", exc)
            return {}

        if not isinstance(result, dict) or "posture_score" not in result:
            logging.debug("CISO triage: unexpected response — %s", type(result))
            return {}

        # Normalise types
        try:
            result["posture_score"] = round(float(result["posture_score"]), 1)
        except (TypeError, ValueError):
            result["posture_score"] = 0.0

        logging.info(
            "CISO triage: posture_score=%.1f label=%s",
            result["posture_score"],
            result.get("posture_label", "?"),
        )
        return result

    @staticmethod
    def _build_ai_context_from_model(threat_model: "ThreatModel") -> Dict[str, Any]:
        """Build AI context dict from DSL ## Context keys on the threat model.

        Priority: DSL context_config keys > context/*.yaml (loaded by AIService).
        The report_generator path only uses DSL keys (context/*.yaml is handled
        by AIService in server mode).
        """
        ctx_cfg = getattr(threat_model, "context_config", {})
        _AI_KEYS = {
            "system_description", "sector", "deployment_environment",
            "data_sensitivity", "internet_facing", "user_base",
            "compliance_requirements", "integrations",
        }
        ctx: Dict[str, Any] = {k: v for k, v in ctx_cfg.items() if k in _AI_KEYS}
        ctx.setdefault("system_description", getattr(getattr(threat_model, "tm", None), "description", "") or "")
        ctx.setdefault("data_sensitivity", "High")
        return ctx

    async def _enrich_threats_with_ai(self, threat_model: ThreatModel, all_threats: List[Dict], progress_callback = None) -> List[Dict]:
        if not self.ai_provider:
            logging.warning("AI enrichment skipped: No AI provider initialized.")
            return all_threats

        # Build context from DSL ## Context keys (replaces config/context.yaml)
        self.ai_context = self._build_ai_context_from_model(threat_model)
        if not self.ai_context.get("system_description") and not self.ai_context.get("sector"):
            logging.info("AI enrichment: no AI context keys in ## Context — threats will be generic.")


        logging.info(f"Enriching threats with AI using provider: {type(self.ai_provider).__name__}")

        # Use the cached ai_online flag from the underlying client — avoids a second
        # network round-trip (the client already ran check_connection() during create()).
        try:
            _client = await self.ai_provider._get_client()
            if not _client.ai_online:
                logging.warning(
                    "AI enrichment skipped: Provider %s is offline (cached state).",
                    type(self.ai_provider).__name__,
                )
                return all_threats
        except Exception:
            pass  # If we can't introspect the client, proceed and let generate_threats() fail naturally

        # Combine all components to enrich: servers, actors, and boundaries
        components_to_enrich = []
        for server in threat_model.servers:
            components_to_enrich.append({"name": server.get("name"), "type": "Server", "description": server.get("description", ""), "business_value": server.get("business_value")})
        for actor in threat_model.actors:
            components_to_enrich.append({"name": actor.get("name"), "type": "Actor", "description": actor.get("description", ""), "business_value": actor.get("business_value")})
        for b_name, b_info in threat_model.boundaries.items():
            components_to_enrich.append({"name": b_name, "type": "Boundary", "description": b_info.get("description", ""), "business_value": b_info.get("business_value")})

        total_components = len(components_to_enrich)
        if total_components == 0:
            return all_threats

        if progress_callback:
            progress_callback(f"Starting AI enrichment for {total_components} components...")

        ai_threats: List[Dict] = []
        processed_count = [0]
        semaphore = asyncio.Semaphore(self._enrich_max_concurrent)

        def _build_threat_dict(threat: Dict, component: Dict) -> Dict:
            """Convert a raw LLM threat dict into a normalized threat record."""
            stride_category = threat.get("category", "InformationDisclosure")
            target_name = component.get("name")
            severity_info = self.severity_calculator.get_severity_info(
                stride_category,
                target_name,
                impact=threat.get("business_impact", {}).get("impact_score") if isinstance(threat.get("business_impact"), dict) else None,
                likelihood=threat.get("business_impact", {}).get("likelihood_score") if isinstance(threat.get("business_impact"), dict) else None,
            )
            raw_capecs = [
                c for c in threat.get("capec_ids", [])
                if isinstance(c, str) and c.upper().startswith("CAPEC-")
            ]
            mapping = self.mitre_mapping.map_threat_to_mitre({
                "stride_category": stride_category,
                "capec_ids": raw_capecs,
                "description": threat.get("description", ""),
            })
            return {
                "type": stride_category,
                "description": threat.get("description"),
                "target": target_name,
                "severity": severity_info,
                "mitre_techniques": mapping.get("techniques", []),
                "stride_category": stride_category,
                "capecs": mapping.get("capecs", []),
                "cve": [],  # CVEs come exclusively from CVEService, never from LLM output
                "business_value": component.get("business_value"),
                "confidence": threat.get("confidence", 0.8),
                "source": "AI",
            }

        def _flush_batch_results(results: Dict[str, List[Dict]], batch: List[Dict]) -> None:
            """Distribute batch results into ai_threats and update progress."""
            comp_by_name = {c["name"]: c for c in batch}
            for comp_name, threats_json in results.items():
                component = comp_by_name.get(comp_name)
                if component is None:
                    continue
                for threat in threats_json or []:
                    if not isinstance(threat, dict):
                        continue
                    try:
                        ai_threats.append(_build_threat_dict(threat, component))
                    except Exception as exc:
                        logging.warning("Skipping malformed batch threat for %s: %s", comp_name, exc)
            # Update progress for all components in this batch
            processed_count[0] += len(batch)
            if progress_callback:
                names = ", ".join(c["name"] for c in batch)
                progress_callback(
                    f"AI Enrichment: {processed_count[0]}/{total_components} components processed ({names})"
                )

        async def process_batch(batch: List[Dict]) -> None:
            async with semaphore:
                try:
                    results = await self.ai_provider.generate_threats_batch(batch, self.ai_context)
                    _flush_batch_results(results, batch)
                except Exception as e:
                    logging.error("Batch AI enrichment failed (%s): %s — falling back to individual calls", [c["name"] for c in batch], e)
                    # Fall back: call generate_threats per component sequentially
                    for component in batch:
                        try:
                            threats_json = await self.ai_provider.generate_threats(component, self.ai_context)
                            _flush_batch_results({component["name"]: threats_json}, [component])
                        except Exception as exc:
                            logging.error("Error enriching component %s: %s", component.get("name"), exc)
                            processed_count[0] += 1

        async def process_component_individual(component: Dict) -> None:
            async with semaphore:
                try:
                    generated_threats = await self.ai_provider.generate_threats(component, self.ai_context)
                    processed_count[0] += 1
                    if progress_callback:
                        progress_callback(f"AI Enrichment: {processed_count[0]}/{total_components} components processed ({component.get('name')})")
                    for threat in generated_threats:
                        if not isinstance(threat, dict):
                            continue
                        try:
                            ai_threats.append(_build_threat_dict(threat, component))
                        except Exception as exc:
                            logging.warning("Skipping malformed threat for %s: %s", component.get("name"), exc)
                except Exception as e:
                    logging.error("Error enriching component %s: %s", component.get("name"), e)
                    processed_count[0] += 1

        use_batch = (
            self._enrich_batch_size > 1
            and hasattr(self.ai_provider, "generate_threats_batch")
        )
        if use_batch:
            batch_size = self._enrich_batch_size
            batches = [
                components_to_enrich[i: i + batch_size]
                for i in range(0, len(components_to_enrich), batch_size)
            ]
            logging.info(
                "AI report enrichment (batch): %d components → %d batch(es) of up to %d",
                total_components, len(batches), batch_size,
            )
            await asyncio.gather(*[process_batch(b) for b in batches])
        else:
            logging.info("AI report enrichment (individual): %d components", total_components)
            tasks = [process_component_individual(c) for c in components_to_enrich]
            await asyncio.gather(*tasks)

        # Simple deduplication: identify unique AI threats based on category and description
        existing_threats_signatures = set()
        for threat in all_threats:
            signature = (threat.get("stride_category"), threat.get("description"))
            existing_threats_signatures.add(signature)

        unique_ai_threats = []
        for ai_threat in ai_threats:
            signature = (ai_threat.get("stride_category"), ai_threat.get("description"))
            if signature not in existing_threats_signatures:
                unique_ai_threats.append(ai_threat)
                existing_threats_signatures.add(signature)
        
        return all_threats + unique_ai_threats

    def generate_html_report(self, threat_model, grouped_threats: Dict[str, List], 
                             output_file: Path = Path("stride_mitre_report.html"), 
                             all_detailed_threats: Optional[List[Dict]] = None,
                             report_title: str = "🛡️ STRIDE & MITRE ATT&CK Threat Model Report",
                             progress_callback = None) -> Path:
        """Generates a complete HTML report with MITRE ATT&CK"""
        # Temporarily set threat_model_ref for _get_all_threats_with_mitre_info
        original_threat_model_ref = self.threat_model_ref
        self.threat_model_ref = threat_model # Set the current threat_model

        try:
            total_threats_analyzed = threat_model.mitre_analysis_results.get('total_threats', 0)
            total_mitre_techniques_mapped = threat_model.mitre_analysis_results.get('mitre_techniques_count', 0)

            if all_detailed_threats is None:
                all_detailed_threats = self._get_all_threats_with_mitre_info(grouped_threats, threat_model)

            if self.ai_provider:
                 original_count = len(all_detailed_threats)
                 all_detailed_threats = asyncio.run(self._enrich_threats_with_ai(threat_model, all_detailed_threats, progress_callback=progress_callback))
                 ai_added = len(all_detailed_threats) - original_count
                 logging.info(f"AI enrichment complete. Added {ai_added} new threats.")

            # Recompute STRIDE distribution from the full threat list (pytm + AI + LLM)
            stride_distribution: Dict[str, int] = {}
            for t in all_detailed_threats:
                cat = t.get('stride_category', '')
                if cat in self._VALID_STRIDE:
                    stride_distribution[cat] = stride_distribution.get(cat, 0) + 1

            self.all_detailed_threats = all_detailed_threats
            # Cache the final enriched threat list on the model so generate_global_project_report
            # can include AI-enriched threats without re-running the enrichment pipeline.
            threat_model._report_all_detailed_threats = all_detailed_threats
            summary_stats = self.generate_summary_stats(all_detailed_threats)
            stride_categories = sorted(
                c for c in self._VALID_STRIDE
                if any(t['stride_category'] == c for t in all_detailed_threats)
            )
            
            unique_business_values = self._get_all_business_values(threat_model)
            
            EXCLUDE_TARGETS = ["Unspecified →", "Unspecified", "→"]
            unique_targets = sorted(list(set(threat['target'] for threat in all_detailed_threats if threat.get('target') and threat.get('target') not in EXCLUDE_TARGETS)))

            attack_chains = AttackChainAnalyzer().analyze(
                all_detailed_threats, threat_model.dataflows
            )

            completeness = _score_model_completeness(threat_model)
            threat_graph = self._build_threat_graph_data(threat_model, all_detailed_threats)
            attack_id_validation = AttackIdValidator().validate_all(all_detailed_threats)

            # CISO triage pass — runs after full ranked threat list is available
            ciso_triage = {}
            if self.ai_provider and all_detailed_threats:
                try:
                    ciso_triage = asyncio.run(self._run_ciso_triage(all_detailed_threats))
                except Exception as exc:
                    logging.warning("CISO triage failed: %s", exc)
            # Cache on the model so generate_json_export can include it without re-running.
            threat_model._ciso_triage = ciso_triage if ciso_triage else None
            threat_model._completeness = completeness
            threat_model._attack_id_validation = attack_id_validation

            # Build a serialised summary of GDAF scenarios for the HTML template.
            # Uses getattr for safety — works even if gdaf_scenarios was never populated.
            gdaf_data = []
            for scenario in getattr(threat_model, 'gdaf_scenarios', [])[:10]:
                hops_summary = []
                for hop in getattr(scenario, 'hops', []):
                    tech_ids = [
                        getattr(t, 'id', str(t))
                        for t in getattr(hop, 'techniques', [])[:3]
                    ]
                    tech_names = [
                        getattr(t, 'name', str(t))
                        for t in getattr(hop, 'techniques', [])[:3]
                    ]
                    hops_summary.append({
                        "node": getattr(hop, 'asset_name', str(hop)),
                        "asset_type": getattr(hop, 'asset_type', ''),
                        "protocol": getattr(hop, 'protocol', ''),
                        "is_encrypted": getattr(hop, 'is_encrypted', False),
                        "is_authenticated": getattr(hop, 'is_authenticated', False),
                        "hop_score": getattr(hop, 'hop_score', 0.0),
                        "hop_position": getattr(hop, 'hop_position', ''),
                        "techniques": [
                            f"{tid} — {tname}"
                            for tid, tname in zip(tech_ids, tech_names)
                        ],
                    })
                gdaf_data.append({
                    "scenario_id": getattr(scenario, 'scenario_id', ''),
                    "objective": getattr(scenario, 'objective_name', 'Unknown'),
                    "objective_description": getattr(scenario, 'objective_description', ''),
                    "business_impact": getattr(scenario, 'objective_business_impact', ''),
                    "actor": getattr(scenario, 'actor_name', ''),
                    "actor_sophistication": getattr(scenario, 'actor_sophistication', ''),
                    "entry_point": getattr(scenario, 'entry_point', ''),
                    "target_asset": getattr(scenario, 'target_asset', ''),
                    "path": " → ".join(h["node"] for h in hops_summary),
                    "score": round(float(getattr(scenario, 'path_score', 0)), 2),
                    "risk_level": getattr(scenario, 'risk_level', 'LOW'),
                    "hop_count": len(hops_summary),
                    "hops": hops_summary,
                    "detection_coverage": round(float(getattr(scenario, 'detection_coverage', 0.0)), 2),
                    "unacceptable_risk": bool(getattr(scenario, 'unacceptable_risk', False)),
                })

            template = self.env.get_template('report_template.html')
            html = template.render(
                title="STRIDE & MITRE ATT&CK Report",
                report_title=report_title,
                total_threats_analyzed=total_threats_analyzed,
                total_mitre_techniques_mapped=total_mitre_techniques_mapped,
                stride_distribution=stride_distribution,
                summary_stats=summary_stats,
                all_threats=all_detailed_threats,
                stride_categories=stride_categories,
                unique_business_values=unique_business_values,
                unique_targets=unique_targets,
                severity_calculation_note=self.severity_calculator.get_calculation_explanation(),
                implemented_mitigation_ids=self.implemented_mitigations,
                attack_chains=attack_chains,
                gdaf_scenarios=gdaf_data,
                ciso_triage=ciso_triage,
                completeness=completeness,
                attack_id_validation=attack_id_validation,
                threat_graph=threat_graph,
            )

            with open(output_file, "w", encoding="utf-8") as f:
                f.write(html)

        finally:
            self.threat_model_ref = original_threat_model_ref # Reset
        
        return output_file

    def generate_json_export(self, threat_model, grouped_threats: Dict[str, List],
                             output_file: Path = Path("mitre_analysis.json")) -> Path:
        """Generates a versioned JSON export (schema_version 1.0) of the analysis data."""
        original_threat_model_ref = self.threat_model_ref
        self.threat_model_ref = threat_model

        try:
            all_detailed_threats = self._get_all_threats_with_mitre_info(grouped_threats, threat_model)
            export_data = ReportSerializer.serialize(threat_model, all_detailed_threats)

            # Include cached CISO triage if available (set by generate_html_report)
            cached_triage = getattr(threat_model, "_ciso_triage", None)
            if isinstance(cached_triage, dict) and cached_triage:
                export_data["ciso_triage"] = cached_triage

            # Include model completeness (compute fresh if not cached)
            # Include ATT&CK ID validation if cached
            from threat_analysis.core.attack_id_validator import ValidationReport as _VR
            cached_validation = getattr(threat_model, "_attack_id_validation", None)
            if not isinstance(cached_validation, _VR):
                cached_validation = AttackIdValidator().validate_all(all_detailed_threats)
            if cached_validation.has_issues:
                export_data["attack_id_validation"] = {
                    "total_checked": cached_validation.total_techniques_checked,
                    "n_invalid": cached_validation.n_invalid,
                    "n_revoked": cached_validation.n_revoked,
                    "n_deprecated": cached_validation.n_deprecated,
                    "issues": [
                        {
                            "technique_id": i.technique_id,
                            "issue_type": i.issue_type,
                            "threat_id": i.threat_id,
                            "threat_name": i.threat_name,
                        }
                        for i in cached_validation.all_issues
                    ],
                }

            from threat_analysis.core.model_completeness import CompletenessReport as _CR
            cached_completeness = getattr(threat_model, "_completeness", None)
            if not isinstance(cached_completeness, _CR):
                cached_completeness = _score_model_completeness(threat_model)
            export_data["model_completeness"] = {
                "score": cached_completeness.score,
                "grade": cached_completeness.grade,
                "checks": [
                    {
                        "id": c.id,
                        "label": c.label,
                        "weight": c.weight,
                        "passed": c.passed,
                        "total": c.total,
                        "score_pct": c.pct,
                        "hint": c.hint,
                    }
                    for c in cached_completeness.checks
                ],
            }

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
        finally:
            self.threat_model_ref = original_threat_model_ref

        return output_file

    def _get_boundary_str_for_target(self, target_name: str, threat_model) -> str:
        """Returns '<BoundaryName> (TRUSTED|UNTRUSTED)' for a target component, or '' if unknown."""
        for collection in (threat_model.servers, threat_model.actors):
            for entry in collection:
                if entry.get('name') == target_name:
                    obj = entry.get('object')
                    b = getattr(obj, 'inBoundary', None)
                    if b:
                        trusted = getattr(b, 'isTrusted', False)
                        return f"{b.name} ({'TRUSTED' if trusted else 'UNTRUSTED'})"
                    return ""
        return ""

    def generate_remediation_checklist(
        self,
        threat_model,
        grouped_threats: Dict[str, List],
        output_file: Path,
    ) -> Path:
        """Generates a CSV remediation checklist from all threats.

        Columns: ID | Component | Trust Boundary | STRIDE Category | Severity | Score |
                 Source | Description | MITRE Techniques | CAPEC IDs | CVE IDs |
                 D3FEND Mitigations | Confidence | Status
        """
        output_file = Path(output_file)
        original_ref = self.threat_model_ref
        self.threat_model_ref = threat_model
        try:
            all_threats = self._get_all_threats_with_mitre_info(grouped_threats, threat_model)
        finally:
            self.threat_model_ref = original_ref

        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ID", "Component", "Trust Boundary", "STRIDE Category",
                "Severity", "Score", "Source", "Description",
                "MITRE Techniques", "CAPEC IDs", "CVE IDs", "D3FEND Mitigations",
                "Confidence", "Status",
            ])
            for i, t in enumerate(all_threats, start=1):
                target = t.get("target", "")
                mitre = "; ".join(
                    f"{tech.get('id', '')} {tech.get('name', '')}".strip()
                    for tech in t.get("mitre_techniques", [])
                )
                capecs = "; ".join(c.get("capec_id", "") for c in t.get("capecs", []))
                cves = "; ".join(t.get("cve", []))
                defend = "; ".join(
                    m.get("id", "")
                    for tech in t.get("mitre_techniques", [])
                    for m in tech.get("defend_mitigations", [])
                )
                severity = t.get("severity", {})
                writer.writerow([
                    f"T-{i:04d}",
                    target,
                    self._get_boundary_str_for_target(target, threat_model),
                    t.get("stride_category", ""),
                    severity.get("level", ""),
                    severity.get("score", ""),
                    t.get("source", ""),
                    t.get("description", ""),
                    mitre,
                    capecs,
                    cves,
                    defend,
                    f"{t.get('confidence', 1.0):.2f}",
                    "TODO",
                ])
        logging.info(f"Remediation checklist: {output_file} ({len(all_threats)} threats)")
        return output_file

    def generate_stix_export(self, threat_model, grouped_threats: Dict[str, List],
                             output_dir: Path = Path("output/STIX_Export")) -> Path:
        """Generates a STIX export of the analysis data"""
        output_dir.mkdir(parents=True, exist_ok=True)

        all_detailed_threats = self._get_all_threats_with_mitre_info(grouped_threats, threat_model)

        stix_generator = StixGenerator(threat_model, all_detailed_threats)
        stix_bundle = stix_generator.generate_stix_bundle()

        output_file = output_dir / f"{threat_model.tm.name}_stix_attack_flow.json"

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(stix_bundle, f, indent=4)

        logging.info(f"STIX report generated at {output_file}")

        return output_file

    def open_report_in_browser(self, html_file: Path) -> bool:
        """Opens the report in the browser"""
        try:
            webbrowser.open(str(html_file.resolve().as_uri()))
            return True
        except Exception as e:
            return False
    def _export_detailed_threats(self, grouped_threats: Dict[str, List], threat_model: ThreatModel) -> List[Dict[str, Any]]:
        return self._get_all_threats_with_mitre_info(grouped_threats, threat_model)

    def _get_all_threats_with_mitre_info(self, grouped_threats: Dict[str, List], threat_model: ThreatModel) -> List[Dict[str, Any]]:
        """Gathers detailed information for all threats, including MITRE ATT&CK mapping and severity."""
        pytm_threat_dicts = []

        # Load VEX and BOM once — VEX takes priority for CVE scoring, BOM is fallback
        _vex_loader = _get_vex_loader(threat_model)
        _bom_loader = _get_bom_loader(threat_model)
        if _vex_loader:
            logging.info("CVE scoring: standalone VEX file(s) found — used as primary CVE source")
        elif _bom_loader:
            logging.info("CVE scoring: no standalone VEX — using BOM CVE data (with state if available)")
        _warn_bom_mismatches(_bom_loader, threat_model)

        # Process threats from grouped_threats (PyTM and custom threats)
        for threat_type, threats in grouped_threats.items():
            for item in threats:
                if isinstance(item, tuple) and len(item) == 2:
                    threat, target = item
                    target_name = self._get_target_name_for_severity_calc(target)
                    threat_description = getattr(threat, 'description', f"Threat of type {threat_type} affecting {target_name}")
                    # pytm Finding objects have no stride_category — use the group key (already validated)
                    stride_category = getattr(threat, 'stride_category', None) or threat_type
                    threat_source = getattr(threat, 'source', 'pytm')
                else:
                    continue

                data_classification = None
                if hasattr(threat, 'target') and hasattr(threat.target, 'data') and hasattr(threat.target.data, 'classification'):
                    data_classification = threat.target.data.classification.name

                threat_impact = getattr(threat, 'impact', None)
                threat_likelihood = getattr(threat, 'likelihood', None)

                # Get business_value of the target
                business_value = None
                if hasattr(target, 'name'):
                    for actor_data in threat_model.actors:
                        if actor_data.get('object') == target:
                            business_value = actor_data.get('business_value')
                            break
                    if not business_value:
                        for server_data in threat_model.servers:
                            if server_data.get('object') == target:
                                business_value = server_data.get('business_value')
                                break
                    if not business_value:
                        for boundary_data in threat_model.boundaries.values():
                            if boundary_data.get('boundary') == target:
                                business_value = boundary_data.get('business_value')
                                break

                # --- MITRE mapping (done before severity so D3FEND is available) ---
                threat_dict = {
                    "description": threat_description,
                    "stride_category": stride_category,
                    "capec_ids": getattr(threat, 'capec_ids', []),
                    "source": threat_source,
                }
                mapping_results = self.mitre_mapping.map_threat_to_mitre(threat_dict)
                mitre_techniques = mapping_results.get('techniques', [])
                capecs = mapping_results.get('capecs', [])

                # --- CVE lookup (done before severity to feed RiskContext) ---
                cve_ids_for_threat = set()
                cwe_ids_for_threat: List[str] = []

                target_names_to_check = []
                if isinstance(target, tuple) and len(target) == 2:
                    source_obj = target[0]
                    sink_obj = target[1]
                    source_name = extract_name_from_object(source_obj)
                    sink_name = extract_name_from_object(sink_obj)
                    if source_name != "Unspecified":
                        target_names_to_check.append(source_name)
                    if sink_name != "Unspecified":
                        target_names_to_check.append(sink_name)
                else:
                    target_names_to_check.append(target_name)

                threat_capecs = {capec['capec_id'] for capec in capecs}
                for name_to_check in target_names_to_check:
                    equipment_cves = _resolve_active_cves(
                        name_to_check, _vex_loader, _bom_loader, self.cve_service
                    )
                    for cve_id in equipment_cves:
                        cve_capecs = self.cve_service.get_capecs_for_cve(cve_id.upper())
                        if threat_capecs.intersection(cve_capecs):
                            cve_ids_for_threat.add(cve_id)
                            cwe_ids_for_threat.extend(
                                self.cve_service.get_cwes_for_cve(cve_id.upper())
                            )

                # --- Network exposure signal ---
                network_exposed = _is_network_exposed(target)

                # --- D3FEND coverage signal (+ fixed CVEs from VEX/BOM as mitigation) ---
                has_d3fend = any(
                    tech.get('defend_mitigations')
                    for tech in mitre_techniques
                )
                if not has_d3fend:
                    has_d3fend = any(
                        _resolve_has_fixed_cves(n, _vex_loader, _bom_loader)
                        for n in target_names_to_check
                    )

                # --- Build unified RiskContext and score ---
                risk_ctx = RiskContext(
                    has_cve_match=bool(cve_ids_for_threat),
                    cwe_ids=list(set(cwe_ids_for_threat)),
                    network_exposed=network_exposed,
                    has_d3fend_mitigations=has_d3fend,
                )
                severity_info = self.severity_calculator.get_severity_info(
                    stride_category, target_name,
                    classification=data_classification,
                    impact=threat_impact,
                    likelihood=threat_likelihood,
                    risk_context=risk_ctx,
                )

                pytm_threat_dicts.append({
                    "type": threat_type,
                    "description": threat_description,
                    "target": target_name,
                    "severity": severity_info,
                    "mitre_techniques": mitre_techniques,
                    "stride_category": stride_category,
                    "capecs": capecs,
                    "cve": sorted(list(cve_ids_for_threat)),
                    "business_value": business_value,
                    "confidence": getattr(threat, 'confidence', 1.0),
                    "source": threat_source,
                    "risk_signals": {
                        "cve_match": risk_ctx.has_cve_match,
                        "cwe_high_risk": risk_ctx.cwe_high_risk,
                        "network_exposed": risk_ctx.network_exposed,
                        "d3fend_mitigations": risk_ctx.has_d3fend_mitigations,
                    },
                })

        # Collect component-level AI threats (added by AIService._enrich_with_ai_threats)
        ai_element_threat_dicts = []
        enriched_elements = (
            [(d.get('object'), d.get('name', ''), d.get('business_value')) for d in threat_model.actors] +
            [(d.get('object'), d.get('name', ''), d.get('business_value')) for d in threat_model.servers]
        )
        # Dataflows are stored as pytm objects directly (not dicts)
        for df in threat_model.dataflows:
            enriched_elements.append((df, getattr(df, 'name', ''), None))

        for element_obj, element_name, business_value in enriched_elements:
            if element_obj is None:
                continue
            for et in getattr(element_obj, 'threats', []):
                if getattr(et, 'source', 'pytm') != 'AI':
                    continue
                stride_category = getattr(et, 'stride_category', getattr(et, 'category', 'Unknown'))
                target_name = element_name or getattr(element_obj, 'name', 'Unknown')
                threat_description = getattr(et, 'description', f"AI threat on {target_name}")

                threat_dict_for_mapping = {
                    "description": threat_description,
                    "stride_category": stride_category,
                    "capec_ids": getattr(et, 'capec_ids', []),
                    "source": "AI",
                }
                mapping_results = self.mitre_mapping.map_threat_to_mitre(threat_dict_for_mapping)
                ai_mitre_techniques = mapping_results.get('techniques', [])
                ai_capecs = mapping_results.get('capecs', [])

                # CVE lookup for AI-element threats
                ai_cve_ids: set = set()
                ai_cwe_ids: List[str] = []
                ai_threat_capecs = {c['capec_id'] for c in ai_capecs}
                _ai_equipment_cves = _resolve_active_cves(
                    target_name, _vex_loader, _bom_loader, self.cve_service
                )
                for cve_id in _ai_equipment_cves:
                    if ai_threat_capecs.intersection(
                        self.cve_service.get_capecs_for_cve(cve_id.upper())
                    ):
                        ai_cve_ids.add(cve_id)
                        ai_cwe_ids.extend(self.cve_service.get_cwes_for_cve(cve_id.upper()))

                _ai_has_d3fend = any(
                    t.get('defend_mitigations') for t in ai_mitre_techniques
                )
                if not _ai_has_d3fend:
                    _ai_has_d3fend = _resolve_has_fixed_cves(target_name, _vex_loader, _bom_loader)
                ai_risk_ctx = RiskContext(
                    has_cve_match=bool(ai_cve_ids),
                    cwe_ids=list(set(ai_cwe_ids)),
                    network_exposed=_is_network_exposed(element_obj),
                    has_d3fend_mitigations=_ai_has_d3fend,
                )
                severity_info = self.severity_calculator.get_severity_info(
                    stride_category, target_name,
                    impact=getattr(et, 'impact', None),
                    likelihood=getattr(et, 'likelihood', None),
                    risk_context=ai_risk_ctx,
                )
                ai_element_threat_dicts.append({
                    "type": stride_category,
                    "description": threat_description,
                    "target": target_name,
                    "severity": severity_info,
                    "mitre_techniques": ai_mitre_techniques,
                    "stride_category": stride_category,
                    "capecs": ai_capecs,
                    "cve": sorted(ai_cve_ids),
                    "business_value": business_value,
                    "confidence": getattr(et, 'confidence', 0.9),
                    "source": "AI",
                    "risk_signals": {
                        "cve_match": ai_risk_ctx.has_cve_match,
                        "cwe_high_risk": ai_risk_ctx.cwe_high_risk,
                        "network_exposed": ai_risk_ctx.network_exposed,
                        "d3fend_mitigations": ai_risk_ctx.has_d3fend_mitigations,
                    },
                    "soc_analysis": (getattr(et, "ai_details", {}) or {}).get("soc_analysis"),
                })

        # Merge: AI wins on semantic duplicates within same (target, stride_category)
        all_detailed_threats = ThreatConsolidator.deduplicate(pytm_threat_dicts, ai_element_threat_dicts)

        # Process global RAG threats
        if hasattr(threat_model.tm, 'global_threats_llm'): # Access via threat_model
            for threat in threat_model.tm.global_threats_llm:
                target_name = "Threat Model (Global)" # RAG threats are system-level
                threat_description = getattr(threat, 'description', 'RAG-generated global threat')
                stride_category = getattr(threat, 'category', 'Generic RAG Threat')
                threat_source = getattr(threat, 'source', 'LLM')

                severity_info = self.severity_calculator.get_severity_info(
                    stride_category,
                    target_name,
                    impact=getattr(threat, 'impact', None),
                    likelihood=getattr(threat, 'likelihood', None)
                )

                threat_dict = {
                    "description": threat_description,
                    "stride_category": stride_category,
                    "capec_ids": getattr(threat, 'capec_ids', []),
                    "source": threat_source
                }
                mapping_results = self.mitre_mapping.map_threat_to_mitre(threat_dict)
                mitre_techniques = mapping_results.get('techniques', [])
                capecs = mapping_results.get('capecs', [])

                all_detailed_threats.append({
                    "type": threat_source, # Use threat_source as type for consistent filtering in UI
                    "description": threat_description,
                    "target": target_name,
                    "severity": severity_info,
                    "mitre_techniques": mitre_techniques,
                    "stride_category": stride_category,
                    "capecs": capecs,
                    "cve": [], # RAG threats don't have CVEs by default
                    "confidence": getattr(threat, 'confidence', 0.75),
                    "source": threat_source
                })
        
        # Rank by composite score and trim to configured maximum
        all_detailed_threats = rank_and_trim(
            all_detailed_threats,
            max_total=self._ranking_max_total,
            min_stride_coverage=self._ranking_min_stride,
            weights=self._ranking_weights if self._ranking_weights else None,
        )

        # Stamp each threat with a stable key and apply analyst decisions
        model_file_path = getattr(threat_model, "_model_file_path", None)
        risk_loader = AcceptedRiskLoader.from_model_path(model_file_path)
        for t in all_detailed_threats:
            t["threat_key"] = compute_threat_key(t)
            decision = risk_loader.get_decision(t)
            t["accepted_risk"] = decision  # None or {"decision": ..., "rationale": ..., ...}

        return all_detailed_threats

    def _get_target_name_for_severity_calc(self, target: Any) -> str:
        """Determines the target name for severity calculation, handling different target types."""
        return get_target_name(target)

    _VALID_STRIDE: frozenset = frozenset({
        'Spoofing', 'Tampering', 'Repudiation',
        'Information Disclosure', 'Denial of Service', 'Elevation of Privilege',
    })

    def generate_summary_stats(self, all_detailed_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generates summary statistics based on severity scores.

        Only counts threats that belong to one of the 6 canonical STRIDE categories
        and have a non-Unknown severity level.
        """
        if not all_detailed_threats: return {}
        known_threats = [
            t for t in all_detailed_threats
            if t.get('stride_category') in self._VALID_STRIDE
            and t.get('severity', {}).get('level', 'UNKNOWN').upper() != 'UNKNOWN'
        ]
        all_scores = [t['severity']['score'] for t in known_threats if 'severity' in t and 'score' in t['severity']]
        if not all_scores: return {}
        severity_distribution: Dict[str, int] = {}
        for threat in known_threats:
            level = threat.get('severity', {}).get('level', 'UNKNOWN')
            severity_distribution[level] = severity_distribution.get(level, 0) + 1
        return {
            "total_threats": len(all_scores),
            "average_severity": sum(all_scores) / len(all_scores),
            "max_severity": max(all_scores),
            "min_severity": min(all_scores),
            "severity_distribution": severity_distribution
        }

    def _extract_graph_metadata_for_frontend(self, threat_model: ThreatModel) -> dict:
        """
        Extracts a simplified graph structure (nodes and edges with their connections)
        suitable for frontend visualization and interaction.
        """
        graph_metadata = {
            "nodes": {},
            "edges": {}
        }
        
        def _sanitize_name_for_id(name: str) -> str:
            if not name:
                return "unnamed"
            sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', str(name))
            if sanitized and sanitized[0].isdigit():
                sanitized = f"_{sanitized}"
            return sanitized or "unnamed"

        # Process nodes (Actors, Servers, Boundaries)
        for name, info in threat_model.boundaries.items():
            sanitized_name = _sanitize_name_for_id(name)
            cluster_id = f"cluster_{sanitized_name}" # The actual ID of the cluster group in SVG
            graph_metadata["nodes"][cluster_id] = {
                "id": cluster_id,
                "type": "boundary",
                "label": name,
                "connections": [] # Will be populated by edges
            }
            # Also add the hidden node for boundary connections. This is what edges connect to.
            hidden_node_name = f"__hidden_node_{sanitized_name}"
            graph_metadata["nodes"][hidden_node_name] = {
                "id": hidden_node_name,
                "type": "hidden_boundary_node", # Mark as hidden for UI purposes
                "label": f"Hidden node for {name}",
                "connections": []
            }
        
        for actor_info in threat_model.actors:
            name = actor_info['name']
            sanitized_name = _sanitize_name_for_id(name)
            graph_metadata["nodes"][sanitized_name] = {
                "id": sanitized_name,
                "type": "actor",
                "label": name,
                "connections": []
            }

        for server_info in threat_model.servers:
            name = server_info['name']
            sanitized_name = _sanitize_name_for_id(name)
            graph_metadata["nodes"][sanitized_name] = {
                "id": sanitized_name,
                "type": "server",
                "label": name,
                "connections": []
            }
        
        # Process dataflows (edges)
        for df in threat_model.dataflows:
            source_name = getattr(df.source, 'name', None)
            sink_name = getattr(df.sink, 'name', None)
            protocol = getattr(df, 'protocol', None)
            
            if not source_name or not sink_name:
                logging.warning(f"Skipping dataflow with missing source or sink: {df}")
                continue
            
            sanitized_source = _sanitize_name_for_id(source_name)
            sanitized_sink = _sanitize_name_for_id(sink_name)

            is_source_boundary = False
            for b_name, info in threat_model.boundaries.items():
                if b_name == source_name:
                    sanitized_source = f"__hidden_node_{_sanitize_name_for_id(b_name)}"
                    is_source_boundary = True
                    break

            is_sink_boundary = False
            for b_name, info in threat_model.boundaries.items():
                if b_name == sink_name:
                    sanitized_sink = f"__hidden_node_{_sanitize_name_for_id(b_name)}"
                    is_sink_boundary = True
                    break
            
            actual_src_id = _sanitize_name_for_id(source_name)
            actual_dst_id = _sanitize_name_for_id(sink_name)
            edge_id = f"edge_{actual_src_id}_{actual_dst_id}"
            
            graph_metadata["edges"][edge_id] = {
                "id": edge_id,
                "source": sanitized_source,
                "target": sanitized_sink,
                "protocol": protocol,
                "label": df.name if hasattr(df, 'name') else f"{source_name} to {sink_name}"
            }
            
            if sanitized_source in graph_metadata["nodes"]:
                graph_metadata["nodes"][sanitized_source]["connections"].append(edge_id)
            if sanitized_sink in graph_metadata["nodes"]:
                graph_metadata["nodes"][sanitized_sink]["connections"].append(edge_id)

            if is_source_boundary:
                actual_boundary_id = _sanitize_name_for_id(source_name)
                if actual_boundary_id in graph_metadata["nodes"]:
                    graph_metadata["nodes"][actual_boundary_id]["connections"].append(edge_id)
            if is_sink_boundary:
                actual_boundary_id = _sanitize_name_for_id(sink_name)
                if actual_boundary_id in graph_metadata["nodes"]:
                    graph_metadata["nodes"][actual_boundary_id]["connections"].append(edge_id)
        
        return graph_metadata

    # -----------------------------------------------------------------
    # Threat graph data for interactive visualization
    # -----------------------------------------------------------------

    _SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

    def _build_threat_graph_data(
        self,
        threat_model: "ThreatModel",
        all_threats: List[Dict],
    ) -> Dict:
        """Build a JSON-serialisable graph for the interactive threat visualization.

        Nodes  = actors + servers (boundaries shown as containers, not nodes).
        Edges  = dataflows between components.
        The ``threats_by_node`` dict maps node ids to a compact threat list
        so the template JS can render a click panel without extra requests.

        Returns a dict with keys ``nodes``, ``edges``, ``threats_by_node``.
        An empty dict is returned when the model has no components.
        """
        # --- build per-component threat index ---------------------------------
        threats_by_node: Dict[str, List[Dict]] = {}
        for t in all_threats:
            target = t.get("target") or ""
            if not target or target in ("Unspecified →", "Unspecified", "→"):
                continue
            sev_raw = t.get("severity", {})
            sev_level = (
                sev_raw.get("level") if isinstance(sev_raw, dict) else str(sev_raw)
            ) or "LOW"
            threats_by_node.setdefault(target, []).append({
                "id":     t.get("id", ""),
                "name":   (t.get("name") or t.get("description", ""))[:80],
                "sev":    sev_level.upper(),
                "stride": t.get("stride_category", ""),
                "source": t.get("source", ""),
            })

        # --- nodes ------------------------------------------------------------
        _highest_sev: Dict[str, str] = {}
        for node_name, node_threats in threats_by_node.items():
            best = max(node_threats, key=lambda x: self._SEV_ORDER.get(x["sev"], 0))
            _highest_sev[node_name] = best["sev"]

        nodes: List[Dict] = []
        seen_node_ids: set = set()

        def _add_node(name: str, ntype: str, boundary: str = "") -> None:
            if not name or name in seen_node_ids:
                return
            seen_node_ids.add(name)
            nodes.append({
                "id":       name,
                "type":     ntype,
                "boundary": boundary,
                "severity": _highest_sev.get(name, ""),
                "n_threats": len(threats_by_node.get(name, [])),
            })

        def _extract_name(item) -> str:
            """Extract name from a model dict (actors/servers list entry)."""
            if isinstance(item, dict):
                name = item.get("name")
                if name:
                    return str(name)
                obj = item.get("object")
                return str(getattr(obj, "name", "") or "")
            return str(getattr(item, "name", "") or "")

        def _extract_boundary(item) -> str:
            bname = item.get("boundary") if isinstance(item, dict) else getattr(item, "inBoundary", "")
            if bname is None:
                return ""
            if hasattr(bname, "name"):
                return str(bname.name)
            return str(bname)

        for a in threat_model.actors:
            _add_node(_extract_name(a), "Actor", _extract_boundary(a))

        for s in threat_model.servers:
            _add_node(_extract_name(s), "Server", _extract_boundary(s))

        # Fallback: if actors/servers lists are empty or yielded no names,
        # reconstruct nodes from the threat targets so the graph is never blank
        # when threats exist (e.g. servers-only model with no actors declared).
        if not nodes and threats_by_node:
            for target_name in threats_by_node:
                _add_node(target_name, "Server", "")

        if not nodes:
            return {}

        # --- edges (dataflows) -----------------------------------------------
        edges: List[Dict] = []
        for df in threat_model.dataflows:
            src_name = getattr(getattr(df, "source", None), "name", "") or ""
            dst_name = getattr(getattr(df, "sink", None), "name", "") or ""
            if not src_name or not dst_name:
                continue
            edges.append({
                "source":        src_name,
                "target":        dst_name,
                "protocol":      (getattr(df, "protocol", "") or "").strip(),
                "encrypted":     bool(getattr(df, "is_encrypted", False)),
                "authenticated": bool(getattr(df, "is_authenticated", False)),
                "label":         getattr(df, "name", "") or "",
            })

        # Compact threats_by_node (cap at 20 per node to keep JSON small)
        compact_threats = {
            k: sorted(v, key=lambda x: self._SEV_ORDER.get(x["sev"], 0), reverse=True)[:20]
            for k, v in threats_by_node.items()
        }

        return {
            "nodes": nodes,
            "edges": edges,
            "threats_by_node": compact_threats,
        }

    def _get_all_business_values(self, threat_model: ThreatModel) -> List[str]:
        """Collects all unique business values from boundaries, actors, and servers."""
        business_values = set()
        for boundary_data in threat_model.boundaries.values():
            if boundary_data.get('business_value'):
                business_values.add(str(boundary_data['business_value']))
        for actor_data in threat_model.actors:
            if actor_data.get('business_value'):
                business_values.add(str(actor_data['business_value']))
        for server_data in threat_model.servers:
            if server_data.get('business_value'):
                business_values.add(str(server_data['business_value']))
        return sorted(list(business_values))

    def generate_global_project_report(self, all_models: List[ThreatModel], output_dir: Path):
        """Generates a single global report for all models in the project."""
        all_threats_details = []
        total_threats_analyzed = 0
        all_stride_distribution = defaultdict(int)

        for model in all_models:
            if hasattr(model, '_report_all_detailed_threats') and model._report_all_detailed_threats:
                # Use the already-enriched threat list (includes AI/LLM threats) cached by generate_html_report
                threats_details = model._report_all_detailed_threats
            else:
                grouped_threats = model.grouped_threats
                threats_details = self._get_all_threats_with_mitre_info(grouped_threats, model)
            all_threats_details.extend(threats_details)

            total_threats_analyzed += model.mitre_analysis_results.get('total_threats', 0)
            for k, v in model.mitre_analysis_results.get('stride_distribution', {}).items():
                all_stride_distribution[k] += v

        summary_stats = self.generate_summary_stats(all_threats_details)
        total_mitre_techniques_mapped = len(set(tech['id'] for threat in all_threats_details for tech in threat.get('mitre_techniques', [])))

        dummy_model = ThreatModel("Global Project", cve_service=self.cve_service)
        dummy_model.mitre_analysis_results = {
            'total_threats': total_threats_analyzed,
            'mitre_techniques_count': total_mitre_techniques_mapped,
            'stride_distribution': all_stride_distribution
        }
        # Aggregate dataflows from all sub-models so AttackChainAnalyzer can find chains
        for model in all_models:
            dummy_model.dataflows.extend(model.dataflows)

        self.generate_html_report(
            threat_model=dummy_model,
            grouped_threats={},
            output_file=output_dir / "global_threat_report.html",
            all_detailed_threats=all_threats_details,
            report_title="🛡️ Global Project Threat Model Report"
        )
        logging.info(f"✅ Generated global project report with {len(all_threats_details)} total threats at {output_dir / 'global_threat_report.html'}")

    def generate_project_reports(self, project_path: Path, output_dir: Path, progress_callback = None, ai_service=None) -> Optional[ThreatModel]:
        """
        Generates all reports for a project, ensuring a consistent legend across all diagrams.
        Returns the main threat model of the project.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        static_src_dir = Path(__file__).parent.parent / 'server' / 'static'
        static_dest_dir = output_dir / 'static'
        if static_src_dir.exists():
            if static_dest_dir.exists():
                shutil.rmtree(static_dest_dir)
            try:
                shutil.copytree(static_src_dir, static_dest_dir)
                logging.info(f"Copied static files to {static_dest_dir}")
            except Exception as e:
                logging.error(f"Failed to copy static files: {e}")

        # Only count models reachable from main.md via submodel= links — not every
        # .md file in the directory, which could include unrelated templates.
        if not (project_path / "main.md").exists() and not (project_path / "model.md").exists():
            logging.error("No main.md or model.md found in the project. Aborting.")
            return None
        # Pass 1: Gather project-wide metadata (only from models reachable via submodel= links)
        if progress_callback: progress_callback(10, "Gathering project-wide metadata...")
        all_models = self._get_all_project_models(project_path)
        total_models = max(len(all_models), 1)
        project_protocols, project_protocol_styles = self._aggregate_project_data(all_models)

        # Resolve root model file: main.md (multi-model project) or model.md (single model with data)
        main_model_path = project_path / "main.md"
        if not main_model_path.exists():
            fallback = project_path / "model.md"
            if fallback.exists():
                main_model_path = fallback
                logging.info("generate_project_reports: using model.md (single-model directory)")
        main_threat_model = None
        try:
            with open(main_model_path, "r", encoding="utf-8") as f:
                markdown_content = f.read()
            main_threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name=main_model_path.stem,
                model_description=f"Threat model for {main_model_path.stem}",
                cve_service=self.cve_service,
                validate=True,
                model_file_path=str(main_model_path),
            )
        except Exception as e:
            logging.error(f"Failed to create main threat model for project: {e}")

        if main_threat_model is None:
            logging.error("Main threat model could not be created. Aborting project report generation.")
            return None

        all_processed_models = []
        if progress_callback: progress_callback(20, f"Processing {total_models} models...")
        
        # Internal helper to track progress across recursion.
        # Each model has _SUB_STEPS granular steps; fractional progress is emitted between models.
        _SUB_STEPS = 6
        processed_count = [0]    # full models completed
        sub_step_count = [0]     # sub-steps within current model
        def tracked_progress_callback(message, is_new_model=False):
            if is_new_model:
                processed_count[0] += 1
                sub_step_count[0] = 0
            else:
                sub_step_count[0] = min(sub_step_count[0] + 1, _SUB_STEPS)
            effective = (processed_count[0] - 1) + sub_step_count[0] / _SUB_STEPS
            percent = 20 + int((min(max(effective, 0), total_models) / total_models) * 70)
            if progress_callback: progress_callback(percent, message)

        self._recursively_generate_reports(
            model_path=main_model_path,
            project_path=project_path,
            output_dir=output_dir,
            breadcrumb=[(main_threat_model.tm.name, f"{main_model_path.stem}_diagram.html")],
            project_protocols=project_protocols,
            project_protocol_styles=project_protocol_styles,
            all_project_models=all_processed_models,
            threat_model=main_threat_model,
            progress_callback=tracked_progress_callback
        )

        if all_processed_models:
            # A2: populate sub_models so RAG gets cross-model context
            for tm in all_processed_models:
                if tm is not main_threat_model:
                    main_threat_model.sub_models.append(tm)

            # A2: run cross-model RAG analysis before the global report
            if ai_service and getattr(ai_service, 'rag_generator', None) and getattr(ai_service, 'ai_online', False):
                try:
                    if progress_callback: progress_callback(93, "Running cross-model RAG analysis...")
                    rag_threats = ai_service.generate_rag_threats_sync(main_threat_model)
                    if rag_threats:
                        if not hasattr(main_threat_model.tm, 'global_threats_llm'):
                            main_threat_model.tm.global_threats_llm = []
                        main_threat_model.tm.global_threats_llm.extend(rag_threats)
                        logging.info("Cross-model RAG: added %d global threats to main model.", len(rag_threats))
                except Exception as exc:
                    logging.warning("Cross-model RAG analysis failed (non-fatal): %s", exc)

            if progress_callback: progress_callback(95, "Generating global project report...")
            self.generate_global_project_report(all_processed_models, output_dir)
        
        if progress_callback: progress_callback(100, "Project generation complete!")
        return main_threat_model

    def _get_all_project_models(self, project_path: Path) -> List[ThreatModel]:
        """
        Discovers and parses all models reachable from main.md via submodel= links.

        Previously this used glob("**/*.md") which would accidentally include every
        unrelated model present in the directory (e.g. when the user pointed the
        generator at a large template directory).  Following submodel= links ensures
        only the models that belong to this project are processed.
        """
        root = project_path / "main.md"
        if not root.exists():
            root = project_path / "model.md"
        if not root.exists():
            return []

        all_models: List[ThreatModel] = []
        visited: set = set()

        def _visit(md_path: Path) -> None:
            resolved = md_path.resolve()
            if resolved in visited:
                return
            visited.add(resolved)
            try:
                with open(md_path, "r", encoding="utf-8") as f:
                    markdown_content = f.read()
                threat_model = create_threat_model(
                    markdown_content=markdown_content,
                    model_name=md_path.stem,
                    model_description=f"Threat model for {md_path.stem}",
                    cve_service=self.cve_service,
                    validate=False,
                )
                if threat_model:
                    all_models.append(threat_model)
                # Follow submodel= links declared on servers
                import re as _re
                for match in _re.finditer(r'submodel\s*=\s*["\']?([^"\'\s,]+)["\']?', markdown_content):
                    sub_rel = match.group(1).strip()
                    sub_path = (md_path.parent / sub_rel).resolve()
                    if sub_path.exists() and sub_path.is_file():
                        _visit(sub_path)
            except Exception as e:
                logging.error(f"Error parsing model file {md_path}: {e}")

        _visit(root)
        return all_models

    def _aggregate_project_data(self, all_models: List[ThreatModel]) -> tuple[set, dict]:
        """
        Aggregates used protocols and protocol styles from a list of threat models.
        """
        project_protocols = set()
        project_protocol_styles = {}

        for model in all_models:
            if hasattr(model, 'dataflows'):
                for df in model.dataflows:
                    protocol = getattr(df, 'protocol', None)
                    if protocol:
                        project_protocols.add(protocol)

            if hasattr(model, 'get_all_protocol_styles'):
                styles = model.get_all_protocol_styles()
                project_protocol_styles.update(styles)

        return project_protocols, project_protocol_styles

    def _collect_parent_connections(self, parent_tm: ThreatModel, server_name: str) -> List[Dict]:
        """Returns incoming/outgoing dataflow stubs for server_name in parent_tm.

        A dataflow with bidirectional=True generates both an incoming AND an outgoing
        stub so that _build_ghost_connections can render a single purple bidirectional
        ghost node instead of two separate green/orange ghosts.
        """
        result = []
        for df in parent_tm.dataflows:
            src = df.source
            snk = df.sink
            src_name = src.name if hasattr(src, "name") else str(src)
            snk_name = snk.name if hasattr(snk, "name") else str(snk)
            is_bidir = bool(getattr(df, "bidirectional", False))
            proto = getattr(df, "protocol", "") or ""
            is_enc = bool(getattr(df, "is_encrypted", False))
            is_auth = bool(getattr(df, "is_authenticated", False))
            df_name = getattr(df, "name", "")

            if snk_name.lower() == server_name.lower():
                result.append({
                    "direction": "incoming",
                    "peer": src_name,
                    "protocol": proto,
                    "is_encrypted": is_enc,
                    "is_authenticated": is_auth,
                    "name": df_name,
                })
                if is_bidir:
                    # bidirectional=True: server also sends back to the same peer
                    result.append({
                        "direction": "outgoing",
                        "peer": src_name,
                        "protocol": proto,
                        "is_encrypted": is_enc,
                        "is_authenticated": is_auth,
                        "name": df_name,
                    })
            elif src_name.lower() == server_name.lower():
                result.append({
                    "direction": "outgoing",
                    "peer": snk_name,
                    "protocol": proto,
                    "is_encrypted": is_enc,
                    "is_authenticated": is_auth,
                    "name": df_name,
                })
                if is_bidir:
                    # bidirectional=True: peer also sends back to server
                    result.append({
                        "direction": "incoming",
                        "peer": snk_name,
                        "protocol": proto,
                        "is_encrypted": is_enc,
                        "is_authenticated": is_auth,
                        "name": df_name,
                    })
        return result

    def _recursively_generate_reports(self, model_path: Path, project_path: Path, output_dir: Path, breadcrumb: List[tuple[str, str]], project_protocols: set, project_protocol_styles: dict, all_project_models: List[ThreatModel], threat_model: Optional[ThreatModel] = None, progress_callback = None, parent_connections: Optional[List[Dict]] = None):
        """
        Recursively generates reports for each model in the project.
        """
        model_name = model_path.stem
        if progress_callback: progress_callback(f"Loading model: {model_name}...", is_new_model=True)

        try:
            with open(model_path, "r", encoding="utf-8") as f:
                markdown_content = f.read()

            if threat_model is None:
                threat_model = create_threat_model(
                    markdown_content=markdown_content,
                    model_name=model_name,
                    model_description=f"Threat model for {model_name}",
                    cve_service=self.cve_service,
                    validate=True
                )

            if not threat_model:
                logging.error(f"Failed to create or use threat model for {model_path}")
                return

            if progress_callback: progress_callback(f"Running STRIDE analysis: {model_name}...")
            grouped_threats = threat_model.process_threats()
            all_project_models.append(threat_model)

            if progress_callback: progress_callback(f"Generating HTML report: {model_name}...")
            self.generate_html_report(threat_model, grouped_threats, output_dir / f"{model_name}_threat_report.html", progress_callback=None)
            if progress_callback: progress_callback(f"Generating JSON export: {model_name}...")
            self.generate_json_export(threat_model, grouped_threats, output_dir / f"{model_name}.json")
            try:
                self.generate_remediation_checklist(threat_model, grouped_threats, output_dir / f"{model_name}_remediation_checklist.csv")
            except Exception as e:
                logging.warning(f"Could not generate remediation checklist for {model_name}: {e}")
            if progress_callback: progress_callback(f"Generating diagram: {model_name}...")
            self.generate_diagram_html(threat_model, output_dir, breadcrumb, project_protocols, project_protocol_styles, external_connections=parent_connections)

            # Save markdown model and generate metadata for graphical editor
            md_output_path = output_dir / f"{model_name}.md"
            with open(md_output_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            
            diagram_generator = DiagramGenerator()
            diagram_generator.generate_metadata(threat_model, markdown_content, str(md_output_path))

            if progress_callback: progress_callback(f"Generating STIX report: {model_name}...")
            try:
                stix_output_file = output_dir / f"{model_name}_stix_report.json"
                all_detailed_threats = threat_model.get_all_threats_details()
                stix_generator_instance = StixGenerator(
                    threat_model=threat_model,
                    all_detailed_threats=all_detailed_threats
                )
                stix_bundle = stix_generator_instance.generate_stix_bundle()
                with open(stix_output_file, "w", encoding="utf-8") as f:
                    json.dump(stix_bundle, f, indent=4)
                logging.info(f"STIX report generated for {model_name} at {stix_output_file}")
            except Exception as e:
                logging.error(f"❌ Failed to generate STIX report for {model_name}: {e}")

            if progress_callback: progress_callback(f"Generating ATT&CK Navigator: {model_name}...")
            try:
                navigator_output_file = output_dir / f"{model_name}_attack_navigator_layer.json"
                all_detailed_threats = threat_model.get_all_threats_details()
                navigator_generator = AttackNavigatorGenerator(
                    threat_model_name=threat_model.tm.name,
                    all_detailed_threats=all_detailed_threats
                )
                navigator_generator.save_layer_to_file(str(navigator_output_file))
                logging.info(f"ATT&CK Navigator layer generated for {model_name} at {navigator_output_file}")
            except Exception as e:
                logging.error(f"❌ Failed to generate ATT&CK Navigator layer for {model_name}: {e}")

            try:
                all_detailed_threats = threat_model.get_all_threats_details()
                attack_flow_gen = AttackFlowGenerator(
                    threats=all_detailed_threats,
                    model_name=threat_model.tm.name,
                )
                attack_flow_gen.generate_and_save_flows(str(output_dir))
                logging.info(f"Attack Flow files generated for {model_name} in {output_dir / 'afb'}")
            except Exception as e:
                logging.error(f"❌ Failed to generate Attack Flow for {model_name}: {e}")

            for server_props in threat_model.servers:
                if 'submodel' in server_props:
                    submodel_path_str = server_props['submodel']
                    try:
                        submodel_path = _validate_path_within_project(str(model_path.parent / submodel_path_str), base_dir=project_path)

                        if submodel_path.is_file():
                            submodel_relative_parent = Path(submodel_path_str).parent
                            sub_output_dir = output_dir / submodel_relative_parent
                            sub_output_dir.mkdir(parents=True, exist_ok=True)

                            sub_model_display_name = submodel_relative_parent.name if str(submodel_relative_parent) != '.' else submodel_path.stem

                            current_model_breadcrumb_path = Path(breadcrumb[-1][1])
                            current_model_dir = current_model_breadcrumb_path.parent
                            submodel_rel_path = Path(submodel_path_str)
                            new_link_path_obj = (current_model_dir / submodel_rel_path).with_name(f"{submodel_rel_path.stem}_diagram.html")
                            breadcrumb_link = Path(os.path.normpath(str(new_link_path_obj))).as_posix()
                            new_breadcrumb = breadcrumb + [(sub_model_display_name, breadcrumb_link)]

                            # Pre-create the sub-model so we can:
                            # 1. Store _submodel_tm in server_props for GDAF bridging
                            # 2. Collect parent connections for the child's diagram
                            with open(submodel_path, "r", encoding="utf-8") as f:
                                sub_md = f.read()
                            sub_tm = create_threat_model(
                                markdown_content=sub_md,
                                model_name=submodel_path.stem,
                                model_description=f"Sub-model of {server_props['name']}",
                                cve_service=self.cve_service,
                                validate=True,
                            )
                            if sub_tm:
                                # Store reference for GDAF attack-path bridging
                                server_props['_submodel_tm'] = sub_tm
                                # Collect incoming/outgoing dataflows of the parent server
                                parent_conns = self._collect_parent_connections(
                                    threat_model, server_props['name']
                                )
                                self._recursively_generate_reports(
                                    model_path=submodel_path,
                                    threat_model=sub_tm,
                                    project_path=project_path,
                                    output_dir=sub_output_dir,
                                    breadcrumb=new_breadcrumb,
                                    project_protocols=project_protocols,
                                    project_protocol_styles=project_protocol_styles,
                                    all_project_models=all_project_models,
                                    progress_callback=progress_callback,
                                    parent_connections=parent_conns,
                                )
                    except ValueError as e:
                        logging.warning(f"Skipping submodel referenced in '{model_path.name}' because it was not found: {e}")
                        continue
        except Exception as e:
            logging.error(f"Error processing model at {model_path}: {e}", exc_info=True)

    def _compute_severity_map(self, threat_model) -> Dict[str, str]:
        """Build {sanitized_node_name: severity_level} from processed threats for B2 heat map.

        Reads mitre_analysis_results so process_threats() must have been called first.
        Returns an empty dict when no severity data is available.
        """
        import re as _re

        def _san(name: str) -> str:
            s = _re.sub(r'[^a-zA-Z0-9_]', '_', str(name or ''))
            return (f'_{s}' if s and s[0].isdigit() else s) or 'unnamed'

        _ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        result: Dict[str, str] = {}

        _IMPACT_MAP = {5: 'CRITICAL', 4: 'HIGH', 3: 'MEDIUM', 2: 'LOW', 1: 'LOW'}

        for pt in threat_model.mitre_analysis_results.get('processed_threats', []):
            target = pt.get('target')
            if target is None:
                continue
            if isinstance(target, tuple):
                names = [getattr(t, 'name', None) for t in target if t is not None]
            else:
                names = [getattr(target, 'name', str(target))]

            sev_info = pt.get('severity_info') or {}
            level = (sev_info.get('level') or '').upper()
            if level not in _ORDER:
                # Fallback: derive severity from original_threat impact (pytm threats)
                original = pt.get('original_threat')
                if original is not None:
                    impact = getattr(original, 'impact', 0) or 0
                    level = _IMPACT_MAP.get(int(impact), '')
            if level not in _ORDER:
                continue

            for name in names:
                if not name:
                    continue
                sid = _san(name)
                if _ORDER.get(level, 0) > _ORDER.get(result.get(sid, ''), 0):
                    result[sid] = level

        # Also check AI element threats
        all_elements = (
            [(d.get('object'), d.get('name', '')) for d in threat_model.actors]
            + [(d.get('object'), d.get('name', '')) for d in threat_model.servers]
        )
        for df in threat_model.dataflows:
            all_elements.append((df, getattr(df, 'name', '')))

        for element_obj, element_name in all_elements:
            if element_obj is None or not element_name:
                continue
            max_impact = max(
                (getattr(t, 'impact', 0) or 0 for t in getattr(element_obj, 'threats', [])),
                default=0,
            )
            if max_impact > 0:
                level = _IMPACT_MAP.get(max_impact, 'LOW')
                sid = _san(element_name)
                if _ORDER.get(level, 0) > _ORDER.get(result.get(sid, ''), 0):
                    result[sid] = level

        return result

    def generate_diagram_html(self, threat_model: ThreatModel, output_dir: Path, breadcrumb: List[tuple[str, str]], project_protocols: set, project_protocol_styles: dict, external_connections: Optional[List[Dict]] = None):
        """
        Generates an HTML file containing just the diagram for navigation.
        external_connections: stubs from parent model (incoming/outgoing) rendered as ghost nodes.
        """
        diagram_generator = DiagramGenerator()
        model_name = threat_model.tm.name

        dot_code = diagram_generator.generate_dot_file_from_model(threat_model, str(output_dir / f"{model_name}.dot"), project_protocol_styles, external_connections=external_connections)
        if not dot_code:
            logging.error(f"Failed to generate DOT code for {model_name}")
            return

        svg_path = diagram_generator.generate_diagram_from_dot(dot_code, str(output_dir / f"{model_name}.svg"), "svg")
        if not svg_path:
            logging.error(f"Failed to generate SVG for {model_name}")
            return

        with open(svg_path, "r", encoding="utf-8") as f:
            svg_content = f.read()

        svg_content = diagram_generator.add_links_to_svg(svg_content, threat_model)

        template = self.env.get_template('navigable_diagram_template.html')

        # Before rendering, calculate the correct relative paths for the breadcrumb.
        # The 'breadcrumb' variable contains links relative to the project output root.
        # We need to convert them to be relative to the current file's location.
        processed_breadcrumb = []
        if breadcrumb:
            # The path of the HTML file we are currently generating, relative to the project output root.
            current_html_path_str = breadcrumb[-1][1]
            current_html_dir = Path(current_html_path_str).parent

            for name, link_target_str in breadcrumb:
                # link_target_str is relative to the project output root.
                # We need to make it relative to the current HTML file's directory.
                relative_link = os.path.relpath(link_target_str, start=current_html_dir).replace('\\', '/')
                processed_breadcrumb.append((name, relative_link))

        parent_link = None
        if len(processed_breadcrumb) > 1:
            parent_link = processed_breadcrumb[-2][1]

        current_diagram_path = Path(breadcrumb[-1][1]) if breadcrumb else Path()
        current_dir_depth = len(current_diagram_path.parent.parts)

        legend_html = diagram_generator._generate_legend_html(
            threat_model,
            project_protocols=project_protocols,
            project_protocol_styles=project_protocol_styles
        )

        graph_metadata = self._extract_graph_metadata_for_frontend(threat_model)
        severity_map = self._compute_severity_map(threat_model)
        # Report file lives in the same output_dir; use a relative link
        report_url = f"{model_name}_threat_report.html"
        html = template.render(
            title=f"Diagram - {model_name}",
            svg_content=svg_content,
            breadcrumb=processed_breadcrumb,
            parent_link=parent_link,
            legend_html=legend_html,
            current_dir_depth=current_dir_depth,
            graph_metadata_json=json.dumps(graph_metadata),
            severity_map_json=json.dumps(severity_map),
            report_url=report_url,
        )

        diagram_html_path = output_dir / f"{model_name}_diagram.html"
        with open(diagram_html_path, "w", encoding="utf-8") as f:
            f.write(html)
        logging.info(f"Generated diagram HTML: {diagram_html_path}")