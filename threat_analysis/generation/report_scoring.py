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
Per-threat scoring pipeline: VEX/BOM/CVE resolution, network exposure, MITRE
mapping and severity scoring. Shared by pytm-derived and AI-derived threats via
ScoringMixin._get_all_threats_with_mitre_info (mixed into ReportGenerator).
"""
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from threat_analysis.core.threat_ranker import rank_and_trim
from threat_analysis.core.accepted_risks import AcceptedRiskLoader, compute_threat_key
from threat_analysis.core.threat_consolidator import ThreatConsolidator
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.severity_calculator_module import RiskContext
from .utils import extract_name_from_object, get_target_name


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

    Resolution order:
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


def score_threat(
    *,
    mitre_mapping: Any,
    cve_service: Any,
    severity_calculator: Any,
    description: str,
    stride_category: str,
    capec_ids: List[str],
    source: str,
    target_name: str,
    cve_lookup_names: List[str],
    network_exposure_subject: Any,
    vex_loader: Optional[Any],
    bom_loader: Optional[Any],
    impact: Optional[int] = None,
    likelihood: Optional[int] = None,
    classification: Optional[str] = None,
) -> Dict[str, Any]:
    """Runs the MITRE + CVE/CWE + network exposure + D3FEND + severity scoring
    pipeline for one threat.

    ``target_name`` is the single name used for the severity call and the report's
    "target" field; ``cve_lookup_names`` is the (possibly larger — e.g. both
    endpoints of a dataflow) set of component names checked for matching CVEs.

    Returns ``{severity, mitre_techniques, capecs, cve, risk_signals}``. This is
    the single scoring path used for both pytm-derived and AI-derived threats in
    ScoringMixin._get_all_threats_with_mitre_info — previously duplicated inline
    for each, which risked the two silently diverging over time.
    """
    threat_dict = {
        "description": description,
        "stride_category": stride_category,
        "capec_ids": capec_ids,
        "source": source,
    }
    mapping_results = mitre_mapping.map_threat_to_mitre(threat_dict)
    mitre_techniques = mapping_results.get('techniques', [])
    capecs = mapping_results.get('capecs', [])

    cve_ids_for_threat: set = set()
    cwe_ids_for_threat: List[str] = []
    threat_capecs = {c['capec_id'] for c in capecs}
    for name in cve_lookup_names:
        equipment_cves = _resolve_active_cves(name, vex_loader, bom_loader, cve_service)
        for cve_id in equipment_cves:
            cve_capecs = cve_service.get_capecs_for_cve(cve_id.upper())
            if threat_capecs.intersection(cve_capecs):
                cve_ids_for_threat.add(cve_id)
                cwe_ids_for_threat.extend(cve_service.get_cwes_for_cve(cve_id.upper()))

    network_exposed = _is_network_exposed(network_exposure_subject)

    has_d3fend = any(tech.get('defend_mitigations') for tech in mitre_techniques)
    if not has_d3fend:
        has_d3fend = any(
            _resolve_has_fixed_cves(n, vex_loader, bom_loader) for n in cve_lookup_names
        )

    risk_ctx = RiskContext(
        has_cve_match=bool(cve_ids_for_threat),
        cwe_ids=list(set(cwe_ids_for_threat)),
        network_exposed=network_exposed,
        has_d3fend_mitigations=has_d3fend,
    )
    severity_info = severity_calculator.get_severity_info(
        stride_category, target_name,
        classification=classification, impact=impact, likelihood=likelihood,
        risk_context=risk_ctx,
    )
    return {
        "severity": severity_info,
        "mitre_techniques": mitre_techniques,
        "capecs": capecs,
        "cve": sorted(cve_ids_for_threat),
        "risk_signals": {
            "cve_match": risk_ctx.has_cve_match,
            "cwe_high_risk": risk_ctx.cwe_high_risk,
            "network_exposed": risk_ctx.network_exposed,
            "d3fend_mitigations": risk_ctx.has_d3fend_mitigations,
        },
    }


class ScoringMixin:
    """Mixed into ReportGenerator. Builds the fully-scored, MITRE-mapped threat
    list consumed by every export format (HTML, JSON, STIX, CSV checklist)."""

    def _export_detailed_threats(self, grouped_threats: Dict[str, List], threat_model: ThreatModel) -> List[Dict[str, Any]]:
        return self._get_all_threats_with_mitre_info(grouped_threats, threat_model)

    def _get_all_threats_with_mitre_info(self, grouped_threats: Dict[str, List], threat_model: ThreatModel) -> List[Dict[str, Any]]:
        """Gathers detailed information for all threats, including MITRE ATT&CK mapping and severity."""
        # Sync severity multipliers from the actual model's '## Severity Multipliers' DSL
        # section (already parsed onto threat_model.severity_multipliers by ModelParser).
        # self.severity_calculator is injected at construction time and may be a long-lived
        # singleton (server mode) reused across different models — without this, it would
        # score every model using whichever multipliers happened to be loaded first (or
        # none at all). Always sync (even with an empty dict) so a model with no
        # multipliers of its own correctly clears any left over from a previous one.
        self.severity_calculator.update_target_multipliers(
            getattr(threat_model, "severity_multipliers", {}) or {}
        )

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

                score_result = score_threat(
                    mitre_mapping=self.mitre_mapping,
                    cve_service=self.cve_service,
                    severity_calculator=self.severity_calculator,
                    description=threat_description,
                    stride_category=stride_category,
                    capec_ids=getattr(threat, 'capec_ids', []),
                    source=threat_source,
                    target_name=target_name,
                    cve_lookup_names=target_names_to_check,
                    network_exposure_subject=target,
                    vex_loader=_vex_loader,
                    bom_loader=_bom_loader,
                    impact=threat_impact,
                    likelihood=threat_likelihood,
                    classification=data_classification,
                )

                pytm_threat_dicts.append({
                    "type": threat_type,
                    "description": threat_description,
                    "target": target_name,
                    "severity": score_result["severity"],
                    "mitre_techniques": score_result["mitre_techniques"],
                    "stride_category": stride_category,
                    "capecs": score_result["capecs"],
                    "cve": score_result["cve"],
                    "business_value": business_value,
                    "confidence": getattr(threat, 'confidence', 1.0),
                    "source": threat_source,
                    "risk_signals": score_result["risk_signals"],
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
        # Boundaries are also an AI-enrichment target (A3, see decisions.md) — omitting
        # them here silently dropped every AI threat attached to a boundary from the
        # final report, even though AIService._enrich_with_ai_threats() and the SOC
        # analysis pass both process boundary elements.
        for b_name, b_info in threat_model.boundaries.items():
            boundary_obj = b_info.get('boundary')
            if boundary_obj is not None:
                enriched_elements.append((boundary_obj, b_name, b_info.get('business_value')))

        for element_obj, element_name, business_value in enriched_elements:
            if element_obj is None:
                continue
            for et in getattr(element_obj, 'threats', []):
                if getattr(et, 'source', 'pytm') != 'AI':
                    continue
                stride_category = getattr(et, 'stride_category', getattr(et, 'category', 'Unknown'))
                target_name = element_name or getattr(element_obj, 'name', 'Unknown')
                threat_description = getattr(et, 'description', f"AI threat on {target_name}")

                score_result = score_threat(
                    mitre_mapping=self.mitre_mapping,
                    cve_service=self.cve_service,
                    severity_calculator=self.severity_calculator,
                    description=threat_description,
                    stride_category=stride_category,
                    capec_ids=getattr(et, 'capec_ids', []),
                    source="AI",
                    target_name=target_name,
                    cve_lookup_names=[target_name],
                    network_exposure_subject=element_obj,
                    vex_loader=_vex_loader,
                    bom_loader=_bom_loader,
                    impact=getattr(et, 'impact', None),
                    likelihood=getattr(et, 'likelihood_score', None),
                )

                ai_element_threat_dicts.append({
                    "type": stride_category,
                    "description": threat_description,
                    "target": target_name,
                    "severity": score_result["severity"],
                    "mitre_techniques": score_result["mitre_techniques"],
                    "stride_category": stride_category,
                    "capecs": score_result["capecs"],
                    "cve": score_result["cve"],
                    "business_value": business_value,
                    "confidence": getattr(et, 'confidence', 0.9),
                    "source": "AI",
                    "risk_signals": score_result["risk_signals"],
                    "soc_analysis": (getattr(et, "ai_details", {}) or {}).get("soc_analysis"),
                })

        # Merge: AI wins on semantic duplicates within same (target, stride_category)
        all_detailed_threats = ThreatConsolidator.deduplicate(pytm_threat_dicts, ai_element_threat_dicts)

        # Process global RAG threats
        if hasattr(threat_model.tm, 'global_threats_llm'): # Access via threat_model
            for threat in threat_model.tm.global_threats_llm:
                # RAG threats are system-level (cross-component) by design, but the LLM
                # is explicitly asked for affected_components — use it for a target more
                # specific than a generic label when available (also lets severity
                # multipliers on those components apply, same as any other threat).
                ai_details = getattr(threat, 'ai_details', None) or {}
                affected = [c for c in (ai_details.get('affected_components') or []) if c]
                target_name = " → ".join(affected) if affected else "Threat Model (Global)"
                threat_description = getattr(threat, 'description', 'RAG-generated global threat')
                stride_category = getattr(threat, 'category', 'Generic RAG Threat')
                threat_source = getattr(threat, 'source', 'LLM')

                severity_info = self.severity_calculator.get_severity_info(
                    stride_category,
                    target_name,
                    impact=getattr(threat, 'impact', None),
                    likelihood=getattr(threat, 'likelihood_score', None)
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
