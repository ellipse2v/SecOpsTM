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
from threat_analysis.utils import resolve_gdaf_context
from threat_analysis.mitigation_suggestions import get_framework_mitigation_suggestions
from threat_analysis.core.cve_service import CVEService
import yaml
import asyncio


project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.generation.stix_generator import StixGenerator
from threat_analysis.generation.attack_flow_generator import AttackFlowGenerator
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.stride_constants import STRIDE_CATEGORIES as _STRIDE_CATEGORIES_CONST
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.core.attack_chain import AttackChainAnalyzer
from threat_analysis.core.model_completeness import score_model as _score_model_completeness
from threat_analysis.core.attack_id_validator import AttackIdValidator
from threat_analysis.core.report_serializer import ReportSerializer

from .report_scoring import (
    ScoringMixin,
    _is_network_exposed,
    _boundary_untrusted,
)
from .report_ai_analysis import AIAnalysisMixin, _narrative_has_id_leakage  # noqa: F401 (re-export)
from .report_project import ProjectReportMixin


def load_implemented_mitigations(mitigations_file: Optional[Path]) -> Set[str]:
    """Loads implemented mitigation IDs from a file."""
    if not mitigations_file or not mitigations_file.exists():
        return set()
    with open(mitigations_file, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip() and not line.strip().startswith("#")}

class ReportGenerator(ScoringMixin, AIAnalysisMixin, ProjectReportMixin):
    """Class for generating HTML and JSON reports"""

    def __init__(self, severity_calculator, mitre_mapping,
                 implemented_mitigations_path: Optional[Path] = None,
                 cve_service: Optional[CVEService] = None,
                 ai_config_path: Optional[Path] = None,
                 context_path: Optional[Path] = None,  # kept for backwards compat, unused
                 threat_model_ref: Optional[ThreatModel] = None,
                 disable_rag: bool = False):
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
        self._ai_config_path = ai_config_path
        self._ai_service = None  # lazily built by _get_ai_service()
        self._disable_rag = disable_rag
        self.threat_model_ref = threat_model_ref # Store the reference
        # Threat ranking / volume control — defaults (overridden from ai_config below)
        self._ranking_max_total: int = 0
        self._ranking_min_stride: bool = True
        self._ranking_weights: Dict[str, float] = {}
        self._enrich_batch_size: int = 5
        self._enrich_max_concurrent: int = 3
        self._debate_config: Dict = {}
        self._attack_flows_config: Dict = {}

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
            self._debate_config = ai_config.get("debate", {}) or {}
            self._attack_flows_config = ai_config.get("attack_flows", {}) or {}

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

            # AI enrichment must run BEFORE _get_all_threats_with_mitre_info(): it mutates
            # threat_model in place (element.threats, tm.global_threats_llm), and that
            # method's own collectors are what turn those mutations into AI/LLM entries
            # in all_detailed_threats below.
            if self.ai_provider:
                asyncio.run(self._run_ai_enrichment(threat_model, progress_callback=progress_callback))

            if all_detailed_threats is None:
                all_detailed_threats = self._get_all_threats_with_mitre_info(grouped_threats, threat_model)
                _ai_count = sum(1 for t in all_detailed_threats if t.get('source') in ('AI', 'LLM'))
                logging.info(f"AI enrichment complete. {_ai_count} AI/LLM threat(s) included.")

            # Recompute STRIDE distribution from the full threat list (pytm + AI + LLM)
            stride_distribution: Dict[str, int] = {}
            for t in all_detailed_threats:
                cat = t.get('stride_category', '')
                if cat in self._VALID_STRIDE:
                    stride_distribution[cat] = stride_distribution.get(cat, 0) + 1

            # Assign stable T-0001-style ids now (same scheme as ReportSerializer) so
            # downstream consumers built from this same list — CISO triage, threat graph —
            # cite ids that actually match the final JSON/HTML report, instead of CISO
            # triage inventing its own reference format because no id existed yet.
            for _i, _t in enumerate(all_detailed_threats):
                _t.setdefault("id", f"T-{_i + 1:04d}")

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
            attack_id_validation = AttackIdValidator().validate_all(all_detailed_threats)

            threat_model._completeness = completeness
            threat_model._attack_id_validation = attack_id_validation

            # Red/Blue adversarial debate — mutates gdaf_scenarios in place (score/risk_level only).
            # Runs BEFORE CISO triage and the threat graph so both can cite debate-adjusted
            # GDAF outcomes instead of pre-debate scores.
            debate_results = []
            if self._debate_config.get("enabled") and self.ai_provider and getattr(threat_model, "gdaf_scenarios", None):
                try:
                    debate_results = asyncio.run(self._run_debate(threat_model))
                except Exception as exc:
                    logging.warning("Red/Blue debate failed (non-fatal): %s", exc)
            threat_model.debate_results = debate_results

            # Re-write the .afb Attack Flow files if the debate changed any scenario score.
            # run_gdaf_engine() (called earlier in the pipeline, before this method) already
            # wrote them once from the pre-debate scenarios — without this, the .afb files
            # would permanently disagree with the debate-adjusted scores/risk_levels shown
            # in this same HTML report.
            if debate_results:
                try:
                    from threat_analysis.generation.attack_flow_builder import AttackFlowBuilder  # noqa: PLC0415
                    AttackFlowBuilder(
                        threat_model.gdaf_scenarios, model_name=str(threat_model.tm.name)
                    ).generate_and_save(str(Path(output_file).parent))
                except Exception as exc:
                    logging.warning("Failed to re-write .afb files after debate (non-fatal): %s", exc)

            # Built after the debate so GDAF path overlays reflect debate-adjusted scores.
            threat_graph = self._build_threat_graph_data(
                threat_model, all_detailed_threats,
                gdaf_scenarios=getattr(threat_model, "gdaf_scenarios", None),
                debate_results=debate_results,
            )

            # CISO triage pass — runs after the full ranked threat list AND the debate are
            # available, so the briefing can reference GDAF attack scenarios and debate outcomes.
            ciso_triage = {}
            if self.ai_provider and all_detailed_threats:
                try:
                    ciso_triage = asyncio.run(self._run_ciso_triage(
                        all_detailed_threats,
                        gdaf_scenarios=getattr(threat_model, "gdaf_scenarios", None),
                        debate_results=debate_results,
                    ))
                except Exception as exc:
                    logging.warning("CISO triage failed: %s", exc)
            # Cache on the model so generate_json_export can include it without re-running.
            threat_model._ciso_triage = ciso_triage if ciso_triage else None

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
                    "pre_debate_score": (
                        round(float(getattr(scenario, 'path_score_pre_debate')), 2)
                        if getattr(scenario, 'path_score_pre_debate', None) is not None else None
                    ),
                    "risk_level": getattr(scenario, 'risk_level', 'LOW'),
                    "hop_count": len(hops_summary),
                    "hops": hops_summary,
                    "detection_coverage": round(float(getattr(scenario, 'detection_coverage', 0.0)), 2),
                    "unacceptable_risk": bool(getattr(scenario, 'unacceptable_risk', False)),
                })

            # Build a serialised summary of debate results for the HTML template.
            debate_data = []
            for result in debate_results:
                rounds_data = []
                for turn in result.rounds:
                    rounds_data.append({
                        "role": turn.role,
                        "round_index": turn.round_index,
                        "viability_score": turn.viability_score,
                        "techniques_attempted": turn.techniques_attempted,
                        "techniques_blocked": turn.techniques_blocked,
                        "failed_alternatives": turn.failed_alternatives,
                        "rationale": turn.rationale,
                        "detection_gaps": [
                            {
                                "step": g.step, "control_family": g.control_family,
                                "covered": g.covered, "detail": g.detail, "confidence": g.confidence,
                            }
                            for g in turn.detection_gaps
                        ],
                        "evidence": [
                            {
                                "claim": e.claim, "evidence_type": e.evidence_type,
                                "evidence_ref": e.evidence_ref, "confidence": e.confidence,
                                "verified": e.verified,
                            }
                            for e in turn.evidence
                        ],
                    })
                debate_data.append({
                    "scenario_id": result.scenario_id,
                    "objective_name": result.objective_name,
                    "entry_point": result.entry_point,
                    "target_asset": result.target_asset,
                    "blocked_paths": result.blocked_paths,
                    "residual_detection_gaps": [
                        {
                            "step": g.step, "control_family": g.control_family,
                            "covered": g.covered, "detail": g.detail, "confidence": g.confidence,
                        }
                        for g in result.residual_detection_gaps
                    ],
                    "red_failed_attempts": result.red_failed_attempts,
                    "round_count": result.round_count,
                    "convergence_delta": result.convergence_delta,
                    "converged": result.converged,
                    "final_viability": result.final_viability,
                    "residual_path_viable": result.residual_path_viable,
                    "debate_factor": result.debate_factor,
                    "rounds": rounds_data,
                })

            # Automatically-discovered attack paths — best path per STRIDE category through
            # the threats' own MITRE techniques, found independently of GDAF (no analyst-
            # defined objectives/actors needed). Complements GDAF's analyst-driven scenarios
            # with paths the threat data itself suggests.
            discovered_attack_paths = []
            if self._attack_flows_config.get("enabled", True):
                try:
                    discovered_attack_paths = AttackFlowGenerator(
                        all_detailed_threats, model_name=str(threat_model.tm.name),
                        allowed_categories=self._attack_flows_config.get("generate_for_categories"),
                    ).get_paths_summary()
                except Exception as exc:
                    logging.warning("Discovered attack path summary failed (non-fatal): %s", exc)
                    discovered_attack_paths = []
                if discovered_attack_paths:
                    try:
                        asyncio.run(self._generate_path_narratives(discovered_attack_paths))
                    except Exception as exc:
                        logging.warning("Attack path narrative pass failed (non-fatal): %s", exc)

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
                debate_results=debate_data,
                discovered_attack_paths=discovered_attack_paths,
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
            # Reuse the AI-enriched list cached by generate_html_report() if available —
            # otherwise this recomputes pytm-only threats and silently drops AI/LLM threats
            # (generate_html_report must run first in the same process for the cache to exist).
            cached_threats = getattr(threat_model, "_report_all_detailed_threats", None)
            if cached_threats:
                all_detailed_threats = cached_threats
            else:
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

        # Reuse the AI-enriched list cached by generate_html_report() if available — see
        # generate_json_export() for why this matters.
        cached_threats = getattr(threat_model, "_report_all_detailed_threats", None)
        if cached_threats:
            all_detailed_threats = cached_threats
        else:
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
    _VALID_STRIDE: frozenset = _STRIDE_CATEGORIES_CONST

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
        gdaf_scenarios: Optional[List[Any]] = None,
        debate_results: Optional[List[Any]] = None,
    ) -> Dict:
        """Build a JSON-serialisable graph for the interactive threat visualization.

        Nodes  = actors + servers (boundaries shown as containers, not nodes).
        Edges  = dataflows between components.
        The ``threats_by_node`` dict maps node ids to a compact threat list
        so the template JS can render a click panel without extra requests.

        ``gdaf_scenarios``/``debate_results`` are optional — when provided (post-debate),
        a ``gdaf_paths`` list is included so the template JS can let the user highlight a
        GDAF attack path (entry actor → hop assets → target) over the graph, showing
        whether the Red/Blue debate found that path still viable.

        Returns a dict with keys ``nodes``, ``edges``, ``threats_by_node``, ``gdaf_paths``.
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

        # --- GDAF attack paths (post-debate, if available) --------------------
        debate_by_scenario = {getattr(r, "scenario_id", None): r for r in (debate_results or [])}
        gdaf_paths: List[Dict] = []
        for scenario in (gdaf_scenarios or [])[:10]:
            entry = getattr(scenario, "entry_point", "") or ""
            hop_names = [getattr(h, "asset_name", "") for h in getattr(scenario, "hops", [])]
            node_sequence = [n for n in ([entry] + hop_names) if n]
            # dedupe consecutive repeats (entry_point sometimes equals the first hop)
            node_sequence = [n for i, n in enumerate(node_sequence) if i == 0 or n != node_sequence[i - 1]]
            if len(node_sequence) < 2:
                continue
            debate_result = debate_by_scenario.get(getattr(scenario, "scenario_id", None))
            gdaf_paths.append({
                "scenario_id": getattr(scenario, "scenario_id", ""),
                "objective_name": getattr(scenario, "objective_name", ""),
                "actor_name": getattr(scenario, "actor_name", ""),
                "risk_level": getattr(scenario, "risk_level", "LOW"),
                "path_score": round(float(getattr(scenario, "path_score", 0) or 0), 2),
                "debated": debate_result is not None,
                "residual_path_viable": bool(getattr(debate_result, "residual_path_viable", True)) if debate_result is not None else None,
                "nodes": node_sequence,
            })

        return {
            "nodes": nodes,
            "edges": edges,
            "threats_by_node": compact_threats,
            "gdaf_paths": gdaf_paths,
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