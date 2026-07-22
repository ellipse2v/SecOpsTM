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
Multi-model ("project") report generation: discovers every model reachable from
main.md via submodel= links, generates a per-model report/diagram/STIX/Navigator/
Attack-Flow bundle for each, then a single global report aggregating all of them.
Mixed into ReportGenerator (report_generator.py).
"""
import json
import logging
import os
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from threat_analysis.utils import _validate_path_within_project
from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.generation.stix_generator import StixGenerator
from threat_analysis.generation.attack_navigator_generator import AttackNavigatorGenerator
from threat_analysis.generation.attack_flow_generator import AttackFlowGenerator
from .utils import get_enriched_threats


class ProjectReportMixin:
    """Mixed into ReportGenerator. Requires self.cve_service and the sibling
    ReportGenerator methods (generate_html_report, generate_json_export,
    generate_remediation_checklist, generate_diagram_html, generate_summary_stats)."""

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
        if all_models:
            dummy_model.context_config = all_models[0].context_config.copy()
        dummy_model.mitre_analysis_results = {
            'total_threats': total_threats_analyzed,
            'mitre_techniques_count': total_mitre_techniques_mapped,
            'stride_distribution': all_stride_distribution
        }
        # Aggregate dataflows from all sub-models so AttackChainAnalyzer can find chains
        for model in all_models:
            dummy_model.dataflows.extend(model.dataflows)

        # Copy gdaf_scenarios from main_threat_model (if available)
        # NOTE: all_models[0] is guaranteed to be the main_threat_model due to the
        # ordering in generate_project_reports() where main_threat_model is built first
        # and all_processed_models is constructed as [main_threat_model] + sub_models.
        if all_models:
            main_model = all_models[0]
            if hasattr(main_model, 'gdaf_scenarios') and main_model.gdaf_scenarios:
                dummy_model.gdaf_scenarios = main_model.gdaf_scenarios

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

            # GDAF: Goal-Driven Attack Flow (run BEFORE global report so scenarios are available)
            try:
                from threat_analysis.utils import run_gdaf_engine
                _scenarios = run_gdaf_engine(main_threat_model, export_path=output_dir, progress_callback=progress_callback)
                if _scenarios:
                    logging.info(
                        "GDAF (project): %d scenarios from %d model(s) in %s/gdaf",
                        len(_scenarios), 1 + len(getattr(main_threat_model, "sub_models", [])), output_dir,
                    )
            except Exception as _gdaf_exc:
                logging.warning("GDAF (project) generation skipped (non-fatal): %s", _gdaf_exc)

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
                all_detailed_threats = get_enriched_threats(threat_model)
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
                all_detailed_threats = get_enriched_threats(threat_model)
                navigator_generator = AttackNavigatorGenerator(
                    threat_model_name=threat_model.tm.name,
                    all_detailed_threats=all_detailed_threats
                )
                navigator_generator.save_layer_to_file(str(navigator_output_file))
                logging.info(f"ATT&CK Navigator layer generated for {model_name} at {navigator_output_file}")
            except Exception as e:
                logging.error(f"❌ Failed to generate ATT&CK Navigator layer for {model_name}: {e}")

            try:
                all_detailed_threats = get_enriched_threats(threat_model)
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
