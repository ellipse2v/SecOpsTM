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
from .utils import extract_name_from_object, get_target_name

project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.generation.stix_generator import StixGenerator
from threat_analysis.generation.attack_navigator_generator import AttackNavigatorGenerator
from threat_analysis.core.models_module import ThreatModel
from threat_analysis.core.mitre_mapping_module import MitreMapping

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
                 cve_service: Optional[CVEService] = None):
        self.severity_calculator = severity_calculator
        self.mitre_mapping = mitre_mapping
        self.env = Environment(loader=FileSystemLoader(Path(__file__).parent.parent / 'templates'), extensions=['jinja2.ext.do'])
        self.implemented_mitigations = load_implemented_mitigations(implemented_mitigations_path)
        self.all_detailed_threats = []
        self.cve_service = cve_service if cve_service else CVEService(project_root)

    def generate_html_report(self, threat_model, grouped_threats: Dict[str, List], 
                             output_file: Path = Path("stride_mitre_report.html"), 
                             all_detailed_threats: Optional[List[Dict]] = None,
                             report_title: str = "🛡️ STRIDE & MITRE ATT&CK Threat Model Report") -> Path:
        """Generates a complete HTML report with MITRE ATT&CK"""
        total_threats_analyzed = threat_model.mitre_analysis_results.get('total_threats', 0)
        total_mitre_techniques_mapped = threat_model.mitre_analysis_results.get('mitre_techniques_count', 0)
        stride_distribution = threat_model.mitre_analysis_results.get('stride_distribution', {})

        if all_detailed_threats is None:
            all_detailed_threats = self._get_all_threats_with_mitre_info(grouped_threats, threat_model)
        
        self.all_detailed_threats = all_detailed_threats
        summary_stats = self.generate_summary_stats(all_detailed_threats)
        stride_categories = sorted(list(set(threat['stride_category'] for threat in all_detailed_threats)))
        
        unique_business_values = self._get_all_business_values(threat_model)
        
        EXCLUDE_TARGETS = ["Unspecified →", "Unspecified", "→"]
        unique_targets = sorted(list(set(threat['target'] for threat in all_detailed_threats if threat.get('target') and threat.get('target') not in EXCLUDE_TARGETS)))

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
            implemented_mitigation_ids=self.implemented_mitigations
        )

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

        return output_file

    def generate_json_export(self, threat_model, grouped_threats: Dict[str, List],
                             output_file: Path = Path("mitre_analysis.json")) -> Path:
        """Generates a JSON export of the analysis data"""
        export_data = {
            "analysis_date": datetime.now().isoformat(),
            "architecture": threat_model.tm.name,
            "threats_detected": sum(len(threats) for threats in grouped_threats.values()),
            "threat_types": list(grouped_threats.keys()),
            "mitre_mapping": self.mitre_mapping.capec_to_mitre_map,
            "severity_levels": {
                "CRITICAL": "9.0-10.0",
                "HIGH": "7.5-8.9",
                "MEDIUM": "6.0-7.4",
                "LOW": "4.0-5.9",
                "INFORMATIONAL": "1.0-3.9"
            },
            "detailed_threats": self._export_detailed_threats(grouped_threats, threat_model)
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

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
            webbrowser.open(html_file)
            return True
        except Exception as e:
            return False
    def _export_detailed_threats(self, grouped_threats: Dict[str, List], threat_model: ThreatModel) -> List[Dict[str, Any]]:
        return self._get_all_threats_with_mitre_info(grouped_threats, threat_model)

    def _get_all_threats_with_mitre_info(self, grouped_threats: Dict[str, List], threat_model: ThreatModel) -> List[Dict[str, Any]]:
        """Gathers detailed information for all threats, including MITRE ATT&CK mapping and severity."""
        all_detailed_threats = []
        
        for threat_type, threats in grouped_threats.items():
            for item in threats:
                if isinstance(item, tuple) and len(item) == 2:
                    threat, target = item
                    target_name = self._get_target_name_for_severity_calc(target)
                    threat_description = getattr(threat, 'description', f"Threat of type {threat_type} affecting {target_name}")
                    stride_category = getattr(threat, 'stride_category', threat_type)
                else:
                    continue

                data_classification = None
                if hasattr(threat, 'target') and hasattr(threat.target, 'data') and hasattr(threat.target.data, 'classification'):
                    data_classification = threat.target.data.classification.name
                
                threat_impact = getattr(threat, 'impact', None)
                threat_likelihood = getattr(threat, 'likelihood', None)

                # Get business_value of the target
                business_value = None
                # Check if target is a pytm object (Actor, Server, Boundary)
                if hasattr(target, 'name'):
                    # Search in threat_model's stored components
                    # Actors
                    for actor_data in threat_model.actors:
                        if actor_data.get('object') == target:
                            business_value = actor_data.get('business_value')
                            break
                    # Servers
                    if not business_value:
                        for server_data in threat_model.servers:
                            if server_data.get('object') == target:
                                business_value = server_data.get('business_value')
                                break
                    # Boundaries
                    if not business_value:
                        for boundary_data in threat_model.boundaries.values():
                            if boundary_data.get('boundary') == target:
                                business_value = boundary_data.get('business_value')
                                break
                
                severity_info = self.severity_calculator.get_severity_info(stride_category, target_name, classification=data_classification, impact=threat_impact, likelihood=threat_likelihood)
                
                threat_dict = {
                    "description": threat_description,
                    "stride_category": stride_category,
                    "capec_ids": getattr(threat, 'capec_ids', [])
                }
                mapping_results = self.mitre_mapping.map_threat_to_mitre(threat_dict)
                mitre_techniques = mapping_results.get('techniques', [])
                capecs = mapping_results.get('capecs', [])

                cve_ids_for_threat = set()
                
                target_names_to_check = []
                if isinstance(target, tuple) and len(target) == 2:
                    source_name = extract_name_from_object(target[0])
                    sink_name = extract_name_from_object(target[1])
                    if source_name != "Unspecified": target_names_to_check.append(source_name)
                    if sink_name != "Unspecified": target_names_to_check.append(sink_name)
                else:
                    target_names_to_check.append(target_name)

                for name_to_check in target_names_to_check:
                    equipment_cves = self.cve_service.get_cves_for_equipment(name_to_check)
                    if equipment_cves:
                        threat_capecs = {capec['capec_id'] for capec in capecs}
                        for cve_id in equipment_cves:
                            cve_capecs = self.cve_service.get_capecs_for_cve(cve_id.upper())
                            if threat_capecs.intersection(cve_capecs):
                                cve_ids_for_threat.add(cve_id)

                all_detailed_threats.append({
                    "type": threat_type,
                    "description": threat_description,
                    "target": target_name,
                    "severity": severity_info,
                    "mitre_techniques": mitre_techniques,
                    "stride_category": stride_category,
                    "capecs": capecs,
                    "cve": sorted(list(cve_ids_for_threat)),
                    "business_value": business_value
                })
        return all_detailed_threats

    def _get_target_name_for_severity_calc(self, target: Any) -> str:
        """Determines the target name for severity calculation, handling different target types."""
        return get_target_name(target)

    def generate_summary_stats(self, all_detailed_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generates summary statistics based on severity scores."""
        if not all_detailed_threats: return {}
        all_scores = [threat['severity']['score'] for threat in all_detailed_threats if 'severity' in threat and 'score' in threat['severity']]
        if not all_scores: return {}
        severity_distribution = {}
        for threat in all_detailed_threats:
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

        self.generate_html_report(
            threat_model=dummy_model,
            grouped_threats={},
            output_file=output_dir / "global_threat_report.html",
            all_detailed_threats=all_threats_details,
            report_title="🛡️ Global Project Threat Model Report"
        )
        logging.info(f"✅ Generated global project report with {len(all_threats_details)} total threats at {output_dir / 'global_threat_report.html'}")

    def generate_project_reports(self, project_path: Path, output_dir: Path) -> Optional[ThreatModel]:
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

        all_models = self._get_all_project_models(project_path)
        if not all_models:
            logging.error("No threat models found in the project. Aborting.")
            return None

        project_protocols, project_protocol_styles = self._aggregate_project_data(all_models)

        main_model_path = project_path / "main.md"
        main_threat_model = None
        try:
            with open(main_model_path, "r", encoding="utf-8") as f:
                markdown_content = f.read()
            main_threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name=main_model_path.stem,
                model_description=f"Threat model for {main_model_path.stem}",
                cve_service=self.cve_service,
                validate=True
            )
        except Exception as e:
            logging.error(f"Failed to create main threat model for project: {e}")

        if main_threat_model is None:
            logging.error("Main threat model could not be created. Aborting project report generation.")
            return None

        all_processed_models = []
        self._recursively_generate_reports(
            model_path=main_model_path,
            project_path=project_path,
            output_dir=output_dir,
            breadcrumb=[(main_threat_model.tm.name, f"{main_model_path.stem}_diagram.html")],
            project_protocols=project_protocols,
            project_protocol_styles=project_protocol_styles,
            all_project_models=all_processed_models,
            threat_model=main_threat_model
        )

        if all_processed_models:
            self.generate_global_project_report(all_processed_models, output_dir)

        return main_threat_model

    def _get_all_project_models(self, project_path: Path) -> List[ThreatModel]:
        """
        Recursively finds and parses all 'model.md' or 'main.md' files in a project directory.
        """
        all_models = []
        model_files = list(project_path.glob("**/model.md")) + list(project_path.glob("**/main.md"))

        for model_path in model_files:
            try:
                with open(model_path, "r", encoding="utf-8") as f:
                    markdown_content = f.read()

                threat_model = create_threat_model(
                    markdown_content=markdown_content,
                    model_name=model_path.stem,
                    model_description=f"Threat model for {model_path.stem}",
                    cve_service=self.cve_service,
                    validate=False
                )
                if threat_model:
                    all_models.append(threat_model)
            except Exception as e:
                logging.error(f"Error parsing model file {model_path}: {e}")
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

    def _recursively_generate_reports(self, model_path: Path, project_path: Path, output_dir: Path, breadcrumb: List[tuple[str, str]], project_protocols: set, project_protocol_styles: dict, all_project_models: List[ThreatModel], threat_model: Optional[ThreatModel] = None):
        """
        Recursively generates reports for each model in the project.
        """
        model_name = model_path.stem

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

            grouped_threats = threat_model.process_threats()
            all_project_models.append(threat_model)

            self.generate_html_report(threat_model, grouped_threats, output_dir / f"{model_name}_threat_report.html")
            self.generate_json_export(threat_model, grouped_threats, output_dir / f"{model_name}.json")
            self.generate_diagram_html(threat_model, output_dir, breadcrumb, project_protocols, project_protocol_styles)

            # Save markdown model and generate metadata for graphical editor
            md_output_path = output_dir / f"{model_name}.md"
            with open(md_output_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            
            diagram_generator = DiagramGenerator()
            diagram_generator.generate_metadata(threat_model, markdown_content, str(md_output_path))

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

            for server in threat_model.servers:
                if 'submodel' in server:
                    submodel_path_str = server['submodel']
                    try:
                        submodel_path = _validate_path_within_project(str(model_path.parent / submodel_path_str), base_dir=project_path)

                        if submodel_path.is_file():
                            submodel_relative_parent = Path(submodel_path_str).parent
                            sub_output_dir = output_dir / submodel_relative_parent
                            sub_output_dir.mkdir(parents=True, exist_ok=True)

                            sub_model_display_name = submodel_relative_parent.name if str(submodel_relative_parent) != '.' else submodel_path.stem
                            
                            # Create a relative link for the breadcrumb, ensuring it's relative to the project output root.
                            current_model_breadcrumb_path = Path(breadcrumb[-1][1])
                            current_model_dir = current_model_breadcrumb_path.parent
                            
                            submodel_rel_path = Path(submodel_path_str)
                            
                            # Combine the current model's directory with the submodel's relative path
                            # and then replace the filename to get the correct diagram link.
                            new_link_path_obj = (current_model_dir / submodel_rel_path).with_name(f"{submodel_rel_path.stem}_diagram.html")
                            
                            # Normalize the path to handle cases like "." or ".." and ensure forward slashes
                            breadcrumb_link = Path(os.path.normpath(str(new_link_path_obj))).as_posix()

                            new_breadcrumb = breadcrumb + [(sub_model_display_name, breadcrumb_link)]

                            self._recursively_generate_reports(
                                model_path=submodel_path,
                                project_path=project_path,
                                output_dir=sub_output_dir,
                                breadcrumb=new_breadcrumb,
                                project_protocols=project_protocols,
                                project_protocol_styles=project_protocol_styles,
                                all_project_models=all_project_models
                            )
                    except ValueError as e:
                        logging.warning(f"Skipping submodel referenced in '{model_path.name}' because it was not found: {e}")
                        continue
        except Exception as e:
            logging.error(f"Error processing model at {model_path}: {e}", exc_info=True)

    def generate_diagram_html(self, threat_model: ThreatModel, output_dir: Path, breadcrumb: List[tuple[str, str]], project_protocols: set, project_protocol_styles: dict):
        """
        Generates an HTML file containing just the diagram for navigation.
        """
        diagram_generator = DiagramGenerator()
        model_name = threat_model.tm.name

        dot_code = diagram_generator.generate_dot_file_from_model(threat_model, output_dir / f"{model_name}.dot", project_protocol_styles)
        if not dot_code:
            logging.error(f"Failed to generate DOT code for {model_name}")
            return

        svg_path = diagram_generator.generate_diagram_from_dot(dot_code, output_dir / f"{model_name}.svg", "svg")
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
        html = template.render(
            title=f"Diagram - {model_name}",
            svg_content=svg_content,
            breadcrumb=processed_breadcrumb,
            parent_link=parent_link,
            legend_html=legend_html,
            current_dir_depth=current_dir_depth, # Pass the depth to the template
            graph_metadata_json=json.dumps(graph_metadata)
        )

        diagram_html_path = output_dir / f"{model_name}_diagram.html"
        with open(diagram_html_path, "w", encoding="utf-8") as f:
            f.write(html)
        logging.info(f"Generated diagram HTML: {diagram_html_path}")