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
import logging
from typing import List, Dict, Any, Optional
import base64
import datetime
import zipfile
import shutil
import tempfile
from io import BytesIO
import json
from pathlib import Path
import datetime
import subprocess
import re
import glob

# Hardcoded configuration values (previously from config.py)
TIMESTAMP = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
OUTPUT_BASE_DIR = Path("output") / TIMESTAMP
TMP_DIR = Path("output") / "tmp"

# Filename templates
HTML_REPORT_FILENAME_TPL = "stride_mitre_report_{timestamp}.html"
JSON_REPORT_FILENAME_TPL = "mitre_analysis_{timestamp}.json"
DOT_DIAGRAM_FILENAME_TPL = "tm_diagram_{timestamp}.dot"
SVG_DIAGRAM_FILENAME_TPL = "tm_diagram_{timestamp}.svg"
HTML_DIAGRAM_FILENAME_TPL = "tm_diagram_{timestamp}.html"
JSON_NAVIGATOR_FILENAME_TPL = "attack_navigator_layer_{timestamp}.json"

from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.core.mitre_mapping_module import MitreMapping
from threat_analysis.severity_calculator_module import SeverityCalculator
from threat_analysis.generation.report_generator import ReportGenerator
from threat_analysis.generation.diagram_generator import DiagramGenerator
from threat_analysis.generation.attack_navigator_generator import AttackNavigatorGenerator
from threat_analysis.generation.stix_generator import StixGenerator
from threat_analysis.generation.attack_flow_generator import AttackFlowGenerator
from threat_analysis.core.model_validator import ModelValidator
from pathlib import Path
from threat_analysis.core.cve_service import CVEService
from threat_analysis.generation.graphviz_to_json_metadata import GraphvizToJsonMetadataConverter

PROJECT_ROOT = Path(__file__).resolve().parents[2]

class ThreatModelService:
    def __init__(self):
        self.mitre_mapping = MitreMapping(threat_model_path="")
        self.severity_calculator = SeverityCalculator()
        self.diagram_generator = DiagramGenerator()
        
        cve_definitions_path = PROJECT_ROOT / "cve_definitions.yml"
        self.cve_service = CVEService(
            PROJECT_ROOT, cve_definitions_path, is_path_explicit=False
        )
        self.report_generator = ReportGenerator(
            self.severity_calculator, 
            self.mitre_mapping,
            implemented_mitigations_path=None, 
            cve_service=self.cve_service
        )
        self.stix_generator = None 
        self.element_positions = {}

    def _generate_positions_from_graphviz(self, threat_model):
        """
        Generates element positions by using the Graphviz JSON output.
        """
        print("--- [DEBUG V5] ENTERING _generate_positions_from_graphviz ---")
        logging.info("Generating layout positions using Graphviz JSON...")

        try:
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            if not dot_code:
                return {}

            result = subprocess.run(
                ["dot", "-Tjson"],
                input=dot_code,
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=True
            )
            graphviz_json = json.loads(result.stdout)

            converter = GraphvizToJsonMetadataConverter()
            positions = converter.convert(graphviz_json, threat_model)
            
            logging.info("Successfully generated positions from Graphviz JSON.")
            return positions

        except (subprocess.CalledProcessError, json.JSONDecodeError, Exception) as e:
            logging.error(f"An unexpected error occurred in _generate_positions_from_graphviz: {e}", exc_info=True)
            if isinstance(e, subprocess.CalledProcessError):
                logging.error(f"Stderr: {e.stderr}")
            return {}
            
    def _get_element_name(self, element):
        if hasattr(element, 'name'):
            return element.name
        elif isinstance(element, dict) and 'name' in element:
            return element['name']
        elif isinstance(element, str):
            return element
        return "Unknown"

    def check_version_compatibility(self, markdown_path: str, metadata_path: str) -> bool:
        try:
            with open(markdown_path, 'r') as f:
                markdown_content = f.read()
            markdown_version = "1.0"
            markdown_version_id = "unknown"
            for line in markdown_content.split('\n'):
                if line.startswith('# Version:'):
                    markdown_version = line.replace('# Version:', '').strip()
                elif line.startswith('# Version ID:'):
                    markdown_version_id = line.replace('# Version ID:', '').strip()
                    break
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            metadata_version = metadata.get('version', '1.0')
            metadata_version_id = metadata.get('version_id', 'unknown')
            if markdown_version != metadata_version:
                logging.warning(f"Version mismatch: Markdown {markdown_version} vs Metadata {metadata_version}")
                return False
            if markdown_version_id != metadata_version_id:
                logging.warning(f"Version ID mismatch: Markdown {markdown_version_id} vs Metadata {metadata_version_id}")
                return False
            logging.info(f"Version compatibility check passed: {markdown_version} ({markdown_version_id})")
            return True
        except Exception as e:
            logging.error(f"Error checking version compatibility: {e}")
            return False

    def get_element_positions(self):
        return self.element_positions

    def save_model_with_metadata(self, markdown_content: str, output_path: str, positions_data: Optional[dict] = None):
        version = "1.0"
        last_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        version_id = f"{version}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        version_info = f"# Version: {version}\n# Version ID: {version_id}\n# Last Updated: {last_updated}\n\n"
        if not markdown_content.startswith('# Version:'):
            markdown_content = version_info + markdown_content
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        
        element_positions = {}
        if positions_data:
            element_positions = positions_data
        else:
            # Fallback to generate positions from Graphviz if no positions_data provided
            threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name="SavedThreatModel",
                model_description="Model saved with metadata",
                cve_service=self.cve_service,
                validate=True
            )
            if threat_model:
                element_positions = self._generate_positions_from_graphviz(threat_model)
        
        metadata = {
            "version": version,
            "version_id": version_id,
            "last_updated": last_updated,
            "model_file": os.path.basename(output_path),
            "positions": element_positions
        }
        metadata_path = output_path.replace('.md', '_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        return metadata_path

    def _merge_with_ui_positions(self, base_positions: dict, ui_positions: dict) -> dict:
        if 'boundaries' in ui_positions:
            for boundary_name, ui_pos in ui_positions['boundaries'].items():
                if boundary_name in base_positions['boundaries']:
                    base_positions['boundaries'][boundary_name].update({
                        'x': ui_pos.get('x', 0),
                        'y': ui_pos.get('y', 0),
                        'width': ui_pos.get('width', 0),
                        'height': ui_pos.get('height', 0)
                    })
        if isinstance(ui_positions, dict) and 'actors' in ui_positions:
            for actor_name, ui_pos in ui_positions['actors'].items():
                if actor_name in base_positions['actors']:
                    base_positions['actors'][actor_name].update({
                        'x': ui_pos.get('x', 0),
                        'y': ui_pos.get('y', 0)
                    })
        if isinstance(ui_positions, dict) and 'servers' in ui_positions:
            for server_name, ui_pos in ui_positions['servers'].items():
                if server_name in base_positions['servers']:
                    base_positions['servers'][server_name].update({
                        'x': ui_pos.get('x', 0),
                        'y': ui_pos.get('y', 0)
                    })
        if 'dataflows' in ui_positions:
            for df_name, ui_pos in ui_positions['dataflows'].items():
                if df_name in base_positions['dataflows']:
                    base_positions['dataflows'][df_name]['points'] = ui_pos.get('points', [])
        return base_positions

    def markdown_to_json_for_gui(self, markdown_content: str):
        """
        Converts markdown content to a JSON structure suitable for the GUI.
        """
        if not markdown_content:
            raise ValueError("Markdown content is empty")

        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name="TempModelForConversion",
            model_description="Temporary model for GUI conversion",
            cve_service=self.cve_service,
            validate=False,
        )
        if not threat_model:
            raise RuntimeError("Failed to create threat model from markdown")

        model_json = {
            "boundaries": [],
            "actors": [],
            "servers": [],
            "data": [],
            "dataflows": [],
        }
        
        element_to_id = {}

        for name, b_info in threat_model.boundaries.items():
            boundary_obj = b_info['boundary']
            b_id = str(id(boundary_obj))
            element_to_id[boundary_obj] = b_id
            
            parent_id = None
            if hasattr(boundary_obj, 'inBoundary') and boundary_obj.inBoundary:
                parent_id = element_to_id.get(boundary_obj.inBoundary)

            model_json["boundaries"].append({
                "id": b_id,
                "name": name,
                "type": "BOUNDARY",
                "parentId": parent_id,
                "description": b_info.get('description', ''),
                "isTrusted": b_info.get('isTrusted', False),
                "isFilled": b_info.get('isFilled', False),
                "lineStyle": b_info.get('line_style', 'solid'),
                "color": b_info.get('color', 'lightgray'),
            })

        for actor_info in threat_model.actors:
            actor_obj = actor_info['object']
            a_id = str(id(actor_obj))
            element_to_id[actor_obj] = a_id

            parent_id = None
            if actor_info.get('boundary'):
                parent_id = element_to_id.get(actor_info['boundary'])

            model_json["actors"].append({
                "id": a_id,
                "name": actor_info['name'],
                "parentId": parent_id,
                "description": actor_info.get('description', ''),
            })

        for server_info in threat_model.servers:
            server_obj = server_info['object']
            s_id = str(id(server_obj))
            element_to_id[server_obj] = s_id

            parent_id = None
            if server_info.get('boundary'):
                parent_id = element_to_id.get(server_info['boundary'])

            model_json["servers"].append({
                "id": s_id,
                "name": server_info['name'],
                "parentId": parent_id,
                "description": server_info.get('description', ''),
                "os": server_info.get('os', ''),
                "stereotype": server_info.get('type', 'server'),
            })

        for name, data_obj in threat_model.data_objects.items():
            d_id = str(id(data_obj))
            element_to_id[data_obj] = d_id
            
            classification_obj = getattr(data_obj, 'classification', 'public')
            classification_val = str(getattr(classification_obj, 'name', classification_obj)).lower()

            model_json["data"].append({
                "id": d_id,
                "name": name,
                "description": getattr(data_obj, 'description', ''),
                "classification": classification_val,
            })

        for df in threat_model.dataflows:
            df_id = str(id(df))
            
            from_name = getattr(df.source, 'name', None)
            to_name = getattr(df.sink, 'name', None)

            if from_name and to_name:
                data_name = ""
                # df.data is a list of Data objects. We'll take the name of the first one for the GUI.
                if hasattr(df, 'data') and df.data:
                    try:
                        # A DataSet is iterable, not subscriptable.
                        first_data_obj = next(iter(df.data))
                        if hasattr(first_data_obj, 'name'):
                            data_name = first_data_obj.name
                    except StopIteration:
                        # DataSet is empty
                        pass
                
                properties = {
                    "name": getattr(df, 'name', f"{from_name}_to_{to_name}"),
                    "protocol": getattr(df, 'protocol', None),
                    "description": getattr(df, 'description', ''),
                    "color": getattr(df, 'color', '#000000'),
                    "data": data_name,
                    "isEncrypted": getattr(df, 'is_encrypted', False) or getattr(df, 'isEncrypted', False),
                    "isAuthenticated": getattr(df, 'is_authenticated', False) or getattr(df, 'authenticatedWith', False),
                }

                model_json["dataflows"].append({
                    "id": df_id,
                    "from": from_name,
                    "to": to_name,
                    "properties": properties
                })

        return model_json

    def _extract_graph_metadata_for_frontend(self, threat_model) -> dict:
        """
        Extracts a simplified graph structure (nodes and edges with their connections)
        suitable for frontend visualization and interaction.
        """
        graph_metadata = {
            "nodes": {},
            "edges": {}
        }
        
        # Helper to sanitize names consistently with DiagramGenerator
        def _sanitize_name_for_id(name: str) -> str:
            if not name:
                return "unnamed"
            sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', str(name))
            if sanitized and sanitized[0].isdigit():
                sanitized = f"_{sanitized}"
            return sanitized or "unnamed"

        # Process nodes (Actors, Servers, Boundaries)
        # Note: Boundaries are handled as clusters in Graphviz, but also have "hidden nodes"
        # for connecting edges. The main "node" will be the cluster itself.
        # We need to ensure we capture actual interactive nodes.

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

            # Check if source/sink are boundaries and adjust to use their hidden nodes
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
            
            # Construct the edge ID as it will appear in the SVG
            # Use actual element names for consistency with DiagramGenerator's robust ID generation
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
            
            # Add connections to nodes (using hidden nodes for boundaries)
            if sanitized_source in graph_metadata["nodes"]:
                graph_metadata["nodes"][sanitized_source]["connections"].append(edge_id)
            if sanitized_sink in graph_metadata["nodes"]:
                graph_metadata["nodes"][sanitized_sink]["connections"].append(edge_id)

            # If the source or sink was a boundary, also add the connection to the actual boundary cluster
            if is_source_boundary:
                actual_boundary_id = _sanitize_name_for_id(source_name)
                if actual_boundary_id in graph_metadata["nodes"]:
                    graph_metadata["nodes"][actual_boundary_id]["connections"].append(edge_id)
            if is_sink_boundary:
                actual_boundary_id = _sanitize_name_for_id(sink_name)
                if actual_boundary_id in graph_metadata["nodes"]:
                    graph_metadata["nodes"][actual_boundary_id]["connections"].append(edge_id)
        
        return graph_metadata

    def update_diagram_logic(self, markdown_content: str, submodels: list | None = None):
        logging.info("update_diagram_logic: Starting diagram update.")
        if not markdown_content:
            logging.error("update_diagram_logic: Markdown content is empty.")
            raise ValueError("Markdown content is empty")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_md_path = os.path.join(tmpdir, "live_model.md")
            with open(tmp_md_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            logging.info(f"Saved live markdown to {tmp_md_path}")

            threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name="WebThreatModel",
                model_description="Live-updated threat model",
                cve_service=self.cve_service,
                validate=False,
            )
            if not threat_model:
                raise RuntimeError("Failed to create threat model")
            
            if submodels:
                for submodel_data in submodels:
                    sub_path = submodel_data['path']
                    sub_content = submodel_data['content']
                    sub_model = create_threat_model(
                        markdown_content=sub_content,
                        model_name=os.path.basename(sub_path),
                        model_description=f"Submodel for {sub_path}",
                        cve_service=self.cve_service,
                        validate=False
                    )
                    if sub_model:
                        threat_model.sub_models.append(sub_model)

            validator = ModelValidator(threat_model)
            errors = validator.validate()
            if errors:
                logging.warning(f"update_diagram_logic: Model validation failed with errors: {errors}")
                error_html = "<div class='validation-errors'><h3>Validation Errors:</h3><ul>"
                for error in errors:
                    error_html += f"<li>{error}</li>"
                error_html += "</ul></div>"
                return {
                    "diagram_html": error_html,
                    "diagram_svg": "",
                    "legend_html": "",
                    "validation_errors": errors
                }

            self.element_positions = self._generate_positions_from_graphviz(threat_model)
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            #logging.info(
            #    f"Generated DOT code (first 500 chars): \n{dot_code[:500]}..."
            #)
            if not dot_code:
                raise RuntimeError("Failed to generate DOT code from model")

            temp_svg_path = os.path.join(tmpdir, "live_preview.svg")
            svg_path = self.diagram_generator.generate_diagram_from_dot(
                dot_code, temp_svg_path, "svg"
            )
            logging.info(f"update_diagram_logic: SVG generated at {svg_path}")
            if not svg_path or not os.path.exists(svg_path):
                raise RuntimeError("Failed to generate SVG diagram")

            with open(svg_path, "r", encoding="utf-8") as f:
                svg_content = f.read()

            # Post-process SVG to fix image paths
            static_path_base = str(PROJECT_ROOT / 'threat_analysis' / 'server' / 'static')
            svg_content = svg_content.replace(static_path_base, '/static')
            
            legend_html = self.diagram_generator._generate_legend_html(threat_model)
            full_html = self.diagram_generator._create_complete_html(
                svg_content, legend_html, threat_model
            )
            
            graph_metadata = self._extract_graph_metadata_for_frontend(threat_model)
            
            logging.debug(f"Generated graph_metadata for frontend: {json.dumps(graph_metadata, indent=2)}")
            
            logging.info("update_diagram_logic: Successfully updated diagram.")
            return {
                "diagram_html": full_html,
                "diagram_svg": svg_content,
                "legend_html": legend_html,
                "graph_metadata": graph_metadata,
            }

    def export_files_logic(self, markdown_content: str, export_format: str):
        logging.info(f"Entering export_files_logic function for format: {export_format}")
        if not markdown_content or not export_format:
            raise ValueError("Missing markdown content or export format")
        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name="ExportedThreatModel",
            model_description="Exported from web interface",
            cve_service=self.cve_service,
            validate=True,
        )
        if not threat_model:
            raise RuntimeError("Failed to create or validate threat model")
        validator = ModelValidator(threat_model)
        errors = validator.validate()
        if errors:
            raise ValueError("Validation failed: " + ", ".join(errors))
        os.makedirs(OUTPUT_BASE_DIR, exist_ok=True)
        if export_format == "svg":
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            output_filename = "diagram.svg"
            output_path = os.path.join(
                OUTPUT_BASE_DIR, output_filename
            )
            # Use custom SVG generator for export to get better quality with SVG icons
            generated_path = self.diagram_generator.generate_custom_svg_export(
                dot_code, output_path
            )
            if not generated_path:
                raise RuntimeError("Failed to generate SVG file")
            return output_path, output_filename
        elif export_format == "diagram":
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            svg_path_temp = os.path.join(
                OUTPUT_BASE_DIR, "temp_diagram.svg"
            )
            # Use custom SVG generator for better quality in diagram export
            self.diagram_generator.generate_custom_svg_export(
                dot_code, svg_path_temp
            )
            output_filename = "diagram.html"
            output_path = os.path.join(
                OUTPUT_BASE_DIR, output_filename
            )
            graph_metadata = self._extract_graph_metadata_for_frontend(threat_model)
            self.diagram_generator._generate_html_with_legend(
                Path(svg_path_temp), Path(output_path), threat_model, graph_metadata
            )
            return output_path, output_filename
        elif export_format == "report":
            grouped_threats = threat_model.process_threats()
            output_filename = "threat_report.html"
            output_path = os.path.join(
                OUTPUT_BASE_DIR, output_filename
            )
            self.report_generator.generate_html_report(
                threat_model, grouped_threats, Path(output_path)
            )
            return output_path, output_filename
        elif export_format == "markdown":
            output_filename = "threat_model.md"
            output_path = os.path.join(
                OUTPUT_BASE_DIR, output_filename
            )
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            return output_path, output_filename
        else:
            raise ValueError("Invalid export format")

    def generate_full_project_export(self, markdown_content: str, export_path: str, submodels: list | None = None):
        logging.info("Entering generate_full_project_export function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        if submodels:
            logging.info("--- Starting Project-Based Generation (Server Mode) ---")
            with tempfile.TemporaryDirectory() as tmp_project_dir:
                project_path = Path(tmp_project_dir)
                
                # Write main model file
                main_md_path = project_path / "main.md"
                with open(main_md_path, "w", encoding="utf-8") as f:
                    f.write(markdown_content)

                # Write all sub-model files
                for submodel in submodels:
                    submodel_path_str = submodel.get('path', '').lstrip('./\\')
                    if not submodel_path_str:
                        continue
                    
                    submodel_path = project_path / submodel_path_str
                    submodel_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(submodel_path, "w", encoding="utf-8") as f:
                        f.write(submodel['content'])
                
                self.report_generator.generate_project_reports(project_path, Path(export_path))

                # Create a summary of generated files for the response
                generated_files = {}
                for root, _, files in os.walk(export_path):
                    for file in files:
                        file_key = os.path.splitext(file)[0]
                        generated_files[file_key] = os.path.join(root, file)
                
                return {
                    "reports": generated_files,
                    "diagrams": {} # Simplified for project view
                }

        else:
            # Single-file generation (unchanged)
            logging.info("--- Starting Single-File Generation (Server Mode) ---")
            threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name="ExportedThreatModel",
                model_description="Exported from web interface",
                cve_service=self.cve_service,
                validate=True,
            )
            if not threat_model:
                raise RuntimeError("Failed to create or validate threat model")

            validator = ModelValidator(threat_model)
            errors = validator.validate()
            if errors:
                raise ValueError("Validation failed: " + ", ".join(errors))

            markdown_filename = "threat_model.md"
            markdown_filepath = os.path.join(export_path, markdown_filename)
            with open(markdown_filepath, "w", encoding="utf-8") as f:
                f.write(markdown_content)

            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            svg_filename = "tm_diagram.svg"
            svg_filepath = os.path.join(export_path, svg_filename)
            self.diagram_generator.generate_diagram_from_dot(
                dot_code, svg_filepath, format="svg"
            )

            html_diagram_filename = "tm_diagram.html"
            html_diagram_filepath = os.path.join(
                export_path, html_diagram_filename
            )
            graph_metadata = self._extract_graph_metadata_for_frontend(threat_model)
            self.diagram_generator._generate_html_with_legend(
                Path(svg_filepath), Path(html_diagram_filepath), threat_model, graph_metadata
            )

            grouped_threats = threat_model.process_threats()
            html_report_filename = "stride_mitre_report.html"
            html_report_filepath = os.path.join(export_path, html_report_filename)
            self.report_generator.generate_html_report(
                threat_model, grouped_threats, Path(html_report_filepath)
            )

            json_analysis_filename = "mitre_analysis.json"
            json_analysis_filepath = os.path.join(
                export_path, json_analysis_filename
            )
            self.report_generator.generate_json_export(
                threat_model, grouped_threats, Path(json_analysis_filepath)
            )

            all_detailed_threats = threat_model.get_all_threats_details()
            navigator_generator = AttackNavigatorGenerator(
                threat_model_name=str(threat_model.tm.name),
                all_detailed_threats=all_detailed_threats
            )
            navigator_filename = JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=TIMESTAMP)
            navigator_filepath = os.path.join(export_path, navigator_filename)
            navigator_generator.save_layer_to_file(navigator_filepath)

            stix_generator_instance = StixGenerator(
                threat_model=threat_model,
                all_detailed_threats=all_detailed_threats
            )
            stix_bundle = stix_generator_instance.generate_stix_bundle()
            stix_filename = f"stix_report_{TIMESTAMP}.json"
            stix_filepath = os.path.join(export_path, stix_filename)
            with open(stix_filepath, "w", encoding="utf-8") as f:
                json.dump(stix_bundle, f, indent=4)

            return {
                "reports": {
                    "html": html_report_filepath,
                    "json": json_analysis_filepath,
                    "stix": stix_filepath,
                },
                "diagrams": {
                    "svg": svg_filepath,
                    "html": html_diagram_filepath,
                    "navigator": navigator_filepath,
                }
            }

    def export_all_files_logic(self, markdown_content: str, submodels: list | None = None):
        logging.info("Entering export_all_files_logic function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        export_dir_name = f"export_{timestamp}"
        export_path = os.path.join(OUTPUT_BASE_DIR, export_dir_name)
        os.makedirs(export_path, exist_ok=True)

        result = self.generate_full_project_export(markdown_content, export_path, submodels=submodels)

        threat_model_temp = create_threat_model(markdown_content=markdown_content, model_name="temp", model_description="temp", cve_service=self.cve_service)
        element_positions = self._generate_positions_from_graphviz(threat_model_temp) if threat_model_temp else {}
        
        version = "1.0"
        version_id = f"{version}-{timestamp.replace('-', '').replace(':', '').replace('_', '')}"
        last_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        metadata = {
            "version": version,
            "version_id": version_id,
            "last_updated": last_updated,
            "model_file": "threat_model.md",
            "positions": element_positions
        }
        
        metadata_filename = "element_positions.json"
        metadata_filepath = os.path.join(export_path, metadata_filename)
        with open(metadata_filepath, 'w') as f:
            json.dump(metadata, f, indent=2)
        logging.info(f"Element positions metadata with synchronized versioning saved to: {metadata_filepath}")

        zip_buffer = BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", zipfile.ZIP_DEFLATED
        ) as zf:
            for root, _, files in os.walk(export_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, export_path)
                    zf.write(
                        file_path,
                        arcname
                    )
        zip_buffer.seek(0)

        shutil.rmtree(export_path)

        return zip_buffer, timestamp

    def export_navigator_stix_logic(self, markdown_content: str, submodels: list | None = None):
        logging.info("Entering export_navigator_stix_logic function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        export_dir_name = f"navigator_stix_export_{timestamp}"
        export_path = os.path.join(OUTPUT_BASE_DIR, export_dir_name)
        os.makedirs(export_path, exist_ok=True)

        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name="ExportedThreatModel",
            model_description="Exported from web interface",
            cve_service=self.cve_service,
            validate=True,
        )
        if not threat_model:
            raise RuntimeError("Failed to create or validate threat model")

        if submodels:
            for submodel_data in submodels:
                sub_model = create_threat_model(
                    markdown_content=submodel_data['content'],
                    model_name=os.path.basename(submodel_data['path']),
                    model_description=f"Submodel for {submodel_data['path']}",
                    cve_service=self.cve_service,
                    validate=False
                )
                if sub_model:
                    threat_model.sub_models.append(sub_model)

        validator = ModelValidator(threat_model)
        errors = validator.validate()
        if errors:
            raise ValueError("Validation failed: " + ", ".join(errors))

        all_detailed_threats = threat_model.get_all_threats_details()
        navigator_generator = AttackNavigatorGenerator(
            threat_model_name=str(threat_model.tm.name),
            all_detailed_threats=all_detailed_threats
        )
        navigator_filename = JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=timestamp)
        navigator_filepath = os.path.join(export_path, navigator_filename)
        navigator_generator.save_layer_to_file(navigator_filepath)

        stix_generator_instance = StixGenerator(
            threat_model=threat_model,
            all_detailed_threats=all_detailed_threats
        )
        stix_bundle = stix_generator_instance.generate_stix_bundle()
        stix_filename = f"stix_report_{timestamp}.json"
        stix_filepath = os.path.join(export_path, stix_filename)
        with open(stix_filepath, "w", encoding="utf-8") as f:
            json.dump(stix_bundle, f, indent=4)

        zip_buffer = BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", zipfile.ZIP_DEFLATED
        ) as zf:
            zf.write(navigator_filepath, os.path.basename(navigator_filepath))
            zf.write(stix_filepath, os.path.basename(stix_filepath))
        zip_buffer.seek(0)

        shutil.rmtree(export_path)

        return zip_buffer, timestamp
    
    def export_attack_flow_logic(self, markdown_content: str):
        logging.info("Entering export_attack_flow_logic function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        with tempfile.TemporaryDirectory() as temp_export_dir:
            threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name="ExportedThreatModel",
                model_description="Exported from web interface",
                cve_service=self.cve_service,
                validate=True,
            )
            if not threat_model:
                raise RuntimeError("Failed to create or validate threat model")

            threat_model.process_threats()
            all_detailed_threats = threat_model.get_all_threats_details()

            attack_flow_generator = AttackFlowGenerator(
                threats=all_detailed_threats,
                model_name=str(threat_model.tm.name)
            )
            attack_flow_generator.generate_and_save_flows(temp_export_dir)

            afb_dir = os.path.join(temp_export_dir, "afb")
            if not os.path.exists(afb_dir) or not os.listdir(afb_dir):
                logging.warning("No attack flow files were generated.")
                return None, None

            zip_buffer = BytesIO()
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(afb_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, afb_dir)
                        zf.write(file_path, arcname)
            zip_buffer.seek(0)

            return zip_buffer, timestamp

    def load_project(self, project_path: str):
        """
        Loads all threat models from a project directory.
        """
        logging.info(f"Loading project from path: {project_path}")
        models = []
        if project_path and os.path.isdir(project_path):
            model_files = glob.glob(os.path.join(project_path, '**', 'main.md'), recursive=True)
            model_files.extend(glob.glob(os.path.join(project_path, '**', 'model.md'), recursive=True))

            if not model_files:
                logging.warning(f"No model files ('main.md' or 'model.md') found in {project_path}")
                # Optional: return a default empty model if no files are found
                models.append({
                    "path": "main.md",
                    "content": "# Threat Model: New Project\n\n"
                })
                return models

            for model_file in model_files:
                try:
                    with open(model_file, "r", encoding="utf-8") as f:
                        content = f.read()
                        models.append({
                            "path": os.path.relpath(model_file, project_path),
                            "content": content
                        })
                except Exception as e:
                    logging.error(f"Error reading model file {model_file}: {e}")
            
            logging.info(f"Loaded {len(models)} model(s) from project.")

        else:
            logging.error(f"Project path not found or not a directory: {project_path}")
            # Return a default model so the UI doesn't break
            models.append({
                "path": "main.md",
                "content": "# Threat Model: New Project\n\n## Description\nProject path not found. Starting with a blank model."
            })
            
        return models

    def resolve_submodels(self, main_model_content: str, project_files: list[dict]):
        """
        Recursively parses a main model for sub_model_path references and resolves them
        against a provided file list.

        Args:
            main_model_content: The string content of the main threat model.
            project_files: A list of dictionaries, where each dict represents a file and has
                           'path' and 'content' keys.

        Returns:
            A list of dictionaries for each resolved sub-model, containing 'path' and 'content'.
        """
        logging.info("Starting recursive sub-model resolution...")
        
        file_map = {file['path'].replace('\\\\', '/'): file['content'] for file in project_files}
        resolved_submodels = {}  # Use a dict to avoid duplicates, mapping path to content
        
        # Regex to find lines like: sub_model_path="path/to/model.md"
        sub_model_regex = re.compile(r'sub_model_path\s*=\s*"(.*?)"')

        def find_and_resolve(content: str):
            """Helper function to find paths in content and recurse."""
            found_paths = sub_model_regex.findall(content)
            
            for path in found_paths:
                # Normalize path separators for consistency
                normalized_path = os.path.normpath(path).replace('\\\\', '/')
                
                # If we haven't processed this sub-model yet
                if normalized_path not in resolved_submodels:
                    if normalized_path in file_map:
                        logging.info(f"Resolved sub-model at path: {normalized_path}")
                        sub_model_content = file_map[normalized_path]
                        resolved_submodels[normalized_path] = sub_model_content
                        
                        # Recurse: Look for sub-models within this newly found sub-model
                        find_and_resolve(sub_model_content)
                    else:
                        logging.warning(f"Could not find sub-model for path: {normalized_path} in the provided project files.")

        # Start the process with the main model's content
        find_and_resolve(main_model_content)
        
        # Convert the dictionary of resolved models back to a list
        final_list = [{"path": path, "content": content} for path, content in resolved_submodels.items()]
        logging.info(f"Finished resolution. Found {len(final_list)} unique sub-models.")
        return final_list
