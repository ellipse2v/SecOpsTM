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
import base64
import datetime
import zipfile
import shutil
from io import BytesIO
import json
from threat_analysis import config

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

    def _extract_element_positions(self, threat_model):
        positions = {
            "boundaries": {},
            "actors": {},
            "servers": {},
            "dataflows": {}
        }
        for boundary_name, boundary_info in threat_model.boundaries.items():
            positions["boundaries"][boundary_name] = {
                "x": 0,
                "y": 0,
                "width": 0,
                "height": 0
            }
        for actor_info in threat_model.actors:
            actor_name = actor_info.get('name', 'Unknown')
            positions["actors"][actor_name] = {
                "x": 0,
                "y": 0,
                "boundary": actor_info.get('boundary_name', None)
            }
        for server_info in threat_model.servers:
            server_name = server_info.get('name', 'Unknown')
            positions["servers"][server_name] = {
                "x": 0,
                "y": 0,
                "boundary": server_info.get('boundary_name', None)
            }
        for dataflow in threat_model.dataflows:
            dataflow_name = dataflow.name
            positions["dataflows"][dataflow_name] = {
                "source": self._get_element_name(dataflow.source),
                "target": self._get_element_name(dataflow.sink),
                "points": []
            }
        return positions

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

    def save_model_with_metadata(self, markdown_content: str, output_path: str, positions_data: dict = None):
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
            # Fallback to extract positions if no positions_data provided (e.g., non-GUI save)
            threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name="SavedThreatModel",
                model_description="Model saved with metadata",
                cve_service=self.cve_service,
                validate=True
            )
            if threat_model:
                element_positions = self._extract_element_positions(threat_model)
        
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
                "parentId": parent_id,
                "description": b_info.get('description', ''),
                "isTrusted": b_info.get('isTrusted', False),
                "lineStyle": b_info.get('line_style', 'solid'),
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
            model_json["data"].append({
                "id": d_id,
                "name": name,
                "description": getattr(data_obj, 'description', ''),
                "classification": getattr(data_obj, 'classification', 'public'),
            })

        for df in threat_model.dataflows:
            df_id = str(id(df))
            
            from_id = element_to_id.get(df.source)
            to_id = element_to_id.get(df.sink)

            if from_id and to_id:
                model_json["dataflows"].append({
                    "id": df_id,
                    "name": df.name,
                    "from": from_id,
                    "to": to_id,
                    "protocol": df.protocol,
                    "description": getattr(df, 'description', ''),
                    "isEncrypted": getattr(df, 'is_encrypted', False),
                    "isAuthenticated": getattr(df, 'is_authenticated', False),
                })

        return model_json

    def update_diagram_logic(self, markdown_content: str):
        logging.info("update_diagram_logic: Starting diagram update.")
        if not markdown_content:
            logging.error("update_diagram_logic: Markdown content is empty.")
            raise ValueError("Markdown content is empty")
        tmp_md_path = os.path.join(config.TMP_DIR, "live_model.md")
        os.makedirs(config.TMP_DIR, exist_ok=True)
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
        self.element_positions = self._extract_element_positions(threat_model)
        dot_code = self.diagram_generator._generate_manual_dot(threat_model)
        logging.info(
            f"Generated DOT code (first 500 chars): \n{dot_code[:500]}..."
        )
        if not dot_code:
            raise RuntimeError("Failed to generate DOT code from model")
        temp_svg_path = os.path.join(config.TMP_DIR, "live_preview.svg")
        os.makedirs(os.path.dirname(temp_svg_path), exist_ok=True)
        svg_path = self.diagram_generator.generate_diagram_from_dot(
            dot_code, temp_svg_path, "svg"
        )
        logging.info(f"update_diagram_logic: SVG generated at {svg_path}")
        if not svg_path or not os.path.exists(svg_path):
            raise RuntimeError("Failed to generate SVG diagram")
        with open(svg_path, "r", encoding="utf-8") as f:
            svg_content = f.read()
        legend_html = self.diagram_generator._generate_legend_html(threat_model)
        full_html = self.diagram_generator._create_complete_html(
            svg_content, legend_html, threat_model
        )
        logging.info("update_diagram_logic: Successfully updated diagram.")
        return {
            "diagram_html": full_html,
            "diagram_svg": svg_content,
            "legend_html": legend_html,
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
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
        if export_format == "svg":
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            output_filename = "diagram.svg"
            output_path = os.path.join(
                config.OUTPUT_BASE_DIR, output_filename
            )
            generated_path = self.diagram_generator.generate_diagram_from_dot(
                dot_code, output_path, "svg"
            )
            if not generated_path:
                raise RuntimeError("Failed to generate SVG file")
            return output_path, output_filename
        elif export_format == "diagram":
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            svg_path_temp = os.path.join(
                config.OUTPUT_BASE_DIR, "temp_diagram.svg"
            )
            self.diagram_generator.generate_diagram_from_dot(
                dot_code, svg_path_temp, "svg"
            )
            output_filename = "diagram.html"
            output_path = os.path.join(
                config.OUTPUT_BASE_DIR, output_filename
            )
            self.diagram_generator._generate_html_with_legend(
                svg_path_temp, output_path, threat_model
            )
            return output_path, output_filename
        elif export_format == "report":
            grouped_threats = threat_model.process_threats()
            output_filename = "threat_report.html"
            output_path = os.path.join(
                config.OUTPUT_BASE_DIR, output_filename
            )
            self.report_generator.generate_html_report(
                threat_model, grouped_threats, output_path
            )
            return output_path, output_filename
        elif export_format == "markdown":
            output_filename = "threat_model.md"
            output_path = os.path.join(
                config.OUTPUT_BASE_DIR, output_filename
            )
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            return output_path, output_filename
        else:
            raise ValueError("Invalid export format")

    def generate_full_project_export(self, markdown_content: str, export_path: str):
        logging.info("Entering generate_full_project_export function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

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
            dot_code, svg_filepath, "svg"
        )

        html_diagram_filename = "tm_diagram.html"
        html_diagram_filepath = os.path.join(
            export_path, html_diagram_filename
        )
        self.diagram_generator._generate_html_with_legend(
            svg_filepath, html_diagram_filepath, threat_model
        )

        grouped_threats = threat_model.process_threats()
        html_report_filename = "stride_mitre_report.html"
        html_report_filepath = os.path.join(export_path, html_report_filename)
        self.report_generator.generate_html_report(
            threat_model, grouped_threats, html_report_filepath
        )

        json_analysis_filename = "mitre_analysis.json"
        json_analysis_filepath = os.path.join(
            export_path, json_analysis_filename
        )
        self.report_generator.generate_json_export(
            threat_model, grouped_threats, json_analysis_filepath
        )

        all_detailed_threats = threat_model.get_all_threats_details()
        navigator_generator = AttackNavigatorGenerator(
            threat_model_name=threat_model.tm.name,
            all_detailed_threats=all_detailed_threats
        )
        navigator_filename = config.JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=config.TIMESTAMP)
        navigator_filepath = os.path.join(export_path, navigator_filename)
        navigator_generator.save_layer_to_file(navigator_filepath)

        stix_generator_instance = StixGenerator(
            threat_model=threat_model,
            all_detailed_threats=all_detailed_threats
        )
        stix_bundle = stix_generator_instance.generate_stix_bundle()
        stix_filename = f"stix_report_{config.TIMESTAMP}.json"
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

    def export_all_files_logic(self, markdown_content: str):
        logging.info("Entering export_all_files_logic function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        export_dir_name = f"export_{timestamp}"
        export_path = os.path.join(config.OUTPUT_BASE_DIR, export_dir_name)
        os.makedirs(export_path, exist_ok=True)

        result = self.generate_full_project_export(markdown_content, export_path)

        element_positions = self._extract_element_positions(create_threat_model(markdown_content=markdown_content, cve_service=self.cve_service))
        
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

    def export_navigator_stix_logic(self, markdown_content: str):
        logging.info("Entering export_navigator_stix_logic function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        export_dir_name = f"navigator_stix_export_{timestamp}"
        export_path = os.path.join(config.OUTPUT_BASE_DIR, export_dir_name)
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

        validator = ModelValidator(threat_model)
        errors = validator.validate()
        if errors:
            raise ValueError("Validation failed: " + ", ".join(errors))

        all_detailed_threats = threat_model.get_all_threats_details()
        navigator_generator = AttackNavigatorGenerator(
            threat_model_name=threat_model.tm.name,
            all_detailed_threats=all_detailed_threats
        )
        navigator_filename = config.JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=timestamp)
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
        temp_export_dir = os.path.join(config.TMP_DIR, f"attack_flow_{timestamp}")
        os.makedirs(temp_export_dir, exist_ok=True)

        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name="ExportedThreatModel",
            model_description="Exported from web interface",
            validate=True,
        )
        if not threat_model:
            raise RuntimeError("Failed to create or validate threat model")

        threat_model.process_threats()
        all_detailed_threats = threat_model.get_all_threats_details()

        attack_flow_generator = AttackFlowGenerator(
            threats=all_detailed_threats,
            model_name=threat_model.tm.name
        )
        attack_flow_generator.generate_and_save_flows(temp_export_dir)

        afb_dir = os.path.join(temp_export_dir, "afb")
        if not os.path.exists(afb_dir) or not os.listdir(afb_dir):
            logging.warning("No attack flow files were generated.")
            shutil.rmtree(temp_export_dir)
            return None, None

        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(afb_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, afb_dir)
                    zf.write(file_path, arcname)
        zip_buffer.seek(0)

        shutil.rmtree(temp_export_dir)

        return zip_buffer, timestamp