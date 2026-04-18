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
import datetime
import zipfile
import shutil
import tempfile
from io import BytesIO
import json
from pathlib import Path
from typing import Optional
import asyncio
import queue

from threat_analysis.core.model_factory import create_threat_model
from threat_analysis.core.model_validator import ModelValidator
from threat_analysis.generation.attack_navigator_generator import AttackNavigatorGenerator
from threat_analysis.generation.stix_generator import StixGenerator
from threat_analysis.generation.attack_flow_generator import AttackFlowGenerator
from threat_analysis.utils import resolve_gdaf_context, resolve_bom_directory

TIMESTAMP_FORMAT = "%Y-%m-%d_%H-%M-%S"
OUTPUT_BASE_DIR_TPL = "output"

# Filename templates
JSON_NAVIGATOR_FILENAME_TPL = "attack_navigator_layer_{timestamp}.json"

class ExportService:
    def __init__(self, cve_service, diagram_generator, report_generator, ai_service, diagram_service, ai_status_event_queue: queue.Queue = None):
        self.cve_service = cve_service
        self.diagram_generator = diagram_generator
        self.report_generator = report_generator
        self.ai_service = ai_service
        self.diagram_service = diagram_service
        self.ai_status_event_queue = ai_status_event_queue

    def _get_output_dir(self):
        timestamp = datetime.datetime.now().strftime(TIMESTAMP_FORMAT)
        return Path(OUTPUT_BASE_DIR_TPL) / timestamp

    def export_files_logic(self, markdown_content: str, export_format: str,
                           model_file_path: Optional[str] = None):
        logging.info(f"Entering export_files_logic for format: {export_format}")
        if not markdown_content or not export_format:
            raise ValueError("Missing markdown content or export format")

        threat_model = create_threat_model(
            markdown_content=markdown_content, model_name="ExportedThreatModel",
            model_description="Exported from web interface", cve_service=self.cve_service, validate=True,
            model_file_path=model_file_path,
        )
        if not threat_model:
            raise RuntimeError("Failed to create or validate threat model")

        validator = ModelValidator(threat_model)
        errors = validator.validate()
        if errors:
            raise ValueError("Validation failed: " + ", ".join(errors))

        output_dir = self._get_output_dir()
        os.makedirs(output_dir, exist_ok=True)

        if export_format == "svg":
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            output_filename = "diagram.svg"
            output_path = output_dir / output_filename
            generated_path = self.diagram_generator.generate_custom_svg_export(dot_code, output_path)
            if not generated_path:
                raise RuntimeError("Failed to generate SVG file")
            return str(output_path), output_filename
        elif export_format == "diagram":
            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            svg_path_temp = output_dir / "temp_diagram.svg"
            self.diagram_generator.generate_custom_svg_export(dot_code, svg_path_temp)
            output_filename = "diagram.html"
            output_path = output_dir / output_filename
            graph_metadata = self.diagram_service._extract_graph_metadata_for_frontend(threat_model)
            severity_map = self.report_generator._compute_severity_map(threat_model)
            self.diagram_generator._generate_html_with_legend(svg_path_temp, output_path, threat_model, graph_metadata, severity_map)
            return str(output_path), output_filename
        elif export_format == "report":
            grouped_threats = threat_model.process_threats()
            output_filename = "threat_report.html"
            output_path = output_dir / output_filename
            self.report_generator.generate_html_report(threat_model, grouped_threats, output_path)
            return str(output_path), output_filename
        elif export_format == "markdown":
            output_filename = "threat_model.md"
            output_path = output_dir / output_filename
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(markdown_content)
            return str(output_path), output_filename
        else:
            raise ValueError(f"Invalid export format: {export_format}")

    def generate_full_project_export(self, markdown_content: str, export_path: Path, submodels: list | None = None, progress_callback = None, project_root: Path | None = None, model_file_path: Optional[str] = None):
        export_path = Path(export_path)
        timestamp = datetime.datetime.now().strftime(TIMESTAMP_FORMAT)
        result = {
            "reports": {},
            "diagrams": {}
        }
        
        if submodels and len(submodels) > 0:
            logging.info("--- Starting Project-Based Generation (Server Mode) ---")
            
            # If project_root is provided, use it. Otherwise create a temporary one.
            cleanup_needed = False
            if project_root:
                project_path = Path(project_root)
            else:
                if progress_callback: progress_callback(5, "Preparing temporary project directory...")
                project_path = Path(tempfile.mkdtemp())
                cleanup_needed = True
                (project_path / "main.md").write_text(markdown_content, encoding="utf-8")
                for submodel in submodels:
                    submodel_path_str = submodel.get('path', '').lstrip('./\\')
                    if not submodel_path_str: continue
                    submodel_path = project_path / submodel_path_str
                    submodel_path.parent.mkdir(parents=True, exist_ok=True)
                    submodel_path.write_text(submodel['content'], encoding="utf-8")
            
            if progress_callback: progress_callback(10, "Initializing project generation...")
            main_threat_model = self.report_generator.generate_project_reports(
                project_path, export_path,
                progress_callback=progress_callback,
                ai_service=self.ai_service,
            )
            
            if cleanup_needed:
                shutil.rmtree(project_path)
            
            if main_threat_model:
                model_name = main_threat_model.tm.name
                result["reports"] = {
                    "global_html": "global_threat_report.html",
                    "html": f"{model_name}_threat_report.html",
                    "json": f"{model_name}.json",
                    "stix": f"{model_name}_stix_report.json",
                    "navigator": f"{model_name}_attack_navigator_layer.json",
                    "checklist": f"{model_name}_remediation_checklist.csv",
                }
                result["diagrams"] = {
                    "html": f"{model_name}_diagram.html",
                    "svg": f"{model_name}.svg"
                }
        else:
            logging.info("--- Starting Single-File Generation (Server Mode) ---")
            threat_model = create_threat_model(
                markdown_content=markdown_content, model_name="ExportedThreatModel",
                model_description="Exported from web interface", cve_service=self.cve_service, validate=True,
                model_file_path=model_file_path,
            )
            if not threat_model:
                raise RuntimeError("Failed to create or validate threat model")
            validator = ModelValidator(threat_model)
            if errors := validator.validate():
                raise ValueError("Validation failed: " + ", ".join(errors))

            (export_path / "threat_model.md").write_text(markdown_content, encoding="utf-8")

            # Process threats first so severity_map is available for the diagram HTML
            def single_file_progress_cb(message, is_new_model=False):
                if progress_callback:
                    progress_callback(50, message)

            grouped_threats = threat_model.process_threats()

            dot_code = self.diagram_generator._generate_manual_dot(threat_model)
            svg_filepath = export_path / "tm_diagram.svg"
            self.diagram_generator.generate_diagram_from_dot(dot_code, str(svg_filepath), format="svg")
            graph_metadata = self.diagram_service._extract_graph_metadata_for_frontend(threat_model)
            severity_map = self.report_generator._compute_severity_map(threat_model)

            html_diagram_path = export_path / "tm_diagram.html"
            self.diagram_generator._generate_html_with_legend(
                svg_filepath, html_diagram_path, threat_model, graph_metadata, severity_map,
                report_url="stride_mitre_report.html",
            )
            json_report_path = export_path / "mitre_analysis.json"
            self.report_generator.generate_json_export(threat_model, grouped_threats, json_report_path)

            try:
                self.report_generator.generate_remediation_checklist(
                    threat_model, grouped_threats, export_path / "remediation_checklist.csv"
                )
            except Exception as e:
                logging.warning(f"Could not generate remediation checklist: {e}")

            all_detailed_threats = threat_model.get_all_threats_details()
            navigator_generator = AttackNavigatorGenerator(threat_model_name=str(threat_model.tm.name), all_detailed_threats=all_detailed_threats)
            navigator_filename = JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=timestamp)
            navigator_generator.save_layer_to_file(str(export_path / navigator_filename))

            stix_generator = StixGenerator(threat_model=threat_model, all_detailed_threats=all_detailed_threats)
            stix_bundle = stix_generator.generate_stix_bundle()
            stix_filename = f"stix_report_{timestamp}.json"
            (export_path / stix_filename).write_text(json.dumps(stix_bundle, indent=4), encoding="utf-8")

            try:
                attack_flow_gen = AttackFlowGenerator(
                    threats=all_detailed_threats,
                    model_name=str(threat_model.tm.name),
                )
                attack_flow_gen.generate_and_save_flows(str(export_path))
                logging.info("Attack Flow files generated in %s/afb", export_path)
            except Exception as e:
                logging.error("Failed to generate Attack Flow: %s", e)

            # GDAF: Goal-Driven Attack Flow (objective-based, requires context with attack_objectives)
            # Run BEFORE the HTML report so that gdaf_scenarios are available in the report.
            try:
                from threat_analysis.core.gdaf_engine import GDAFEngine
                from threat_analysis.generation.attack_flow_builder import AttackFlowBuilder
                _context_path = resolve_gdaf_context(threat_model)
                if _context_path:
                    _bom_dir = resolve_bom_directory(threat_model)
                    _gdaf = GDAFEngine(threat_model, _context_path, bom_directory=_bom_dir)
                    _scenarios = _gdaf.run()
                    if _scenarios:
                        threat_model.gdaf_scenarios = _scenarios
                        _builder = AttackFlowBuilder(_scenarios, model_name=str(threat_model.tm.name))
                        _builder.generate_and_save(str(export_path))
                        logging.info("GDAF: generated %d attack scenarios in %s/gdaf", len(_scenarios), export_path)
                    else:
                        logging.info("GDAF: no scenarios produced (check context attack_objectives/threat_actors)")
            except Exception as e:
                logging.warning("GDAF generation skipped (non-fatal): %s", e)

            # HTML report generated last so it includes GDAF scenarios
            report_path = export_path / "stride_mitre_report.html"
            self.report_generator.generate_html_report(threat_model, grouped_threats, report_path, progress_callback=single_file_progress_cb)

            result["reports"] = {
                "html": "stride_mitre_report.html",
                "json": "mitre_analysis.json",
                "stix": stix_filename,
                "navigator": navigator_filename,
                "checklist": "remediation_checklist.csv",
            }
            result["diagrams"] = {
                "html": "tm_diagram.html",
                "svg": "tm_diagram.svg"
            }
            
        return result

    def export_all_files_logic(self, markdown_content: str, submodels: list | None = None,
                               model_file_path: Optional[str] = None):
        logging.info("Entering export_all_files_logic.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime(TIMESTAMP_FORMAT)
        export_dir_name = f"export_{timestamp}"
        output_dir = self._get_output_dir().parent
        export_path = output_dir / export_dir_name
        os.makedirs(export_path, exist_ok=True)

        if submodels and len(submodels) > 0:
            self.generate_full_project_export(markdown_content, export_path, submodels=submodels,
                                              model_file_path=model_file_path)
        else:
            self.generate_full_project_export(markdown_content, export_path,
                                              model_file_path=model_file_path)
        
        threat_model_temp = create_threat_model(markdown_content=markdown_content, model_name="temp", model_description="temp", cve_service=self.cve_service)
        element_positions = self.diagram_service._generate_positions_from_graphviz(threat_model_temp) if threat_model_temp else {}
        
        version_id = f"1.0-{timestamp.replace('-', '').replace(':', '').replace('_', '')}"
        metadata = {
            "version": "1.0", "version_id": version_id,
            "last_updated": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "model_file": "threat_model.md", "positions": element_positions
        }
        (export_path / "element_positions.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(export_path):
                for file in files:
                    zf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), export_path))
        zip_buffer.seek(0)
        shutil.rmtree(export_path)
        return zip_buffer, timestamp

    def export_navigator_stix_logic(self, markdown_content: str, submodels: list | None = None,
                                    model_file_path: Optional[str] = None):
        logging.info("Entering export_navigator_stix_logic.")
        if not markdown_content: raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime(TIMESTAMP_FORMAT)
        output_dir = self._get_output_dir()
        os.makedirs(output_dir, exist_ok=True)

        threat_model = create_threat_model(
            markdown_content=markdown_content, model_name="ExportedThreatModel",
            model_description="Exported for STIX/Navigator", cve_service=self.cve_service, validate=True,
            model_file_path=model_file_path,
        )
        if not threat_model:
            raise RuntimeError("Failed to create threat model")
        if submodels and len(submodels) > 0:
            for sub_data in submodels:
                sub_model = create_threat_model(
                    markdown_content=sub_data['content'], model_name=os.path.basename(sub_data['path']),
                    cve_service=self.cve_service, validate=False
                )
                if sub_model: threat_model.sub_models.append(sub_model)
        
        validator = ModelValidator(threat_model)
        if errors := validator.validate():
            raise ValueError("Validation failed: " + ", ".join(errors))

        all_detailed_threats = threat_model.get_all_threats_details()
        navigator_generator = AttackNavigatorGenerator(threat_model_name=str(threat_model.tm.name), all_detailed_threats=all_detailed_threats)
        navigator_filepath = output_dir / JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=timestamp)
        navigator_generator.save_layer_to_file(str(navigator_filepath))

        stix_generator = StixGenerator(threat_model=threat_model, all_detailed_threats=all_detailed_threats)
        stix_bundle = stix_generator.generate_stix_bundle()
        stix_filepath = output_dir / f"stix_report_{timestamp}.json"
        stix_filepath.write_text(json.dumps(stix_bundle, indent=4), encoding="utf-8")

        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(navigator_filepath, os.path.basename(navigator_filepath))
            zf.write(stix_filepath, os.path.basename(stix_filepath))
        zip_buffer.seek(0)
        shutil.rmtree(output_dir)
        return zip_buffer, timestamp
    
    def export_attack_flow_logic(self, markdown_content: str,
                                 model_file_path: Optional[str] = None):
        logging.info("Entering export_attack_flow_logic.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime(TIMESTAMP_FORMAT)
        with tempfile.TemporaryDirectory() as temp_export_dir:
            threat_model = create_threat_model(
                markdown_content=markdown_content, model_name="ExportedThreatModel",
                model_description="Exported from web interface", cve_service=self.cve_service, validate=True,
                model_file_path=model_file_path,
            )
            if not threat_model:
                raise RuntimeError("Failed to create or validate threat model")

            threat_model.process_threats()
            all_detailed_threats = threat_model.get_all_threats_details()

            attack_flow_generator = AttackFlowGenerator(threats=all_detailed_threats, model_name=threat_model.tm.name)
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
