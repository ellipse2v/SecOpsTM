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
        
        # In the web server context, the CVE service should be initialized when needed
        # or passed in by the main server application. For now, pass None to avoid eager instantiation.
        cve_definitions_path = PROJECT_ROOT / "cve_definitions.yml"
        self.cve_service = CVEService(
            PROJECT_ROOT, cve_definitions_path, is_path_explicit=False
        )
        self.report_generator = ReportGenerator(
            self.severity_calculator, 
            self.mitre_mapping,
            implemented_mitigations_path=None, # No default hardcoded path
            cve_service=self.cve_service # No eager instantiation
        )
        self.stix_generator = None # Initialize later with threat_model and all_detailed_threats

    def update_diagram_logic(self, markdown_content: str):
        logging.info("update_diagram_logic: Starting diagram update.")
        if not markdown_content:
            logging.error("update_diagram_logic: Markdown content is empty.")
            raise ValueError("Markdown content is empty")

        # Save the received markdown to a temporary file
        tmp_md_path = os.path.join(config.TMP_DIR, "live_model.md")
        os.makedirs(config.TMP_DIR, exist_ok=True)
        with open(tmp_md_path, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        logging.info(f"Saved live markdown to {tmp_md_path}")

        # 1. Create a new ThreatModel instance for each request
        threat_model = create_threat_model(
            markdown_content=markdown_content,
            model_name="WebThreatModel",
            model_description="Live-updated threat model",
            cve_service=self.cve_service,
            validate=False,  # No need to validate on every update
        )
        if not threat_model:
            raise RuntimeError("Failed to create threat model")

        # --- Model Validation ---
        validator = ModelValidator(threat_model)
        errors = validator.validate()
        if errors:
            logging.warning(f"update_diagram_logic: Model validation failed with errors: {errors}")
            # Return errors to the frontend
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

        # 3. Generate the DOT code from the model
        dot_code = self.diagram_generator._generate_manual_dot(threat_model)
        logging.info(
            f"Generated DOT code (first 500 chars): \n{dot_code[:500]}..."
        )
        if not dot_code:
            raise RuntimeError("Failed to generate DOT code from model")

        # 4. Generate the SVG from the DOT code
        # We create a temporary file for the SVG output
        temp_svg_path = os.path.join(config.TMP_DIR, "live_preview.svg")
        # Ensure directory exists
        os.makedirs(os.path.dirname(temp_svg_path), exist_ok=True)
        svg_path = self.diagram_generator.generate_diagram_from_dot(
            dot_code, temp_svg_path, "svg"
        )
        logging.info(f"update_diagram_logic: SVG generated at {svg_path}")

        if not svg_path or not os.path.exists(svg_path):
            raise RuntimeError("Failed to generate SVG diagram")

        # 5. Read the SVG content
        with open(svg_path, "r", encoding="utf-8") as f:
            svg_content = f.read()

        # 6. Generate the legend
        legend_html = self.diagram_generator._generate_legend_html(threat_model)

        # 7. Combine into a full HTML document for other purposes if needed
        full_html = self.diagram_generator._create_complete_html(
            svg_content, legend_html, threat_model
        )

        # 8. Return raw SVG, legend, and full HTML
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

        # --- Model Validation ---
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

        else:
            raise ValueError("Invalid export format")

    def export_all_files_logic(self, markdown_content: str):
        logging.info("Entering export_all_files_logic function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        export_dir_name = f"export_{timestamp}"
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

        # --- Model Validation ---
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

        # Generate ATT&CK Navigator Layer
        all_detailed_threats = threat_model.get_all_threats_details()
        navigator_generator = AttackNavigatorGenerator(
            threat_model_name=threat_model.tm.name,
            all_detailed_threats=all_detailed_threats
        )
        navigator_filename = config.JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=config.TIMESTAMP)
        navigator_filepath = os.path.join(export_path, navigator_filename)
        navigator_generator.save_layer_to_file(navigator_filepath)
        logging.info(f"ATT&CK Navigator layer saved to: {navigator_filepath}")
        if not os.path.exists(navigator_filepath) or os.path.getsize(navigator_filepath) == 0:
            logging.error(f"Generated Navigator file is missing or empty: {navigator_filepath}")
            raise RuntimeError("Failed to generate Navigator layer.")

        # Generate STIX report
        stix_generator_instance = StixGenerator(
            threat_model=threat_model,
            all_detailed_threats=all_detailed_threats
        )
        stix_bundle = stix_generator_instance.generate_stix_bundle()
        stix_filename = f"stix_report_{config.TIMESTAMP}.json"
        stix_filepath = os.path.join(export_path, stix_filename)
        with open(stix_filepath, "w", encoding="utf-8") as f:
            json.dump(stix_bundle, f, indent=4)
        logging.info(f"STIX report saved to: {stix_filepath}")
        if not os.path.exists(stix_filepath) or os.path.getsize(stix_filepath) == 0:
            logging.error(f"Generated STIX file is missing or empty: {stix_filepath}")
            raise RuntimeError("Failed to generate STIX report.")

        zip_buffer = BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", zipfile.ZIP_DEFLATED
        ) as zf:
            for root, _, files in os.walk(export_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, export_path)
                    zf.write(
                        file_path, arcname
                    )
                    logging.info(f"Added {arcname} to zip. Size: {os.path.getsize(file_path)} bytes")
        zip_buffer.seek(0)
        logging.info(f"Zip buffer size: {zip_buffer.getbuffer().nbytes} bytes")

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

        # --- Model Validation ---
        validator = ModelValidator(threat_model)
        errors = validator.validate()
        if errors:
            raise ValueError("Validation failed: " + ", ".join(errors))

        # Generate all files (even if we only zip two of them)
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

        # Generate ATT&CK Navigator Layer
        all_detailed_threats = threat_model.get_all_threats_details()
        navigator_generator = AttackNavigatorGenerator(
            threat_model_name=threat_model.tm.name,
            all_detailed_threats=all_detailed_threats
        )
        navigator_filename = config.JSON_NAVIGATOR_FILENAME_TPL.format(timestamp=timestamp)
        navigator_filepath = os.path.join(export_path, navigator_filename)
        navigator_generator.save_layer_to_file(navigator_filepath)
        logging.info(f"ATT&CK Navigator layer saved to: {navigator_filepath}")
        if not os.path.exists(navigator_filepath) or os.path.getsize(navigator_filepath) == 0:
            logging.error(f"Generated Navigator file is missing or empty: {navigator_filepath}")
            raise RuntimeError("Failed to generate Navigator layer.")

        # Generate STIX report
        stix_generator_instance = StixGenerator(
            threat_model=threat_model,
            all_detailed_threats=all_detailed_threats
        )
        stix_bundle = stix_generator_instance.generate_stix_bundle()
        stix_filename = f"stix_report_{timestamp}.json"
        stix_filepath = os.path.join(export_path, stix_filename)
        with open(stix_filepath, "w", encoding="utf-8") as f:
            json.dump(stix_bundle, f, indent=4)
        logging.info(f"STIX report saved to: {stix_filepath}")
        if not os.path.exists(stix_filepath) or os.path.getsize(stix_filepath) == 0:
            logging.error(f"Generated STIX file is missing or empty: {stix_filepath}")
            raise RuntimeError("Failed to generate STIX report.")

        zip_buffer = BytesIO()
        with zipfile.ZipFile(
            zip_buffer, "w", zipfile.ZIP_DEFLATED
        ) as zf:
            # Only add the navigator and stix files to the zip
            zf.write(navigator_filepath, os.path.basename(navigator_filepath))
            zf.write(stix_filepath, os.path.basename(stix_filepath))
        zip_buffer.seek(0)
        logging.info(f"Zip buffer size: {zip_buffer.getbuffer().nbytes} bytes")

        shutil.rmtree(export_path)

        return zip_buffer, timestamp
    
    def export_attack_flow_logic(self, markdown_content: str):
        logging.info("Entering export_attack_flow_logic function.")
        if not markdown_content:
            raise ValueError("Missing markdown content")

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        # Use a temporary directory for generation
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
            return None, None # No files to zip

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
