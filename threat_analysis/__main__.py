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

import time
_start_time_main = time.time()

"""
Main STRIDE threat analysis module with MITRE ATT&CK integration
Complete orchestration of security analysis - Modified version
"""
import os
import sys
import argparse
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import importlib.util
import inspect
import traceback

from threat_analysis import config # Re-add config import
from threat_analysis.server.server import run_server, get_model_name # Re-add this import
from threat_analysis.utils import resolve_path, _validate_path_within_project, compare_threat_reports

# Import library modules
# Lazy imports will be handled within methods

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

class SecOpsTMFramework:
    """Main framework for threat analysis"""

    def __init__(
        self, markdown_content: str, model_name: str, model_description: str, model_file_path: str,
        original_model_path: Optional[str] = None,
        implemented_mitigations_path: Optional[str] = None,
        cve_service: 'CVEService' = None, # Use forward reference for lazy loading
        ai_config_path: Optional[Path] = None,
        context_path: Optional[Path] = None,
        cve_definitions_path: Optional[Path] = None, # New parameter
    ):
        """Initializes the analysis framework"""
        self.markdown_content = markdown_content
        self.model_name = model_name
        self.model_description = model_description
        self.model_file_path = model_file_path
        self.original_model_path = original_model_path or model_file_path
        self.cve_service = cve_service

        # --- Output path management ---
        self.output_base_dir = config.OUTPUT_BASE_DIR
        os.makedirs(self.output_base_dir, exist_ok=True)
        logging.info(
            f"📁 Output files will be generated in: "
            f"{os.path.abspath(self.output_base_dir)}"
        )

        self.html_report_filename = config.HTML_REPORT_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.json_report_filename = config.JSON_REPORT_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.dot_diagram_filename = config.DOT_DIAGRAM_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.svg_diagram_filename = config.SVG_DIAGRAM_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        self.html_diagram_filename = config.HTML_DIAGRAM_FILENAME_TPL.format(
            timestamp=config.TIMESTAMP
        )
        # --- End of output path management ---

        self._implemented_mitigations_path = implemented_mitigations_path
        self._ai_config_path = ai_config_path
        self._context_path = context_path
        self._cve_definitions_path = cve_definitions_path
        self._initialize_components()

        logging.info(f"🚀 Analysis framework initialized: {self.model_name}")

        # NEW: Diagnostic to check if the model has been populated
        model_stats = self.threat_model.get_statistics()

        if (
            model_stats["actors"] == 0
            and model_stats["servers"] == 0
            and model_stats["dataflows"] == 0
        ):
            logging.warning(
                "⚠️ WARNING: The model appears to be empty or was not parsed "
                "correctly. Check your \'threat_model.md\'."
            )

        # Analysis state (after model loading)
        self.analysis_completed = False
        self.grouped_threats = {}
        self.custom_threats_list = []
        self.elements_with_custom_threats = set()

    def _initialize_components(self) -> None:
        """Instantiate all heavy components (CVEService, MitreMapping, ReportGenerator, etc.).

        Extracted from ``__init__`` to allow unit-testing of individual components without
        constructing the entire framework object.
        """
        cve_service_module = importlib.import_module("threat_analysis.core.cve_service")
        CVEService = cve_service_module.CVEService

        mitre_mapping_module = importlib.import_module("threat_analysis.core.mitre_mapping_module")
        MitreMapping = mitre_mapping_module.MitreMapping

        severity_calculator_module = importlib.import_module("threat_analysis.severity_calculator_module")
        SeverityCalculator = severity_calculator_module.SeverityCalculator

        report_generator_module = importlib.import_module("threat_analysis.generation.report_generator")
        ReportGenerator = report_generator_module.ReportGenerator

        diagram_generator_module = importlib.import_module("threat_analysis.generation.diagram_generator")
        DiagramGenerator = diagram_generator_module.DiagramGenerator

        self.cve_service = self.cve_service if self.cve_service else CVEService(
            PROJECT_ROOT,
            self._cve_definitions_path,
            is_path_explicit=bool(self._cve_definitions_path),
        )

        self.mitre_mapper = MitreMapping(threat_model_path=self.model_file_path)
        self.threat_model = self._load_and_validate_model(self.markdown_content)

        self.severity_calculator = SeverityCalculator(
            markdown_file_path=str(Path("threatModel_Template/threat_model.md"))
        )
        self.report_generator = ReportGenerator(
            self.severity_calculator, self.mitre_mapper,
            implemented_mitigations_path=Path(self._implemented_mitigations_path) if self._implemented_mitigations_path else None,
            cve_service=self.cve_service,
            ai_config_path=self._ai_config_path,
            context_path=self._context_path,
            threat_model_ref=self.threat_model,
        )
        self.diagram_generator = DiagramGenerator()

    def _load_and_validate_model(self, markdown_content: str) -> 'ThreatModel': # Use forward reference for type hint
        """Loads and validates the threat model from the Markdown DSL content."""
        logging.info(f"⏳ Loading model from provided Markdown content...")
        try:
            # Lazy import ThreatModel and create_threat_model
            models_module = importlib.import_module("threat_analysis.core.models_module")
            ThreatModel = models_module.ThreatModel
            model_factory_module = importlib.import_module("threat_analysis.core.model_factory")
            create_threat_model = model_factory_module.create_threat_model

            threat_model = create_threat_model(
                markdown_content=markdown_content,
                model_name=self.model_name,
                model_description=self.model_description,
                cve_service=self.cve_service, # type: ignore
                validate=True,
                model_file_path=self.original_model_path,
            )
            if not threat_model:
                raise RuntimeError("create_threat_model returned None")
            return threat_model
        except Exception as e:
            logging.error(f"❌ Error parsing or validating model: {e}")
            raise RuntimeError(f"Failed to load or validate threat model: {e}")

    def run_analysis(self) -> Dict[str, List[Tuple[Any, Any]]]:
        """Executes the threat analysis."""
        logging.info("🔬 Starting STRIDE threat analysis...")

        if self.threat_model:
            self.grouped_threats = self.threat_model.process_threats()
        self.analysis_completed = True
        logging.info("✅ Threat analysis completed.")
        return self.grouped_threats

    def generate_reports(self) -> Dict[str, str]:
        """Generates HTML and JSON reports in the timestamped directory."""
        if not self.analysis_completed:
            logging.warning(
                "⚠️ Analysis has not been run. Execute run_analysis() first."
            )
            return {}

        logging.info("📊 Generating reports...")

        html_output_full_path = os.path.join(
            self.output_base_dir, self.html_report_filename
        )
        json_output_full_path = os.path.join(
            self.output_base_dir, self.json_report_filename
        )

        html_report_path = self.report_generator.generate_html_report(
            self.threat_model, self.grouped_threats, Path(html_output_full_path)
        )
        json_report_path = self.report_generator.generate_json_export(
            self.threat_model, self.grouped_threats, Path(json_output_full_path)
        )
        logging.info("✅ Reports generated.")
        return {"html": str(html_report_path), "json": str(json_report_path)}
        return {"html": str(html_report_path), "json": str(json_report_path)}

    def generate_stix_report(self) -> Optional[str]:
        """Generates STIX report in the timestamped directory."""
        if not self.analysis_completed:
            logging.warning(
                "⚠️ Analysis has not been run. Execute run_analysis() first."
            )
            return None

        logging.info("📊 Generating STIX report...")

        stix_output_dir = Path(self.output_base_dir)

        stix_report_path = self.report_generator.generate_stix_export(
            self.threat_model, self.grouped_threats, stix_output_dir
        )

        logging.info("✅ STIX report generated.")
        return str(stix_report_path)
        return str(stix_report_path)

    def generate_diagrams(self) -> Dict[str, Optional[str]]:
        """Generates DOT, SVG and HTML diagrams in the timestamped directory."""
        logging.info("🖼️ Generating diagrams...")
        if not self.diagram_generator.check_graphviz_installation():
            logging.warning(
                self.diagram_generator.get_installation_instructions()
            )
            return {"dot": None, "svg": None, "html": None}

        dot_output_full_path = os.path.join(
            self.output_base_dir, self.dot_diagram_filename
        )
        svg_output_full_path = os.path.join(
            self.output_base_dir, self.svg_diagram_filename
        )
        html_output_full_path = os.path.join(
            self.output_base_dir, self.html_diagram_filename
        )

        # Generate DOT file
        dot_code = self.diagram_generator.generate_dot_file_from_model(
            self.threat_model, dot_output_full_path
        )

        svg_path = None
        html_path = None

        if dot_code:
            try:
                # Generate SVG
                svg_path = self.diagram_generator.generate_diagram_from_dot(
                    dot_code, svg_output_full_path, "svg"
                )

                # Generate HTML with embedded SVG and positioned legend
                if svg_path:
                    html_path = (
                        self.diagram_generator._generate_html_with_legend(
                            Path(svg_path), Path(html_output_full_path), self.threat_model
                        )
                    )
            except Exception as e:
                logging.error(
                    f"❌ Error generating diagram from DOT code: {e}"
                )

        return {"dot": dot_output_full_path, "svg": svg_path, "html": str(html_path) if html_path else None}

    def generate_navigator_layer(self) -> Optional[str]:
        """Generates and saves the ATT&CK Navigator layer."""
        if not self.analysis_completed:
            logging.warning("⚠️ Analysis not run, cannot generate Navigator layer.")
            return None

        logging.info("🗺️ Generating ATT&CK Navigator layer...")
        try:
            # Lazy import AttackNavigatorGenerator
            attack_navigator_module = importlib.import_module("threat_analysis.generation.attack_navigator_generator")
            AttackNavigatorGenerator = attack_navigator_module.AttackNavigatorGenerator

            # We need all detailed threats, not just grouped ones.
            if self.threat_model:
                all_threats = self.threat_model.get_all_threats_details()
            else:
                all_threats = []
            
            navigator_generator = AttackNavigatorGenerator(
                threat_model_name=self.model_name,
                all_detailed_threats=all_threats
            )
            
            output_filename = f"attack_navigator_layer_{config.TIMESTAMP}.json"
            output_path = os.path.join(self.output_base_dir, output_filename)
            
            navigator_generator.save_layer_to_file(output_path)
            logging.info(f"✅ ATT&CK Navigator layer saved to: {output_path}")
            return output_path
        except Exception as e:
            logging.error(f"❌ Failed to generate ATT&CK Navigator layer: {e}")
            return None

    def open_report_in_browser(self, report_path: str):
        """Opens the HTML report in the default browser."""
        try:
            if os.path.exists(report_path):
                import webbrowser

                webbrowser.open(os.path.abspath(report_path))

            else:
                logging.warning(
                    f"⚠️ HTML report not found at: "
                    f"{os.path.abspath(report_path)}"
                )
        except Exception:
            pass

def generate_and_save_attack_flow(threat_model: 'ThreatModel', output_dir: Path, model_name: str):
    """Generates and saves Attack Flow files based on STRIDE categories."""
    logging.info(f"🌊 Generating Attack Flow files for {model_name}...")
    try:
        # Lazy import AttackFlowGenerator
        attack_flow_module = importlib.import_module("threat_analysis.generation.attack_flow_generator")
        AttackFlowGenerator = attack_flow_module.AttackFlowGenerator

        # The generator now expects the raw threat data to perform its own filtering.
        raw_threats = threat_model.mitre_analysis_results.get("processed_threats", [])
        if not raw_threats:
            logging.warning("No raw threats found, skipping Attack Flow generation.")
            return

        flow_generator = AttackFlowGenerator(
            threats=raw_threats,
            model_name=model_name
        )
        flow_generator.generate_and_save_flows(output_dir)
        logging.info(f"✅ Attack Flow generation process completed for {model_name}.")

    except Exception as e:
        logging.error(f"❌ Failed to generate Attack Flow files for {model_name}: {e}")
        traceback.print_exc()

def load_iac_plugins() -> Dict[str, 'IaCPlugin']:
    """Dynamically loads IaC plugins from the iac_plugins directory.

    Returns:
        A dictionary mapping plugin names to their instantiated objects.
    """
    # Lazy import IaCPlugin
    iac_plugins_module = importlib.import_module("threat_analysis.iac_plugins")
    IaCPlugin = iac_plugins_module.IaCPlugin # Import the base class here

    plugins = {}
    plugins_dir = Path(__file__).parent / "iac_plugins"

    for plugin_file in plugins_dir.glob("*_plugin.py"):
        module_name = plugin_file.stem
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
        if spec and spec.loader:
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, IaCPlugin) and obj is not IaCPlugin:
                    try:
                        plugin_instance = obj()
                        plugins[plugin_instance.name] = plugin_instance
                        logging.info(f"Loaded IaC plugin: {plugin_instance.name}")
                    except TypeError as e:
                        logging.error(f"Failed to instantiate plugin {name}: {e}")
    return plugins


class CustomArgumentParser:
    def __init__(self, loaded_plugins: Dict[str, 'IaCPlugin']):
        self.parser = argparse.ArgumentParser(
            description="SecOpsTM Framework",
            epilog=(
                "This script also accepts SecOpsTM arguments. "
                "Use --help with SecOpsTM commands for more details." +
                "\n\nIaC Plugin Options: " +
                "\n  " + "\n  ".join([f"--{name}-path <path> ({plugin.description})" for name, plugin in loaded_plugins.items()])
            ),
            formatter_class=argparse.RawTextHelpFormatter # To preserve newlines in epilog
        )
        self.parser.add_argument(
            "--model-file",
            type=str,
            default="threatModel_Template/threat_model.md",
            help="Path to the threat model Markdown file.",
        )
        self.parser.add_argument(
            "--server", action="store_true", help="Launch the unified web server with menu."
        )
        self.parser.add_argument(
            "--log-level",
            type=str,
            default=None,
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
            help="Set the logging level (e.g., DEBUG, INFO, WARNING). Overrides the config file setting.",
        )


        self.parser.add_argument(
            "--project",
            type=str,
            help="Path to the project directory for hierarchical threat models.",
        )
        self.parser.add_argument(
            "--navigator",
            action="store_true",
            help="Generate a MITRE ATT&CK Navigator layer.",
        )
        self.parser.add_argument(
            "--attack-flow",
            action="store_true",
            help="Generate an Attack Flow JSON file for visualization.",
        )
        self.parser.add_argument(
            "--implemented-mitigations-file",
            type=str,
            help="Path to the implemented mitigations file. If not provided, the tool will look for a file named \'implemented_mitigations.txt\' in the same directory as the model or project.",
        )
        self.parser.add_argument(
            "--cve-definitions-file",
            type=str,
            help="Path to the CVE definitions file. If not provided, the tool will look for a file named \'cve_definitions.yml\' in the same directory as the model or project.",
        )

        # Dynamically add arguments for IaC plugins
        for name, plugin in loaded_plugins.items():
            self.parser.add_argument(
                f"--{name}-path",
                type=str,
                help=f"Path to the {plugin.name} configuration (e.g., project root, playbook).",
            )
        self.parser.add_argument(
            "--ai-config-file",
            type=str,
            default="config/ai_config.yaml",
            help="Path to the AI configuration file (e.g., ai_config.yaml).",
        )
        self.parser.add_argument(
            "--ai-context-file",
            type=str,
            default="config/context.yaml",
            help="Path to the AI context file (e.g., context.yaml).",
        )
        self.parser.add_argument(
            "--output-format",
            type=str,
            default="all",
            choices=["all", "html", "json", "stix"],
            help="Output format(s) to generate. Use 'json' for CI pipelines.",
        )
        self.parser.add_argument(
            "--output-file",
            type=str,
            default=None,
            help="Write the primary output to this path instead of the default timestamped directory.",
        )
        self.parser.add_argument(
            "--stdout",
            action="store_true",
            help="Print JSON report to stdout (implies --output-format json). Useful for CI pipelines.",
        )
        self.parser.add_argument(
            "--diff",
            nargs=2,
            metavar=("OLD_REPORT", "NEW_REPORT"),
            help="Compare two JSON reports and print added/resolved/changed threats. "
                 "Example: --diff output/report_old.json output/report_new.json",
        )

    def parse_args(self):
        return self.parser.parse_known_args()

def diff_threat_reports(old_path: str, new_path: str) -> int:
    """Compare two versioned JSON threat reports and print a human-readable diff.

    Delegates comparison logic to ``compare_threat_reports`` in ``threat_analysis.utils``.
    Returns exit code: 0 if no differences, 1 if differences were found, 2 on I/O error.
    """
    import json as _json

    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old_report = _json.load(f)
        with open(new_path, "r", encoding="utf-8") as f:
            new_report = _json.load(f)
    except (OSError, ValueError) as exc:
        logging.error("--diff: failed to load reports: %s", exc)
        return 2

    result = compare_threat_reports(old_report, new_report)
    added = result["added"]
    resolved = result["resolved"]
    changed_pairs = result["changed"]

    if not (added or resolved or changed_pairs):
        print("No threat differences between the two reports.")
        return 0

    if added:
        print(f"\n[+] {len(added)} NEW threat(s):")
        for t in added:
            print(f"    [{t.get('severity','?')}] {t.get('name','')} → {t.get('target','')} ({t.get('stride_category','')})")

    if resolved:
        print(f"\n[-] {len(resolved)} RESOLVED threat(s):")
        for t in resolved:
            print(f"    [{t.get('severity','?')}] {t.get('name','')} → {t.get('target','')} ({t.get('stride_category','')})")

    if changed_pairs:
        print(f"\n[~] {len(changed_pairs)} SEVERITY CHANGE(s):")
        for entry in changed_pairs:
            old_t = entry["old"]
            new_t = entry["new"]
            print(f"    {old_t.get('name','')} → {old_t.get('target','')}: "
                  f"{old_t.get('severity','?')} → {new_t.get('severity','?')}")

    return 1


def run_single_analysis(args: argparse.Namespace, loaded_iac_plugins: Dict[str, 'IaCPlugin']):
    """Runs the analysis for a single threat model file or an IaC input."""
    markdown_content_for_analysis = ""
    iac_plugin_used = False
    base_model_filepath: Optional[Path] = None
    implemented_mitigations_path: Optional[Path] = None
    cve_definitions_path: Optional[Path] = None
    cve_service: Optional[CVEService] = None

    # Check for IaC plugin arguments
    for plugin_name, plugin_instance in loaded_iac_plugins.items():
        arg_name = f"{plugin_name}_path"
        if hasattr(args, arg_name) and getattr(args, arg_name):
            logging.info(f"Processing IaC configuration with {plugin_name} plugin...")
            config_path = _validate_path_within_project(getattr(args, arg_name))
            iac_input_filename = config_path.stem # Get filename without extension
            try:
                parsed_data = plugin_instance.parse_iac_config(str(config_path)) # Pass as string
                iac_generated_content = plugin_instance.generate_threat_model_components(parsed_data)
                logging.info(f"Successfully generated threat model components from {plugin_name}.")
                iac_plugin_used = True

                # Load base protocol styles
                base_protocol_styles_path = config.BASE_PROTOCOL_STYLES_FILEPATH
                if base_protocol_styles_path.exists():
                    with open(base_protocol_styles_path, "r", encoding="utf-8") as f:
                        base_styles_content = f.read()
                    markdown_content_for_analysis = base_styles_content + "\n" + iac_generated_content
                else:
                    logging.warning(f"⚠️ Warning: Base protocol styles file not found: {base_protocol_styles_path}. Proceeding without it.")
                    markdown_content_for_analysis = iac_generated_content

                # Save generated content to a temporary .md file for further processing
                temp_model_name = f"{iac_input_filename}_{config.TIMESTAMP}.md"
                base_model_filepath = config.OUTPUT_BASE_DIR / temp_model_name
                os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
                with open(base_model_filepath, "w", encoding="utf-8") as f:
                    f.write(markdown_content_for_analysis)
                logging.info(f"Generated IaC threat model saved to: {base_model_filepath}")

                break # Process only one IaC plugin at a time
            except Exception as e:
                logging.error(f"❌ Error processing {plugin_name} config: {e}")
                sys.exit(1)

    if not iac_plugin_used:
        # If no IaC plugin was used, read from the specified model file
        original_model_path = _validate_path_within_project(args.model_file)
        with open(original_model_path, "r", encoding="utf-8") as f:
            markdown_content_for_analysis = f.read()
        
        # Ensure the output directory exists
        os.makedirs(config.OUTPUT_BASE_DIR, exist_ok=True)
        # Copy/Save the model file to the output directory
        base_model_filepath = config.OUTPUT_BASE_DIR / original_model_path.name
        with open(base_model_filepath, "w", encoding="utf-8") as f:
            f.write(markdown_content_for_analysis)
        logging.info(f"Model file saved to output directory: {base_model_filepath}")

    # Resolve paths for implemented mitigations and CVE definitions
    base_dir = base_model_filepath.parent if base_model_filepath else Path.cwd()

    implemented_mitigations_path, _ = resolve_path(
        args.implemented_mitigations_file, base_dir, "implemented_mitigations.txt"
    )
    cve_definitions_path, is_cve_path_explicit = resolve_path(
        args.cve_definitions_file, base_dir, "cve_definitions.yml"
    )

    # Lazy import CVEService
    cve_service_module = importlib.import_module("threat_analysis.core.cve_service")
    CVEService = cve_service_module.CVEService
    cve_service = CVEService(
        PROJECT_ROOT, cve_definitions_path, is_cve_path_explicit
    )

    ai_config_path = PROJECT_ROOT / (args.ai_config_file if hasattr(args, "ai_config_file") else "config/ai_config.yaml")
    context_path = PROJECT_ROOT / (args.ai_context_file if hasattr(args, "ai_context_file") else "config/context.yaml")

    framework = SecOpsTMFramework(
        markdown_content=markdown_content_for_analysis,
        model_name=get_model_name(markdown_content_for_analysis), # Derive from content
        model_description="Threat model generated from markdown file", # Derive or default
        model_file_path=str(base_model_filepath),
        original_model_path=str(original_model_path) if not iac_plugin_used else None,
        implemented_mitigations_path=str(implemented_mitigations_path) if implemented_mitigations_path else None,
        cve_service=cve_service,
        ai_config_path=ai_config_path,
        context_path=context_path,
        cve_definitions_path=cve_definitions_path # Pass cve_definitions_path to SecOpsTMFramework
    )

    threats = framework.run_analysis()

    if not threats:
        logging.error("Threat analysis failed. Please check the logs for validation errors.")
        validator = ModelValidator(framework.threat_model)
        errors = validator.validate()
        for error in errors:
            logging.error(f"- {error}")
        sys.exit(1)

    output_format = getattr(args, "output_format", "all")
    to_stdout = getattr(args, "stdout", False)
    explicit_output_file = getattr(args, "output_file", None)

    if to_stdout:
        output_format = "json"

    reports = {}
    if output_format in ("all", "html", "json"):
        reports = framework.generate_reports()

    if output_format in ("all", "stix"):
        framework.generate_stix_report()

    if output_format == "all":
        diagrams = framework.generate_diagrams()
        framework.diagram_generator.generate_metadata(
            threat_model=framework.threat_model,
            markdown_content=framework.markdown_content,
            output_path=str(base_model_filepath)
        )

    if args.navigator:
        framework.generate_navigator_layer()

    if args.attack_flow:
        generate_and_save_attack_flow(
            threat_model=framework.threat_model,
            output_dir=framework.output_base_dir,
            model_name=framework.model_name
        )

    # --output-file: copy primary output to the requested path
    if explicit_output_file and reports:
        primary_key = "json" if output_format == "json" else "html"
        primary_path = reports.get(primary_key) or reports.get("html") or reports.get("json")
        if primary_path and os.path.exists(primary_path):
            import shutil
            shutil.copy2(primary_path, explicit_output_file)
            logging.info(f"Output copied to {explicit_output_file}")

    # --stdout: print the JSON report to stdout for CI consumption
    if to_stdout:
        json_path = reports.get("json")
        if json_path and os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8") as _f:
                sys.stdout.write(_f.read())
        else:
            logging.error("--stdout requested but JSON report was not generated.")

class ColoredFormatter(logging.Formatter):
    """Custom formatter to add color to log messages."""

    # ANSI escape codes for colors
    COLOR_CODES = {
        'WARNING': '\033[93m',  # Yellow
        'ERROR': '\033[91m',    # Red
        'CRITICAL': '\033[95m', # Magenta
        'INFO': '\033[0m',      # Reset (Default)
        'DEBUG': '\033[0m',     # Reset
    }
    GREEN_CODE = '\033[92m'
    RESET_CODE = '\033[0m'

    # Keywords that trigger green color for INFO logs
    AI_INIT_KEYWORDS = [
        "Initializing RAGThreatGenerator",
        "Initializing embedding provider",
        "Load pretrained SentenceTransformer",
        "Using mistral LLM",
        "LLM initialized with model",
        "RAGThreatGenerator components initialized",
        "RAG service initialized",
        "AI services initialized",
        "Background AI initialization complete",
        "Starting AI initialization"
    ]

    def format(self, record):
        color = self.COLOR_CODES.get(record.levelname, self.RESET_CODE)
        
        # Selectively apply green to specific AI initialization INFO logs
        if record.levelname == 'INFO':
            msg = record.getMessage()
            if any(keyword in msg for keyword in self.AI_INIT_KEYWORDS):
                color = self.GREEN_CODE
                
        log_message = super().format(record)
        return f"{color}{log_message}{self.RESET_CODE}"

# --- Main entry point ---
def main():
    """Entry point for the `secopstm` CLI command."""
    print("\n🚀 SecOpsTM Framework is starting...")
    # --- Argument Parsing ---
    loaded_iac_plugins = load_iac_plugins()
    custom_parser = CustomArgumentParser(loaded_iac_plugins)
    args, remaining_argv = custom_parser.parse_args()

    # --- Logger Configuration ---
    logging.info(f"[{time.time() - _start_time_main:.4f}s] Configuring logger...")
    logger = logging.getLogger()
    
    # Determine log level
    log_level_str = args.log_level if args.log_level else config.LOG_LEVEL
    numeric_level = getattr(logging, log_level_str.upper(), None)
    if not isinstance(numeric_level, int):
        logging.warning(f"[{time.time() - _start_time_main:.4f}s] Invalid log level: {log_level_str}. Defaulting to INFO.")
        numeric_level = logging.INFO
        
    logger.setLevel(numeric_level)

    # Remove all existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create and configure console handler
    console_handler = logging.StreamHandler()
    formatter = ColoredFormatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.propagate = False
    logging.info(f"[{time.time() - _start_time_main:.4f}s] Logger configured.")

    # Reconstruct sys.argv for PyTM
    sys.argv = [sys.argv[0]] + remaining_argv

    logging.info(f"[{time.time() - _start_time_main:.4f}s] Starting main execution path.")
    if getattr(args, "diff", None):
        old_path, new_path = args.diff
        sys.exit(diff_threat_reports(old_path, new_path))

    if args.server: # Use the new --server argument
        try:
            run_server(model_filepath=args.model_file, project_path=args.project)
        except ImportError:
            logging.error(
                f"[{time.time() - _start_time_main:.4f}s] ❌ Flask is not installed. Please install it to use the web server: "
                "pip install Flask"
            )
            sys.exit(1)
    elif args.project:

        project_path = _validate_path_within_project(args.project)
        output_dir = Path(config.OUTPUT_BASE_DIR) / project_path.name
        output_dir.mkdir(parents=True, exist_ok=True)

        # Resolve root model file: main.md (multi-model project) or model.md (single-model directory)
        _root_model_file = project_path / "main.md"
        if not _root_model_file.exists() and (project_path / "model.md").exists():
            _root_model_file = project_path / "model.md"
            logging.info("Project mode: using model.md (single-model directory with data)")

        implemented_mitigations_path, _ = resolve_path(
            args.implemented_mitigations_file, project_path, "implemented_mitigations.txt"
        )
        # Also check project cve/ subdir
        _cve_subdir = project_path / "cve"
        _cve_arg = args.cve_definitions_file
        if not _cve_arg and _cve_subdir.exists():
            _cve_candidates = list(_cve_subdir.glob("*.yml")) + list(_cve_subdir.glob("*.yaml"))
            if _cve_candidates:
                _cve_arg = str(_cve_candidates[0])
        cve_definitions_path, is_cve_path_explicit = resolve_path(
            _cve_arg, project_path, "cve_definitions.yml"
        )

        # Lazy import CVEService
        cve_service_module = importlib.import_module("threat_analysis.core.cve_service")
        CVEService = cve_service_module.CVEService
        cve_service = CVEService(
            PROJECT_ROOT, cve_definitions_path, is_cve_path_explicit
        )

        # Lazy import SeverityCalculator
        severity_calculator_module = importlib.import_module("threat_analysis.severity_calculator_module")
        SeverityCalculator = severity_calculator_module.SeverityCalculator
        severity_calculator = SeverityCalculator(markdown_file_path=str(_root_model_file))
        
        # Lazy import MitreMapping
        mitre_mapping_module = importlib.import_module("threat_analysis.core.mitre_mapping_module")
        MitreMapping = mitre_mapping_module.MitreMapping
        mitre_mapping = MitreMapping(threat_model_path=str(_root_model_file))

        ai_config_path = PROJECT_ROOT / (args.ai_config_file if hasattr(args, 'ai_config_file') else "config/ai_config.yaml")
        context_path = PROJECT_ROOT / (args.ai_context_file if hasattr(args, 'ai_context_file') else "config/context.yaml")

        # Lazy import ReportGenerator
        report_generator_module = importlib.import_module("threat_analysis.generation.report_generator")
        ReportGenerator = report_generator_module.ReportGenerator
        report_generator = ReportGenerator(
            severity_calculator,
            mitre_mapping,
            implemented_mitigations_path=Path(implemented_mitigations_path),
            cve_service=cve_service,
            ai_config_path=ai_config_path,
            context_path=context_path,
            threat_model_ref=None # Project reports are generated per model, ref is set internally
        )

        project_threat_model = report_generator.generate_project_reports(project_path, output_dir)

        if args.navigator and project_threat_model:
            logging.info("🗺️ Generating ATT&CK Navigator layer for project...")
            try:
                # Lazy import AttackNavigatorGenerator
                attack_navigator_module = importlib.import_module("threat_analysis.generation.attack_navigator_generator")
                AttackNavigatorGenerator = attack_navigator_module.AttackNavigatorGenerator
                
                all_threats = project_threat_model.get_all_threats_details()
                navigator_generator = AttackNavigatorGenerator(
                    threat_model_name=str(project_threat_model.tm.name),
                    all_detailed_threats=all_threats
                )
                output_filename = f"attack_navigator_all_layer_{project_path.name.replace('example_', '')}_{config.TIMESTAMP}.json"
                output_path = output_dir / output_filename
                navigator_generator.save_layer_to_file(str(output_path))
                logging.info(f"✅ Project ATT&CK Navigator layer saved to: {output_path}")
            except Exception as e:
                logging.error(f"❌ Failed to generate project ATT&CK Navigator layer: {e}")

        if args.attack_flow and project_threat_model:
            generate_and_save_attack_flow(
                threat_model=project_threat_model,
                output_dir=output_dir,
                model_name=project_threat_model.tm.name
            )

    else:
        run_single_analysis(args, loaded_iac_plugins)

        # if "html" in reports and reports["html"]:
        #     framework.open_report_in_browser(reports["html"])


if __name__ == "__main__":
    main()
