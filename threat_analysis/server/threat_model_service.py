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

import logging
import threading
from typing import List, Dict, Any, Optional
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

class ThreatModelService:
    def __init__(self):
        # Lazy imports to speed up server startup
        from threat_analysis.core.mitre_mapping_module import MitreMapping
        from threat_analysis.severity_calculator_module import SeverityCalculator
        from threat_analysis.generation.report_generator import ReportGenerator
        from threat_analysis.generation.diagram_generator import DiagramGenerator
        from threat_analysis.core.cve_service import CVEService
        from threat_analysis.server.ai_service import AIService
        from threat_analysis.server.diagram_service import DiagramService
        from threat_analysis.server.export_service import ExportService
        from threat_analysis.server.model_management_service import ModelManagementService

        self.mitre_mapping = MitreMapping(threat_model_path="")
        self.severity_calculator = SeverityCalculator()
        self.diagram_generator = DiagramGenerator()
        
        cve_definitions_path = PROJECT_ROOT / "cve_definitions.yml"
        self.cve_service = CVEService(
            PROJECT_ROOT, cve_definitions_path, is_path_explicit=False
        )
        
        ai_config_path = PROJECT_ROOT / "config" / "ai_config.yaml"
        context_path = PROJECT_ROOT / "config" / "context.yaml"
        
        # Import queue locally to avoid circular dependency issues
        from threat_analysis.server.events import ai_status_event_queue
        
        self.report_generator = ReportGenerator(
            self.severity_calculator, 
            self.mitre_mapping,
            implemented_mitigations_path=None, 
            cve_service=self.cve_service,
            ai_config_path=ai_config_path,
            context_path=context_path
        )
        
        self.ai_service = AIService(
            config_path=str(ai_config_path),
            ai_status_event_queue=ai_status_event_queue
        )
        self.diagram_service = DiagramService(self.cve_service, self.diagram_generator)
        self.model_management_service = ModelManagementService(self.cve_service, self.diagram_service)
        
        self.export_service = ExportService(
            self.cve_service,
            self.diagram_generator,
            self.report_generator,
            self.ai_service,
            self.diagram_service,
            ai_status_event_queue=ai_status_event_queue
        )

        # P4: pre-warm CVEService in background — loads ~26 JSONL files once so the
        # first real threat analysis request does not pay the cold-start I/O cost.
        threading.Thread(
            target=self.cve_service._ensure_maps_loaded,
            daemon=True,
            name="cve-warmup",
        ).start()

    @property
    def ai_online(self):
        return self.ai_service.ai_online

    @ai_online.setter
    def ai_online(self, value):
        self.ai_service.ai_online = value

    def generate_markdown_from_prompt_sync(self, prompt, markdown):
        return self.ai_service.generate_markdown_from_prompt_sync(prompt, markdown)

    async def init_ai(self):
        await self.ai_service.init_ai()

    def check_version_compatibility(self, markdown_path: str, metadata_path: str) -> bool:
        return self.model_management_service.check_version_compatibility(markdown_path, metadata_path)

    def get_element_positions(self):
        return self.diagram_service.get_element_positions()

    def save_model_with_metadata(self, markdown_content: str, output_path: str, positions_data: Optional[Dict] = None):
        return self.model_management_service.save_model_with_metadata(markdown_content, output_path, positions_data)

    def markdown_to_json_for_gui(self, markdown_content: str):
        return self.diagram_service.markdown_to_json_for_gui(markdown_content)

    def update_diagram_logic(self, markdown_content: str, submodels: list | None = None):
        return self.diagram_service.update_diagram_logic(markdown_content, submodels)

    def export_files_logic(self, markdown_content: str, export_format: str,
                           model_file_path: Optional[str] = None):
        return self.export_service.export_files_logic(markdown_content, export_format,
                                                      model_file_path=model_file_path)

    def export_all_files_logic(self, markdown_content: str, submodels: list | None = None,
                               model_file_path: Optional[str] = None):
        return self.export_service.export_all_files_logic(markdown_content, submodels,
                                                          model_file_path=model_file_path)

    def generate_full_project_export(self, markdown_content: str, export_path: Path, submodels: list | None = None, progress_callback = None, project_root: Path | None = None, model_file_path: Optional[str] = None):
        return self.export_service.generate_full_project_export(markdown_content, export_path, submodels, progress_callback=progress_callback, project_root=project_root, model_file_path=model_file_path)

    def export_navigator_stix_logic(self, markdown_content: str, submodels: list | None = None,
                                    model_file_path: Optional[str] = None):
        return self.export_service.export_navigator_stix_logic(markdown_content, submodels,
                                                               model_file_path=model_file_path)

    def export_attack_flow_logic(self, markdown_content: str,
                                 model_file_path: Optional[str] = None):
        return self.export_service.export_attack_flow_logic(markdown_content,
                                                            model_file_path=model_file_path)

    async def generate_markdown_from_prompt(self, prompt: str, markdown: Optional[str] = None):
        async for chunk in self.ai_service.generate_markdown_from_prompt(prompt, markdown):
            yield chunk

    def _get_element_name(self, element: Any) -> str:
        if isinstance(element, dict):
            return element.get('name', 'Unknown')
        if hasattr(element, 'name'):
            return str(element.name)
        if isinstance(element, str):
            return element
        return "Unknown"

    def _merge_with_ui_positions(self, base_positions: dict, ui_positions: dict) -> dict:
        return self.diagram_service._merge_with_ui_positions(base_positions, ui_positions)

    def load_project(self, project_path: str) -> List[Dict[str, str]]:
        import glob
        import os
        if not os.path.isdir(project_path):
            return [{"path": "main.md", "content": f"Project path not found: {project_path}"}]
        
        project_files = []
        # Find all .md files, prioritizing main.md
        md_files = glob.glob(os.path.join(project_path, "**/*.md"), recursive=True)
        
        for file_path in md_files:
            rel_path = os.path.relpath(file_path, project_path)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                project_files.append({"path": rel_path, "content": content})
            except Exception as e:
                logging.error(f"Error reading {file_path}: {e}")
        
        if not any(f["path"] == "main.md" for f in project_files):
             project_files.insert(0, {"path": "main.md", "content": "# New Threat Model\n\n"})
             
        return project_files

    def resolve_submodels(self, main_model_content: str, project_files: List[Dict[str, str]]) -> List[Dict[str, str]]:
        import re
        submodels = []
        # Simple regex to find sub_model_path="path/to/submodel.md"
        matches = re.findall(r'sub_model_path\s*=\s*["\'](.*?)["\']', main_model_content)
        
        for sub_path in matches:
            # Look for this path in project_files
            found = False
            for pf in project_files:
                if pf["path"] == sub_path:
                    submodels.append(pf)
                    # Recursively find more submodels
                    submodels.extend(self.resolve_submodels(pf["content"], project_files))
                    found = True
                    break
            if not found:
                logging.warning(f"Submodel {sub_path} not found in project files.")
                
        return submodels
