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
import json
import datetime
from typing import Dict, Optional

from threat_analysis.core.model_factory import create_threat_model

class ModelManagementService:
    def __init__(self, cve_service, diagram_service):
        self.cve_service = cve_service
        self.diagram_service = diagram_service

    def save_model_with_metadata(self, markdown_content: str, output_path: str, positions_data: Optional[Dict] = None):
        version = "1.0"
        last_updated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        version_id = f"{version}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Split content to find if version info exists
        lines = markdown_content.split('\n')
        header_lines = []
        content_lines = []
        in_header = True
        for line in lines:
            if in_header and (line.startswith('# ') or line.strip() == ''):
                header_lines.append(line)
            else:
                in_header = False
                content_lines.append(line)
        
        cleaned_header = [line for line in header_lines if not line.startswith(('# Version:', '# Version ID:', '# Last Updated:'))]
        
        version_info = f"# Version: {version}\n# Version ID: {version_id}\n# Last Updated: {last_updated}"
        
        final_markdown_content = '\n'.join(cleaned_header)
        if final_markdown_content and not final_markdown_content.endswith('\n\n'):
            if not final_markdown_content.endswith('\n'):
                final_markdown_content += '\n'
            final_markdown_content += '\n'

        final_markdown_content = version_info + '\n\n' + '\n'.join(content_lines)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(final_markdown_content)
        
        element_positions = {}
        if positions_data:
            element_positions = positions_data
        else:
            threat_model = create_threat_model(
                markdown_content=final_markdown_content,
                model_name="SavedThreatModel",
                model_description="Model saved with metadata",
                cve_service=self.cve_service,
                validate=True
            )
            if threat_model:
                element_positions = self.diagram_service._generate_positions_from_graphviz(threat_model)
        
        metadata = {
            "version": version,
            "version_id": version_id,
            "last_updated": last_updated,
            "model_file": os.path.basename(output_path),
            "positions": element_positions
        }
        metadata_path = os.path.splitext(output_path)[0] + '_metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logging.info(f"Model saved to {output_path} and metadata to {metadata_path}")
        return metadata_path

    def check_version_compatibility(self, markdown_path: str, metadata_path: str) -> bool:
        try:
            with open(markdown_path, 'r', encoding="utf-8") as f:
                markdown_content = f.read()
            
            markdown_version = "unknown"
            markdown_version_id = "unknown"
            
            for line in markdown_content.split('\n'):
                if line.startswith('# Version:'):
                    markdown_version = line.replace('# Version:', '').strip()
                elif line.startswith('# Version ID:'):
                    markdown_version_id = line.replace('# Version ID:', '').strip()

            with open(metadata_path, 'r', encoding="utf-8") as f:
                metadata = json.load(f)
            
            metadata_version = metadata.get('version', 'unknown')
            metadata_version_id = metadata.get('version_id', 'unknown')

            if markdown_version != metadata_version:
                logging.warning(f"Version mismatch: Markdown '{markdown_version}' vs Metadata '{metadata_version}'")
                return False

            if markdown_version_id != metadata_version_id:
                logging.warning(f"Version ID mismatch: Markdown '{markdown_version_id}' vs Metadata '{metadata_version_id}'")
                return False
            
            logging.info(f"Version compatibility check passed: {markdown_version_id}")
            return True
        except FileNotFoundError:
            logging.warning(f"Compatibility check failed: One of the files not found ({markdown_path} or {metadata_path})")
            return False
        except Exception as e:
            logging.error(f"Error checking version compatibility: {e}")
            return False
