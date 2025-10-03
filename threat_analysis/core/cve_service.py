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

import yaml
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional

class CVEService:
    """
    A service to handle CVE to CAPEC mappings and definitions.
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.cve_definitions_path = self.project_root / "cve_definitions.yml"
        self.cve2capec_db_path = self.project_root / "threat_analysis" / "external_data" / "cve2capec"
        self.cve_definitions = self._load_cve_definitions()
        self.cve_to_capec_map = self._load_cve_to_capec_map()

    def _load_cve_definitions(self) -> Dict[str, List[str]]:
        """Loads the user-defined CVEs for each equipment from cve_definitions.yml."""
        if not self.cve_definitions_path.exists():
            logging.warning(f"⚠️ CVE definitions file not found at {self.cve_definitions_path}. No CVE-based threats will be generated.")
            return {}
        try:
            with open(self.cve_definitions_path, 'r', encoding='utf-8') as f:
                definitions = yaml.safe_load(f) or {}
                return {str(k).strip(): v for k, v in definitions.items()}
        except Exception as e:
            logging.error(f"❌ Error loading CVE definitions file: {e}")
            return {}

    def _load_cve_to_capec_map(self) -> Dict[str, List[str]]:
        """
        Loads the CVE to CAPEC mapping from the cve2capec database.
        The database consists of multiple JSONL files, one for each year.
        """
        cve_map = {}
        if not self.cve2capec_db_path.is_dir():
            logging.warning(f"⚠️ CVE2CAPEC database directory not found at {self.cve2capec_db_path}. Cannot map CVEs to CAPECs.")
            return {}

        for jsonl_file in self.cve2capec_db_path.glob("*.jsonl"):
            try:
                with open(jsonl_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        try:
                            data = json.loads(line)
                            for cve_id, details in data.items():
                                if "CAPEC" in details and details["CAPEC"]:
                                    cve_map[cve_id] = [f"CAPEC-{capec_id}" for capec_id in details["CAPEC"]]
                        except json.JSONDecodeError:
                            logging.warning(f"Could not decode line in {jsonl_file}: {line.strip()}")
            except Exception as e:
                logging.error(f"❌ Error reading {jsonl_file}: {e}")
        
        logging.info(f"✅ Loaded {len(cve_map)} CVE to CAPEC mappings.")
        return cve_map

    def get_capecs_for_cve(self, cve_id: str) -> List[str]:
        """Returns a list of CAPEC IDs for a given CVE ID."""
        return self.cve_to_capec_map.get(cve_id, [])

    def get_cves_for_equipment(self, equipment_name: str) -> List[str]:
        """Returns a list of CVE IDs for a given equipment name."""
        return self.cve_definitions.get(equipment_name.strip(), [])
